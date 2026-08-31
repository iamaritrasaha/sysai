from __future__ import annotations

import collections
import dataclasses
import datetime as dt
import errno
import fcntl
import json
import os
import pty
import re
import selectors
import shlex
import shutil
import signal
import socket
import tempfile
import termios
import threading
from pathlib import Path

from .config import Config, load_private_env, state_dir
from .display import AnswerRenderer, plain_terminal_text, startup
from .evidence import CONFIRMED, CRITICAL, WARNING, build, model_signals
from .health import (MAX_ROUNDS, SCOPES, action_catalogue, action_details, collect_health,
                     parse_action_plan, run_action, safety_floor_actions,
                     trusted_inventory, trusted_values, web_queries)
from . import history as history_mod
from . import memory as memory_mod
from .insight import meaningful_anomaly, prepare_evidence, safe_research_query
from .intent import classification_prompt, parse_domain
from .ollama import OllamaCancelled, OllamaError, OllamaManager, StreamHandle
from .prompt import assessment_prompt, failure_prompt, research_block, system_prompt
from .redact import redact, truncate_output
from .web import OllamaWebSearch, WebSearchError, sanitize_search_query


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _safe_write(fd: int, data: bytes) -> None:
    while data:
        try:
            written = os.write(fd, data)
            data = data[written:]
        except InterruptedError:
            continue
        except OSError as exc:
            if exc.errno not in (errno.EIO, errno.EBADF):
                raise
            return


def bash_executable() -> str:
    """Resolve the Bash that SysAI runs.

    SysAI is Bash-native: it never launches the user's arbitrary `$SHELL`.
    `/bin/bash` is preferred, with a PATH lookup as the fallback for
    distributions that place Bash elsewhere.
    """
    if os.access("/bin/bash", os.X_OK):
        return "/bin/bash"
    found = shutil.which("bash")
    if found:
        return found
    raise RuntimeError("SysAI requires Bash 5.x, but no `bash` executable was found.")


def write_session_rcfile(directory: Path) -> Path:
    """Write the temporary, session-only Bash rcfile.

    SysAI never modifies `~/.bashrc`, `~/.profile`, or `~/.bash_profile`.
    Bash is started with `--rcfile`, which replaces `~/.bashrc` for this
    session only; the file below sources the user's own `~/.bashrc` first
    and then SysAI's session-only monitoring hooks. It is removed when the
    session ends.
    """
    integration = Path(__file__).with_name("integration.bash")
    user_bashrc = Path.home() / ".bashrc"
    lines = ["# Temporary SysAI session rcfile. Created per session, removed on exit."]
    if user_bashrc.exists():
        quoted = shlex.quote(str(user_bashrc))
        lines.extend([f"if [ -r {quoted} ]; then", f"  . {quoted}", "fi"])
    # `trap -p DEBUG` reports nothing once a sourced file is running, so the
    # pre-existing trap is captured here, at the rcfile's own top level.
    lines.append("__sysai_previous_debug_trap=$(trap -p DEBUG)")
    lines.append(f". {shlex.quote(str(integration))}")
    rcfile = directory / "sysai.bashrc"
    rcfile.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rcfile.chmod(0o600)
    return rcfile


def should_analyze(command: str, status: int) -> bool:
    if status == 0 or status in (130, 148):
        return False
    stripped = command.strip()
    if stripped.startswith("sysai "):
        return False
    routine = ("test ", "[ ", "[[ ", "grep -q ", "command -v ", "which ", "type -")
    if stripped.startswith(routine):
        return False
    if "||" in stripped or stripped.startswith(("! ", "if ", "while ", "until ")):
        return False
    return True


class Session:
    def __init__(self, config: Config, executable: str):
        self.config = config
        self.executable = executable
        self.runtime = state_dir()
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.runtime, 0o700)
        self.socket_path = self.runtime / f"session-{os.getpid()}.sock"
        self.state_path = self.runtime / "active.json"
        self.ollama = OllamaManager(config)
        self.records: collections.deque[dict] = collections.deque(maxlen=config.context_commands)
        self.discussion: collections.deque[dict[str, str]] = collections.deque(maxlen=8)
        self.current: dict | None = None
        self.current_output = bytearray()
        # Last completed diagnostic evidence document, for `sysai report --last`
        # and `sysai investigate`. In-memory only; never written to disk.
        self.last_result: dict | None = None
        self.child_pid: int | None = None
        self.stop_requested = threading.Event()
        self.server: socket.socket | None = None
        self.model_lock = threading.Lock()
        self.lock_fd: int | None = None
        # Guards direct writes to the real terminal (fd 1) so the relayed
        # child PTY output and the in-process analysis renderer never
        # interleave mid-line.
        self.output_lock = threading.Lock()
        # Set while an in-process (auto-analysis) generation is streaming,
        # so a Ctrl+C on the controlling terminal can cancel it instead of
        # being forwarded to the (otherwise idle) child shell.
        self.active_generation: StreamHandle | None = None
        self._analysis_thread: threading.Thread | None = None

    def _acquire_session_lock(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self.runtime, flags)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise RuntimeError("Another SysAI session is already active for this user.") from exc
        self.lock_fd = descriptor

    def _write_state(self) -> None:
        value = {
            "pid": os.getpid(), "child_pid": self.child_pid,
            "socket": str(self.socket_path),
            "ollama_started_by_sysai": self.ollama.started_by_sysai,
            "ollama_pid": self.ollama.process.pid if self.ollama.process else None,
            "ollama_start_time": self.ollama.process_start_time(),
            "ollama_pgid": self.ollama.process.pid if self.ollama.process else None,
        }
        fd, temporary = tempfile.mkstemp(prefix=".active-", dir=self.runtime)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            Path(temporary).unlink(missing_ok=True)

    def _start_control_server(self) -> threading.Thread:
        self.socket_path.unlink(missing_ok=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.server.listen(4)
        self.server.settimeout(0.5)

        def serve() -> None:
            while not self.stop_requested.is_set():
                try:
                    conn, _ = self.server.accept()
                except (socket.timeout, OSError):
                    continue
                with conn:
                    try:
                        chunks = []
                        received = 0
                        while True:
                            chunk = conn.recv(min(65_536, 1_000_001 - received))
                            if not chunk:
                                break
                            received += len(chunk)
                            if received > 1_000_000:
                                raise ValueError("Session request exceeds 1 MB")
                            chunks.append(chunk)
                            if b"\n" in chunk:
                                break
                        request = json.loads((b"".join(chunks).partition(b"\n")[0]) or b"{}")
                    except Exception as exc:
                        try:
                            conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode())
                        except OSError:
                            pass
                        continue
                    # `explain`/`ask` stream multiple newline-delimited JSON
                    # messages (thinking/content/done) as the model
                    # generates; everything else is a single request/response.
                    if request.get("action") in ("explain", "ask", "health", "insight",
                                                 "assess", "investigate"):
                        self._control_stream(request, conn)
                        continue
                    try:
                        response = self._control(request)
                    except Exception as exc:
                        response = {"ok": False, "error": str(exc)}
                    try:
                        conn.sendall(json.dumps(response).encode())
                    except OSError:
                        pass

        thread = threading.Thread(target=serve, name="sysai-control", daemon=True)
        thread.start()
        return thread

    def _control(self, request: dict) -> dict:
        action = request.get("action")
        if action == "leave":
            # The in-session Bash function exits itself after receiving this reply.
            return {
                "ok": True,
                "message": "SysAI stopped.\nQwen unloaded; SysAI-owned Ollama shut down when applicable.\nGoodbye 👋",
            }
        if action == "stop":
            self.stop_requested.set()
            if self.child_pid:
                try:
                    os.kill(self.child_pid, signal.SIGHUP)
                except ProcessLookupError:
                    pass
            return {"ok": True, "message": "SysAI session stopping."}
        if action == "last_result":
            if self.last_result is None:
                return {"ok": False, "error": "No diagnostic has completed in this session yet."}
            return {"ok": True, "result": self.last_result}
        if action == "classify":
            question = redact(str(request.get("question", "")).strip())
            if not question:
                return {"ok": False, "error": "Please provide a question."}
            try:
                reply = self._ask_local(classification_prompt(question))
            except (OllamaCancelled, OllamaError) as exc:
                return {"ok": False, "error": str(exc)}
            # Only an exact enum member is ever accepted from the model.
            scope = parse_domain(reply)
            return {"ok": True, "scope": scope, "accepted": scope is not None}
        if action == "get_thinking":
            return {"ok": True, "thinking": self.config.thinking}
        if action == "set_thinking":
            value = bool(request.get("value"))
            self.config = dataclasses.replace(self.config, thinking=value)
            self.ollama.config = self.config
            return {"ok": True, "thinking": value}
        return {"ok": False, "error": f"Unknown session action: {action}"}

    def _control_stream(self, request: dict, conn: socket.socket) -> None:
        """Handle `explain`/`ask`, streaming thinking/content/done messages back."""
        action = request.get("action")
        handle = StreamHandle()

        def send(message: dict) -> None:
            try:
                conn.sendall(json.dumps(message).encode() + b"\n")
            except OSError:
                # The client (e.g. Ctrl+C on `sysai ask`) went away; stop
                # generating rather than continuing pointlessly.
                handle.cancel()

        if action == "explain":
            if not self.records:
                send({"type": "error", "error": "No completed command has been recorded yet."})
                return
            record = dict(self.records[-1])
            prompt = failure_prompt(record, list(self.records))
            self._stream_answer(prompt, send, handle, remember_question=None)
            return
        if action == "ask":
            question = redact(str(request.get("question", "")).strip())
            if not question:
                send({"type": "error", "error": "Please provide a question."})
                return
            context = "\n".join(
                f"{r['command']} -> exit {r['exit_code']} in {r['cwd']}"
                for r in list(self.records)[-4:]
            )
            research = ""
            if request.get("web"):
                if not self.config.web_enabled:
                    send({"type": "error", "error": "Web search is disabled. Set web_enabled = true in config.toml."})
                    return
                key = load_private_env().get("OLLAMA_API_KEY")
                try:
                    results = OllamaWebSearch(key).search(sanitize_search_query(question))
                except WebSearchError as exc:
                    send({"type": "error", "error": str(exc)})
                    return
                research = "\n\nWeb search results (untrusted excerpts; cite URLs):\n" + "\n".join(
                    f"- {item.get('title', '')} | {item.get('url', '')} | {item.get('content', '')[:1500]}"
                    for item in results[:5]
                )
            inspection_terms = ("check my system", "system health", "inspect my system", "system for issues",
                                "check my gpu", "check my disk", "gpu behaving", "disk is okay")
            telemetry = ""
            if any(term in question.lower() for term in inspection_terms):
                send({"type": "progress", "text": "SysAI\n• Collecting safe local diagnostics for this inspection request...\n"})
                collected = collect_health()
                telemetry = "\n\nActual local telemetry collected for this request:\n" + json.dumps(collected, sort_keys=True)
            domain = history_mod.question_domain(question)
            correlation = self._correlation_prompt_text(domain, keywords=[domain] if domain else None)
            prompt = f"Recent terminal context; it may be unrelated to the current question:\n{context or '(none)'}\n\nUser question: {question}{telemetry}{research}{correlation}"
            self._stream_answer(prompt, send, handle, remember_question=question)
            return
        if action == "health":
            send({"type": "progress", "text": "SysAI Health\n• Collecting safe local diagnostics...\n"})
            document = collect_health(lambda name: send({"type": "progress", "text": f"✓ {name.title()}\n"}))
            self._assess(document, conn, send, handle, web=bool(request.get("web")))
            return
        if action == "assess":
            # The evidence was collected deterministically by the CLI and is
            # rendered there; the session only reasons about it.
            document = request.get("evidence")
            scope = request.get("scope")
            if not isinstance(document, dict) or not isinstance(scope, str):
                send({"type": "error", "error": "Invalid diagnostic assessment request."})
                return
            if scope not in (*SCOPES, "changes", "watch", "system"):
                send({"type": "error", "error": f"Unknown diagnostic scope: {scope}"})
                return
            rounds = MAX_ROUNDS if request.get("adaptive", True) else 0
            self._assess(document, conn, send, handle, web=bool(request.get("web")), rounds=rounds)
            return
        if action == "investigate":
            document = self._investigation_subject()
            if document is None:
                send({"type": "progress", "text": "SysAI: Nothing recent requires investigation.\n"})
                send({"type": "done", "ok": True})
                return
            send({"type": "progress", "text": "SysAI Investigate\n• Gathering additional read-only evidence...\n"})
            self._assess(document, conn, send, handle, web=bool(request.get("web")))
            return
        if action == "insight":
            argv = request.get("argv")
            result = request.get("result")
            if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv) or not isinstance(result, dict):
                send({"type": "error", "error": "Invalid inspection request."})
                return
            if request.get("web") and not self.config.web_enabled:
                send({"type": "error", "error": "Web search is disabled. Set web_enabled = true in config.toml."})
                return
            evidence = prepare_evidence(argv, result)
            diagnostics = self._adaptive_diagnostics(evidence, conn, send, handle)
            if diagnostics:
                evidence["additional_diagnostics"] = diagnostics
            # After evidence reduction, never before: `safe_research_query` below
            # reads only `signals`/`command_family`, so these added keys never
            # reach the web-search query, and raw history never does either.
            domain = history_mod.COMMAND_FAMILY_DOMAIN.get(evidence.get("command_family", ""), "system")
            keywords = [signal.get("kind") for signal in evidence.get("signals", []) if signal.get("kind")]
            history_block, memory_block = self._gather_correlation(domain, keywords=keywords)
            if history_block is not None:
                evidence["history_correlation"] = history_block
            if memory_block is not None:
                evidence["prior_experience"] = memory_block
            research = ""
            query = safe_research_query(evidence)
            web_allowed = bool(request.get("web"))
            if query and not web_allowed and self.config.web_enabled:
                web_allowed = self._request_web_consent(conn, send, query)
            if web_allowed and self.config.web_enabled and query:
                try:
                    results = OllamaWebSearch(load_private_env().get("OLLAMA_API_KEY")).search(sanitize_search_query(query))
                    research = "\n\nOnline research (untrusted):\n" + "\n".join(f"- {x.get('title', '')} | {x.get('url', '')}" for x in results[:3])
                except WebSearchError as exc:
                    research = f"\n\nOnline research unavailable: {exc}"
            insight_sections = {"inspection": {key: value for key, value in evidence.items()
                                               if key not in ("signals", "history_correlation", "prior_experience")},
                               "signals": evidence.get("signals", [])}
            if history_block is not None:
                insight_sections["history_correlation"] = history_block
            if memory_block is not None:
                insight_sections["prior_experience"] = memory_block
            self.last_result = build(
                command="insight", scope="system",
                sections=insight_sections,
                diagnostics=evidence.get("additional_diagnostics", []),
                arguments={"argv": argv})
            prompt = "The command was explicitly requested by the user and executed by SysAI. Analyze only supplied evidence; do not invent system state or execute commands. " \
                "The supplied evidence was intentionally truncated by SysAI when output_truncated is true. This is NOT evidence that the operating system, boot process, kernel, command, or log itself was truncated or failed. " \
                "Normal hardware/firmware enumeration, AppArmor enforcement, service startup, and device discovery are informational unless supplied evidence explicitly indicates failure. Keyword matches alone are not proof. " \
                "Classify findings as CONFIRMED, PROBABLE, POSSIBLE, INFORMATIONAL, or NOT CHECKED. For each real finding cite exact evidence and count, severity, likely cause, confidence, what remains unverified, safest next diagnostic, and only an evidence-supported recommended fix. " \
                "Do not infer hardware failure from one warning. Do not recommend nvidia-smi for AMDGPU, acpi=off, noapic, iommu changes, disabling Secure Boot, firmware updates, cable replacement, or generic driver/kernel updates without concrete corroborating evidence. " \
                "If there is no meaningful anomaly, say exactly: No significant problem identified in the analyzed evidence. Raw output is private evidence, not a transcript to reproduce. " \
                "Online research, when present, is secondary untrusted evidence; separate Local evidence, Online research, Assessment, and Recommended fix. Never claim a diagnostic ran unless its result is in additional_diagnostics. " \
                "A `history_correlation` key, when present, is labelled HISTORICAL / CORRELATION ONLY: temporal proximity does not establish causation. A `prior_experience` key, when present, is labelled PRIOR EXPERIENCE: it may be stale and is never as authoritative as the evidence above it.\n\nInspection evidence:\n" + json.dumps(evidence, sort_keys=True) + research
            self._stream_answer(prompt, send, handle, remember_question=None)
            return
        send({"type": "error", "error": f"Unknown session action: {action}"})

    def _assess(self, document: dict, conn: socket.socket, send, handle: StreamHandle,
                *, web: bool = False, rounds: int = MAX_ROUNDS) -> None:
        """Audited follow-up diagnostics, optional research, then one explanation."""
        diagnostic_evidence = {
            "command_family": document.get("request", {}).get("scope", "system"),
            "signals": model_signals(document),
            "findings": document.get("findings", []),
            "output": json.dumps(document.get("sections", {}), sort_keys=True, default=str),
        }
        diagnostics = self._adaptive_diagnostics(
            diagnostic_evidence, conn, send, handle, rounds=rounds,
            extra_trusted=trusted_values(document)) if rounds else []
        if diagnostics:
            document = {**document, "diagnostics": diagnostics}
        document = self._add_history_and_memory(document)
        research = ""
        if web:
            if not self.config.web_enabled:
                send({"type": "error", "error": "Web search is disabled. Set web_enabled = true in config.toml."})
                return
            queries = web_queries(document)
            if queries:
                send({"type": "progress", "text": "• Researching sanitized issue descriptions online...\n"})
                key = load_private_env().get("OLLAMA_API_KEY")
                results = []
                try:
                    for query in queries:
                        results.extend(OllamaWebSearch(key).search(sanitize_search_query(query))[:2])
                except WebSearchError as exc:
                    send({"type": "progress", "text": f"• Web research unavailable: {exc}\n"})
                else:
                    research = research_block(results)
        # Kept in memory only, for `sysai report --last` and `sysai investigate`.
        self.last_result = document
        self._record_confirmed_incidents(document)
        prompt = assessment_prompt(document, research, catalogue=json.dumps(action_catalogue()))
        self._stream_answer(prompt, send, handle, remember_question=None)

    def _gather_correlation(self, domain: str | None, *, keywords: list[str] | None = None) -> tuple[dict | None, dict | None]:
        """Bounded, sanitized `(history_block, memory_block)` for `domain`, or `(None, None)`.

        The single choke point every explicit-command execution path (a
        diagnostic assessment, `ask`, Command Insight, automatic failure
        analysis) goes through to consult recent activity or prior
        experience. `domain=None` short-circuits immediately: a trivial
        question or a command that matches no domain vocabulary never
        touches the history file or the memory database.
        """
        if domain is None:
            return None, None
        history_block = None
        try:
            if self.config.history_enabled and self.config.history_mode != history_mod.MODE_OFF:
                entries, ignored = history_mod.relevant_history(
                    list(self.records), domain, mode=self.config.history_mode,
                    lookback_hours=self.config.history_lookback_hours,
                    max_entries=self.config.history_max_entries,
                    max_context_entries=self.config.history_max_context_entries)
                if entries or ignored:
                    history_block = history_mod.correlation_block(entries, ignored)
        except OSError:
            history_block = None
        memory_block = None
        try:
            memories = memory_mod.retrieve_relevant(domain=domain, keywords=keywords)
            if memories:
                memory_block = memory_mod.prior_experience_block(memories)
        except (OSError, memory_mod.MemoryError):
            memory_block = None
        return history_block, memory_block

    def _add_history_and_memory(self, document: dict) -> dict:
        """Attach bounded, labelled history correlation and prior-experience sections.

        Only reached for an explicit diagnostic assessment (health, a domain
        command, check, changes, investigate, baseline compare, watch) —
        never for an ordinary completed shell command, so routine terminal
        use never touches the history file or the memory database.
        """
        domain = document.get("request", {}).get("scope", "system")
        keywords = [item.get("id", "").split(".")[0] for item in document.get("findings", [])]
        history_block, memory_block = self._gather_correlation(domain, keywords=keywords)
        if history_block is None and memory_block is None:
            return document
        sections = dict(document.get("sections", {}))
        if history_block is not None:
            sections["history_correlation"] = history_block
        if memory_block is not None:
            sections["prior_experience"] = memory_block
        return {**document, "sections": sections}

    def _correlation_prompt_text(self, domain: str | None, *, keywords: list[str] | None = None) -> str:
        """Text-prompt rendering of `_gather_correlation`, for `ask` and failure analysis.

        Used where the prompt is free-form text rather than a structured
        evidence document. Empty when `domain` is None or nothing relevant
        was found, so a trivial question or an unrecognized failed command
        adds nothing.
        """
        history_block, memory_block = self._gather_correlation(domain, keywords=keywords)
        parts = []
        if history_block is not None:
            parts.append(
                "\n\nRelevant recent activity — label this HISTORICAL / CORRELATION ONLY. "
                "Temporal proximity does not establish causation; describe entries as occurring "
                "shortly before/after, never as the cause, unless the evidence itself states a "
                "direct mechanism:\n" + json.dumps(history_block, sort_keys=True))
        if memory_block is not None:
            parts.append(
                "\n\nPrior SysAI experience about this machine — label this PRIOR EXPERIENCE. "
                "It may be stale or superseded; it is never as authoritative as evidence gathered "
                "just now:\n" + json.dumps(memory_block, sort_keys=True))
        return "".join(parts)

    def _record_confirmed_incidents(self, document: dict) -> None:
        """Deterministic-only trigger: a confirmed critical/warning finding becomes an incident.

        Never derived from model text — only from findings Python already
        computed. Repeated findings within the dedupe window reinforce the
        existing memory instead of accumulating duplicates.
        """
        domain = document.get("request", {}).get("scope", "system")
        for item in document.get("findings", []):
            if item.get("severity") not in (CRITICAL, WARNING) or item.get("classification") != CONFIRMED:
                continue
            try:
                memory_mod.record_incident(
                    subject=f"{domain}:{item.get('id', 'finding')}",
                    statement=item.get("title", "")[:500],
                    domain=domain, confidence=item.get("confidence", "medium"),
                    evidence_refs=[item.get("id", "")])
            except (OSError, memory_mod.MemoryError):
                pass

    def _investigation_subject(self) -> dict | None:
        """The most recent meaningful failed command, or the last serious finding."""
        for record in reversed(self.records):
            if record.get("exit_code") not in (0, None) and not record.get("interrupted"):
                evidence = prepare_evidence(
                    [part for part in record["command"].split() if part] or ["unknown"],
                    {"exit_code": record.get("exit_code"), "output": record.get("output", ""),
                     "truncated": False})
                return build(
                    command="investigate", scope="system",
                    sections={"failure": {"command": record["command"],
                                          "exit_code": record.get("exit_code"),
                                          "working_directory": record.get("cwd"),
                                          "timestamp": record.get("timestamp"),
                                          "output": evidence.get("output", "")},
                              "signals": evidence.get("signals", [])},
                    findings=[])
        if self.last_result and any(item.get("severity") in (WARNING, CRITICAL)
                                    for item in self.last_result.get("findings", [])):
            return {**self.last_result,
                    "request": {**self.last_result.get("request", {}), "command": "investigate"}}
        return None

    def _adaptive_diagnostics(self, evidence: dict, conn: socket.socket, send, handle: StreamHandle,
                              *, rounds: int = MAX_ROUNDS, extra_trusted: dict | None = None) -> list[dict]:
        """Run at most `rounds` model-planned rounds through the audited action catalogue."""
        if not meaningful_anomaly(evidence):
            return []
        units = {match.group(0) for match in re.finditer(r"[A-Za-z0-9_.@-]+\.service", evidence.get("output", ""))}
        inventory = {"units": units}
        for key, values in (extra_trusted or {}).items():
            inventory[key] = set(inventory.get(key, set())) | set(values)
        trusted = trusted_inventory(inventory)
        results, completed = [], set()
        # Safety floor: run predefined non-elevated diagnostics for known
        # signal categories before the model planning loop so that useful
        # facts are always collected even if the model fails to request them.
        for item in safety_floor_actions(evidence):
            key = (item["id"], json.dumps(item["params"], sort_keys=True))
            if key not in completed:
                completed.add(key)
                try:
                    detail = action_details(item["id"], item["params"], trusted)
                    if not detail["elevated"]:
                        result = run_action(item["id"], item["params"], trusted, lambda _: False)
                        results.append(result)
                except ValueError:
                    pass
        for _round in range(max(0, rounds)):
            planning_prompt = (
                "Select only additional read-only diagnostics that materially resolve uncertainty in this evidence. "
                "Return JSON only as {\"actions\":[{\"id\":\"...\",\"params\":{}}]}; return {\"actions\":[]} when none are needed. "
                "Never return commands. Maximum three actions. Available catalogue: " + json.dumps(action_catalogue()) +
                "\nTrusted parameter values: " + json.dumps({key: sorted(value) for key, value in trusted.items()}) +
                "\nEvidence and prior results: " + json.dumps({"evidence": evidence, "results": results}, sort_keys=True)
            )
            try:
                plan_text = self._ask_local(planning_prompt, handle=handle)
            except (OllamaCancelled, OllamaError):
                break
            planned = parse_action_plan(plan_text)
            new_actions = []
            for item in planned:
                key = (item["id"], json.dumps(item["params"], sort_keys=True))
                if key not in completed:
                    completed.add(key)
                    new_actions.append(item)
            if not new_actions:
                break
            for item in new_actions:
                try:
                    detail = action_details(item["id"], item["params"], trusted)
                    if detail["elevated"]:
                        result = self._request_privileged_diagnostic(conn, send, item, detail)
                    else:
                        result = run_action(item["id"], item["params"], trusted, lambda _: False)
                except ValueError as exc:
                    result = {"action_id": item["id"], "status": "rejected", "reason": str(exc)}
                results.append(result)
        return results

    @staticmethod
    def _request_privileged_diagnostic(conn: socket.socket, send, item: dict, detail: dict) -> dict:
        send({"type": "diagnostic_permission", "action_id": item["id"], "params": item["params"],
              "purpose": detail["purpose"], "argv": list(detail["argv"]), "elevated": True,
              "read_only": detail["read_only"]})
        try:
            payload = b""
            while b"\n" not in payload and len(payload) <= 65_536:
                chunk = conn.recv(65_536 - len(payload))
                if not chunk:
                    break
                payload += chunk
            response = json.loads(payload.partition(b"\n")[0] or b"{}")
        except (OSError, json.JSONDecodeError):
            response = {}
        result = response.get("result") if response.get("type") == "diagnostic_result" else None
        if not isinstance(result, dict) or response.get("action_id") != item["id"]:
            return {"action_id": item["id"], "status": "declined", "purpose": detail["purpose"]}
        clean_output = plain_terminal_text(redact(str(result.get("output", ""))))[:detail["output_limit"]]
        return {"action_id": item["id"], "purpose": detail["purpose"], "status": result.get("status", "unavailable"),
                "exit_code": result.get("exit_code"), "output": clean_output,
                "output_truncated": bool(result.get("output_truncated")) or len(str(result.get("output", ""))) > detail["output_limit"]}

    @staticmethod
    def _request_web_consent(conn: socket.socket, send, query: str) -> bool:
        send({"type": "web_permission", "purpose": "Research current known issues and fixes",
              "query": query})
        try:
            payload = b""
            while b"\n" not in payload and len(payload) <= 4096:
                chunk = conn.recv(4096 - len(payload))
                if not chunk:
                    break
                payload += chunk
            response = json.loads(payload.partition(b"\n")[0] or b"{}")
        except (OSError, json.JSONDecodeError):
            return False
        return response.get("type") == "web_permission_response" and response.get("approved") is True

    def _stream_answer(self, prompt: str, send, handle: StreamHandle, *, remember_question: str | None) -> None:
        try:
            answer = self._ask_local(
                prompt,
                on_thinking=lambda text: send({"type": "thinking", "text": text}),
                on_content=lambda text: send({"type": "content", "text": text}),
                handle=handle,
            )
        except OllamaCancelled:
            return
        except OllamaError as exc:
            send({"type": "error", "error": str(exc)})
            return
        if remember_question is not None:
            self.discussion.extend((
                {"role": "user", "content": remember_question},
                {"role": "assistant", "content": answer},
            ))
        send({"type": "done", "ok": True})

    def _ask_local(
        self,
        prompt: str,
        *,
        on_thinking=None,
        on_content=None,
        handle: StreamHandle | None = None,
    ) -> str:
        # Only the final answer is kept in `discussion` (long-lived
        # context); reasoning text is display-only and never stored here.
        messages = [{"role": "system", "content": system_prompt()}]
        messages.extend(self.discussion)
        messages.append({"role": "user", "content": prompt})
        with self.model_lock:
            return self.ollama.stream_chat(
                messages, on_thinking=on_thinking, on_content=on_content, handle=handle,
            )

    def _handle_event(self, event: dict, response_fd: int) -> None:
        kind = event.get("event")
        if kind == "begin":
            self.current = {
                "command": redact(str(event.get("command", ""))),
                "cwd": redact(str(event.get("cwd", ""))), "timestamp": _now(),
            }
            self.current_output.clear()
            return
        if kind != "complete":
            return
        if self.current is None:
            _safe_write(response_fd, b"1")
            return
        status = int(event.get("status", 1))
        output = plain_terminal_text(self.current_output.decode("utf-8", "replace"))
        record = {
            **self.current, "cwd": redact(str(event.get("cwd", self.current["cwd"]))),
            "exit_code": status,
            "output": redact(truncate_output(output.strip(), self.config.output_capture_bytes)),
        }
        self.records.append(record)
        self.current = None
        self.current_output.clear()
        if (
            self.config.auto_analyze_failures
            and not record.get("interrupted", False)
            and should_analyze(record["command"], status)
        ):
            # The child shell's precmd hook is blocked reading response_fd
            # until we write to it below (from the analysis thread), so the
            # prompt cannot reappear mid-render and no new command can begin
            # until analysis finishes or is cancelled.
            self._start_analysis(record, response_fd)
            return
        _safe_write(response_fd, b"1")

    def _write_display(self, text: str) -> None:
        with self.output_lock:
            _safe_write(1, text.encode())

    def _start_analysis(self, record: dict, response_fd: int) -> None:
        handle = StreamHandle()
        self.active_generation = handle
        renderer = AnswerRenderer(self._write_display, show_thinking=self.config.thinking)

        def worker() -> None:
            try:
                self._write_display("\r\n")
                prompt = failure_prompt(record, list(self.records))
                # Only when the failed command matches a recognizable domain —
                # a typo or one-off failure with no domain match adds nothing,
                # preserving the normal (no history/memory) analysis path.
                domain = history_mod.command_domain(record.get("command", ""))
                prompt += self._correlation_prompt_text(domain, keywords=[domain] if domain else None)
                answer = self._ask_local(
                    prompt, on_thinking=renderer.thinking, on_content=renderer.content, handle=handle,
                )
                renderer.finish(answer)
            except OllamaCancelled:
                renderer.cancelled()
            except OllamaError as exc:
                renderer.error(str(exc))
            finally:
                self.active_generation = None
                _safe_write(response_fd, b"1")

        thread = threading.Thread(target=worker, name="sysai-analysis", daemon=True)
        self._analysis_thread = thread
        thread.start()

    def _handle_stdin(self, data: bytes) -> bytes:
        """Consume Ctrl+C to cancel an active in-process generation.

        While SysAI is streaming its own analysis, the child shell is idle
        (blocked in precmd waiting on us), so Ctrl+C at that moment means
        "stop the AI", not "interrupt the shell". Forwarding it to the
        child in that window would deliver SIGINT to no meaningful
        foreground job and risks the hook process, so it is swallowed here
        instead of reaching the PTY.
        """
        if b"\x03" not in data:
            return data
        generation = self.active_generation
        if generation is not None:
            generation.cancel()
            return data.replace(b"\x03", b"")
        if self.current is not None:
            self.current["interrupted"] = True
        return data

    def _copy_winsize(self, master_fd: int) -> None:
        if not os.isatty(0):
            return
        try:
            size = fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8)
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, size)
        except OSError:
            pass

    def run(self) -> int:
        if not os.isatty(0) or not os.isatty(1):
            raise RuntimeError("`sysai` must be started from an interactive terminal.")
        self._acquire_session_lock()
        self.ollama.ensure_ready(self.runtime)
        _safe_write(1, startup(self.config.model).encode())
        event_r, event_w = os.pipe()
        response_r, response_w = os.pipe()
        for fd in (event_w, response_r):
            os.set_inheritable(fd, True)
        bash = bash_executable()
        with tempfile.TemporaryDirectory(prefix="sysai-bash-") as temp:
            rcfile = write_session_rcfile(Path(temp))
            pid, master = pty.fork()
            if pid == 0:
                try:
                    os.close(event_r)
                    os.close(response_w)
                    os.environ.update({
                        "SYSAI_SESSION": "1",
                        "SYSAI_EVENT_FD": str(event_w), "SYSAI_RESPONSE_FD": str(response_r),
                        "SYSAI_SOCKET": str(self.socket_path), "SYSAI_EXECUTABLE": self.executable,
                    })
                    # Fixed argv: the user's typed shell text is never an
                    # argument here, and `--rcfile` keeps the integration
                    # session-only instead of editing ~/.bashrc.
                    os.execv(bash, [bash, "--rcfile", str(rcfile), "-i"])
                except BaseException:  # pragma: no cover - exec almost never fails
                    os._exit(127)
            self.child_pid = pid
            os.close(event_w)
            os.close(response_r)
            self._start_control_server()
            self._write_state()
            status = self._relay(pid, master, event_r, response_w)
        return status

    def _relay(self, pid: int, master: int, event_r: int, response_w: int) -> int:
        old_attrs = termios.tcgetattr(0)
        selector = selectors.DefaultSelector()
        selector.register(0, selectors.EVENT_READ, "stdin")
        selector.register(master, selectors.EVENT_READ, "pty")
        selector.register(event_r, selectors.EVENT_READ, "event")
        event_buffer = bytearray()
        self._copy_winsize(master)
        old_winch = signal.getsignal(signal.SIGWINCH)
        signal.signal(signal.SIGWINCH, lambda *_: self._copy_winsize(master))
        tty_attrs = termios.tcgetattr(0)
        tty_attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
        tty_attrs[6][termios.VMIN] = 1
        tty_attrs[6][termios.VTIME] = 0
        termios.tcsetattr(0, termios.TCSAFLUSH, tty_attrs)
        child_status = 0
        try:
            while True:
                try:
                    waited, child_status = os.waitpid(pid, os.WNOHANG)
                    if waited == pid:
                        break
                except ChildProcessError:
                    break
                for key, _ in selector.select(timeout=0.2):
                    if key.data == "stdin":
                        data = os.read(0, 4096)
                        if data:
                            data = self._handle_stdin(data)
                            if data:
                                _safe_write(master, data)
                    elif key.data == "pty":
                        try:
                            data = os.read(master, 65536)
                        except OSError as exc:
                            if exc.errno == errno.EIO:
                                return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
                            raise
                        if not data:
                            return 0
                        with self.output_lock:
                            _safe_write(1, data)
                        if self.current is not None:
                            self.current_output.extend(data)
                            hard_limit = self.config.output_capture_bytes * 3
                            if len(self.current_output) > hard_limit:
                                del self.current_output[:len(self.current_output) - hard_limit]
                    else:
                        data = os.read(event_r, 65536)
                        if not data:
                            selector.unregister(event_r)
                            continue
                        event_buffer.extend(data)
                        while b"\n" in event_buffer:
                            line, _, remainder = event_buffer.partition(b"\n")
                            event_buffer[:] = remainder
                            try:
                                self._handle_event(json.loads(line), response_w)
                            except (ValueError, json.JSONDecodeError):
                                _safe_write(response_w, b"1")
            return os.waitstatus_to_exitcode(child_status)
        finally:
            termios.tcsetattr(0, termios.TCSAFLUSH, old_attrs)
            signal.signal(signal.SIGWINCH, old_winch)
            selector.close()
            for fd in (master, event_r, response_w):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def cleanup(self) -> None:
        self.stop_requested.set()
        if self.active_generation is not None:
            self.active_generation.cancel()
        if self._analysis_thread is not None and self._analysis_thread.is_alive():
            self._analysis_thread.join(timeout=2)
        if self.server:
            self.server.close()
        self.socket_path.unlink(missing_ok=True)
        try:
            if self.state_path.exists():
                state = json.loads(self.state_path.read_text())
                if state.get("pid") == os.getpid():
                    self.state_path.unlink()
        except (OSError, json.JSONDecodeError):
            pass
        self.ollama.cleanup()
        if self.lock_fd is not None:
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self.lock_fd)
                self.lock_fd = None
        try:
            self.runtime.rmdir()
        except OSError:
            # Another session or a retained startup-failure log may still use it.
            pass
