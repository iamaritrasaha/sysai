from __future__ import annotations

import argparse
import dataclasses
import json
import os
import signal
import socket
import sys

from . import __version__, baseline, changes, monitor, reports, updater, whatis
from . import history as history_mod
from . import memory as memory_mod
from .collect import run as _command
from .config import (Config, ModelProfile, load_config, load_model_profiles,
                     save_model_profiles, set_config_value, state_dir)
from .diagnostics import action_details, prompt_permission
from .display import AnswerRenderer
from .doctor import doctor_command
from .domains import DOMAINS, FULL_SYSTEM
from .health import collect_scope
from .insight import classify, execute, permission_failure, permission_purpose
from .intent import keyword_route
from .ollama import OllamaError, OllamaManager, is_owned_ollama_process
from .providers import OllamaCloudProvider, OpenAICompatibleProvider
from .render import render_document
from .session import Session


def _active_socket() -> str | None:
    socket_name = os.environ.get("SYSAI_SOCKET")
    if not socket_name:
        state = state_dir() / "active.json"
        if state.exists():
            try:
                socket_name = json.loads(state.read_text()).get("socket")
            except (OSError, json.JSONDecodeError):
                pass
    return socket_name


def _session_request(action: str, **values) -> dict:
    socket_name = _active_socket()
    if not socket_name:
        return {"ok": False, "error": "No active SysAI session was found."}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(180)
            client.connect(socket_name)
            client.sendall(json.dumps({"action": action, **values}).encode())
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"Could not contact the active SysAI session: {exc}"}


def _stream_session_request(action: str, **values) -> int:
    """Send `explain`/`ask` and render the session's streamed thinking/answer live."""
    socket_name = _active_socket()
    if not socket_name:
        print("SysAI: No active SysAI session was found.", file=sys.stderr)
        return 1
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(180)
        client.connect(socket_name)
        client.sendall(json.dumps({"action": action, **values}).encode() + b"\n")
    except OSError as exc:
        print(f"SysAI: Could not contact the active SysAI session: {exc}", file=sys.stderr)
        return 1

    def write(text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    renderer = AnswerRenderer(write)
    buffer = b""
    error: str | None = None
    ok = False
    saw_done = False
    try:
        with client:
            while True:
                try:
                    chunk = client.recv(65536)
                except socket.timeout:
                    error = "Timed out waiting for a response."
                    break
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, _, buffer = buffer.partition(b"\n")
                    if not line:
                        continue
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    kind = message.get("type")
                    if kind == "thinking":
                        renderer.thinking(str(message.get("text", "")))
                    elif kind == "content":
                        renderer.content(str(message.get("text", "")))
                    elif kind == "progress":
                        # Collector progress is local, fixed text; do not put it
                        # through the model renderer or pretend it is an answer.
                        write(str(message.get("text", "")))
                    elif kind == "diagnostic_permission":
                        action_id = str(message.get("action_id", ""))
                        params = message.get("params", {})
                        trusted = {
                            "units": {params.get("unit")} if isinstance(params.get("unit"), str) else set(),
                            "devices": {params.get("device")} if isinstance(params.get("device"), str) else set(),
                            "interfaces": {params.get("interface")} if isinstance(params.get("interface"), str) else set(),
                            "packages": {params.get("package")} if isinstance(params.get("package"), str) else set(),
                        }
                        try:
                            detail = action_details(action_id, params, trusted)
                            if list(detail["argv"]) != message.get("argv") or not detail["elevated"]:
                                raise ValueError("diagnostic request mismatch")
                            approved = prompt_permission(detail)
                            result = _command(detail["argv"], timeout=detail["timeout"], limit=detail["output_limit"]) if approved else {"status": "declined"}
                        except ValueError:
                            result = {"status": "rejected"}
                        client.sendall(json.dumps({"type": "diagnostic_result", "action_id": action_id, "result": result}).encode() + b"\n")
                    elif kind == "web_permission":
                        print(f"\n{message.get('purpose', 'Search online')}\n\nSanitized query\n  {message.get('query', '')}")
                        try:
                            approved = input("\nAllow once? [y/N] ").strip().lower() in ("y", "yes")
                        except (EOFError, KeyboardInterrupt):
                            approved = False
                        client.sendall(json.dumps({"type": "web_permission_response", "approved": approved}).encode() + b"\n")
                    elif kind == "error":
                        error = str(message.get("error", "unknown error"))
                    elif kind == "done":
                        ok = bool(message.get("ok"))
                        saw_done = True
    except KeyboardInterrupt:
        # Cancel cleanly: drop the connection (the session detects this and
        # stops generating) and return control to the shell prompt.
        renderer.cancelled()
        try:
            client.close()
        except OSError:
            pass
        return 130
    if error:
        renderer.close()
        print(f"SysAI: {error}", file=sys.stderr)
        return 1
    if not saw_done:
        print("SysAI: Connection to the active session was lost.", file=sys.stderr)
        return 1
    renderer.finish()
    return 0 if ok else 1


def hook(args: list[str]) -> int:
    try:
        event_fd = int(os.environ["SYSAI_EVENT_FD"])
        response_fd = int(os.environ["SYSAI_RESPONSE_FD"])
    except (KeyError, ValueError):
        return 0
    if args[0] == "begin":
        payload = {"event": "begin", "command": args[1], "cwd": args[2]}
    else:
        payload = {"event": "complete", "status": int(args[1]), "cwd": args[2]}
    os.write(event_fd, json.dumps(payload).encode() + b"\n")
    if payload["event"] == "complete":
        try:
            os.read(response_fd, 1)
        except OSError:
            pass
    return 0


def _print_response(response: dict) -> int:
    if response.get("ok"):
        if response.get("answer"):
            renderer = AnswerRenderer(sys.stdout.write)
            renderer.content(str(response["answer"]))
            renderer.finish()
        elif response.get("message"):
            print(response["message"])
        return 0
    print(f"SysAI: {response.get('error', 'unknown error')}", file=sys.stderr)
    return 1


def stop_outside() -> int:
    response = _session_request("stop")
    if response.get("ok"):
        print("SysAI stopping. The local model will unload; SysAI-owned Ollama will shut down.")
        return 0
    # Recover state left behind by an abnormally terminated SysAI process.
    state_path = state_dir() / "active.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except (OSError, json.JSONDecodeError):
            state = {}
        # Stop an orphaned SysAI-owned Ollama server.
        pid = state.get("ollama_pid")
        start_time = state.get("ollama_start_time")
        pgid = state.get("ollama_pgid")
        if (
            state.get("ollama_started_by_sysai")
            and all(isinstance(value, int) for value in (pid, start_time, pgid))
            and is_owned_ollama_process(pid, start_time, pgid)
        ):
            try:
                os.killpg(pid, signal.SIGTERM)
            except OSError:
                pass
            state_path.unlink(missing_ok=True)
            print("Stopped the orphaned SysAI-owned Ollama server.")
            return 0
        # Detect stale state: connection was refused but the SysAI process
        # is no longer running.  Clean up silently rather than alarming the
        # user with a "Connection refused" error.
        sysai_pid = state.get("pid")
        if isinstance(sysai_pid, int):
            try:
                os.kill(sysai_pid, 0)
            except ProcessLookupError:
                state_path.unlink(missing_ok=True)
                print("SysAI was already stopped (cleaned up stale state).")
                return 0
            except OSError:
                pass
    return _print_response(response)


def thinking_command(state: str) -> int:
    if state == "status":
        response = _session_request("get_thinking")
        if response.get("ok"):
            print(f"Thinking display: {'on' if response['thinking'] else 'off'} (active session)")
            return 0
        value = load_config().thinking
        print(f"Thinking display: {'on' if value else 'off'} (from config; no active session)")
        return 0
    value = state == "on"
    set_config_value("thinking", value)
    response = _session_request("set_thinking", value=value)
    if response.get("ok"):
        print(f"Thinking display turned {state} for the active session and saved for future sessions.")
    else:
        print(f"Thinking display turned {state}. It will take effect the next time SysAI starts.")
    return 0


def insight_command(argv: list[str], *, raw: bool = False, web: bool = False) -> int:
    allowed, reason, explicit_sudo = classify(argv)
    if not allowed:
        print(f"SysAI: {reason}", file=sys.stderr)
        return 2
    if not _active_socket():
        print("SysAI: No active SysAI session was found.", file=sys.stderr)
        return 1
    print(f"SysAI\n• Inspecting {' '.join(argv)}...")
    result = execute(argv)
    if not explicit_sudo and result.get("exit_code") not in (0, None) and permission_failure(result["output"]):
        prompt = "\nSysAI needs elevated access\n\nPurpose\n  " + permission_purpose(argv) + "\n\nRetry as\n  sudo " + " ".join(argv) + "\n\nAccess\n  Elevated, read-only\n\nAllow once? [y/N] "
        try:
            approved = input(prompt).strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            approved = False
        if approved:
            result = execute(["sudo", *argv])
    if raw and result.get("output"):
        print(result["output"])
    return _stream_session_request("insight", argv=argv, result=result, web=web)


NO_SESSION_NOTE = (
    "SysAI: the local model assessment needs an active SysAI session.\n"
    "       Start one with `sysai`, then run this command again.\n"
    "       The deterministic diagnostics above were collected without it."
)


def _write(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def _assess_or_note(scope: str, document: dict, web: bool, *, adaptive: bool = True) -> int:
    """Hand deterministic evidence to the session for explanation, if one is running."""
    if not _active_socket():
        print(NO_SESSION_NOTE, file=sys.stderr)
        return 0
    return _stream_session_request("assess", scope=scope, evidence=document,
                                   web=web, adaptive=adaptive)


def domain_command(scope: str, *, web: bool = False, command: str | None = None) -> int:
    """Collect one domain deterministically, render it, then explain it."""
    document = collect_scope(scope, web=web, command=command or scope)
    _write(render_document(document))
    _write("\n")
    return _assess_or_note(scope, document, web)


def check_command(question: str, *, web: bool = False) -> int:
    question = " ".join(str(question).split())
    if not question:
        print("SysAI: Please describe what you want checked.", file=sys.stderr)
        return 2
    scope, matched = keyword_route(question)
    method = "keywords"
    if scope is None:
        # Only a genuinely ambiguous question reaches the model, and its reply
        # must be one name from the strict enum or it is discarded.
        response = _session_request("classify", question=question)
        scope = response.get("scope") if response.get("ok") else None
        method = "model" if scope else "fallback"
        if scope not in (*DOMAINS, FULL_SYSTEM):
            scope = FULL_SYSTEM
    _write(f"SysAI Check\n• Question: {question}\n"
           f"• Routed to: {scope} ({method}"
           + (f": {', '.join(matched[:4])}" if matched else "") + ")\n\n")
    document = collect_scope(scope, web=web, command="check")
    document["request"]["arguments"] = {"question": question, "routing": method}
    _write(render_document(document))
    _write("\n")
    return _assess_or_note(scope, document, web)


def investigate_command(*, web: bool = False) -> int:
    if not _active_socket():
        print("SysAI: No active SysAI session was found.", file=sys.stderr)
        return 1
    return _stream_session_request("investigate", web=web)


def what_command(parts: list[str]) -> int:
    """Explain a command. Nothing here executes it."""
    text = parts[0] if len(parts) == 1 else " ".join(parts)
    result = whatis.explain(text)
    _write(whatis.render(result))
    return 0 if not result.get("parse_error") else 2


def report_command(scope: str, *, last: bool = False, as_json: bool = False,
                   output: str | None = None) -> int:
    if last:
        response = _session_request("last_result")
        if not response.get("ok"):
            print(f"SysAI: {response.get('error', 'No previous diagnostic result is available.')}",
                  file=sys.stderr)
            return 1
        document = response["result"]
    else:
        target = FULL_SYSTEM if scope in ("health", "full", "system", FULL_SYSTEM) else scope
        document = collect_scope(target, command="report")
    text = reports.to_json(document) if as_json else reports.to_markdown(document)
    if not output:
        _write(text)
        return 0
    path = reports.write(output, text)
    print(f"SysAI: report written to {path} (mode 0600).")
    return 0


def baseline_command(action: str) -> int:
    try:
        if action == "create":
            path, document = baseline.create()
            print(f"SysAI: baseline written to {path} (mode 0600).")
            print(f"       Created {document['created']}; deterministic sanitized facts only.")
            return 0
        if action == "show":
            _write(baseline.render_snapshot(baseline.load()))
            return 0
        if action == "delete":
            removed = baseline.delete()
            print("SysAI: baseline deleted." if removed else "SysAI: no baseline exists.")
            return 0
        result = baseline.compare(baseline.load())
        _write(baseline.render_comparison(result))
    except baseline.BaselineError as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 1
    if not result["change_count"] or not _active_socket():
        return 0
    _write("\n")
    document = {"schema_version": 1, "request": {"command": "baseline compare", "scope": "system"},
                "system": result["current"].get("system", {}),
                "sections": {"baseline_comparison": {
                    "changed": result["changed"], "added": result["added"],
                    "removed": result["removed"], "baseline_created": result["baseline_created"]}},
                "findings": [], "diagnostics": [], "unavailable": [],
                "timestamp": result["compared_at"]}
    return _stream_session_request("assess", scope="system", evidence=document,
                                   web=False, adaptive=False)


def changes_command(since: str | None, *, web: bool = False) -> int:
    try:
        document = changes.collect_changes(since, web=web)
    except changes.ChangesError as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 2
    _write(changes.render_changes(document))
    _write("\n")
    return _assess_or_note("changes", document, web)


def watch_command(domain: str, duration: int, interval: int, *, web: bool = False) -> int:
    try:
        monitor.validate(duration, interval)
    except monitor.WatchError as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 2
    _write(f"SysAI Watch · {domain}\n"
           f"• Sampling every {interval}s for up to {duration}s. Press Ctrl+C to stop early.\n\n")

    interactive = sys.stdout.isatty()

    def progress(index: int, _sample: dict) -> None:
        if interactive:
            _write(f"\r  sample {index}   ")

    try:
        result = monitor.run_watch(domain, duration, interval, on_sample=progress)
    except monitor.WatchError as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 2
    if interactive:
        _write("\r" + " " * 24 + "\r")
    summary = monitor.summarize(result)
    kernel = monitor.kernel_events_during(result)
    _write(monitor.render_summary(result, summary, kernel))
    _write("\n")
    document = monitor.build_evidence(result, summary, kernel, web=web)
    # One model call, after sampling; never per sample, and no research during it.
    return _assess_or_note("watch", document, web, adaptive=False)


def update_command(action: str) -> int:
    try:
        status = updater.check()
    except updater.UpdateError as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 1
    if action == "check":
        _write(updater.render_check(status))
        return 0
    if not status["update_available"]:
        print(f"SysAI is up to date ({status['current_version']}).")
        return 0
    state = updater.installation_state()
    if state["kind"] == "checkout":
        print(f"SysAI: {status['latest_version']} is available, but this SysAI runs from a "
              f"{state['detail']} at {state['path']}.")
        print("SysAI does not update a repository checkout, and never pulls from a branch.")
        print(updater.manual_instructions(status))
        return 1
    if not status["verifiable"]:
        print(f"SysAI: A newer release exists ({status['latest_version']}), but automatic update "
              "is unavailable because no verifiable release artifact/checksum is published.")
        print(updater.manual_instructions(status))
        return 1
    try:
        result = updater.apply()
    except updater.UpdateError as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 1
    if result.get("applied"):
        print(f"SysAI updated to {result['latest_version']} from a checksum-verified release.")
        return 0
    print(f"SysAI: automatic update was not applied ({result.get('reason', 'unknown')}).")
    print(updater.manual_instructions(status))
    return 1


def history_command(*, all_mode: bool = False, as_json: bool = False) -> int:
    config = load_config()
    mode = history_mod.MODE_ALL if all_mode else config.history_mode
    if not config.history_enabled:
        mode = history_mod.MODE_OFF
    entries, ignored = history_mod.relevant_history(
        [], "system", mode=mode, lookback_hours=config.history_lookback_hours,
        max_entries=config.history_max_entries,
        max_context_entries=config.history_max_context_entries)
    if as_json:
        print(json.dumps({"mode": mode, "ignored_count": ignored, "entries": entries}, sort_keys=True))
        return 0
    _write(history_mod.render_history(entries, ignored, all_mode=all_mode))
    return 0


def memory_command(args: list[str]) -> int:
    action = args[0] if args else "list"
    rest = args[1:]
    if action == "list":
        _write(memory_mod.render_memory_list(memory_mod.list_memories()))
        return 0
    if action == "stats":
        _write(memory_mod.render_memory_overview())
        return 0
    if action == "search":
        query = " ".join(rest)
        if not query:
            print("SysAI: Please provide a search query.", file=sys.stderr)
            return 2
        _write(memory_mod.render_memory_list(memory_mod.search(query)))
        return 0
    if action == "show":
        if not rest:
            print("SysAI: Please provide a memory ID.", file=sys.stderr)
            return 2
        record = memory_mod.get(rest[0])
        if not record:
            print(f"SysAI: No memory with ID {rest[0]}.", file=sys.stderr)
            return 1
        _write(memory_mod.render_memory_list([record]))
        return 0
    if action == "forget":
        if not rest:
            print("SysAI: Please provide a memory ID.", file=sys.stderr)
            return 2
        removed = memory_mod.forget(rest[0])
        print(f"SysAI: memory {rest[0]} " + ("deleted." if removed else "not found."))
        return 0 if removed else 1
    if action == "purge":
        try:
            approved = input(
                "This will delete SysAI's persistent memories.\nContinue? [y/N] "
            ).strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            approved = False
        if not approved:
            print("SysAI: memory purge cancelled.")
            return 1
        count = memory_mod.purge()
        print(f"SysAI: {count} memory record(s) deleted.")
        return 0
    print(f"SysAI: unknown memory action: {action}", file=sys.stderr)
    return 2


def remember_command(text: str) -> int:
    text = " ".join(str(text).split())
    if not text:
        print("SysAI: Please provide something to remember.", file=sys.stderr)
        return 2
    record = memory_mod.remember(text)
    print(f"SysAI: remembered [{record['id']}] {record['statement']}")
    return 0


def feedback_command(args: list[str]) -> int:
    if not args:
        print("SysAI: Please provide feedback, e.g. `sysai feedback yes` or a short correction.",
              file=sys.stderr)
        return 2
    if args == ["yes"]:
        record = memory_mod.record_feedback("The previous SysAI assessment was confirmed correct.",
                                             positive=True)
    elif args == ["no"]:
        record = memory_mod.record_feedback("The previous SysAI assessment was reported incorrect.",
                                             positive=False)
    else:
        record = memory_mod.record_feedback(" ".join(args))
    print(f"SysAI: recorded feedback [{record['id']}].")
    return 0


def context_command() -> int:
    config = load_config()
    session_response = _session_request("last_result")
    session_active = _active_socket() is not None
    entries, ignored = history_mod.relevant_history(
        [], "system", mode=config.history_mode if config.history_enabled else history_mod.MODE_OFF,
        lookback_hours=config.history_lookback_hours, max_entries=config.history_max_entries,
        max_context_entries=config.history_max_context_entries)
    mem_stats = memory_mod.stats()
    lines = ["SysAI Context", "", "Session"]
    lines.append(f"  {'active' if session_active else 'no active session'}")
    if session_response.get("ok") and isinstance(session_response.get("result"), dict):
        last = session_response["result"]
        findings = last.get("findings", [])
        lines.append(f"  Last diagnostic: {last.get('request', {}).get('command', 'unknown')}"
                     f" ({len(findings)} finding(s))")
    lines.append("")
    lines.append("Relevant history")
    lines.append(f"  {len(entries)} event(s), {ignored} ignored as unrelated")
    lines.append("")
    lines.append("Memory")
    lines.append(f"  {mem_stats['total']} total")
    for type_ in memory_mod.TYPES:
        count = mem_stats["by_type"].get(type_, 0)
        if count:
            lines.append(f"    {type_}: {count}")
    _write("\n".join(lines) + "\n")
    return 0


def _qualified_model(value: str) -> tuple[str, str]:
    if ":" in value and value.split(":", 1)[0].lower() in ("ollama", "remote", "openai", "openai-compatible", "openai_compatible"):
        provider, name = value.split(":", 1)
        return ("ollama" if provider.lower() == "ollama" else "openai-compatible", name)
    return load_config().provider, value


def _profile_config(config: Config, profile: ModelProfile) -> Config:
    return dataclasses.replace(config, provider=profile.provider, model=profile.name,
                               ollama_url=profile.base_url if profile.provider == "ollama" else config.ollama_url,
                               ollama_auth_env=profile.api_key_env if profile.provider == "ollama" else "",
                               model_endpoint=profile.base_url, api_key_env=profile.api_key_env,
                               active_model_id=profile.id)


def _profile_status(profile: ModelProfile) -> tuple[bool, str]:
    candidate = _profile_config(load_config(), profile)
    if profile.provider == "ollama":
        manager = OllamaManager(candidate, auth_env=profile.api_key_env)
        if not manager.available():
            return False, "unreachable"
        if profile.name and profile.name not in manager.models():
            return False, "model unavailable"
        return True, profile.base_url
    provider = OpenAICompatibleProvider(candidate)
    return provider.available(), ("configured" if provider.available() else "missing API key")


def add_model_profile() -> int:
    print("Select provider\n\n  1. Ollama Local\n  2. Ollama Cloud\n  3. Remote Ollama\n  4. Compatible API")
    try:
        choice = input("\nSelect [1-4]: ").strip()
        if choice not in ("1", "2", "3", "4"):
            raise ValueError
        if choice == "1":
            print("✓ No configuration required.\nDiscovering models...")
            names = OllamaManager(load_config()).models()
            print("  " + (", ".join(names) if names else "No local models discovered."))
            return 0
        if choice == "2":
            print("✓ Using Ollama Cloud authentication.\nDiscovering models...")
            config = load_config()
            names = [name for name in OllamaManager(config).models() if name.lower().endswith(":cloud")]
            if os.environ.get("OLLAMA_API_KEY"):
                names.extend(OllamaCloudProvider(config).manager.models())
            names = list(dict.fromkeys(names))
            print("  " + (", ".join(names) if names else "Cloud is not configured or no models are available."))
            return 0
        endpoint = input("Endpoint: ").strip().rstrip("/")
        provider = "ollama" if choice == "3" else "openai-compatible"
        api_key_env = ""
        model = ""
        if provider == "ollama":
            candidate = dataclasses.replace(load_config(), ollama_url=endpoint)
            manager = OllamaManager(candidate)
            names, status = manager.models_result()
            if status == "authentication required":
                api_key_env = input("API key environment variable (optional): ").strip()
                manager = OllamaManager(candidate, auth_env=api_key_env)
                names, status = manager.models_result()
            if status != "ok":
                print(f"SysAI: could not discover remote models ({status}).", file=sys.stderr)
                return 1
            if not names:
                print("SysAI: remote Ollama returned no models.", file=sys.stderr)
                return 1
            print("Discovered models: " + ", ".join(names))
        else:
            model = input("Model: ").strip()
            api_key_env = input("API key environment variable (optional): ").strip()
    except (EOFError, KeyboardInterrupt, ValueError):
        print("SysAI: provider setup cancelled.", file=sys.stderr)
        return 1
    if not endpoint or (provider != "ollama" and not model):
        print("SysAI: endpoint and model are required for a compatible API.", file=sys.stderr)
        return 2
    profiles = load_model_profiles()
    prefix = "remote-ollama" if choice == "3" else "api"
    used = {profile.id for profile in profiles}
    index, profile_id = 1, prefix
    while profile_id in used:
        index += 1
        profile_id = f"{prefix}-{index}"
    profile = ModelProfile(profile_id, provider, model, endpoint, api_key_env)
    save_model_profiles([*profiles, profile])
    print(f"SysAI: added model profile {profile.id}. Use `sysai models use {profile.id}` to select it.")
    return 0


def models_command(action: str | None = None, model: str | None = None) -> int:
    config = load_config()
    profiles = load_model_profiles()
    if action == "add":
        return add_model_profile()
    if action == "remove":
        target = next((profile for profile in profiles if profile.id == model), None)
        if target is None:
            print(f"SysAI: no model profile named '{model}'.", file=sys.stderr)
            return 1
        save_model_profiles([profile for profile in profiles if profile.id != model])
        print(f"SysAI: removed model profile {model}.")
        return 0
    if action == "use":
        if not model:
            print("SysAI: please provide a model name.", file=sys.stderr)
            return 2
        profile = next((item for item in profiles if item.id == model), None)
        provider, name = (profile.provider, profile.name) if profile else _qualified_model(model)
        if profile:
            config = _profile_config(config, profile)
        candidate = dataclasses.replace(config, provider=provider, model=name)
        if provider == "ollama":
            manager = OllamaManager(candidate, auth_env=candidate.ollama_auth_env)
            if not manager.available():
                print("SysAI: Ollama is unavailable; cannot verify that model.", file=sys.stderr)
                return 1
            if not manager.model_available():
                print(f"SysAI: Ollama model '{name}' is not installed.", file=sys.stderr)
                return 1
        elif not OpenAICompatibleProvider(candidate).available():
            print("SysAI: remote model requires a configured endpoint and API key environment variable.", file=sys.stderr)
            return 1
        set_config_value("provider", provider)
        set_config_value("model", name)
        set_config_value("ollama_url", candidate.ollama_url)
        set_config_value("ollama_auth_env", candidate.ollama_auth_env)
        set_config_value("model_endpoint", candidate.model_endpoint)
        set_config_value("api_key_env", candidate.api_key_env)
        set_config_value("active_model_id", profile.id if profile else "")
        print(f"SysAI: default model saved: {name} · {provider}")
        return 0
    if action == "consent-reset":
        set_config_value("remote_consent", False)
        print("SysAI: remote-provider consent reset.")
        return 0
    manager = OllamaManager(config)
    local = manager.models() if manager.available() else []
    print("SysAI Models\n\nLOCAL")
    if local:
        for name in local:
            mark = "✓" if config.provider == "ollama" and config.model == name else "○"
            print(f"  {mark} {name}\n    Ollama")
    else:
        print("  (Ollama unavailable or no installed models)")
    print("\nREMOTE")
    remote_profiles = [profile for profile in profiles if profile.provider != "ollama" or profile.base_url != config.ollama_url]
    if remote_profiles:
        for profile in remote_profiles:
            available, detail = _profile_status(profile)
            mark = "✓" if available else "✗"
            selected = " · selected" if config.active_model_id == profile.id else ""
            print(f"  {mark} {profile.id}: {profile.name}\n    {profile.provider} · {profile.base_url}{selected}\n    {detail}")
    else:
        print("  (no remote model configured)")
    print(f"\nDefault\n  {config.model} · {config.provider}")
    return 0


def _startup_choices(config: Config) -> list[tuple[str, str, str, str, str]]:
    """Return (section, provider, model, endpoint, profile_id) choices."""
    choices = []
    local = OllamaManager(config)
    local_models = local.models() if local.available() else []
    for name in local_models:
        section = "OLLAMA CLOUD" if name.lower().endswith(":cloud") else "LOCAL"
        choices.append((section, "ollama", name, config.ollama_url, ""))
    profiles = load_model_profiles()
    for profile in profiles:
        candidate = _profile_config(config, profile)
        if profile.provider == "ollama":
            manager = OllamaManager(candidate)
            names = manager.models() if manager.available() else []
            for name in names:
                if profile.base_url.rstrip("/") == config.ollama_url.rstrip("/"):
                    continue
                choices.append(("REMOTE OLLAMA", "ollama", name, profile.base_url, profile.id))
        elif OpenAICompatibleProvider(candidate).available():
            choices.append(("OTHER", profile.provider, profile.name, profile.base_url, profile.id))
    if os.environ.get("OLLAMA_API_KEY"):
        cloud = OllamaCloudProvider(config)
        for name in cloud.manager.models():
            choices.append(("OLLAMA CLOUD", "ollama-cloud", name, "https://ollama.com", "cloud:" + name))
    return choices


def _choice_config(config: Config, choice: tuple[str, str, str, str, str]) -> Config:
    _section, provider, name, endpoint, profile_id = choice
    if profile_id and not profile_id.startswith("cloud:"):
        profile = next((item for item in load_model_profiles() if item.id == profile_id), None)
        if profile:
            return _profile_config(config, profile)
    return dataclasses.replace(config, provider=provider, model=name,
                               ollama_url=endpoint if provider == "ollama" else config.ollama_url,
                               model_endpoint=endpoint if provider != "ollama" else config.model_endpoint,
                               active_model_id=profile_id)


def select_model() -> Config | None:
    config = load_config()
    choices = _startup_choices(config)
    if not choices:
        print("SysAI Models\n\nLOCAL\n  (no available local models)\n\nOLLAMA CLOUD\n  (not configured)\n\nOTHER\n  (no configured remote API)\n\nAdd a provider with: sysai models add", file=sys.stderr)
        return None
    print("SysAI\nLocal Linux Intelligence\n\nSelect a model\n")
    current = None
    shown_sections = set()
    for index, (section, provider, name, endpoint, profile_id) in enumerate(choices, 1):
        if section not in shown_sections:
            if shown_sections:
                print()
            print(section)
            shown_sections.add(section)
        marked = ((bool(profile_id) and config.active_model_id == profile_id) or
                  (not profile_id and not config.active_model_id and config.provider == provider and config.model == name))
        location = "Local" if section == "LOCAL" else "Cloud" if section == "OLLAMA CLOUD" else endpoint
        print(f"  {index}. {'✓' if marked else ' '} {name}\n      Ollama · {location}" if provider.startswith("ollama") else
              f"  {index}. {'✓' if marked else ' '} {name}\n      Compatible API · {endpoint}")
        if marked:
            current = index
    placeholders = {
        "REMOTE OLLAMA": "(no remote Ollama configured)",
        "OLLAMA CLOUD": "(not configured; sign in with Ollama or set OLLAMA_API_KEY)",
        "OTHER": "(no configured remote API)",
    }
    for section, placeholder in placeholders.items():
        if section not in shown_sections:
            print(f"\n{section}\n  {placeholder}")
    if not any(section in shown_sections for section in ("REMOTE OLLAMA", "OTHER")):
        print("\nAdd a remote model with: sysai models add")
    if len(choices) == 1:
        print("\nPress Enter to continue, or choose another model.")
    else:
        print(f"\nSelect [1-{len(choices)}]" + (f" (default {current})" if current else "") + ": ", end="")
    try:
        raw = input().strip()
        index = current or 1 if not raw else int(raw)
        choice = choices[index - 1]
    except (ValueError, IndexError, EOFError, KeyboardInterrupt):
        print("SysAI: model selection cancelled.", file=sys.stderr)
        return None
    selected = _choice_config(config, choice)
    print(f"\n✓ Model selected: {selected.model}")
    return selected


# Every word argparse owns. A reserved word is never re-interpreted as a raw
# Command Insight command, so `sysai disk` is the disk diagnostic and not an
# attempt to run a program called `disk`.
RESERVED = {
    "explain", "investigate", "ask", "check", "health", "doctor", "what", "report",
    "baseline", "changes", "watch", "update", "thinking", "stop",
    "history", "memories", "remember", "feedback", "context",
    *DOMAINS, "models", "--model", "--help", "-h", "--version",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sysai", description="Local Linux Intelligence Bash session")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--model", dest="model_override", nargs="?", const="__select__", metavar="MODEL",
                        help="select a model, or open the interactive selector")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("explain", help="analyze the most recently completed command")
    investigate = sub.add_parser("investigate", help="gather more safe evidence about the last failure")
    investigate.add_argument("--web", action="store_true", help="research sanitized findings online")

    ask = sub.add_parser("ask", help="ask a local Ubuntu/Linux question")
    ask.add_argument("--web", action="store_true", help="research this sanitized question online")
    ask.add_argument("question", nargs="+")

    check = sub.add_parser("check", help="answer a plain-language question about this machine")
    check.add_argument("--web", action="store_true", help="research sanitized findings online")
    check.add_argument("question", nargs="+")

    health = sub.add_parser("health", help="summarize every diagnostic domain")
    health.add_argument("--web", action="store_true", help="research sanitized detected issues online")

    doctor = sub.add_parser("doctor", help="diagnose SysAI's own installation")
    doctor.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")

    for domain in DOMAINS:
        domain_parser = sub.add_parser(domain, help=f"diagnose {domain}")
        domain_parser.add_argument("--web", action="store_true",
                                   help="research sanitized detected issues online")

    what = sub.add_parser("what", help="explain a command without running it")
    what.add_argument("target", nargs="+", metavar="COMMAND")

    report = sub.add_parser("report", help="produce a sanitized diagnostic report")
    report.add_argument("scope", nargs="?", default="health",
                        choices=["health", "full_system", *DOMAINS])
    report.add_argument("--last", action="store_true",
                        help="report the last completed diagnostic from this session")
    report.add_argument("--json", action="store_true", dest="as_json", help="JSON instead of Markdown")
    report.add_argument("--output", metavar="PATH", help="write the report to PATH (mode 0600)")

    baseline_parser = sub.add_parser("baseline", help="record and compare system facts")
    baseline_parser.add_argument("action", choices=["create", "compare", "show", "delete"])

    changes_parser = sub.add_parser("changes", help="show what changed on this machine")
    changes_parser.add_argument("--since", default=changes.DEFAULT_SINCE,
                                metavar="VALUE",
                                help="last-boot (default), today, yesterday, 48h, 7d, or a date")
    changes_parser.add_argument("--web", action="store_true", help="research sanitized findings online")

    watch = sub.add_parser("watch", help="sample one domain for a bounded window")
    watch.add_argument("domain", choices=list(monitor.WATCHABLE))
    watch.add_argument("--duration", type=int, default=monitor.DEFAULT_DURATION, metavar="SEC")
    watch.add_argument("--interval", type=int, default=1, metavar="SEC")
    watch.add_argument("--web", action="store_true",
                       help="research sanitized findings once, after sampling finishes")

    update = sub.add_parser("update", help="check for or install a verified SysAI release")
    update.add_argument("action", nargs="?", default="apply", choices=["check", "apply"])

    thinking = sub.add_parser("thinking", help="control the live reasoning display")
    thinking.add_argument("state", choices=["on", "off", "status"])
    sub.add_parser("stop", help="stop an active SysAI session")

    models = sub.add_parser("models", help="list available providers/models")
    models.add_argument("action", nargs="?", choices=["add", "remove", "use", "consent-reset"],
                        help="save a default model or reset remote consent")
    models.add_argument("model", nargs="?", help="model name, optionally provider:model")

    history_parser = sub.add_parser("history", help="SysAI's interpretation of recent relevant activity")
    history_parser.add_argument("--all", action="store_true", dest="all_mode",
                                help="show bounded sanitized recent history, not just relevant activity")
    history_parser.add_argument("--json", action="store_true", dest="as_json",
                                help="machine-readable output")

    memory_parser = sub.add_parser("memories", help="local structured experience memory")
    memory_parser.add_argument("action", nargs="?", default="list",
                               choices=["list", "search", "show", "forget", "purge", "stats"])
    memory_parser.add_argument("rest", nargs="*", help="query, ID, etc.")

    remember_parser = sub.add_parser("remember", help="save an explicit local memory")
    remember_parser.add_argument("text", nargs="+")

    feedback_parser = sub.add_parser("feedback", help="confirm, reject, or correct the last assessment")
    feedback_parser.add_argument("text", nargs="+")

    sub.add_parser("context", help="what SysAI currently knows, without dumping data")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "__hook":
        return hook(argv[1:])
    if argv[:2] == ["__session", "stop"]:
        return _print_response(_session_request("leave"))
    # Global insight flags intentionally precede an otherwise ordinary argv.
    if argv and argv[0] in ("--raw", "--web"):
        raw = web = False
        while argv and argv[0] in ("--raw", "--web"):
            flag = argv.pop(0)
            raw |= flag == "--raw"
            web |= flag == "--web"
        if not argv:
            # Preserve ordinary global argparse help/version behavior.
            return main(["--help"])
        if argv[0] in RESERVED:
            return main([argv[0], *(["--web"] if web else []), *argv[1:]])
        return insight_command(argv, raw=raw, web=web)
    if argv and argv[0] not in RESERVED:
        return insight_command(argv)

    parser = build_parser()
    args = parser.parse_args(argv)
    launch_config = None
    if args.model_override is not None:
        if args.model_override == "__select__":
            launch_config = select_model()
        else:
            profile = next((item for item in load_model_profiles() if item.id == args.model_override), None)
            if profile:
                launch_config = _profile_config(load_config(), profile)
            else:
                provider, name = _qualified_model(args.model_override)
                launch_config = dataclasses.replace(load_config(), provider=provider, model=name)
        if launch_config is None:
            return 1
    if args.command == "explain":
        return _stream_session_request("explain")
    if args.command == "investigate":
        return investigate_command(web=args.web)
    if args.command == "ask":
        return _stream_session_request("ask", question=" ".join(args.question), web=args.web)
    if args.command == "check":
        return check_command(" ".join(args.question), web=args.web)
    if args.command == "health":
        return _stream_session_request("health", web=args.web)
    if args.command == "doctor":
        return doctor_command(args.as_json)
    if args.command in DOMAINS:
        return domain_command(args.command, web=args.web)
    if args.command == "what":
        return what_command(args.target)
    if args.command == "report":
        return report_command(args.scope, last=args.last, as_json=args.as_json, output=args.output)
    if args.command == "baseline":
        return baseline_command(args.action)
    if args.command == "changes":
        return changes_command(args.since, web=args.web)
    if args.command == "watch":
        return watch_command(args.domain, args.duration, args.interval, web=args.web)
    if args.command == "update":
        return update_command(args.action)
    if args.command == "thinking":
        return thinking_command(args.state)
    if args.command == "stop":
        return stop_outside()
    if args.command == "models":
        return models_command(args.action, args.model)
    if args.command == "history":
        return history_command(all_mode=args.all_mode, as_json=args.as_json)
    if args.command == "memories":
        return memory_command([args.action, *args.rest])
    if args.command == "remember":
        return remember_command(" ".join(args.text))
    if args.command == "feedback":
        return feedback_command(args.text)
    if args.command == "context":
        return context_command()
    if os.environ.get("SYSAI_SESSION"):
        parser.print_help()
        return 0
    config = launch_config
    if config is None:
        config = select_model()
        if config is None:
            return 1
    if config.provider != "ollama" and not config.remote_consent:
        print("Remote model selected.\n\nSanitized diagnostic context may be sent to a remote service.\n"
              "Local Bash history and private memory remain on this machine.\n")
        try:
            approved = input("Continue? [y/N] ").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            approved = False
        if not approved:
            print("SysAI: remote model selection cancelled.", file=sys.stderr)
            return 1
        set_config_value("remote_consent", True)
        config = dataclasses.replace(config, remote_consent=True)
    executable = os.environ.get("SYSAI_EXECUTABLE", os.path.abspath(sys.argv[0]))
    session = Session(config, executable)
    try:
        return session.run()
    except (OllamaError, RuntimeError) as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        session.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
