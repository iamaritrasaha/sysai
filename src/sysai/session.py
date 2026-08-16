from __future__ import annotations

import collections
import dataclasses
import datetime as dt
import errno
import fcntl
import json
import os
import pty
import selectors
import shlex
import signal
import socket
import tempfile
import termios
import threading
from pathlib import Path

from .config import Config, load_private_env, state_dir
from .display import AnswerRenderer, plain_terminal_text, startup
from .ollama import OllamaCancelled, OllamaError, OllamaManager, StreamHandle
from .prompt import failure_prompt, system_prompt
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
                        request = json.loads(b"".join(chunks) or b"{}")
                    except Exception as exc:
                        try:
                            conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode())
                        except OSError:
                            pass
                        continue
                    # `explain`/`ask` stream multiple newline-delimited JSON
                    # messages (thinking/content/done) as the model
                    # generates; everything else is a single request/response.
                    if request.get("action") in ("explain", "ask"):
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
            # The in-session Zsh function exits itself after receiving this reply.
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
            prompt = f"Recent terminal context:\n{context or '(none)'}\n\nUser question: {question}{research}"
            self._stream_answer(prompt, send, handle, remember_question=question)
            return
        send({"type": "error", "error": f"Unknown session action: {action}"})

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
        integration = Path(__file__).with_name("integration.zsh")
        with tempfile.TemporaryDirectory(prefix="sysai-zdot-") as temp:
            wrapper = Path(temp) / ".zshrc"
            user_zshrc = Path.home() / ".zshrc"
            lines = []
            if user_zshrc.exists():
                lines.append(f"source {shlex.quote(str(user_zshrc))}")
            lines.append(f"source {shlex.quote(str(integration))}")
            wrapper.write_text("\n".join(lines) + "\n", encoding="utf-8")
            wrapper.chmod(0o600)
            pid, master = pty.fork()
            if pid == 0:
                os.close(event_r)
                os.close(response_w)
                os.environ.update({
                    "ZDOTDIR": temp, "SYSAI_SESSION": "1",
                    "SYSAI_EVENT_FD": str(event_w), "SYSAI_RESPONSE_FD": str(response_r),
                    "SYSAI_SOCKET": str(self.socket_path), "SYSAI_EXECUTABLE": self.executable,
                })
                os.execvp("zsh", ["zsh", "-i"])
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
