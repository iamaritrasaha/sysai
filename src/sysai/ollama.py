from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import Config


class OllamaError(RuntimeError):
    pass


class OllamaCancelled(OllamaError):
    """Raised when a caller cancels an in-flight streaming generation."""


class StreamHandle:
    """Cooperative cancellation token for one streaming request.

    ``cancel()`` may be called from a different thread than the one running
    ``OllamaManager.stream_chat``. It marks the stream cancelled and, on a
    best-effort basis, closes the in-flight HTTP response so a blocked read
    unblocks promptly instead of waiting for the next chunk.
    """

    def __init__(self) -> None:
        self._cancel_event = threading.Event()
        self._response = None
        self._lock = threading.Lock()

    def attach(self, response) -> None:
        with self._lock:
            self._response = response
            already_cancelled = self._cancel_event.is_set()
        if already_cancelled:
            self._close(response)

    def cancel(self) -> None:
        self._cancel_event.set()
        with self._lock:
            response = self._response
        if response is not None:
            self._close(response)

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    @staticmethod
    def _close(response) -> None:
        try:
            response.close()
        except OSError:
            pass


def _request(url: str, method: str = "GET", body: dict | None = None, timeout: float = 3,
             headers: dict[str, str] | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", **(headers or {})} if data else (headers or {}),
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


@dataclass
class OllamaManager:
    config: Config
    process: subprocess.Popen | None = None
    started_by_sysai: bool = False
    startup_succeeded: bool = False
    log_path: Path | None = None
    auth_env: str = ""

    def _auth_headers(self) -> dict[str, str]:
        token = os.environ.get(self.auth_env, "") if self.auth_env else ""
        return {"Authorization": f"Bearer {token}"} if token else {}

    def process_start_time(self) -> int | None:
        if self.process is None:
            return None
        return process_start_time(self.process.pid)

    def available(self) -> bool:
        try:
            _request(f"{self.config.ollama_url}/api/version", timeout=1, headers=self._auth_headers())
            return True
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            return False

    def models(self) -> list[str]:
        return self.models_result()[0]

    def models_result(self) -> tuple[list[str], str]:
        try:
            payload = _request(f"{self.config.ollama_url}/api/tags", timeout=2, headers=self._auth_headers())
            return ([str(item["name"]) for item in payload.get("models", []) if isinstance(item, dict) and item.get("name")], "ok")
        except urllib.error.HTTPError as exc:
            return [], "authentication required" if exc.code in (401, 403) else f"HTTP {exc.code}"
        except (OSError, urllib.error.URLError):
            return [], "unreachable"
        except (json.JSONDecodeError, TypeError, KeyError):
            return [], "malformed response"

    def model_available(self) -> bool:
        return self.config.model in self.models()

    def ensure_ready(self, runtime_dir: Path) -> None:
        if self.available():
            return
        runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.log_path = runtime_dir / "ollama.log"
        log = self.log_path.open("ab", buffering=0)
        os.fchmod(log.fileno(), 0o600)
        env = os.environ.copy()
        env["OLLAMA_HOST"] = self.config.ollama_url.replace("http://", "")
        try:
            self.process = subprocess.Popen(
                ["ollama", "serve"], stdout=log, stderr=subprocess.STDOUT,
                env=env, start_new_session=True,
            )
        except FileNotFoundError as exc:
            log.close()
            raise OllamaError("Ollama is not installed or is not on PATH.") from exc
        finally:
            log.close()
        self.started_by_sysai = True
        deadline = time.monotonic() + self.config.startup_timeout_seconds
        while time.monotonic() < deadline:
            if self.available():
                self.startup_succeeded = True
                return
            if self.process.poll() is not None:
                break
            time.sleep(0.2)
        self.stop_owned_server()
        detail = f" See {self.log_path}." if self.log_path else ""
        raise OllamaError(f"Ollama did not become ready within {self.config.startup_timeout_seconds}s.{detail}")

    def stream_chat(
        self,
        messages: list[dict[str, str]],
        *,
        on_thinking: Callable[[str], None] | None = None,
        on_content: Callable[[str], None] | None = None,
        handle: StreamHandle | None = None,
    ) -> str:
        """Stream a chat completion, invoking callbacks as chunks arrive.

        Uses Ollama's native streaming NDJSON protocol (``stream: true``).
        When the configured model supports it and ``think`` is enabled,
        reasoning arrives incrementally in ``message.thinking`` ahead of
        ``message.content``; models without reasoning support simply never
        populate ``thinking``, so ``on_thinking`` is never called and this
        degrades to a normal streamed answer.
        """
        if handle is not None and handle.is_cancelled():
            raise OllamaCancelled("Generation cancelled.")
        body = {
            "model": self.config.model,
            "messages": messages,
            "stream": True,
            "think": self.config.thinking,
            "keep_alive": "5m",
            "options": {"temperature": 0.2},
        }
        request = urllib.request.Request(
            f"{self.config.ollama_url}/api/chat", data=json.dumps(body).encode(),
            method="POST", headers={"Content-Type": "application/json", **self._auth_headers()},
        )
        try:
            response = urllib.request.urlopen(request, timeout=self.config.request_timeout_seconds)
        except (OSError, urllib.error.URLError) as exc:
            raise OllamaError(f"Local Ollama request failed: {exc}") from exc
        if handle is not None:
            handle.attach(response)
        content_parts: list[str] = []
        saw_done = False
        try:
            with response:
                for raw_line in response:
                    if handle is not None and handle.is_cancelled():
                        raise OllamaCancelled("Generation cancelled.")
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if "error" in chunk:
                        raise OllamaError(f"Local Ollama request failed: {chunk['error']}")
                    message = chunk.get("message") or {}
                    thinking_piece = message.get("thinking")
                    if thinking_piece and on_thinking is not None:
                        on_thinking(thinking_piece)
                    content_piece = message.get("content")
                    if content_piece:
                        content_parts.append(content_piece)
                        if on_content is not None:
                            on_content(content_piece)
                    if chunk.get("done"):
                        saw_done = True
                        break
        except (OSError, urllib.error.URLError) as exc:
            if handle is not None and handle.is_cancelled():
                raise OllamaCancelled("Generation cancelled.") from exc
            raise OllamaError(f"Local Ollama request failed: {exc}") from exc
        # Cancelling closes the response to unblock a pending read, which
        # can also make the iterator end quietly (no exception) rather than
        # raise mid-loop. Re-check here so a cancellation never gets
        # reported as a normal (or merely truncated) response.
        if handle is not None and handle.is_cancelled():
            raise OllamaCancelled("Generation cancelled.")
        content = "".join(content_parts).strip()
        if not saw_done and not content:
            raise OllamaError("Ollama stream ended unexpectedly without a response.")
        return content

    def unload(self) -> None:
        if not self.available():
            return
        try:
            _request(
                f"{self.config.ollama_url}/api/generate", "POST",
                {"model": self.config.model, "keep_alive": 0}, timeout=10, headers=self._auth_headers(),
            )
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            pass

    def stop_owned_server(self) -> None:
        if not self.started_by_sysai or self.process is None or self.process.poll() is not None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
            self.process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=2)

    def cleanup(self) -> None:
        self.unload()
        self.stop_owned_server()
        if self.startup_succeeded and self.log_path is not None:
            self.log_path.unlink(missing_ok=True)


def process_start_time(pid: int) -> int | None:
    """Return Linux /proc start ticks, which disambiguate reused PIDs."""
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        remainder = value[value.rfind(")") + 2:].split()
        return int(remainder[19])
    except (OSError, ValueError, IndexError):
        return None


def is_owned_ollama_process(pid: int, start_time: int, pgid: int) -> bool:
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        argv = [part.decode("utf-8", "replace") for part in command if part]
        return (
            len(argv) >= 2
            and Path(argv[0]).name == "ollama"
            and argv[1] == "serve"
            and process_start_time(pid) == start_time
            and os.getpgid(pid) == pgid == pid
        )
    except (OSError, ProcessLookupError):
        return False
