from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import Config


class OllamaError(RuntimeError):
    pass


def _request(url: str, method: str = "GET", body: dict | None = None, timeout: float = 3) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
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

    def process_start_time(self) -> int | None:
        if self.process is None:
            return None
        return process_start_time(self.process.pid)

    def available(self) -> bool:
        try:
            _request(f"{self.config.ollama_url}/api/version", timeout=1)
            return True
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            return False

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

    def chat(self, messages: list[dict[str, str]]) -> str:
        body = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "think": self.config.thinking,
            "keep_alive": "5m",
            "options": {"temperature": 0.2},
        }
        try:
            response = _request(
                f"{self.config.ollama_url}/api/chat", "POST", body,
                timeout=self.config.request_timeout_seconds,
            )
            return response["message"]["content"].strip()
        except (OSError, urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
            raise OllamaError(f"Local Qwen request failed: {exc}") from exc

    def unload(self) -> None:
        if not self.available():
            return
        try:
            _request(
                f"{self.config.ollama_url}/api/generate", "POST",
                {"model": self.config.model, "keep_alive": 0}, timeout=10,
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
