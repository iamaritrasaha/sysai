from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from sysai import cli
from sysai.config import Config
from sysai.display import ANSI_RE, AnswerRenderer
from sysai.ollama import OllamaManager
from sysai.session import Session


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = r"""Analysis of `dmesg` Output

---

1. **AMDGPU Driver Issues**

• **REG_WAIT timeout**
  • **Message:** amdgpu REG_WAIT timeout.
  • **Implication:** Possible driver issue.

• **workqueue hogging CPU**

2. **AppArmor Security Denials**

• See [kernel.org](https://kernel.org).

---

**Summary**

\*\*Key Observations\*\*
1\. \*\*Warning\*\*
"""
CHUNKS = [
    "Analysis of `dme", "sg` Output\n\n--", "-\n\n1. **AMDGPU ", "Driver Issues**\n\n",
    "• **REG_WAIT ", "timeout**\n  • **Mess", "age:** amdgpu REG_WAIT timeout.\n",
    "  • **Implication:** Possible driver issue.\n\n• **workqueue hogging CPU**\n\n",
    "2. **AppArmor Security Denials**\n\n• See [kernel.", "org](https://kernel.", "org).\n\n",
    "---\n\n**Summary**\n\n\\*", "\\*Key Observations\\*\\*\n1\\. \\*\\*Warn", "ing\\*\\*\n",
]


def visible(text: str) -> str:
    return ANSI_RE.sub("", text)


def assert_golden(test: unittest.TestCase, text: str) -> None:
    clean = visible(text)
    for expected in (
        "Analysis of dmesg Output", "1. AMDGPU Driver Issues", "• REG_WAIT timeout",
        "• Message: amdgpu REG_WAIT timeout.", "• workqueue hogging CPU",
        "2. AppArmor Security Denials", "kernel.org (https://kernel.org)", "Summary",
        "Key Observations", "1. Warning",
    ):
        test.assertIn(expected, clean)
    for leaked in ("**", "`dmesg`", "[kernel.org](", "---", r"\*\*"):
        test.assertNotIn(leaked, clean)
    in_box = False
    for line in clean.splitlines():
        if line.startswith("┌─ SysAI "):
            in_box = True
        elif in_box and line.startswith("└"):
            in_box = False
        elif in_box:
            test.assertTrue(line.startswith("│"), line)


class EndToEndRenderingTests(unittest.TestCase):
    @staticmethod
    def _fake_answer(prompt, *, on_thinking=None, on_content=None, handle=None):
        if on_thinking:
            on_thinking("Checking supplied evidence.\n")
        if on_content:
            for chunk in CHUNKS:
                on_content(chunk)
        return GOLDEN

    def _run_client_path(self, action: str, request: dict) -> str:
        session = Session(Config(), "/bin/true")
        if action == "explain":
            session.records.append({"command": "false", "exit_code": 1, "cwd": "/tmp", "timestamp": "now", "output": "failed"})
        server, client = socket.socketpair()

        class ConnectedClient:
            def settimeout(self, timeout): client.settimeout(timeout)
            def connect(self, path): pass
            def sendall(self, data): client.sendall(data)
            def recv(self, size): return client.recv(size)
            def close(self): client.close()
            def __enter__(self): return self
            def __exit__(self, *args): self.close()

        def serve():
            payload = b""
            while b"\n" not in payload:
                payload += server.recv(65536)
            session._control_stream(json.loads(payload.partition(b"\n")[0]), server)
            server.close()

        thread = threading.Thread(target=serve)
        thread.start()
        output = io.StringIO()
        with mock.patch.object(session, "_ask_local", side_effect=self._fake_answer), \
             mock.patch("sysai.session.collect_health", return_value={"checks": {}, "findings": []}), \
             mock.patch("sysai.cli._active_socket", return_value="test.sock"), \
             mock.patch("sysai.cli.socket.socket", return_value=ConnectedClient()), \
             mock.patch("sysai.cli.sys.stdout", output):
            self.assertEqual(cli._stream_session_request(action, **request), 0)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        return output.getvalue()

    def test_ask_explain_health_and_insight_share_golden_renderer(self):
        cases = (
            ("ask", {"question": "explain this", "web": False}),
            ("explain", {}),
            ("health", {"web": False}),
            ("insight", {"argv": ["dmesg"], "result": {"exit_code": 0, "output": "ACPI: table loaded", "truncated": False}, "web": False}),
        )
        outputs = [self._run_client_path(action, request) for action, request in cases]
        for output in outputs:
            assert_golden(self, output)
        boxes = [output[output.index("┌─ SysAI "):] for output in map(visible, outputs)]
        self.assertTrue(all(box == boxes[0] for box in boxes[1:]))

    def test_auto_analysis_uses_same_golden_renderer(self):
        session = Session(Config(), "/bin/true")
        writes = []
        record = {"command": "false", "exit_code": 1, "cwd": "/tmp", "timestamp": "now", "output": "failed"}
        with mock.patch.object(session, "_ask_local", side_effect=self._fake_answer), \
             mock.patch("sysai.session._safe_write", side_effect=lambda fd, data: writes.append((fd, data))):
            session._start_analysis(record, 77)
            session._analysis_thread.join(timeout=3)
        assert_golden(self, b"".join(data for fd, data in writes if fd == 1).decode())

    def test_native_ollama_events_feed_answer_renderer(self):
        class Response:
            def __init__(self):
                self.lines = [json.dumps({"message": {"content": chunk}, "done": index == len(CHUNKS) - 1}).encode() + b"\n"
                              for index, chunk in enumerate(CHUNKS)]
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def __iter__(self): return iter(self.lines)

        written = []
        renderer = AnswerRenderer(written.append)
        with mock.patch("sysai.ollama.urllib.request.urlopen", return_value=Response()):
            OllamaManager(Config()).stream_chat([{"role": "user", "content": "x"}],
                                                on_thinking=renderer.thinking, on_content=renderer.content)
        renderer.finish()
        assert_golden(self, "".join(written))

    def test_stream_box_output_remains_prefixed_through_a_pty(self):
        master, slave = os.openpty()
        collected = bytearray()

        def drain() -> None:
            # A PTY master delivers whatever the line discipline has flipped so
            # far, so a single read can return only the first chunk. Draining
            # until EOF (raised as EIO once the slave is closed) makes the
            # captured output deterministic instead of timing-dependent.
            while True:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                collected.extend(chunk)

        reader = threading.Thread(target=drain)
        reader.start()
        try:
            with mock.patch("sysai.display.shutil.get_terminal_size", return_value=os.terminal_size((28, 24))):
                renderer = AnswerRenderer(lambda value: os.write(slave, value.encode()))
                renderer.content("1. **A deliberately long diagnostic heading that wraps**\n")
                renderer.finish()
        finally:
            os.close(slave)
            reader.join(timeout=5)
            os.close(master)
        self.assertFalse(reader.is_alive())
        output = collected.decode().replace("\r\n", "\n")
        content = [line for line in visible(output).splitlines() if line.startswith("│")]
        self.assertGreater(len(content), 1)
        self.assertTrue(all(line.startswith("│ ") and len(line) <= 27 for line in content))

    def test_installed_copy_uses_same_renderer_golden(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "install"
            config = Path(temp) / "config"
            env = {**os.environ, "SYSAI_INSTALL_ROOT": str(root), "XDG_CONFIG_HOME": str(config)}
            subprocess.run([str(ROOT / "install.sh")], env=env, check=True, capture_output=True, text=True)
            code = (
                "from sysai.display import AnswerRenderer\n"
                "w=[]\nr=AnswerRenderer(w.append)\n"
                f"chunks={CHUNKS!r}\n"
                "[r.content(x) for x in chunks]\nr.finish()\nprint(''.join(w), end='')\n"
            )
            result = subprocess.run(["python3", "-c", code], env={**env, "PYTHONPATH": str(root / "lib/sysai-terminal")},
                                    check=True, capture_output=True, text=True)
        assert_golden(self, result.stdout)


if __name__ == "__main__":
    unittest.main()
