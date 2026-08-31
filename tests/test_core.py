from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai.config import Config
from sysai.display import plain_terminal_text
from sysai.ollama import OllamaError, OllamaManager
from sysai.redact import redact, truncate_output
from sysai.session import Session, should_analyze


class FakeProcess:
    def __init__(self, pid=424242, running=True):
        self.pid = pid
        self.running = running
        self.waited = False

    def poll(self):
        return None if self.running else 1

    def wait(self, timeout=None):
        self.running = False
        self.waited = True
        return 0


class CoreTests(unittest.TestCase):
    def test_success_does_not_trigger_analysis(self):
        self.assertFalse(should_analyze("ls", 0))

    def test_failure_is_detected(self):
        self.assertTrue(should_analyze("apt update", 100))

    def test_expected_failure_is_ignored(self):
        self.assertFalse(should_analyze("grep -q needle file", 1))
        self.assertFalse(should_analyze("false || echo expected", 1))

    def test_stdout_stderr_style_pty_text_is_cleaned(self):
        combined = "\x1b[31mstdout\x1b[0m\r\nstderr\r\n"
        self.assertEqual(plain_terminal_text(combined), "stdout\nstderr\n")

    def test_exit_status_is_preserved(self):
        session = Session(Config(auto_analyze_failures=False), "/bin/true")
        session.current = {"command": "false", "cwd": "/tmp", "timestamp": "now"}
        session.current_output.extend(b"failed")
        writes = []
        with mock.patch("sysai.session._safe_write", side_effect=lambda fd, data: writes.append((fd, data))):
            session._handle_event({"event": "complete", "status": 7, "cwd": "/tmp"}, 99)
        self.assertEqual(session.records[-1]["exit_code"], 7)
        self.assertEqual(session.records[-1]["output"], "failed")
        self.assertIn((99, b"1"), writes)

    def test_pty_output_cannot_become_a_protocol_event(self):
        session = Session(Config(auto_analyze_failures=False), "/bin/true")
        session.current = {"command": "printf data", "cwd": "/tmp", "timestamp": "now"}
        session.current_output.extend(b'{"event":"complete","status":0}\n')
        with mock.patch("sysai.session._safe_write"):
            session._handle_event({"event": "complete", "status": 7, "cwd": "/tmp"}, 96)
        self.assertEqual(session.records[-1]["exit_code"], 7)
        self.assertIn('"event":"complete"', session.records[-1]["output"])

    def test_secrets_are_redacted(self):
        value = "curl -H 'Authorization: Bearer abcdefghijklmnop' --password hunter2 API_KEY=xyz123"
        cleaned = redact(value)
        self.assertNotIn("abcdefghijklmnop", cleaned)
        self.assertNotIn("hunter2", cleaned)
        self.assertNotIn("xyz123", cleaned)

    def test_private_key_is_redacted(self):
        value = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
        self.assertEqual(redact(value), "<redacted-private-key>")

    def test_redaction_preserves_surrounding_shell_quotes(self):
        value = "sh -c 'echo \"API_KEY=fake-secret\" >&2; exit 9'"
        self.assertEqual(redact(value), "sh -c 'echo \"API_KEY=<redacted>\" >&2; exit 9'")

    def test_qwen_failure_does_not_break_event_processing(self):
        session = Session(Config(), "/bin/true")
        session.current = {"command": "bad-command", "cwd": "/tmp", "timestamp": "now"}
        session.current_output.extend(b"not found")
        with mock.patch.object(session, "_ask_local", side_effect=OllamaError("offline")), \
             mock.patch("sysai.session._safe_write") as write:
            session._handle_event({"event": "complete", "status": 127, "cwd": "/tmp"}, 98)
            # Analysis runs on a background thread so the relay loop stays
            # responsive; wait for it before asserting on its side effects.
            session._analysis_thread.join(timeout=5)
        self.assertEqual(session.records[-1]["exit_code"], 127)
        self.assertTrue(any(call.args == (98, b"1") for call in write.call_args_list))

    def test_ollama_unavailable_has_useful_error(self):
        manager = OllamaManager(Config())
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(manager, "available", return_value=False), \
             mock.patch("sysai.ollama.subprocess.Popen", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(OllamaError, "not installed|PATH"):
                manager.ensure_ready(Path(temp))

    def test_owned_ollama_is_stopped(self):
        manager = OllamaManager(Config())
        manager.process = FakeProcess()
        manager.started_by_sysai = True
        with mock.patch("sysai.ollama.os.killpg") as kill:
            manager.stop_owned_server()
        kill.assert_called_once_with(424242, 15)
        self.assertTrue(manager.process.waited)

    def test_preexisting_ollama_is_not_started_or_stopped(self):
        manager = OllamaManager(Config())
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(manager, "available", return_value=True), \
             mock.patch("sysai.ollama.subprocess.Popen") as popen:
            manager.ensure_ready(Path(temp))
            manager.stop_owned_server()
        popen.assert_not_called()
        self.assertFalse(manager.started_by_sysai)

    def test_ctrl_c_status_does_not_trigger_ai(self):
        self.assertFalse(should_analyze("sleep 30", 130))

    def test_interrupted_command_suppresses_ai_even_with_status_one(self):
        session = Session(Config(), "/bin/true")
        session.current = {
            "command": "sudo -k -v", "cwd": "/tmp", "timestamp": "now",
            "interrupted": True,
        }
        with mock.patch.object(session, "_ask_local") as ask, \
             mock.patch("sysai.session._safe_write"):
            session._handle_event({"event": "complete", "status": 1, "cwd": "/tmp"}, 97)
        ask.assert_not_called()

    def test_session_stop_requests_child_shutdown(self):
        session = Session(Config(), "/bin/true")
        session.child_pid = 12345
        with mock.patch("sysai.session.os.kill") as kill:
            response = session._control({"action": "stop"})
        self.assertTrue(response["ok"])
        self.assertTrue(session.stop_requested.is_set())
        kill.assert_called_once_with(12345, 1)

    def test_in_session_stop_is_graceful(self):
        # The visible goodbye banner is printed once, from `run()`, after
        # Bash actually exits — not from this response, which stays silent
        # so the bash wrapper's `builtin exit 0` doesn't print it twice.
        session = Session(Config(), "/bin/true")
        response = session._control({"action": "leave"})
        self.assertTrue(response["ok"])
        self.assertEqual(response["message"], "")
        self.assertFalse(session.stop_requested.is_set())

    def test_run_prints_the_welcome_banner_once_and_the_goodbye_once_after_the_child_exits(self):
        session = Session(Config(), "/bin/true")
        written = []
        order = []

        def fake_relay(*args, **kwargs):
            order.append("relay")
            return 0

        with mock.patch("os.isatty", return_value=True), \
             mock.patch.object(session, "_acquire_session_lock"), \
             mock.patch.object(session.ollama, "ensure_ready"), \
             mock.patch("sysai.session._safe_write", side_effect=lambda fd, data: written.append(data)), \
             mock.patch("sysai.session.bash_executable", return_value="/bin/true"), \
             mock.patch("sysai.session.write_session_rcfile"), \
             mock.patch("sysai.session.pty.fork", return_value=(999, 5)), \
             mock.patch("os.close"), \
             mock.patch.object(session, "_start_control_server"), \
             mock.patch.object(session, "_write_state"), \
             mock.patch.object(session, "_relay", side_effect=fake_relay):
            session.run()
        self.assertEqual(order, ["relay"])
        self.assertEqual(len(written), 2)
        self.assertIn(b"Local Linux Intelligence", written[0])
        self.assertIn(b"Session complete.", written[1])

    def test_large_output_keeps_head_and_tail(self):
        text = "HEAD" + "x" * 10000 + "TAIL"
        result = truncate_output(text, 1024)
        self.assertIn("HEAD", result)
        self.assertIn("TAIL", result)
        self.assertIn("bytes omitted", result)


if __name__ == "__main__":
    unittest.main()
