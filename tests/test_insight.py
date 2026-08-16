from __future__ import annotations

import io
import json
import subprocess
import unittest
from unittest import mock

from sysai import cli
from sysai.cli import insight_command, main
from sysai.display import plain_terminal_text
from sysai.insight import (classify, compact_output, diagnostic_signals, dmesg_evidence,
                           execute, prepare_evidence, safe_research_query)


class InsightTests(unittest.TestCase):
    def _render_stream(self, action: str, messages: list[dict]) -> str:
        class Client:
            def __init__(self):
                self.chunks = [b"".join(json.dumps(message).encode() + b"\n" for message in messages), b""]

            def settimeout(self, timeout): pass
            def connect(self, socket_name): pass
            def sendall(self, data): pass
            def shutdown(self, how): pass
            def recv(self, size): return self.chunks.pop(0)
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *exc_info): self.close()

        output = io.StringIO()
        with mock.patch("sysai.cli._active_socket", return_value="test.sock"), \
             mock.patch("sysai.cli.socket.socket", return_value=Client()), \
             mock.patch("sysai.cli.sys.stdout", output):
            self.assertEqual(cli._stream_session_request(action), 0)
        return plain_terminal_text(output.getvalue())

    def test_insight_and_ask_share_markdown_stream_renderer(self):
        messages = [
            {"type": "content", "text": "**Key AC"},
            {"type": "content", "text": "PI Tables in the Log**\n"},
            {"type": "content", "text": "**Warn"},
            {"type": "content", "text": "ing**\n"},
            {"type": "content", "text": "Run `systemctl --failed`.\n"},
            {"type": "content", "text": "**Summary**\n"},
            {"type": "done", "ok": True},
        ]
        ask = self._render_stream("ask", messages)
        insight = self._render_stream("insight", messages)
        self.assertEqual(insight, ask)
        for expected in ("Key ACPI Tables in the Log", "Warning", "Run systemctl --failed.", "Summary"):
            self.assertIn(expected, ask)
        for forbidden in ("**Key", "**Warning**", "**Summary**", "```"):
            self.assertNotIn(forbidden, ask)

    def test_cli_dispatch_and_flags_preserve_argv(self):
        with mock.patch("sysai.cli.insight_command", return_value=0) as call:
            self.assertEqual(main(["--raw", "--web", "journalctl", "-b"]), 0)
        call.assert_called_once_with(["journalctl", "-b"], raw=True, web=True)

    def test_reserved_command_is_not_insight(self):
        with mock.patch("sysai.cli._stream_session_request", return_value=0) as call:
            self.assertEqual(main(["health"]), 0)
        call.assert_called_once_with("health", web=False)

    def test_safety_rejects_shell_interactive_and_destructive(self):
        self.assertFalse(classify(["journalctl", "-b", "|", "grep"])[0])
        self.assertFalse(classify(["journalctl", "-f"])[0])
        self.assertFalse(classify(["sudo", "rm", "-rf", "/"])[0])
        self.assertTrue(classify(["sudo", "dmesg"])[0])
        for argv in (["systemctl", "restart", "ssh.service"], ["ip", "link", "set", "eth0", "down"],
                     ["sysctl", "-w", "x=1"], ["mount", "/dev/sda1", "/mnt"], ["umount", "/mnt"],
                     ["fsck", "/dev/sda1"], ["mkfs", "/dev/sda1"], ["apt", "install", "x"],
                     ["chmod", "777", "/tmp/x"], ["dd", "if=/dev/zero"], ["dmesg", "-wH"],
                     ["journalctl", "--follow-new"], ["smartctl", "--test=short", "/dev/sda"]):
            self.assertFalse(classify(list(argv))[0], argv)
        for operator in ("|", ">", ">>", "&&", "||", ";", "$(id)", "`id`"):
            self.assertFalse(classify(["dmesg", operator])[0])

    def test_user_typed_sudo_does_not_prompt_twice_and_declined_retry_never_runs(self):
        ok = {"exit_code": 0, "output": "kernel", "truncated": False}
        with mock.patch("sysai.cli._active_socket", return_value="x"), \
             mock.patch("sysai.cli.execute", return_value=ok) as execute_call, \
             mock.patch("sysai.cli._stream_session_request", return_value=0), \
             mock.patch("sysai.cli.input") as prompt, mock.patch("sysai.cli.sys.stdout", io.StringIO()):
            self.assertEqual(insight_command(["sudo", "dmesg"]), 0)
        execute_call.assert_called_once_with(["sudo", "dmesg"])
        prompt.assert_not_called()

        denied = {"exit_code": 1, "output": "Operation not permitted", "truncated": False}
        with mock.patch("sysai.cli._active_socket", return_value="x"), \
             mock.patch("sysai.cli.execute", return_value=denied) as execute_call, \
             mock.patch("sysai.cli._stream_session_request", return_value=0), \
             mock.patch("sysai.cli.input", return_value=""), mock.patch("sysai.cli.sys.stdout", io.StringIO()):
            self.assertEqual(insight_command(["dmesg"]), 0)
        execute_call.assert_called_once_with(["dmesg"])

    def test_raw_mode_stays_sanitized_literal_not_markdown_rendered(self):
        result = {"exit_code": 0, "output": "**literal command output**", "truncated": False}
        output = io.StringIO()
        with mock.patch("sysai.cli._active_socket", return_value="x"), \
             mock.patch("sysai.cli.execute", return_value=result), \
             mock.patch("sysai.cli._stream_session_request", return_value=0), \
             mock.patch("sysai.cli.sys.stdout", output):
            self.assertEqual(insight_command(["dmesg"], raw=True), 0)
        self.assertIn("**literal command output**", output.getvalue())

    def test_execution_uses_argv_and_private_bounded_output(self):
        fake = mock.Mock(returncode=0, stdout="x" * 60_000, stderr="")
        with mock.patch("sysai.insight.subprocess.run", return_value=fake) as run:
            result = execute(["dmesg"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["output"].encode()), 48_100)

    def test_analysis_reduction_sees_middle_before_raw_capture_is_truncated(self):
        middle = "amdgpu: GPU reset after timeout"
        fake = mock.Mock(returncode=0, stdout="normal\n" * 9000 + middle + "\ntail\n" * 9000, stderr="")
        with mock.patch("sysai.insight.subprocess.run", return_value=fake):
            result = execute(["dmesg"])
        self.assertTrue(result["truncated"])
        self.assertIn(middle, result["analysis_output"])
        self.assertIn("bytes omitted by SysAI", result["output"])

    def test_timeout_and_unknown_command_are_clean(self):
        with mock.patch("sysai.insight.subprocess.run", side_effect=subprocess.TimeoutExpired(["dmesg"], 1)):
            self.assertTrue(execute(["dmesg"])["timeout"])
        with mock.patch("sysai.insight.subprocess.run", side_effect=FileNotFoundError):
            self.assertEqual(execute(["missing"])["exit_code"], 127)

    def test_compaction_and_controls(self):
        self.assertIn("repeated 4", compact_output("a\na\na\na\nb"))
        fake = mock.Mock(returncode=0, stdout="safe\x1b]52;c;bad\x07", stderr="")
        with mock.patch("sysai.insight.subprocess.run", return_value=fake):
            self.assertNotIn("\x1b", execute(["dmesg"])["output"])

    def test_dmesg_evidence_prefers_anomalies_and_tail_over_acpi_head(self):
        text = "\n".join(["ACPI: table reservation"] * 40 + ["kernel: I/O error on sda", "context"] + ["tail"] * 30)
        evidence = dmesg_evidence(text)
        self.assertIn("kernel: I/O error on sda", evidence)
        self.assertIn("tail", evidence)
        self.assertEqual(evidence.count("ACPI: table reservation"), 1)

    def test_diagnostic_classification_regressions(self):
        self.assertEqual(diagnostic_signals("ACPI: SSDT table loaded\nPCI: enumeration complete"), [])
        isolated = diagnostic_signals("amdgpu: REG_WAIT timeout")
        self.assertEqual(isolated[0]["classification"], "possible")
        self.assertNotIn("hardware", isolated[0]["kind"])
        repeated = diagnostic_signals("amdgpu: GPU reset 1\namdgpu: GPU reset 2")
        self.assertEqual(repeated[0]["classification"], "warning")
        apparmor = diagnostic_signals("apparmor=\"DENIED\" operation=\"open\"")
        self.assertEqual(apparmor[0]["classification"], "informational")
        service = diagnostic_signals("example.service: Failed with result 'exit-code'")
        self.assertEqual(service[0]["classification"], "warning")

    def test_truncation_metadata_and_web_query_are_sysai_owned_and_private(self):
        raw = "amdgpu: GPU reset /home/alice 10.0.0.4 host-secret"
        evidence = prepare_evidence(["dmesg"], {"output": raw, "truncated": True, "exit_code": 0})
        self.assertTrue(evidence["output_truncated"])
        self.assertEqual(evidence["truncation_reason"], "SysAI bounded capture limit")
        query = safe_research_query(evidence)
        self.assertIn("gpu_reset", query)
        self.assertNotIn("alice", query)
        self.assertNotIn("10.0.0.4", query)
        self.assertNotIn("host-secret", query)


if __name__ == "__main__":
    unittest.main()
