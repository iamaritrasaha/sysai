from __future__ import annotations

import os
import json
import io
import unittest
from unittest import mock

import socket

from sysai import collect
from sysai.cli import main
from sysai.display import ANSI_RE, AnswerRenderer
from sysai.domains import analyze_disk, analyze_thermal
from sysai.health import (_command, action_catalogue, action_details, collect_health,
                          parse_action_plan, prompt_permission, run_action,
                          safety_floor_actions, web_queries)
from sysai.session import Session
from sysai.config import Config


class HealthTests(unittest.TestCase):
    def test_health_cli_parses_web(self):
        with mock.patch("sysai.cli._stream_session_request", return_value=0) as request:
            self.assertEqual(main(["health", "--web"]), 0)
        request.assert_called_once_with("health", web=True)

    def test_collector_is_structured_with_missing_tools(self):
        with mock.patch("sysai.collect.shutil.which", return_value=None):
            result = collect_health()
        self.assertIn("sections", result)
        self.assertIn("services", result["sections"])
        # A missing utility is NOT CHECKED, never an invented failure.
        reasons = {item["reason"] for item in result["unavailable"]}
        self.assertTrue(any("not installed" in reason for reason in reasons))
        self.assertTrue(all(item["classification"] == "NOT CHECKED"
                            for item in result["unavailable"]))

    def test_command_timeout_and_no_shell(self):
        with mock.patch("sysai.collect.shutil.which", return_value="/bin/true"), \
             mock.patch("sysai.collect.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired(["x"], 1)) as run:
            result = _command(("x", "--fixed"))
        self.assertEqual(result["reason"], "timed out")
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertNotIn("sudo", run.call_args.args[0])

    def test_health_web_queries_do_not_contain_raw_logs(self):
        evidence = {"findings": [{"kind": "failed_service", "evidence": {"raw": "SECRET LOG /home/alice 10.0.0.1"}}]}
        queries = web_queries(evidence)
        self.assertTrue(queries)
        self.assertNotIn("alice", " ".join(queries))
        self.assertNotIn("10.0.0.1", " ".join(queries))

    def test_normal_mount_options_do_not_become_findings(self):
        sections = {"filesystems": [
            {"mountpoint": "/", "fstype": "ext4", "currently_read_only": False,
             "mount_options": ["rw", "errors=remount-ro"], "capacity_percent": 30,
             "inode_percent": 12},
        ], "errors": {}, "smart": {"tool_available": False}}
        self.assertEqual(analyze_disk(sections), [])

    def test_snap_squashfs_mounts_are_never_collected(self):
        proc_mounts = ("/dev/loop0 /snap/core/1 squashfs ro,nodev 0 0\n"
                       "/dev/sda1 / ext4 rw,relatime 0 0\n")
        with mock.patch("sysai.collect.read_text", return_value=proc_mounts):
            points = [row["mountpoint"] for row in collect.mounts()]
        self.assertNotIn("/snap/core/1", points)

    def test_uptime_only_uses_first_proc_field(self):
        with mock.patch("sysai.collect.read_text", return_value="100.0 99999.0"):
            self.assertEqual(collect.uptime_seconds(), 100.0)

    def test_absent_thermal_sensors_are_not_a_failure(self):
        with mock.patch("sysai.collect.Path.glob", return_value=[]):
            self.assertEqual(collect.thermal_zones(), [])
        self.assertEqual(analyze_thermal({"summary": {"max_celsius": None}, "throttling": {}}), [])

    def test_action_catalogue_rejects_unknown_and_untrusted_parameters(self):
        with self.assertRaisesRegex(ValueError, "unknown"):
            action_details("model.run_this", {}, {})
        with self.assertRaisesRegex(ValueError, "untrusted"):
            action_details("systemd.unit_status", {"unit": "x.service; rm -rf /"}, {"units": set()})

    def test_privileged_action_needs_per_action_approval(self):
        trusted = {"devices": {"/dev/sdb"}}
        with mock.patch("sysai.diagnostics.run") as command:
            declined = run_action("disk.smart_health", {"device": "/dev/sdb"}, trusted, lambda _: False)
        self.assertEqual(declined["status"], "declined")
        command.assert_not_called()
        with mock.patch("sysai.diagnostics.run", return_value={"status": "ok"}) as command:
            run_action("disk.smart_health", {"device": "/dev/sdb"}, trusted, lambda _: True)
        self.assertEqual(command.call_args.args[0][0], "sudo")

    def test_permission_prompt_defaults_to_no(self):
        detail = {"purpose": "Inspect SMART health for /dev/sdb", "argv": ("sudo", "smartctl", "-a", "/dev/sdb")}
        self.assertFalse(prompt_permission(detail, input_fn=lambda _: "", output=lambda _: None))

    def test_model_thinking_cannot_become_action(self):
        with self.assertRaises(ValueError):
            action_details("sudo rm -rf /", {}, {})

    def test_action_plan_accepts_ids_only_and_is_bounded(self):
        self.assertEqual(parse_action_plan('{"command":"rm -rf /"}'), [])
        plan = parse_action_plan('{"actions":[' + ",".join(
            '{"id":"system.kernel_version","params":{}}' for _ in range(5)) + "]}")
        self.assertEqual(len(plan), 3)
        self.assertIn("gpu.pci_driver", {item["id"] for item in action_catalogue()})
        with self.assertRaisesRegex(ValueError, "unexpected"):
            action_details("system.kernel_version", {"command": "uname -a"}, {})

    def test_approval_is_once_only_and_rejection_never_executes(self):
        trusted = {"devices": {"/dev/sdb"}}
        approvals = []
        with mock.patch("sysai.diagnostics.run") as command:
            result = run_action("disk.smart_health", {"device": "/dev/sdb"}, trusted,
                                lambda detail: approvals.append(detail["id"]) or False)
        self.assertEqual(result["status"], "declined")
        self.assertEqual(approvals, ["disk.smart_health"])
        command.assert_not_called()

    def test_adaptive_loop_executes_only_validated_action_ids(self):
        session = Session(Config(), "/bin/true")
        evidence = {"signals": [{"classification": "warning"}], "output": "amdgpu: GPU reset"}
        plans = iter((
            '{"actions":[{"id":"system.kernel_version","params":{}}]}',
            '{"actions":[]}',
        ))
        with mock.patch.object(session, "_ask_local", side_effect=lambda *args, **kwargs: next(plans)), \
             mock.patch("sysai.diagnostics.run", return_value={"status": "ok", "output": "6.8.0"}) as command:
            results = session._adaptive_diagnostics(evidence, mock.Mock(), mock.Mock(), mock.Mock())
        self.assertEqual(results[0]["action_id"], "system.kernel_version")
        self.assertEqual(command.call_args.args[0], ("uname", "-r"))

        session = Session(Config(), "/bin/true")
        plans = iter(('{"actions":[{"id":"model.shell","params":{"argv":["rm","-rf","/"]}}]}', '{"actions":[]}'))
        with mock.patch.object(session, "_ask_local", side_effect=lambda *args, **kwargs: next(plans)), \
             mock.patch("sysai.diagnostics.run") as command:
            results = session._adaptive_diagnostics(evidence, mock.Mock(), mock.Mock(), mock.Mock())
        self.assertEqual(results[0]["status"], "rejected")
        command.assert_not_called()

    def test_cli_rejects_privileged_diagnostic_without_one_time_approval(self):
        class Client:
            def __init__(self):
                permission = {"type": "diagnostic_permission", "action_id": "disk.smart_health",
                              "params": {"device": "/dev/sdb"}, "purpose": "Inspect SMART health for /dev/sdb",
                              "argv": ["sudo", "smartctl", "-a", "/dev/sdb"], "elevated": True, "read_only": True}
                self.chunks = [(json.dumps(permission) + "\n" + json.dumps({"type": "done", "ok": True}) + "\n").encode(), b""]
                self.sent = []
            def settimeout(self, timeout): pass
            def connect(self, name): pass
            def sendall(self, data): self.sent.append(data)
            def recv(self, size): return self.chunks.pop(0)
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass

        client, output = Client(), io.StringIO()
        with mock.patch("sysai.cli._active_socket", return_value="x"), \
             mock.patch("sysai.cli.socket.socket", return_value=client), \
             mock.patch("sysai.cli.prompt_permission", return_value=False), \
             mock.patch("sysai.cli._command") as command, \
             mock.patch("sysai.cli.sys.stdout", output):
            self.assertEqual(__import__("sysai.cli", fromlist=["_stream_session_request"])._stream_session_request("health"), 0)
        command.assert_not_called()
        response = json.loads(client.sent[-1])
        self.assertEqual(response["result"]["status"], "declined")

    def test_health_local_when_web_disabled_does_not_call_provider(self):
        session = Session(Config(web_enabled=False), "/bin/true")
        with mock.patch("sysai.session.collect_health", return_value={"checks": {}}), \
             mock.patch.object(session, "_ask_local", return_value="ok"), \
             mock.patch("sysai.session.OllamaWebSearch") as provider:
            # A non-web health request remains completely local.
            import socket
            a, b = socket.socketpair()
            try:
                session._control_stream({"action": "health", "web": False}, a)
            finally:
                a.close(); b.close()
        provider.assert_not_called()

    def test_system_inspection_question_collects_real_telemetry(self):
        session = Session(Config(), "/bin/true")
        seen = []
        with mock.patch("sysai.session.collect_health", return_value={"checks": {"gpu": {"status": "ok"}}}) as collect, \
             mock.patch.object(session, "_ask_local", side_effect=lambda prompt, **_: seen.append(prompt) or "ok"):
            import socket
            a, b = socket.socketpair()
            try:
                session._control_stream({"action": "ask", "question": "Check my system for issues"}, a)
            finally:
                a.close(); b.close()
        collect.assert_called_once()
        self.assertIn("Actual local telemetry collected", seen[0])
        self.assertIn('"gpu"', seen[0])

    def test_markdown_rendering_and_controls(self):
        written = []
        renderer = AnswerRenderer(written.append)
        renderer.content("### Disk usage\n**Warning** use `df -h`\n- item\n```bash\nsudo apt update\n```\nunsafe\x1b[31m\n")
        renderer.finish()
        text = "".join(written)
        self.assertIn("│ Disk usage\n│ ──────────", text)
        self.assertIn("• item", text)
        self.assertIn("│ sudo apt update", text)
        self.assertNotIn("###", text)
        self.assertNotIn("**", text)
        self.assertNotIn("`", text)
        self.assertNotIn("\x1b[31m", text)

    def test_markdown_respects_no_color_and_keeps_commands_copyable(self):
        written = []
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            renderer = AnswerRenderer(written.append)
            renderer.content("Use `systemctl --failed`\n")
            renderer.finish()
        text = "".join(written)
        self.assertIn("systemctl --failed", text)
        self.assertNotIn("\x1b", text)

    def test_markdown_split_tokens_stay_inside_box(self):
        written = []
        renderer = AnswerRenderer(written.append)
        renderer.content("### File")
        renderer.content("system\n**Warn")
        renderer.content("ing**\n```ba")
        renderer.content("sh\necho hi\n```\n")
        renderer.finish()
        text = "".join(written)
        self.assertIn("│ Filesystem", text)
        self.assertIn("│ ──────────", text)
        self.assertIn("│ Warning", text)
        self.assertIn("│ echo hi", text)
        self.assertTrue(all(not line.startswith("─") for line in text.splitlines()))

    def test_parse_action_plan_extracts_json_embedded_in_prose(self):
        """parse_action_plan must work even when the model wraps JSON in prose."""
        prose = (
            "Sure, I will select the relevant diagnostics.\n\n"
            '{"actions":[{"id":"gpu.amd_status","params":{}},{"id":"system.kernel_version","params":{}}]}\n\n'
            "Those should help narrow the issue."
        )
        result = parse_action_plan(prose)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["id"], "gpu.amd_status")
        self.assertEqual(result[1]["id"], "system.kernel_version")

    def test_parse_action_plan_rejects_prose_without_actions(self):
        """Prose with no JSON actions block returns an empty plan."""
        self.assertEqual(parse_action_plan("No diagnostics are needed here."), [])
        self.assertEqual(parse_action_plan('{"command":"rm -rf /"}'), [])

    def test_safety_floor_covers_gpu_and_hardware_signals(self):
        """Safety floor actions are returned for known signal categories."""
        gpu_evidence = {"signals": [{"kind": "gpu_reset", "classification": "warning"}]}
        floor = safety_floor_actions(gpu_evidence)
        ids = [item["id"] for item in floor]
        self.assertIn("system.kernel_version", ids)
        self.assertIn("gpu.pci_driver", ids)
        self.assertIn("gpu.amd_status", ids)
        self.assertIn("gpu.temperature", ids)

        hw_evidence = {"signals": [{"kind": "hardware_error", "classification": "warning"}]}
        hw_floor = safety_floor_actions(hw_evidence)
        hw_ids = [item["id"] for item in hw_floor]
        self.assertIn("system.kernel_version", hw_ids)

    def test_safety_floor_is_empty_for_no_known_categories(self):
        """Unknown or informational-only signals produce no safety floor."""
        self.assertEqual(safety_floor_actions({"signals": []}), [])
        self.assertEqual(safety_floor_actions({"signals": [{"kind": "apparmor_denial", "classification": "informational"}]}), [])

    def test_adaptive_diagnostics_safety_floor_runs_for_gpu_anomaly(self):
        """Safety floor diagnostics run automatically for AMDGPU signal."""
        session = Session(Config(), "/bin/true")
        gpu_evidence = {
            "signals": [{"kind": "gpu_reset", "classification": "possible"}],
            "output": "amdgpu: REG_WAIT timeout",
        }
        # Model always returns empty plan so only the safety floor produces results.
        with mock.patch.object(session, "_ask_local", return_value='{"actions":[]}'), \
             mock.patch("sysai.diagnostics.run", return_value={"status": "ok", "output": "6.8.0"}) as command:
            results = session._adaptive_diagnostics(gpu_evidence, mock.Mock(), mock.Mock(), mock.Mock())
        action_ids = [r.get("action_id") for r in results]
        self.assertIn("gpu.pci_driver", action_ids)
        self.assertIn("gpu.amd_status", action_ids)
        self.assertIn("system.kernel_version", action_ids)
        # Underlying command is executed without shell
        for call in command.call_args_list:
            self.assertNotIn("shell", call.kwargs)

    def test_insight_adaptive_diagnostics_full_path(self):
        """Integration: insight path collects GPU safety-floor diagnostics and feeds them to the model."""
        session = Session(Config(), "/bin/true")
        gpu_dmesg_output = "amdgpu: REG_WAIT timeout 1000000 0 0 0 0 0 0\n" * 3
        call_log = []

        def fake_ask(prompt, *, on_thinking=None, on_content=None, handle=None):
            call_log.append(prompt)
            if "select" in prompt.lower() and "diagnostics" in prompt.lower():
                return '{"actions":[]}'  # Let safety floor do the work
            if on_content:
                on_content("AMDGPU REG_WAIT timeout detected.")
            return "AMDGPU REG_WAIT timeout detected."

        server_end, client_end = socket.socketpair()
        with mock.patch.object(session, "_ask_local", side_effect=fake_ask), \
             mock.patch("sysai.diagnostics.run", return_value={"status": "ok", "output": "test"}):
            session._control_stream(
                {"action": "insight", "argv": ["dmesg"], "web": False,
                 "result": {"exit_code": 0, "output": gpu_dmesg_output, "truncated": False}},
                server_end,
            )
        server_end.close()

        messages = []
        client_end.settimeout(2)
        try:
            raw = client_end.recv(65536)
            client_end.close()
        except OSError:
            raw = b""

        # The final answer prompt must include the additional_diagnostics
        final_prompt = next((p for p in call_log if "additional_diagnostics" in p), None)
        self.assertIsNotNone(final_prompt, "Final insight prompt must include diagnostics")
        # Visible output must not contain raw action envelopes
        visible = ANSI_RE.sub("", raw.decode())
        self.assertNotIn('"actions"', visible)

    def test_thinking_text_cannot_trigger_actions(self):
        """Action-like content in thinking must not cause any action to execute."""
        session = Session(Config(), "/bin/true")
        evidence_no_anomaly = {
            "signals": [{"kind": "apparmor_denial", "classification": "informational"}],
            "output": "apparmor DENIED",
        }
        command_calls = []
        with mock.patch("sysai.diagnostics.run", side_effect=lambda *a, **kw: command_calls.append(a)):
            result = session._adaptive_diagnostics(evidence_no_anomaly, mock.Mock(), mock.Mock(), mock.Mock())
        # informational-only → no diagnostics (safety floor doesn't fire)
        self.assertEqual(result, [])
        self.assertEqual(command_calls, [])


if __name__ == "__main__":
    unittest.main()
