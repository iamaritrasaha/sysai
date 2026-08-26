from __future__ import annotations

import io
import json
import socket
import unittest
from unittest import mock

from sysai.cli import investigate_command
from sysai.config import Config
from sysai.diagnostics import MAX_ROUNDS
from sysai.evidence import CONFIRMED, WARNING, build, finding
from sysai.session import Session


def _messages(session, request):
    server, client = socket.socketpair()
    try:
        session._control_stream(request, server)
        server.close()
        client.settimeout(2)
        raw = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            raw += chunk
    finally:
        client.close()
    return [json.loads(line) for line in raw.splitlines() if line]


class InvestigateTests(unittest.TestCase):
    def test_nothing_recent_is_reported_plainly(self):
        session = Session(Config(), "/bin/true")
        with mock.patch.object(session, "_ask_local") as ask:
            messages = _messages(session, {"action": "investigate"})
        ask.assert_not_called()
        progress = " ".join(item.get("text", "") for item in messages if item["type"] == "progress")
        self.assertIn("Nothing recent requires investigation", progress)
        self.assertEqual(messages[-1], {"type": "done", "ok": True})

    def test_the_most_recent_failure_is_classified_and_investigated(self):
        session = Session(Config(), "/bin/true")
        session.records.append({"command": "ls /nope", "exit_code": 2, "cwd": "/tmp",
                                "timestamp": "now", "output": "ls: cannot access"})
        document = session._investigation_subject()
        self.assertIsNotNone(document)
        self.assertEqual(document["request"]["command"], "investigate")
        self.assertEqual(document["sections"]["failure"]["exit_code"], 2)
        self.assertIn("signals", document["sections"])

    def test_successful_and_interrupted_commands_are_not_investigated(self):
        session = Session(Config(), "/bin/true")
        session.records.append({"command": "ls", "exit_code": 0, "cwd": "/tmp",
                                "timestamp": "now", "output": ""})
        session.records.append({"command": "sleep 9", "exit_code": 130, "cwd": "/tmp",
                                "timestamp": "now", "output": "", "interrupted": True})
        self.assertIsNone(session._investigation_subject())

    def test_a_serious_previous_finding_is_used_when_no_command_failed(self):
        session = Session(Config(), "/bin/true")
        session.last_result = build(
            command="gpu", scope="gpu", sections={},
            findings=[finding("gpu.kernel_events", "gpu", WARNING, CONFIRMED,
                              title="3 GPU events", count=3)])
        document = session._investigation_subject()
        self.assertEqual(document["request"]["command"], "investigate")
        self.assertEqual(document["findings"][0]["id"], "gpu.kernel_events")

    def test_informational_previous_findings_are_not_investigated(self):
        session = Session(Config(), "/bin/true")
        session.last_result = build(
            command="packages", scope="packages", sections={},
            findings=[finding("packages.pending_upgrades", "packages", "informational",
                              "INFORMATIONAL", title="2 upgrades", count=2)])
        self.assertIsNone(session._investigation_subject())

    def test_only_audited_action_ids_can_run_and_rounds_are_bounded(self):
        session = Session(Config(), "/bin/true")
        session.records.append({"command": "dmesg", "exit_code": 1, "cwd": "/tmp",
                                "timestamp": "now", "output": "amdgpu: GPU reset begin"})
        planning = []

        def ask(prompt, **_kwargs):
            if "Return JSON only" in prompt:
                planning.append(prompt)
                return '{"actions":[{"id":"rm -rf /","params":{}}]}'
            return "assessment"

        with mock.patch.object(session, "_ask_local", side_effect=ask), \
             mock.patch("sysai.diagnostics.run",
                        return_value={"status": "ok", "exit_code": 0, "output": "x"}) as run:
            _messages(session, {"action": "investigate"})
        self.assertLessEqual(len(planning), MAX_ROUNDS)
        for call in run.call_args_list:
            self.assertNotIn("rm", call.args[0])

    def test_elevated_actions_still_require_one_time_approval(self):
        session = Session(Config(), "/bin/true")
        evidence = {"signals": [{"kind": "filesystem_error", "classification": "warning"}],
                    "output": "I/O error on /dev/sda"}
        requested = []

        def send(message):
            requested.append(message)

        connection = mock.Mock()
        connection.recv.return_value = json.dumps(
            {"type": "diagnostic_result", "action_id": "disk.smart_health",
             "result": {"status": "declined"}}).encode() + b"\n"
        with mock.patch.object(session, "_ask_local",
                               return_value='{"actions":[{"id":"disk.smart_health",'
                                            '"params":{"device":"/dev/sda"}}]}'), \
             mock.patch("sysai.diagnostics.run") as run, \
             mock.patch("sysai.diagnostics.trusted_inventory",
                        return_value={"units": set(), "devices": {"/dev/sda"},
                                      "interfaces": set(), "packages": set()}):
            results = session._adaptive_diagnostics(evidence, connection, send, mock.Mock())
        self.assertTrue(any(item.get("type") == "diagnostic_permission" for item in requested))
        # The declined elevated action never executes locally in the session.
        for call in run.call_args_list:
            self.assertNotIn("smartctl", call.args[0])
        self.assertTrue(any(item.get("status") == "declined" for item in results))

    def test_no_repair_action_exists_in_the_catalogue(self):
        from sysai.diagnostics import FIXED_ACTIONS, _PARAMETERIZED
        forbidden = {"start", "stop", "restart", "enable", "disable", "mask", "install",
                     "remove", "purge", "upgrade", "fsck", "mkfs", "dd", "rm", "chmod", "chown"}
        for action_id, (argv, _purpose) in FIXED_ACTIONS.items():
            with self.subTest(action=action_id):
                self.assertFalse(forbidden & set(argv))
        for action_id, spec in _PARAMETERIZED.items():
            with self.subTest(action=action_id):
                argv = spec[3]("x.service" if spec[0] == "unit" else "/dev/sda")
                self.assertFalse(forbidden & set(argv[1:]))

    def test_cli_investigate_needs_an_active_session(self):
        with mock.patch("sysai.cli._active_socket", return_value=None), \
             mock.patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(investigate_command(), 1)
        self.assertIn("No active SysAI session", errors.getvalue())

    def test_cli_investigate_forwards_the_web_flag(self):
        with mock.patch("sysai.cli._active_socket", return_value="x.sock"), \
             mock.patch("sysai.cli._stream_session_request", return_value=0) as stream:
            self.assertEqual(investigate_command(web=True), 0)
        stream.assert_called_once_with("investigate", web=True)


if __name__ == "__main__":
    unittest.main()
