from __future__ import annotations

import io
import unittest
from unittest import mock

from sysai import cli
from sysai.domains import DOMAINS
from sysai.monitor import WATCHABLE


class CommandSurfaceTests(unittest.TestCase):
    def test_help_lists_every_documented_command(self):
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            with self.assertRaises(SystemExit):
                cli.main(["--help"])
        text = output.getvalue()
        for command in ("explain", "investigate", "ask", "check", "health", "doctor",
                        *DOMAINS, "what", "report", "baseline", "changes", "watch",
                        "update", "thinking", "stop"):
            self.assertIn(command, text)

    def test_every_new_command_dispatches_to_its_handler(self):
        cases = [
            (["doctor"], "sysai.cli.doctor_command"),
            (["doctor", "--json"], "sysai.cli.doctor_command"),
            (["what", "ls"], "sysai.cli.what_command"),
            (["check", "is", "my", "gpu", "ok"], "sysai.cli.check_command"),
            (["report"], "sysai.cli.report_command"),
            (["report", "gpu", "--json"], "sysai.cli.report_command"),
            (["baseline", "create"], "sysai.cli.baseline_command"),
            (["changes"], "sysai.cli.changes_command"),
            (["changes", "--since", "yesterday"], "sysai.cli.changes_command"),
            (["watch", "memory"], "sysai.cli.watch_command"),
            (["update", "check"], "sysai.cli.update_command"),
            (["update"], "sysai.cli.update_command"),
            (["investigate"], "sysai.cli.investigate_command"),
        ]
        for argv, target in cases:
            with self.subTest(argv=argv):
                with mock.patch(target, return_value=0) as handler:
                    self.assertEqual(cli.main(argv), 0)
                handler.assert_called_once()

    def test_each_domain_command_routes_to_its_own_domain(self):
        for domain in DOMAINS:
            with self.subTest(domain=domain):
                with mock.patch("sysai.cli.domain_command", return_value=0) as handler:
                    cli.main([domain])
                self.assertEqual(handler.call_args.args[0], domain)
                self.assertFalse(handler.call_args.kwargs["web"])

    def test_domain_commands_accept_web(self):
        with mock.patch("sysai.cli.domain_command", return_value=0) as handler:
            cli.main(["gpu", "--web"])
        self.assertTrue(handler.call_args.kwargs["web"])

    def test_watch_only_accepts_watchable_domains(self):
        with mock.patch("sysai.cli.watch_command", return_value=0):
            for domain in WATCHABLE:
                with self.subTest(domain=domain):
                    self.assertEqual(cli.main(["watch", domain]), 0)
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["watch", "packages"])

    def test_watch_defaults_match_the_documented_contract(self):
        with mock.patch("sysai.cli.watch_command", return_value=0) as handler:
            cli.main(["watch", "gpu"])
        self.assertEqual(handler.call_args.args, ("gpu", 30, 1))


class CommandInsightCompatibilityTests(unittest.TestCase):
    def test_existing_command_insight_forms_still_work(self):
        cases = (
            (["dmesg"], ["dmesg"], False, False),
            (["--web", "dmesg"], ["dmesg"], False, True),
            (["--raw", "dmesg"], ["dmesg"], True, False),
            (["sudo", "dmesg"], ["sudo", "dmesg"], False, False),
            (["journalctl", "-b"], ["journalctl", "-b"], False, False),
            (["--raw", "--web", "lspci", "-k"], ["lspci", "-k"], True, True),
        )
        for argv, expected, raw, web in cases:
            with self.subTest(argv=argv):
                with mock.patch("sysai.cli.insight_command", return_value=0) as insight:
                    self.assertEqual(cli.main(argv), 0)
                self.assertEqual(insight.call_args.args[0], expected)
                self.assertEqual(insight.call_args.kwargs.get("raw", False), raw)
                self.assertEqual(insight.call_args.kwargs.get("web", False), web)

    def test_reserved_words_are_never_treated_as_inspection_commands(self):
        for word in ("gpu", "memory", "disk", "network", "boot", "services", "packages",
                     "thermal", "doctor", "check", "what", "report", "baseline",
                     "changes", "watch", "update", "investigate"):
            with self.subTest(word=word):
                self.assertIn(word, cli.RESERVED)
        with mock.patch("sysai.cli.insight_command") as insight, \
             mock.patch("sysai.cli.domain_command", return_value=0):
            cli.main(["disk"])
        insight.assert_not_called()

    def test_a_global_web_flag_before_a_reserved_word_reaches_that_command(self):
        with mock.patch("sysai.cli.domain_command", return_value=0) as handler, \
             mock.patch("sysai.cli.insight_command") as insight:
            self.assertEqual(cli.main(["--web", "gpu"]), 0)
        insight.assert_not_called()
        self.assertTrue(handler.call_args.kwargs["web"])

    def test_bare_global_flags_still_fall_back_to_help(self):
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            with self.assertRaises(SystemExit):
                cli.main(["--web"])
        self.assertIn("usage: sysai", output.getvalue())

    def test_legacy_commands_keep_their_existing_wiring(self):
        with mock.patch("sysai.cli._stream_session_request", return_value=0) as stream:
            self.assertEqual(cli.main(["explain"]), 0)
        stream.assert_called_once_with("explain")
        with mock.patch("sysai.cli._stream_session_request", return_value=0) as stream:
            self.assertEqual(cli.main(["ask", "--web", "what", "is", "this"]), 0)
        stream.assert_called_once_with("ask", question="what is this", web=True)
        with mock.patch("sysai.cli._stream_session_request", return_value=0) as stream:
            self.assertEqual(cli.main(["health"]), 0)
        stream.assert_called_once_with("health", web=False)
        with mock.patch("sysai.cli.thinking_command", return_value=0) as thinking:
            cli.main(["thinking", "status"])
        thinking.assert_called_once_with("status")
        with mock.patch("sysai.cli.stop_outside", return_value=0) as stop:
            cli.main(["stop"])
        stop.assert_called_once()


class DomainCommandTests(unittest.TestCase):
    def test_deterministic_facts_render_even_without_a_session(self):
        output = io.StringIO()
        document = {"request": {"scope": "gpu", "arguments": {}}, "sections": {},
                    "findings": [], "unavailable": []}
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.cli.collect_scope", return_value=document), \
             mock.patch("sysai.cli.render_document", return_value="deterministic output\n"), \
             mock.patch("sysai.cli._active_socket", return_value=None), \
             mock.patch("sysai.cli.sys.stderr", io.StringIO()) as errors:
            code = cli.domain_command("gpu")
        self.assertEqual(code, 0)
        self.assertIn("deterministic output", output.getvalue())
        self.assertIn("needs an active SysAI session", errors.getvalue())

    def test_an_active_session_receives_the_collected_evidence(self):
        output = io.StringIO()
        document = {"request": {"scope": "gpu", "arguments": {}}, "sections": {},
                    "findings": [], "unavailable": []}
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.cli.collect_scope", return_value=document), \
             mock.patch("sysai.cli.render_document", return_value="x\n"), \
             mock.patch("sysai.cli._active_socket", return_value="s.sock"), \
             mock.patch("sysai.cli._stream_session_request", return_value=0) as stream:
            cli.domain_command("gpu", web=True)
        self.assertEqual(stream.call_args.args, ("assess",))
        self.assertEqual(stream.call_args.kwargs["scope"], "gpu")
        self.assertIs(stream.call_args.kwargs["evidence"], document)
        self.assertTrue(stream.call_args.kwargs["web"])


if __name__ == "__main__":
    unittest.main()
