from __future__ import annotations

import io
import unittest
from unittest import mock

from sysai import intent
from sysai.cli import check_command
from sysai.config import Config
from sysai.domains import DOMAINS, FULL_SYSTEM, SCOPES
from sysai.session import Session


class IntentRoutingTests(unittest.TestCase):
    def test_deterministic_routes_for_the_documented_questions(self):
        cases = {
            "why is my PC slow?": FULL_SYSTEM,
            "why does my internet disconnect?": "network",
            "is my GPU okay?": "gpu",
            "why is boot slow?": "boot",
            "why is my RAM filling up?": "memory",
            "my screen freezes sometimes": "gpu",
            "the laptop is running hot and the fans are loud": "thermal",
            "I have no space left on the disk": "disk",
            "a systemd unit keeps failing to start": "services",
            "apt says I have broken install state": "packages",
        }
        for question, expected in cases.items():
            with self.subTest(question=question):
                scope, matched = intent.keyword_route(question)
                self.assertEqual(scope, expected)
                self.assertTrue(matched)

    def test_a_question_naming_several_subsystems_becomes_full_system(self):
        scope, _matched = intent.keyword_route("my gpu and my network both misbehave")
        self.assertEqual(scope, FULL_SYSTEM)

    def test_an_unrecognized_question_is_inconclusive_not_guessed(self):
        self.assertEqual(intent.keyword_route("what is the airspeed velocity of a swallow"),
                         (None, []))

    def test_the_model_reply_must_match_the_strict_enum(self):
        for reply in ("gpu", "  GPU  ", "The answer is: memory"):
            self.assertIn(intent.parse_domain(reply), SCOPES)
        for reply in ("run dmesg", "definitely_not_a_domain", "", "{\"cmd\": \"rm -rf /\"}"):
            self.assertIsNone(intent.parse_domain(reply))

    def test_an_invented_domain_falls_back_instead_of_being_used(self):
        result = intent.route("something inexplicable is happening",
                              ask_model=lambda _prompt: "storage_subsystem_deep_scan")
        self.assertEqual(result["scope"], FULL_SYSTEM)
        self.assertEqual(result["method"], "fallback")

    def test_a_model_supplied_command_can_never_become_a_scope(self):
        result = intent.route("something inexplicable is happening",
                              ask_model=lambda _prompt: "sudo rm -rf / --no-preserve-root")
        self.assertEqual(result["scope"], FULL_SYSTEM)
        self.assertEqual(result["method"], "fallback")

    def test_a_model_failure_falls_back_rather_than_raising(self):
        def broken(_prompt):
            raise RuntimeError("model offline")
        self.assertEqual(intent.route("mysterious behaviour", ask_model=broken)["scope"],
                         FULL_SYSTEM)

    def test_the_classification_prompt_forbids_commands_and_lists_the_enum(self):
        prompt = intent.classification_prompt("why is it slow")
        self.assertIn("Do not suggest commands", prompt)
        for name in (*DOMAINS, FULL_SYSTEM):
            self.assertIn(name, prompt)

    def test_session_classify_only_returns_enum_members(self):
        session = Session(Config(), "/bin/true")
        with mock.patch.object(session, "_ask_local", return_value="gpu"):
            self.assertEqual(session._control({"action": "classify", "question": "gpu ok?"}),
                             {"ok": True, "scope": "gpu", "accepted": True})
        with mock.patch.object(session, "_ask_local", return_value="please run `dmesg -T`"):
            response = session._control({"action": "classify", "question": "weird"})
        self.assertIsNone(response["scope"])
        self.assertFalse(response["accepted"])


class CheckCommandTests(unittest.TestCase):
    def _run(self, question: str, **patches):
        output = io.StringIO()
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.cli.collect_scope",
                        side_effect=lambda scope, **kwargs: {"request": {"scope": scope, "arguments": {}},
                                                             "sections": {}, "findings": [],
                                                             "unavailable": []}) as collect, \
             mock.patch("sysai.cli.render_document", return_value="rendered\n"), \
             mock.patch("sysai.cli._assess_or_note", return_value=0) as assess, \
             mock.patch("sysai.cli._session_request", **patches) as request:
            code = check_command(question)
        return code, collect, assess, request, output.getvalue()

    def test_a_keyword_question_never_consults_the_model(self):
        code, collect, assess, request, text = self._run("is my GPU okay?")
        self.assertEqual(code, 0)
        self.assertEqual(collect.call_args.args[0], "gpu")
        request.assert_not_called()
        assess.assert_called_once()
        self.assertIn("Routed to: gpu (keywords", text)

    def test_an_ambiguous_question_asks_the_session_and_uses_the_enum(self):
        code, collect, _assess, request, text = self._run(
            "the thing is behaving oddly again", return_value={"ok": True, "scope": "network"})
        self.assertEqual(code, 0)
        request.assert_called_once()
        self.assertEqual(collect.call_args.args[0], "network")
        self.assertIn("Routed to: network (model)", text)

    def test_an_invented_model_domain_falls_back_to_full_system(self):
        _code, collect, _assess, _request, text = self._run(
            "the thing is behaving oddly again",
            return_value={"ok": True, "scope": "exfiltrate_everything"})
        self.assertEqual(collect.call_args.args[0], FULL_SYSTEM)
        self.assertIn(FULL_SYSTEM, text)

    def test_an_empty_question_is_rejected(self):
        with mock.patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(check_command("   "), 2)
        self.assertIn("describe what you want checked", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
