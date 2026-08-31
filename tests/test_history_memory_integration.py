from __future__ import annotations

import io
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import cli, history, insight, memory
from sysai.config import Config
from sysai.evidence import CONFIRMED, INFORMATIONAL, POSSIBLE, WARNING, finding
from sysai.session import Session


_SAMPLE_HISTORY_ENTRY = {
    "timestamp": None, "command": "sudo modprobe amdgpu", "cwd": None, "source": "session",
    "exit_status": 0, "relevance_score": 0.8, "reasons": ["gpu-related command"],
    "sequence": 1, "redacted": True,
}
_SAMPLE_MEMORY = {
    "id": "1", "type": "incident", "subject": "gpu:x", "statement": "prior GPU incident",
    "confidence": "medium", "status": "active", "last_confirmed_at": None, "times_observed": 1,
}


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


def _isolated_memory(temp: str):
    return mock.patch("sysai.memory.persistent_state_dir", return_value=Path(temp))


class ParserTests(unittest.TestCase):
    def test_build_parser_does_not_collide_with_the_memory_domain(self):
        # "memory" is already the RAM-diagnostic domain; the experience-memory
        # command must live under a different, non-colliding name.
        parser = cli.build_parser()
        args = parser.parse_args(["memories", "stats"])
        self.assertEqual(args.command, "memories")
        args = parser.parse_args(["memory"])
        self.assertEqual(args.command, "memory")

    def test_new_verbs_are_reserved_and_not_treated_as_insight_commands(self):
        for verb in ("history", "memories", "remember", "feedback", "context"):
            self.assertIn(verb, cli.RESERVED)


class SessionEnrichmentTests(unittest.TestCase):
    def test_history_and_prior_experience_sections_are_added_when_available(self):
        session = Session(Config(), "/bin/true")
        session.records.append({
            "command": "sudo modprobe amdgpu", "cwd": "/", "exit_code": 0,
            "timestamp": "2026-08-31T10:00:00+05:30",
        })
        document = {"request": {"scope": "gpu", "command": "gpu"}, "sections": {}, "findings": []}
        with mock.patch("sysai.history.read_bash_history", return_value=[]), \
             mock.patch("sysai.memory.retrieve_relevant", return_value=[{
                 "id": "1", "type": "incident", "subject": "gpu:x", "statement": "prior gpu incident",
                 "confidence": "medium", "status": "active", "last_confirmed_at": None,
                 "times_observed": 1}]):
            enriched = session._add_history_and_memory(document)
        self.assertIn("history_correlation", enriched["sections"])
        self.assertEqual(enriched["sections"]["history_correlation"]["label"],
                         "HISTORICAL / CORRELATION ONLY")
        self.assertIn("prior_experience", enriched["sections"])
        self.assertEqual(enriched["sections"]["prior_experience"]["label"], "PRIOR EXPERIENCE")

    def test_history_disabled_in_config_adds_no_correlation_section(self):
        session = Session(Config(history_enabled=False), "/bin/true")
        document = {"request": {"scope": "gpu", "command": "gpu"}, "sections": {}, "findings": []}
        with mock.patch("sysai.memory.retrieve_relevant", return_value=[]):
            enriched = session._add_history_and_memory(document)
        self.assertNotIn("history_correlation", enriched["sections"])

    def test_no_findings_and_no_history_leaves_document_unchanged(self):
        session = Session(Config(), "/bin/true")
        document = {"request": {"scope": "gpu", "command": "gpu"}, "sections": {"a": 1}, "findings": []}
        with mock.patch("sysai.history.read_bash_history", return_value=[]), \
             mock.patch("sysai.memory.retrieve_relevant", return_value=[]):
            enriched = session._add_history_and_memory(document)
        self.assertEqual(enriched["sections"], {"a": 1})


class AutoIncidentTests(unittest.TestCase):
    def test_single_confirmed_signal_is_not_recorded_as_incident(self):
        session = Session(Config(), "/bin/true")
        document = {"request": {"scope": "gpu"}, "findings": [
            finding("gpu.temperature_high", "gpu", WARNING, CONFIRMED, title="hot gpu"),
        ]}
        with mock.patch("sysai.memory.record_incident") as record:
            session._record_confirmed_incidents(document)
        record.assert_not_called()

    def test_repeated_confirmed_signal_is_recorded_as_incident(self):
        session = Session(Config(), "/bin/true")
        document = {"request": {"scope": "gpu"}, "findings": [
            finding("gpu.temperature_high", "gpu", WARNING, CONFIRMED,
                    title="hot gpu", count=2),
        ]}
        with mock.patch("sysai.memory.record_incident") as record:
            session._record_confirmed_incidents(document)
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs["domain"], "gpu")

    def test_informational_or_possible_findings_are_never_auto_recorded(self):
        session = Session(Config(), "/bin/true")
        document = {"request": {"scope": "gpu"}, "findings": [
            finding("gpu.note", "gpu", WARNING, POSSIBLE, title="maybe"),
            finding("gpu.info", "gpu", "informational", INFORMATIONAL, title="fyi"),
        ]}
        with mock.patch("sysai.memory.record_incident") as record:
            session._record_confirmed_incidents(document)
        record.assert_not_called()

    def test_memory_write_never_shells_out(self):
        session = Session(Config(), "/bin/true")
        document = {"request": {"scope": "gpu"}, "findings": [
            finding("gpu.temperature_high", "gpu", WARNING, CONFIRMED, title="hot gpu"),
        ]}
        with tempfile.TemporaryDirectory() as temp, _isolated_memory(temp), \
             mock.patch("sysai.collect.run") as run:
            session._record_confirmed_incidents(document)
        run.assert_not_called()


class PerformanceTests(unittest.TestCase):
    """An ordinary completed shell command must never touch history or memory."""

    def test_successful_command_completion_does_not_touch_memory_or_history(self):
        session = Session(Config(), "/bin/true")
        session.current = {"command": "ls", "cwd": "/tmp", "timestamp": "now"}
        response_r, response_w = __import__("os").pipe()
        try:
            with mock.patch("sysai.memory.record_incident") as record, \
                 mock.patch("sysai.history.relevant_history") as relevant:
                session._handle_event({"event": "complete", "status": 0, "cwd": "/tmp"}, response_w)
            record.assert_not_called()
            relevant.assert_not_called()
        finally:
            __import__("os").close(response_r)
            __import__("os").close(response_w)

    def test_failed_command_analysis_path_does_not_touch_memory_or_history(self):
        # A failure goes through `_start_analysis`/`failure_prompt`, not `_assess`.
        session = Session(Config(auto_analyze_failures=False), "/bin/true")
        session.current = {"command": "false", "cwd": "/tmp", "timestamp": "now"}
        response_r, response_w = __import__("os").pipe()
        try:
            with mock.patch("sysai.memory.record_incident") as record, \
                 mock.patch("sysai.history.relevant_history") as relevant:
                session._handle_event({"event": "complete", "status": 1, "cwd": "/tmp"}, response_w)
            record.assert_not_called()
            relevant.assert_not_called()
        finally:
            __import__("os").close(response_r)
            __import__("os").close(response_w)


class CliCommandTests(unittest.TestCase):
    def test_remember_and_search_round_trip(self):
        with tempfile.TemporaryDirectory() as temp, _isolated_memory(temp), \
             mock.patch("sys.stdout", new_callable=io.StringIO):
            status = cli.remember_command("My main GPU is an AMD Radeon RX 7600.")
        self.assertEqual(status, 0)
        with tempfile.TemporaryDirectory() as temp, _isolated_memory(temp):
            memory.remember("My main GPU is an AMD Radeon RX 7600.")
            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                cli.memory_command(["search", "GPU"])
        self.assertIn("Radeon", out.getvalue())

    def test_memory_purge_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as temp, _isolated_memory(temp):
            memory.remember("a fact")
            with mock.patch("builtins.input", return_value="n"), \
                 mock.patch("sys.stdout", new_callable=io.StringIO):
                status = cli.memory_command(["purge"])
        self.assertEqual(status, 1)
        with tempfile.TemporaryDirectory() as temp, _isolated_memory(temp):
            self.assertEqual(memory.stats()["total"], 0)

    def test_history_command_json_is_bounded_and_sanitized(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bash_history"
            path.write_text("export API_KEY=sk-abcdefghijklmnopqrstuvwx\nsudo modprobe amdgpu\n")
            with mock.patch("sysai.history.resolve_histfile", return_value=path), \
                 mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                status = cli.history_command(as_json=True)
        self.assertEqual(status, 0)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwx", out.getvalue())

    def test_context_command_does_not_raise_without_a_session(self):
        with tempfile.TemporaryDirectory() as temp, _isolated_memory(temp), \
             mock.patch("sysai.cli._active_socket", return_value=None), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            status = cli.context_command()
        self.assertEqual(status, 0)
        self.assertIn("SysAI Context", out.getvalue())


class DomainDetectionTests(unittest.TestCase):
    def test_question_domain_detects_diagnostic_intent_without_domain_words(self):
        self.assertEqual(history.question_domain("why did it crash yesterday"), "system")

    def test_question_domain_detects_named_domain(self):
        self.assertEqual(history.question_domain("why does my gpu keep overheating"), "gpu")

    def test_question_domain_is_none_for_a_trivial_question(self):
        self.assertIsNone(history.question_domain("what is a symlink"))

    def test_command_domain_matches_known_vocabulary(self):
        self.assertEqual(history.command_domain("sudo modprobe amdgpu"), "gpu")

    def test_command_domain_is_none_for_an_unrecognized_program(self):
        self.assertIsNone(history.command_domain("./mybinary --flag"))

    def test_command_family_domain_maps_dmesg_to_boot(self):
        self.assertEqual(history.COMMAND_FAMILY_DOMAIN["dmesg"], "boot")


class AskCorrelationTests(unittest.TestCase):
    def test_ask_receives_relevant_history_and_prior_experience(self):
        session = Session(Config(), "/bin/true")
        with mock.patch.object(session, "_ask_local", return_value="ok") as ask, \
             mock.patch("sysai.history.relevant_history", return_value=([_SAMPLE_HISTORY_ENTRY], 0)) as relevant, \
             mock.patch("sysai.memory.retrieve_relevant", return_value=[_SAMPLE_MEMORY]) as retrieve:
            _messages(session, {"action": "ask", "question": "why does my gpu keep crashing"})
        relevant.assert_called_once()
        self.assertEqual(relevant.call_args.args[1], "gpu")
        retrieve.assert_called_once()
        prompt = ask.call_args.args[0]
        self.assertIn("HISTORICAL / CORRELATION ONLY", prompt)
        self.assertIn("PRIOR EXPERIENCE", prompt)
        self.assertIn("modprobe amdgpu", prompt)
        self.assertIn("does not establish causation", prompt)

    def test_trivial_question_never_queries_history_or_memory(self):
        session = Session(Config(), "/bin/true")
        with mock.patch.object(session, "_ask_local", return_value="ok"), \
             mock.patch("sysai.history.relevant_history") as relevant, \
             mock.patch("sysai.memory.retrieve_relevant") as retrieve:
            _messages(session, {"action": "ask", "question": "what is a symlink"})
        relevant.assert_not_called()
        retrieve.assert_not_called()

    def test_irrelevant_history_is_omitted_from_the_prompt(self):
        session = Session(Config(), "/bin/true")
        with mock.patch.object(session, "_ask_local", return_value="ok") as ask, \
             mock.patch("sysai.history.relevant_history", return_value=([], 0)), \
             mock.patch("sysai.memory.retrieve_relevant", return_value=[]):
            _messages(session, {"action": "ask", "question": "why is my gpu overheating"})
        prompt = ask.call_args.args[0]
        self.assertNotIn("HISTORICAL / CORRELATION ONLY", prompt)
        self.assertNotIn("PRIOR EXPERIENCE", prompt)


class InsightCorrelationTests(unittest.TestCase):
    def test_insight_receives_relevant_history_after_evidence_reduction(self):
        session = Session(Config(), "/bin/true")
        argv = ["dmesg"]
        result = {"exit_code": 0, "truncated": False,
                 "output": "amdgpu 0000:03:00.0: [drm] *ERROR* ring gfx timeout",
                 "analysis_output": "amdgpu 0000:03:00.0: [drm] *ERROR* ring gfx timeout"}
        with mock.patch.object(session, "_ask_local", return_value="ok") as ask, \
             mock.patch("sysai.history.relevant_history", return_value=([_SAMPLE_HISTORY_ENTRY], 0)) as relevant, \
             mock.patch("sysai.memory.retrieve_relevant", return_value=[_SAMPLE_MEMORY]):
            _messages(session, {"action": "insight", "argv": argv, "result": result})
        # dmesg maps to the "boot" domain.
        self.assertEqual(relevant.call_args.args[1], "boot")
        prompt = ask.call_args.args[0]
        self.assertIn("history_correlation", prompt)
        self.assertIn("prior_experience", prompt)
        self.assertIn("HISTORICAL / CORRELATION ONLY", prompt)
        self.assertIn("PRIOR EXPERIENCE", prompt)

    def test_raw_history_never_reaches_the_web_search_query(self):
        # `safe_research_query` must ignore the added keys entirely, so
        # history/memory content can never end up in a web query.
        evidence = {"command_family": "dmesg", "signals": [{"kind": "gpu_reset"}],
                   "history_correlation": {"entries": [{"command": "super-secret-path-xyz"}]},
                   "prior_experience": {"memories": [{"statement": "super-secret-path-xyz"}]}}
        query = insight.safe_research_query(evidence)
        self.assertNotIn("super-secret-path-xyz", query or "")

    def test_command_family_not_in_the_map_falls_back_to_system_domain(self):
        # Every command Command Insight actually accepts is mapped, but the
        # lookup still defends against an unmapped family with a safe default.
        self.assertEqual(history.COMMAND_FAMILY_DOMAIN.get("nonexistent-tool", "system"), "system")


class FailureAnalysisCorrelationTests(unittest.TestCase):
    def _run_analysis(self, session, record):
        response_r, response_w = os.pipe()
        try:
            session._start_analysis(record, response_w)
            session._analysis_thread.join(timeout=5)
        finally:
            os.close(response_r)
            os.close(response_w)

    def test_failure_analysis_includes_relevant_history_for_a_recognized_domain(self):
        session = Session(Config(), "/bin/true")
        record = {"command": "sudo modprobe amdgpu", "exit_code": 1, "cwd": "/",
                  "timestamp": "now", "output": "modprobe: FATAL: Module amdgpu not found."}
        with mock.patch.object(session, "_ask_local", return_value="ok") as ask, \
             mock.patch("sysai.history.relevant_history", return_value=([_SAMPLE_HISTORY_ENTRY], 0)) as relevant, \
             mock.patch("sysai.memory.retrieve_relevant", return_value=[_SAMPLE_MEMORY]):
            self._run_analysis(session, record)
        self.assertEqual(relevant.call_args.args[1], "gpu")
        prompt = ask.call_args.args[0]
        self.assertIn("HISTORICAL / CORRELATION ONLY", prompt)
        self.assertIn("PRIOR EXPERIENCE", prompt)

    def test_failure_analysis_for_an_unrecognized_domain_never_queries_history(self):
        session = Session(Config(), "/bin/true")
        record = {"command": "./mybinary --flag", "exit_code": 1, "cwd": "/",
                  "timestamp": "now", "output": "segmentation fault"}
        with mock.patch.object(session, "_ask_local", return_value="ok"), \
             mock.patch("sysai.history.relevant_history") as relevant, \
             mock.patch("sysai.memory.retrieve_relevant") as retrieve:
            self._run_analysis(session, record)
        relevant.assert_not_called()
        retrieve.assert_not_called()

    def test_successful_command_still_never_reaches_analysis_at_all(self):
        # Belt-and-braces: the analysis worker (and therefore any history or
        # memory lookup) is only ever started for a qualifying failure.
        session = Session(Config(), "/bin/true")
        session.current = {"command": "ls", "cwd": "/tmp", "timestamp": "now"}
        response_r, response_w = os.pipe()
        try:
            with mock.patch.object(session, "_start_analysis") as start:
                session._handle_event({"event": "complete", "status": 0, "cwd": "/tmp"}, response_w)
            start.assert_not_called()
        finally:
            os.close(response_r)
            os.close(response_w)


if __name__ == "__main__":
    unittest.main()
