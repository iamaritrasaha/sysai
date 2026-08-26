from __future__ import annotations

import io
import json
import tokenize
import unittest
from pathlib import Path
from unittest import mock

from sysai import monitor
from sysai.cli import watch_command


def code_only(source: str) -> str:
    """Source with comments and string literals removed, so prose is not scanned."""
    result = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        result.append(token.string)
    return " ".join(result)


def sampler(*values):
    """Patch the sampler table itself: `_SAMPLERS` binds functions at import."""
    stream = iter(values)
    last = values[-1]
    return lambda: next(stream, last)


class WatchBoundsTests(unittest.TestCase):
    def test_defaults_match_the_documented_contract(self):
        self.assertEqual(monitor.DEFAULT_DURATION, 30)
        self.assertEqual(monitor.MAX_DURATION, 300)
        self.assertEqual(monitor.MIN_INTERVAL, 1)

    def test_out_of_range_windows_are_refused_rather_than_clamped(self):
        with self.assertRaisesRegex(monitor.WatchError, "at most 300 seconds"):
            monitor.validate(301, 1)
        with self.assertRaisesRegex(monitor.WatchError, "at least 1 second"):
            monitor.validate(30, 0)
        with self.assertRaisesRegex(monitor.WatchError, "cannot be longer than"):
            monitor.validate(5, 10)

    def test_a_valid_window_is_accepted_unchanged(self):
        self.assertEqual(monitor.validate(30, 1), (30, 1))

    def test_an_unwatchable_domain_is_rejected(self):
        with self.assertRaisesRegex(monitor.WatchError, "cannot be watched"):
            monitor.run_watch("packages", 5, 1)

    def test_there_is_no_daemon_timer_or_startup_hook(self):
        # Prose in docstrings mentions what watch deliberately does not do, so
        # only real code is inspected.
        code = code_only(Path(monitor.__file__).read_text(encoding="utf-8"))
        for forbidden in ("systemctl", "crontab", "daemon", "fork", "Thread", "atexit",
                          "subprocess", "Popen", "WantedBy", "OnCalendar"):
            self.assertNotIn(forbidden, code)


class WatchSamplingTests(unittest.TestCase):
    def _fake_clock(self, step: float = 1.0):
        state = {"now": 0.0}

        def clock():
            return state["now"]

        def sleep(seconds):
            state["now"] += seconds
        return clock, sleep, state

    def test_sampling_stops_at_the_requested_duration(self):
        clock, sleep, _state = self._fake_clock()
        with mock.patch.dict(monitor._SAMPLERS, {"memory": sampler({"used_percent": 10.0})}):
            result = monitor.run_watch("memory", 5, 1, sleep=sleep, clock=clock)
        self.assertFalse(result["interrupted"])
        self.assertEqual(result["requested_duration"], 5)
        self.assertLessEqual(result["sample_count"], 7)
        self.assertGreaterEqual(result["sample_count"], 5)

    def test_ctrl_c_stops_cleanly_and_still_summarizes(self):
        clock, _sleep, _state = self._fake_clock()
        calls = {"count": 0}

        def sleep(_seconds):
            calls["count"] += 1
            if calls["count"] == 2:
                raise KeyboardInterrupt
        with mock.patch.dict(monitor._SAMPLERS, {"memory": sampler({"used_percent": 10.0})}):
            result = monitor.run_watch("memory", 30, 1, sleep=sleep, clock=lambda: 0.0)
        self.assertTrue(result["interrupted"])
        self.assertEqual(result["sample_count"], 2)
        summary = monitor.summarize(result)
        self.assertTrue(summary["interrupted"])
        self.assertIn("RAM used (%)", summary["metrics"])

    def test_samples_are_summarized_into_first_last_min_and_max(self):
        clock, sleep, _state = self._fake_clock()
        with mock.patch.dict(monitor._SAMPLERS, {"memory": sampler(
                {"used_percent": 10.0}, {"used_percent": 40.0}, {"used_percent": 25.0})}):
            result = monitor.run_watch("memory", 2, 1, sleep=sleep, clock=clock)
        metrics = monitor.summarize(result)["metrics"]["RAM used (%)"]
        self.assertEqual(metrics["first"], 10.0)
        self.assertEqual(metrics["max"], 40.0)
        self.assertEqual(metrics["min"], 10.0)

    def test_network_link_state_transitions_become_events(self):
        clock, sleep, _state = self._fake_clock()

        def link(state):
            return {"interfaces": [{"interface": "eth0", "operstate": state, "carrier": 1,
                                    "rx_bytes": 1, "tx_bytes": 1, "rx_errors": 0, "tx_errors": 0}]}

        with mock.patch.dict(monitor._SAMPLERS, {"network": sampler(
                link("up"), link("up"), link("down"), link("up"))}):
            result = monitor.run_watch("network", 3, 1, sleep=sleep, clock=clock)
        events = monitor.summarize(result)["events"]
        self.assertTrue(any(item["kind"] == "link_state_change" for item in events))

    def test_raw_samples_never_reach_the_evidence_document(self):
        clock, sleep, _state = self._fake_clock()
        with mock.patch.dict(monitor._SAMPLERS, {"memory": sampler({"used_percent": 10.0})}):
            result = monitor.run_watch("memory", 2, 1, sleep=sleep, clock=clock)
        document = monitor.build_evidence(result, monitor.summarize(result),
                                          {"available": True, "count": 0, "sample": []})
        serialized = json.dumps(document)
        self.assertNotIn('"samples": [', serialized)
        self.assertFalse(document["sections"]["raw_samples_retained"])

    def test_kernel_events_are_limited_to_the_sampling_window(self):
        result = {"domain": "gpu", "started_wall": 1_800_000_000.0, "sample_count": 1}
        with mock.patch("sysai.collect.journal",
                        return_value={"status": "ok", "output": "amdgpu: GPU reset begin"}) as journal:
            events = monitor.kernel_events_during(result)
        self.assertIn("--since", journal.call_args.args)
        self.assertEqual(events["count"], 1)

    def test_an_unavailable_journal_is_not_checked_rather_than_zero(self):
        result = {"domain": "gpu", "started_wall": 1_800_000_000.0, "sample_count": 1}
        with mock.patch("sysai.collect.journal",
                        return_value={"status": "unavailable", "reason": "journalctl not installed"}):
            events = monitor.kernel_events_during(result)
        self.assertFalse(events["available"])
        self.assertIn("not installed", events["reason"])


class WatchCommandTests(unittest.TestCase):
    def test_exactly_one_model_call_happens_and_only_after_sampling(self):
        output = io.StringIO()
        order = []
        clock = iter([0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch.dict(monitor._SAMPLERS,
                             {"memory": lambda: order.append("sample") or {"used_percent": 10.0}}), \
             mock.patch("sysai.monitor.time.sleep"), \
             mock.patch("sysai.monitor.time.monotonic", side_effect=lambda: next(clock, 99.0)), \
             mock.patch("sysai.monitor.kernel_events_during",
                        return_value={"available": True, "count": 0, "sample": []}), \
             mock.patch("sysai.cli._assess_or_note",
                        side_effect=lambda *a, **k: order.append("assess") or 0) as assess:
            code = watch_command("memory", 3, 1)
        self.assertEqual(code, 0)
        self.assertEqual(order.count("assess"), 1)
        self.assertEqual(order[-1], "assess")
        self.assertFalse(assess.call_args.kwargs["adaptive"])

    def test_no_web_research_happens_during_sampling(self):
        output = io.StringIO()
        clock = iter([0.0, 1.0, 2.0, 3.0])
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch.dict(monitor._SAMPLERS, {"memory": sampler({"used_percent": 10.0})}), \
             mock.patch("sysai.monitor.time.sleep"), \
             mock.patch("sysai.monitor.time.monotonic", side_effect=lambda: next(clock, 99.0)), \
             mock.patch("sysai.monitor.kernel_events_during",
                        return_value={"available": True, "count": 0, "sample": []}), \
             mock.patch("sysai.web.OllamaWebSearch.search") as search, \
             mock.patch("sysai.cli._assess_or_note", return_value=0):
            watch_command("memory", 2, 1, web=True)
        search.assert_not_called()

    def test_invalid_bounds_are_rejected_before_any_sampling(self):
        with mock.patch("sysai.monitor.run_watch") as run, \
             mock.patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(watch_command("memory", 9999, 1), 2)
        run.assert_not_called()
        self.assertIn("at most 300 seconds", errors.getvalue())

    def test_the_summary_says_samples_were_discarded(self):
        result = {"domain": "memory", "requested_duration": 5, "interval": 1, "samples": [],
                  "sample_count": 3, "interrupted": False, "started_wall": 0.0, "ended_wall": 5.0}
        text = monitor.render_summary(result, {"metrics": {}, "events": []},
                                      {"available": True, "count": 0, "sample": []})
        self.assertIn("held in memory only", text)


if __name__ == "__main__":
    unittest.main()
