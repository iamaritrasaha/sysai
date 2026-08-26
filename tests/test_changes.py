from __future__ import annotations

import datetime as dt
import io
import unittest
from unittest import mock

from sysai import changes
from sysai.cli import changes_command


APT_HISTORY = """Start-Date: 2026-08-20  09:15:04
Commandline: apt install preload
Requested-By: someone (1000)
Install: preload:amd64 (0.6.4-5build2)
End-Date: 2026-08-20  09:15:06

Start-Date: 2026-08-25  22:07:15
Commandline: packagekit role='remove-packages'
Remove: thunderbird:amd64 (2:1snap1-0ubuntu3), transmission-gtk:amd64 (4.0.5-1)
End-Date: 2026-08-25  22:07:16
"""

DPKG_LOG = """2026-08-25 22:07:15 status half-configured thunderbird:amd64 2:1snap1
2026-08-25 22:07:16 remove thunderbird:amd64 2:1snap1-0ubuntu3 <none>
2026-08-25 22:30:01 upgrade linux-image-generic:amd64 6.8.0-40 6.8.0-45
2026-08-25 23:00:00 install preload:amd64 <none> 0.6.4-5build2
malformed line that must be ignored
"""


class SinceParsingTests(unittest.TestCase):
    def test_last_boot_is_the_default(self):
        self.assertEqual(changes.DEFAULT_SINCE, "last-boot")
        with mock.patch("sysai.changes.boot_time",
                        return_value=dt.datetime(2026, 8, 26, 22, 0).astimezone()):
            since, label = changes.resolve_since(None)
        self.assertEqual(label, "last-boot")
        self.assertEqual(since.hour, 22)

    def test_relative_and_absolute_values_are_parsed_deterministically(self):
        now = dt.datetime.now().astimezone()
        yesterday, label = changes.resolve_since("yesterday")
        self.assertEqual(label, "yesterday")
        self.assertEqual((now.date() - yesterday.date()).days, 1)
        self.assertEqual(yesterday.hour, 0)
        exact, label = changes.resolve_since("2026-08-20")
        self.assertEqual(label, "2026-08-20")
        self.assertEqual((exact.year, exact.month, exact.day), (2026, 8, 20))
        duration, _label = changes.resolve_since("48h")
        self.assertLessEqual((now - duration).days, 2)

    def test_an_unrecognized_since_value_is_refused_with_guidance(self):
        with self.assertRaisesRegex(changes.ChangesError, "Unrecognized --since"):
            changes.resolve_since("whenever-ish")

    def test_last_boot_without_uptime_is_an_error_not_a_guess(self):
        with mock.patch("sysai.changes.boot_time", return_value=None):
            with self.assertRaisesRegex(changes.ChangesError, "boot time"):
                changes.resolve_since("last-boot")


class LogParsingTests(unittest.TestCase):
    def test_apt_history_is_parsed_into_timestamped_operations(self):
        since = dt.datetime(2026, 8, 25, 0, 0).astimezone()
        with mock.patch("sysai.collect.read_tail", side_effect=[None, APT_HISTORY]):
            entries, available = changes.apt_history(since)
        self.assertTrue(available)
        # The 2026-08-20 entry falls outside the window and is excluded.
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["operations"]["remove"], ["thunderbird", "transmission-gtk"])
        self.assertTrue(entries[0]["timestamp"].startswith("2026-08-25T22:07:15"))

    def test_dpkg_entries_outside_the_window_are_excluded(self):
        since = dt.datetime(2026, 8, 25, 22, 45).astimezone()
        with mock.patch("sysai.domains.collect.read_tail", side_effect=[None, DPKG_LOG]):
            entries = changes.package_changes(since)
        self.assertEqual([item["package"] for item in entries], ["preload"])

    def test_malformed_log_lines_are_ignored_not_guessed_at(self):
        since = dt.datetime(2026, 1, 1).astimezone()
        with mock.patch("sysai.domains.collect.read_tail", side_effect=[None, DPKG_LOG]):
            entries = changes.package_changes(since)
        self.assertEqual(len(entries), 3)
        self.assertTrue(all("timestamp" in item and "action" in item for item in entries))

    def test_kernel_package_changes_are_identified(self):
        since = dt.datetime(2026, 1, 1).astimezone()
        with mock.patch("sysai.domains.collect.read_tail", side_effect=[None, DPKG_LOG]):
            entries = changes.package_changes(since)
        kernel = changes.kernel_changes(entries)
        self.assertEqual([item["package"] for item in kernel], ["linux-image-generic"])
        self.assertEqual(kernel[0]["previous_version"], "6.8.0-40")
        self.assertEqual(kernel[0]["version"], "6.8.0-45")


class CorrelationTests(unittest.TestCase):
    def test_temporal_correlation_is_never_stated_as_causation(self):
        sections = {
            "kernel": {"change_count": 0, "changes": []},
            "packages": {"change_count": 2, "changes": [
                {"timestamp": "2026-08-25T22:07:16", "package": "thunderbird", "action": "remove"},
                {"timestamp": "2026-08-25T23:00:00", "package": "preload", "action": "install"}]},
            "failures": {"first_error_timestamp": "2026-08-25T23:30:00"},
            "services": {"failed_count": 0},
        }
        finding = next(item for item in changes.analyze_changes(sections)
                       if item["id"] == "changes.preceded_first_error")
        self.assertEqual(finding["classification"], "POSSIBLE")
        self.assertEqual(finding["confidence"], "low")
        self.assertIn("not evidence of cause", finding["probable_cause"])
        self.assertIn("before the first", finding["title"])
        for word in ("caused", "because of", "responsible for"):
            self.assertNotIn(word, finding["title"])

    def test_the_rendered_output_states_the_correlation_caveat(self):
        sections = {"window": {"since": "a", "until": "b", "since_value": "last-boot"},
                    "kernel": {"change_count": 0}, "packages": {"change_count": 0},
                    "apt": {"operation_count": 0}, "reboots": {"count": 0},
                    "configuration": {"changed_count": 0}, "failures": {}}
        text = changes.render_changes({"sections": sections})
        self.assertIn("correlation, not cause", text)

    def test_no_correlation_finding_without_a_recorded_failure(self):
        sections = {"kernel": {"change_count": 0, "changes": []},
                    "packages": {"change_count": 3, "changes": []},
                    "failures": {"first_error_timestamp": None}, "services": {"failed_count": 0}}
        ids = {item["id"] for item in changes.analyze_changes(sections)}
        self.assertNotIn("changes.preceded_first_error", ids)


class ChangesCommandTests(unittest.TestCase):
    def test_a_bad_since_value_exits_with_a_usage_code(self):
        with mock.patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(changes_command("whenever-ish"), 2)
        self.assertIn("Unrecognized --since", errors.getvalue())

    def test_the_collector_never_scans_the_whole_filesystem(self):
        source = __import__("pathlib").Path(changes.__file__).read_text(encoding="utf-8")
        self.assertNotIn('Path("/").rglob', source)
        self.assertNotIn("rglob", source)
        self.assertNotIn('Path.home()', source)
        # /etc is listed one level deep for modification times only.
        self.assertIn('Path("/etc").iterdir()', source)

    def test_configuration_evidence_records_names_and_times_but_no_contents(self):
        with mock.patch("sysai.changes.boot_time",
                        return_value=dt.datetime.now().astimezone() - dt.timedelta(hours=1)):
            document = changes.collect_changes("last-boot")
        for entry in document["sections"]["configuration"]["changed"]:
            self.assertEqual(set(entry), {"path", "modified"})

    def test_a_real_collection_produces_a_valid_document(self):
        output = io.StringIO()
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.cli._assess_or_note", return_value=0):
            self.assertEqual(changes_command("last-boot"), 0)
        self.assertIn("SysAI Changes", output.getvalue())
        self.assertIn("Window", output.getvalue())


if __name__ == "__main__":
    unittest.main()
