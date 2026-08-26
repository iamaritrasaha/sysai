from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import baseline
from sysai.cli import baseline_command


SNAPSHOT = {
    "schema_version": baseline.SCHEMA_VERSION,
    "created": "2026-08-20T10:00:00+05:30",
    "sysai_version": "0.1.0",
    "system": {"kernel": "7.0.0-29-generic", "architecture": "x86_64",
               "os": {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.4 LTS"}},
    "gpu": {"vendors": ["amd"], "drivers": ["amdgpu"], "device_count": 1},
    "memory": {"total_bytes": 16_000_000_000, "swap_total_bytes": 4_000_000_000},
    "filesystems": [{"mountpoint": "/", "fstype": "ext4", "total_bytes": 234_000_000_000,
                     "capacity_percent": 39.5}],
    "network": {"interfaces": [{"interface": "enp9s0", "kind": "wired"}]},
    "services": {"failed_count": 0, "failed_units": [], "system_state": "running"},
    "boot": {"failed_unit_count": 0, "critical_journal_count": 0, "reboot_required": False},
    "packages": {"installed_count": 2297, "held": [],
                 "versions": {"mesa-vulkan-drivers": "26.0.7", "systemd": "255.4-1ubuntu8"}},
}


class BaselineStorageTests(unittest.TestCase):
    def test_create_writes_atomically_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with mock.patch("sysai.baseline.snapshot", return_value=SNAPSHOT):
                path, document = baseline.create(directory)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), document)
            # No temporary artefact is left behind by the atomic replace.
            self.assertEqual([item.name for item in directory.iterdir()], [baseline.FILENAME])

    def test_baselines_live_in_the_xdg_state_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
                path = baseline.baseline_path()
            self.assertEqual(path, Path(temp) / "sysai" / baseline.FILENAME)
            self.assertEqual(stat.S_IMODE((Path(temp) / "sysai").stat().st_mode), 0o700)

    def test_loading_a_missing_baseline_explains_how_to_create_one(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(baseline.BaselineError, "sysai baseline create"):
                baseline.load(Path(temp))

    def test_a_corrupt_baseline_is_reported_not_crashed_on(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline.baseline_path(Path(temp)).write_text("{ this is not json", encoding="utf-8")
            with self.assertRaisesRegex(baseline.BaselineError, "corrupt"):
                baseline.load(Path(temp))

    def test_a_schema_mismatch_is_refused_rather_than_misread(self):
        with tempfile.TemporaryDirectory() as temp:
            baseline.baseline_path(Path(temp)).write_text(
                json.dumps({**SNAPSHOT, "schema_version": 99}), encoding="utf-8")
            with self.assertRaisesRegex(baseline.BaselineError, "schema version"):
                baseline.load(Path(temp))

    def test_delete_reports_whether_anything_was_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.assertFalse(baseline.delete(directory))
            with mock.patch("sysai.baseline.snapshot", return_value=SNAPSHOT):
                baseline.create(directory)
            self.assertTrue(baseline.delete(directory))
            self.assertFalse(baseline.baseline_path(directory).exists())


class BaselineContentTests(unittest.TestCase):
    def test_a_real_snapshot_holds_no_private_identifiers_or_raw_logs(self):
        document = baseline.snapshot()
        serialized = json.dumps(document)
        for forbidden in ("dmesg", "journalctl", "kernel:", "Authorization", "BEGIN PRIVATE KEY"):
            self.assertNotIn(forbidden, serialized)
        for placeholder_source in ("gpu_event_sample", "critical_sample", "error_sample",
                                   "output", "transcript", "reasoning"):
            self.assertNotIn(placeholder_source, serialized)

    def test_a_snapshot_records_the_documented_deterministic_facts(self):
        document = baseline.snapshot()
        self.assertEqual(document["schema_version"], baseline.SCHEMA_VERSION)
        for key in ("system", "gpu", "memory", "filesystems", "network",
                    "services", "boot", "packages"):
            self.assertIn(key, document)
        self.assertIn("sysai_version", document)

    def test_network_facts_keep_names_but_not_addresses(self):
        document = baseline.snapshot()
        for entry in document["network"]["interfaces"]:
            self.assertEqual(set(entry), {"interface", "kind"})


class BaselineCompareTests(unittest.TestCase):
    def test_no_change_is_reported_as_unchanged(self):
        result = baseline.compare(SNAPSHOT, SNAPSHOT)
        self.assertEqual(result["change_count"], 0)
        self.assertIn("Unchanged since baseline", baseline.render_comparison(result))

    def test_differences_are_computed_in_python_with_readable_labels(self):
        current = json.loads(json.dumps(SNAPSHOT))
        current["system"]["kernel"] = "7.0.0-30-generic"
        current["packages"]["versions"]["mesa-vulkan-drivers"] = "26.0.8"
        current["services"]["failed_count"] = 1
        current["services"]["failed_units"] = ["cups.service"]
        result = baseline.compare(SNAPSHOT, current)
        labels = {item["label"]: (item["previous"], item["current"]) for item in result["changed"]}
        self.assertEqual(labels["Kernel"], ("7.0.0-29-generic", "7.0.0-30-generic"))
        self.assertEqual(labels["mesa-vulkan-drivers"], ("26.0.7", "26.0.8"))
        self.assertEqual(labels["Failed services"], (0, 1))
        text = baseline.render_comparison(result)
        self.assertIn("Kernel\n  7.0.0-29-generic -> 7.0.0-30-generic", text)
        self.assertIn("Failed services\n  0 -> 1", text)

    def test_volatile_capacity_drift_is_not_reported_as_a_change(self):
        current = json.loads(json.dumps(SNAPSHOT))
        current["filesystems"][0]["capacity_percent"] = 41.2
        self.assertEqual(baseline.compare(SNAPSHOT, current)["change_count"], 0)

    def test_added_and_removed_facts_are_distinguished(self):
        current = json.loads(json.dumps(SNAPSHOT))
        current["packages"]["versions"]["new-package"] = "1.0"
        del current["packages"]["versions"]["systemd"]
        result = baseline.compare(SNAPSHOT, current)
        self.assertEqual([item["label"] for item in result["added"]], ["new-package"])
        self.assertEqual([item["label"] for item in result["removed"]], ["systemd"])


class BaselineCommandTests(unittest.TestCase):
    def test_compare_without_a_baseline_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.dict(os.environ, {"XDG_STATE_HOME": temp}), \
             mock.patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(baseline_command("compare"), 1)
        self.assertIn("No baseline exists yet", errors.getvalue())

    def test_compare_never_asks_the_model_when_nothing_changed(self):
        output = io.StringIO()
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.baseline.load", return_value=SNAPSHOT), \
             mock.patch("sysai.baseline.snapshot", return_value=SNAPSHOT), \
             mock.patch("sysai.cli._stream_session_request") as stream:
            self.assertEqual(baseline_command("compare"), 0)
        stream.assert_not_called()

    def test_show_renders_the_stored_snapshot(self):
        output = io.StringIO()
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.baseline.load", return_value=SNAPSHOT):
            self.assertEqual(baseline_command("show"), 0)
        self.assertIn("SysAI Baseline", output.getvalue())
        self.assertIn("7.0.0-29-generic", output.getvalue())


if __name__ == "__main__":
    unittest.main()
