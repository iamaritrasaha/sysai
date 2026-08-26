from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import reports
from sysai.cli import report_command
from sysai.evidence import CONFIRMED, WARNING, build, finding
from sysai.privacy import LOCAL, SHARED


def _document() -> dict:
    return build(
        command="gpu", scope="gpu", level=LOCAL,
        sections={"driver": {"drivers_in_use": ["amdgpu"]},
                  "kernel": {"gpu_event_sample": [
                      "Aug 26 22:35:53 workstation-7 kernel: amdgpu reset; host 192.168.1.42 "
                      "mac a4:bb:6d:1f:2e:3c serial: WX41A99KKF12 path /home/alice/logs"]}},
        findings=[finding("gpu.kernel_events", "gpu", WARNING, CONFIRMED,
                          title="3 GPU events", evidence={"sample": ["reset"]}, count=3,
                          probable_cause="driver recovery",
                          suggested_next_diagnostic="journal.kernel_errors")],
        diagnostics=[{"action_id": "gpu.pci_driver", "purpose": "Inspect PCI GPU devices",
                      "status": "ok"}],
        unavailable_checks=[{"check": "amd-smi", "domain": "gpu",
                             "reason": "not installed", "classification": "NOT CHECKED"}])


class ReportContentTests(unittest.TestCase):
    def test_markdown_has_every_required_section(self):
        text = reports.to_markdown(_document())
        for heading in ("# SysAI Diagnostic Report", "**Generated:**", "**Scope:**",
                        "## System summary", "## Findings", "## Evidence",
                        "## Diagnostics performed", "## What was NOT checked",
                        "## Confidence", "## Recommended next steps", "## Privacy note"):
            self.assertIn(heading, text)

    def test_unavailable_checks_are_labelled_not_checked(self):
        text = reports.to_markdown(_document())
        self.assertIn("**amd-smi** — not installed (NOT CHECKED)", text)

    def test_reports_are_always_sanitized_at_the_shared_level(self):
        text = reports.to_markdown(_document())
        for secret in ("workstation-7", "192.168.1.42", "a4:bb:6d:1f:2e:3c",
                       "WX41A99KKF12", "/home/alice"):
            self.assertNotIn(secret, text)
        for placeholder in ("<host>", "<ipv4>", "<mac>", "<serial>", "/home/<user>"):
            self.assertIn(placeholder, text)

    def test_json_reports_are_sanitized_and_declare_their_level(self):
        payload = json.loads(reports.to_json(_document()))
        self.assertEqual(payload["privacy"]["level"], SHARED)
        self.assertNotIn("192.168.1.42", json.dumps(payload))

    def test_report_states_that_sysai_never_applies_repairs(self):
        self.assertIn("never applies repairs", reports.to_markdown(_document()))

    def test_an_empty_findings_list_is_stated_rather_than_invented(self):
        text = reports.to_markdown(build(command="gpu", scope="gpu", sections={}, findings=[]))
        self.assertIn("No findings were produced", text)


class ReportFileTests(unittest.TestCase):
    def test_files_are_written_with_restrictive_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = reports.write(Path(temp) / "report.md", "content\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(encoding="utf-8"), "content\n")

    def test_no_file_is_created_without_an_explicit_output_path(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.cli.collect_scope", return_value=_document()), \
             mock.patch.dict(os.environ, {"HOME": temp}):
            code = report_command("gpu")
            self.assertEqual(list(Path(temp).iterdir()), [])
        self.assertEqual(code, 0)
        self.assertIn("# SysAI Diagnostic Report", output.getvalue())

    def test_writing_a_report_announces_the_path(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "out.md"
            with mock.patch("sysai.cli.sys.stdout", output), \
                 mock.patch("sysai.cli.collect_scope", return_value=_document()), \
                 mock.patch("builtins.print", side_effect=lambda *a, **k: output.write(" ".join(map(str, a)) + "\n")):
                code = report_command("gpu", output=str(target))
            self.assertTrue(target.exists())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(code, 0)
        self.assertIn("report written to", output.getvalue())

    def test_last_uses_the_sessions_previous_result(self):
        output = io.StringIO()
        with mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("sysai.cli._session_request",
                        return_value={"ok": True, "result": _document()}) as request, \
             mock.patch("sysai.cli.collect_scope") as collect:
            code = report_command("health", last=True)
        self.assertEqual(code, 0)
        request.assert_called_once_with("last_result")
        collect.assert_not_called()
        self.assertIn("SysAI Diagnostic Report", output.getvalue())

    def test_last_without_a_previous_result_fails_cleanly(self):
        with mock.patch("sysai.cli._session_request",
                        return_value={"ok": False, "error": "No diagnostic has completed"}), \
             mock.patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(report_command("health", last=True), 1)
        self.assertIn("No diagnostic has completed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
