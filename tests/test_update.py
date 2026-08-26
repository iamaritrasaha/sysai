from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import updater
from sysai.cli import update_command


def _release(version="9.9.9", assets=None):
    return json.dumps({
        "tag_name": f"v{version}", "name": f"SysAI {version}",
        "published_at": "2026-08-20T10:00:00Z", "body": "Adds things.",
        "prerelease": False, "html_url": f"https://example.invalid/releases/v{version}",
        "assets": assets or [],
    }).encode()


def _archive(directory: Path, name: str = "sysai-9.9.9.tar.gz") -> bytes:
    source = directory / "sysai-9.9.9"
    source.mkdir()
    (source / "install.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path = directory / name
    with tarfile.open(path, "w:gz") as archive:
        archive.add(source, arcname="sysai-9.9.9")
    return path.read_bytes()


class VersionTests(unittest.TestCase):
    def test_semantic_versions_are_compared_numerically(self):
        self.assertTrue(updater.is_newer("0.2.0", "0.1.0"))
        self.assertTrue(updater.is_newer("v0.10.0", "0.9.0"))
        self.assertFalse(updater.is_newer("0.1.0", "0.1.0"))
        self.assertFalse(updater.is_newer("0.0.9", "0.1.0"))

    def test_an_unparseable_version_is_never_treated_as_newer(self):
        self.assertFalse(updater.is_newer("latest", "0.1.0"))
        self.assertFalse(updater.is_newer("main", "0.1.0"))


class CheckTests(unittest.TestCase):
    def test_check_only_reads_metadata_and_changes_nothing(self):
        with mock.patch("sysai.updater.run") as run:
            status = updater.check(fetch=lambda url, **kwargs: _release("9.9.9"))
        run.assert_not_called()
        self.assertTrue(status["update_available"])
        self.assertEqual(status["latest_version"], "9.9.9")
        self.assertIn("Adds things", status["notes"])

    def test_the_same_version_reports_no_update(self):
        status = updater.check(fetch=lambda url, **kwargs: _release(updater.__version__))
        self.assertFalse(status["update_available"])
        self.assertIn("up to date", updater.render_check(status))

    def test_a_repository_without_releases_says_so_plainly(self):
        import urllib.error
        error = urllib.error.HTTPError(updater.RELEASES_API, 404, "Not Found", {}, None)
        with mock.patch("sysai.updater.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(updater.UpdateError, "No published release"):
                updater.fetch_release()

    def test_other_http_failures_are_reported_without_a_traceback(self):
        import urllib.error
        error = urllib.error.HTTPError(updater.RELEASES_API, 503, "Unavailable", {}, None)
        with mock.patch("sysai.updater.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(updater.UpdateError, "HTTP 503"):
                updater.fetch_release()

    def test_a_release_without_a_checksum_manifest_is_not_verifiable(self):
        assets = [{"name": "sysai-9.9.9.tar.gz", "browser_download_url": "https://x.invalid/a", "size": 1}]
        status = updater.check(fetch=lambda url, **kwargs: _release("9.9.9", assets))
        self.assertFalse(status["verifiable"])
        self.assertIsNone(status["checksum_manifest"])

    def test_a_release_with_a_checksum_manifest_is_verifiable(self):
        assets = [{"name": "sysai-9.9.9.tar.gz", "browser_download_url": "https://x.invalid/a", "size": 1},
                  {"name": "SHA256SUMS", "browser_download_url": "https://x.invalid/s", "size": 1}]
        status = updater.check(fetch=lambda url, **kwargs: _release("9.9.9", assets))
        self.assertTrue(status["verifiable"])
        self.assertEqual(status["checksum_manifest"], "SHA256SUMS")


class ApplyTests(unittest.TestCase):
    ASSETS = [{"name": "sysai-9.9.9.tar.gz", "browser_download_url": "https://x.invalid/a", "size": 1},
              {"name": "SHA256SUMS", "browser_download_url": "https://x.invalid/s", "size": 1}]

    def test_without_a_verifiable_artifact_no_update_is_attempted(self):
        with mock.patch("sysai.updater.installation_state",
                        return_value={"kind": "installed", "path": "/x", "dirty": False,
                                      "detail": "installed copy"}), \
             mock.patch("sysai.updater.run") as run:
            result = updater.apply(fetch=lambda url, **kwargs: _release("9.9.9"))
        self.assertFalse(result["applied"])
        self.assertEqual(result["reason"], "no-verifiable-artifact")
        run.assert_not_called()

    def test_a_checksum_mismatch_refuses_the_update(self):
        def fetch(url, **kwargs):
            if url == updater.RELEASES_API:
                return _release("9.9.9", self.ASSETS)
            if url.endswith("/s"):
                return (("0" * 64) + "  sysai-9.9.9.tar.gz\n").encode()
            return b"tampered artifact bytes"
        with mock.patch("sysai.updater.installation_state",
                        return_value={"kind": "installed", "path": "/x", "dirty": False,
                                      "detail": "installed copy"}), \
             mock.patch("sysai.updater.run") as run:
            with self.assertRaisesRegex(updater.UpdateError, "Checksum mismatch"):
                updater.apply(fetch=fetch)
        run.assert_not_called()

    def test_an_artifact_absent_from_the_manifest_is_refused(self):
        def fetch(url, **kwargs):
            if url == updater.RELEASES_API:
                return _release("9.9.9", self.ASSETS)
            if url.endswith("/s"):
                return (("0" * 64) + "  something-else.tar.gz\n").encode()
            return b"bytes"
        with mock.patch("sysai.updater.installation_state",
                        return_value={"kind": "installed", "path": "/x", "dirty": False,
                                      "detail": "installed copy"}):
            with self.assertRaisesRegex(updater.UpdateError, "does not list"):
                updater.apply(fetch=fetch)

    def test_a_verified_artifact_runs_the_releases_own_installer(self):
        with tempfile.TemporaryDirectory() as temp:
            data = _archive(Path(temp))
            digest = hashlib.sha256(data).hexdigest()

            def fetch(url, **kwargs):
                if url == updater.RELEASES_API:
                    return _release("9.9.9", self.ASSETS)
                if url.endswith("/s"):
                    return f"{digest}  sysai-9.9.9.tar.gz\n".encode()
                return data

            installs = []

            def install(argv, timeout=0, limit=0):
                installs.append(argv)
                return {"status": "ok", "exit_code": 0, "output": ""}

            with mock.patch("sysai.updater.installation_state",
                            return_value={"kind": "installed", "path": "/x", "dirty": False,
                                          "detail": "installed copy"}):
                result = updater.apply(fetch=fetch, install=install)
        self.assertTrue(result["applied"])
        self.assertEqual(len(installs), 1)
        self.assertTrue(installs[0][0].endswith("install.sh"))

    def test_a_development_checkout_is_never_updated_in_place(self):
        for dirty, reason in ((False, "development-checkout"), (True, "dirty-checkout")):
            with self.subTest(dirty=dirty):
                with mock.patch("sysai.updater.installation_state",
                                return_value={"kind": "checkout", "path": "/repo", "dirty": dirty,
                                              "detail": "checkout"}), \
                     mock.patch("sysai.updater.run") as run:
                    result = updater.apply(fetch=lambda url, **kwargs: _release("9.9.9", self.ASSETS))
                self.assertFalse(result["applied"])
                self.assertEqual(result["reason"], reason)
                run.assert_not_called()

    def test_archives_with_traversal_or_link_entries_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            payload = directory / "evil.tar.gz"
            victim = directory / "victim.txt"
            victim.write_text("safe", encoding="utf-8")
            with tarfile.open(payload, "w:gz") as archive:
                info = tarfile.TarInfo("../escaped.txt")
                info.size = 0
                archive.addfile(info, io.BytesIO(b""))
            work = directory / "work"
            work.mkdir()
            with self.assertRaisesRegex(updater.UpdateError, "unsafe path"):
                updater._extract(payload.read_bytes(), "evil.tar.gz", work)
            self.assertEqual(victim.read_text(encoding="utf-8"), "safe")

    def test_nothing_pulls_a_branch_or_pipes_a_download_into_a_shell(self):
        source = Path(updater.__file__).read_text(encoding="utf-8")
        for forbidden in ("git pull", '"pull"', "| sh", "|sh", "curl ", "shell=True",
                          "os.system", "refs/heads/main", "archive/main"):
            self.assertNotIn(forbidden, source)


class UpdateCommandTests(unittest.TestCase):
    def _run(self, action, status, state=None):
        output = io.StringIO()
        printed = []
        with mock.patch("sysai.updater.check", return_value=status), \
             mock.patch("sysai.cli.sys.stdout", output), \
             mock.patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(map(str, a)))), \
             mock.patch("sysai.updater.installation_state",
                        return_value=state or {"kind": "installed", "path": "/x", "dirty": False,
                                               "detail": "installed copy"}), \
             mock.patch("sysai.updater.apply") as apply_:
            code = update_command(action)
        return code, output.getvalue() + "\n".join(printed), apply_

    def test_check_never_applies_anything(self):
        status = {"current_version": "0.1.0", "latest_version": "9.9.9", "release_name": "SysAI",
                  "published": None, "notes": "", "page": "https://x.invalid",
                  "prerelease": False, "update_available": True, "verifiable": True,
                  "artifact": "a.tar.gz", "checksum_manifest": "SHA256SUMS"}
        code, text, apply_ = self._run("check", status)
        self.assertEqual(code, 0)
        apply_.assert_not_called()
        self.assertIn("SysAI Update", text)

    def test_an_unverifiable_release_refuses_and_shows_manual_steps(self):
        status = {"current_version": "0.1.0", "latest_version": "9.9.9", "release_name": "SysAI",
                  "published": None, "notes": "", "page": "https://x.invalid",
                  "prerelease": False, "update_available": True, "verifiable": False,
                  "artifact": None, "checksum_manifest": None}
        code, text, apply_ = self._run("apply", status)
        self.assertEqual(code, 1)
        apply_.assert_not_called()
        self.assertIn("no verifiable release artifact/checksum is published", text)
        self.assertIn("Update manually", text)

    def test_a_checkout_install_is_reported_rather_than_replaced(self):
        status = {"current_version": "0.1.0", "latest_version": "9.9.9", "release_name": "SysAI",
                  "published": None, "notes": "", "page": "https://x.invalid",
                  "prerelease": False, "update_available": True, "verifiable": True,
                  "artifact": "a.tar.gz", "checksum_manifest": "SHA256SUMS"}
        code, text, apply_ = self._run(
            "apply", status,
            state={"kind": "checkout", "path": "/repo", "dirty": True,
                   "detail": "development checkout with uncommitted changes"})
        self.assertEqual(code, 1)
        apply_.assert_not_called()
        self.assertIn("never pulls from a branch", text)

    def test_being_up_to_date_needs_no_action(self):
        status = {"current_version": "0.1.0", "latest_version": "0.1.0", "release_name": "SysAI",
                  "published": None, "notes": "", "page": "https://x.invalid",
                  "prerelease": False, "update_available": False, "verifiable": False,
                  "artifact": None, "checksum_manifest": None}
        code, text, apply_ = self._run("apply", status)
        self.assertEqual(code, 0)
        apply_.assert_not_called()
        self.assertIn("up to date", text)


if __name__ == "__main__":
    unittest.main()
