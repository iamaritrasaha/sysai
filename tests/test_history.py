from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import history


class TokenMatchingTests(unittest.TestCase):
    def test_apt_does_not_match_laptop(self):
        tokens = history._tokens("cd ~/laptop-notes && ls")
        self.assertEqual(history._domain_hits(tokens, "packages"), [])

    def test_apt_matches_apt(self):
        tokens = history._tokens("sudo apt update")
        self.assertEqual(history._domain_hits(tokens, "packages"), ["apt"])

    def test_sudo_prefix_is_stripped_not_matched(self):
        tokens = history._tokens("sudo modprobe amdgpu")
        self.assertNotIn("sudo", tokens)
        self.assertIn("modprobe", tokens)

    def test_path_qualified_command_matches_by_basename(self):
        tokens = history._tokens("/usr/sbin/modprobe amdgpu")
        self.assertIn("modprobe", tokens)

    def test_unknown_domain_falls_back_to_any_domain_match(self):
        tokens = history._tokens("sudo systemctl restart NetworkManager")
        self.assertTrue(history._domain_hits(tokens, "system"))


class BashHistoryParsingTests(unittest.TestCase):
    def test_parses_epoch_timestamp_pairs(self):
        text = "#1700000000\nmodprobe amdgpu\n#1700000100\nsudo nala upgrade\n"
        entries = history.parse_bash_history(text)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["command"], "modprobe amdgpu")
        self.assertIsNotNone(entries[0]["timestamp"])
        self.assertEqual(entries[0]["source"], history.SOURCE_BASH_HISTORY)

    def test_handles_history_without_timestamps(self):
        entries = history.parse_bash_history("ls -la\ncd /tmp\n")
        self.assertEqual([e["command"] for e in entries], ["ls -la", "cd /tmp"])
        self.assertIsNone(entries[0]["timestamp"])

    def test_multiline_command_is_folded_onto_previous_entry(self):
        text = "for i in 1 2 3; do\n  echo $i\ndone\n"
        entries = history.parse_bash_history(text)
        # The indented continuation line folds onto the preceding entry
        # rather than becoming its own history event.
        joined = [e["command"] for e in entries]
        self.assertTrue(any("echo $i" in command for command in joined))
        self.assertNotIn("echo $i", joined)  # never a bare standalone entry

    def test_malformed_marker_line_does_not_raise(self):
        # A line that looks like a marker but isn't a valid epoch is parsed
        # as ordinary text, never raises, and never corrupts later entries.
        entries = history.parse_bash_history("#not-a-number\nls\n")
        self.assertEqual(entries[-1]["command"], "ls")
        self.assertIsNone(entries[-1]["timestamp"])

    def test_empty_text_produces_no_entries(self):
        self.assertEqual(history.parse_bash_history(""), [])

    def test_never_executes_anything(self):
        # A history line containing a destructive command is pure text here.
        entries = history.parse_bash_history("rm -rf /\n")
        self.assertEqual(entries[0]["command"], "rm -rf /")


class BoundedReadTests(unittest.TestCase):
    def test_read_bash_history_is_bounded_by_max_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bash_history"
            path.write_text("\n".join(f"echo {i}" for i in range(500)) + "\n")
            entries = history.read_bash_history(path, lookback_hours=99999, max_entries=10)
        self.assertLessEqual(len(entries), 10)

    def test_read_bash_history_respects_lookback_window(self):
        now = dt.datetime.now().astimezone()
        old = int((now - dt.timedelta(hours=100)).timestamp())
        recent = int((now - dt.timedelta(hours=1)).timestamp())
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bash_history"
            path.write_text(f"#{old}\nold-command\n#{recent}\nrecent-command\n")
            entries = history.read_bash_history(path, lookback_hours=48, max_entries=300)
        commands = [e["command"] for e in entries]
        self.assertIn("recent-command", commands)
        self.assertNotIn("old-command", commands)

    def test_missing_histfile_returns_empty(self):
        self.assertEqual(history.read_bash_history(Path("/nonexistent/does-not-exist")), [])

    def test_large_file_reads_only_the_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bash_history"
            # Bigger than the bounded read window; the marker line must be
            # found only near the end, never by scanning the whole file.
            filler = "x" * 100
            lines = [f"echo {filler}{i}" for i in range(50_000)]
            lines.append("needle-command")
            path.write_text("\n".join(lines) + "\n")
            entries = history.read_bash_history(path, lookback_hours=99999, max_entries=5000)
        self.assertIn("needle-command", [e["command"] for e in entries])


class RedactionTests(unittest.TestCase):
    def test_api_key_assignment_is_redacted(self):
        entry = history._sanitize_entry({"command": "export API_KEY=sk-abcdefghijklmnopqrstuvwx",
                                         "cwd": None, "timestamp": None, "exit_status": None,
                                         "source": "bash_history", "sequence": 1, "redacted": False})
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwx", entry["command"])
        self.assertIn("<redacted>", entry["command"])

    def test_bearer_token_in_curl_is_redacted(self):
        entry = history._sanitize_entry({
            "command": 'curl -H "Authorization: Bearer abcdefghijklmnop12345" https://example.com',
            "cwd": None, "timestamp": None, "exit_status": None,
            "source": "bash_history", "sequence": 1, "redacted": False})
        self.assertNotIn("abcdefghijklmnop12345", entry["command"])

    def test_ssh_password_flag_is_redacted(self):
        entry = history._sanitize_entry({
            "command": "mysql -pSuperSecret123 -u root",
            "cwd": None, "timestamp": None, "exit_status": None,
            "source": "bash_history", "sequence": 1, "redacted": False})
        self.assertNotIn("SuperSecret123", entry["command"])

    def test_home_path_is_sanitized_at_shared_level(self):
        with mock.patch.dict("os.environ", {"USER": "alice", "LOGNAME": "alice"}), \
             mock.patch("sysai.privacy.os.path.expanduser", return_value="/home/alice"):
            entry = history._sanitize_entry({
                "command": "cat /home/alice/.ssh/id_rsa", "cwd": "/home/alice",
                "timestamp": None, "exit_status": None, "source": "bash_history",
                "sequence": 1, "redacted": False})
        self.assertNotIn("alice", entry["command"])


class RelevanceScoringTests(unittest.TestCase):
    def test_domain_matching_command_scores_higher_than_unrelated(self):
        anchor = dt.datetime.now().astimezone()
        gpu_entry = {"command": "sudo modprobe amdgpu", "timestamp": anchor.isoformat(timespec="seconds"),
                     "exit_status": 0, "source": "session"}
        unrelated_entry = {"command": "ls -la", "timestamp": anchor.isoformat(timespec="seconds"),
                           "exit_status": 0, "source": "session"}
        gpu_score, _ = history.score_entry(gpu_entry, "gpu", anchor_time=anchor)
        other_score, _ = history.score_entry(unrelated_entry, "gpu", anchor_time=anchor)
        self.assertGreater(gpu_score, other_score)

    def test_nonzero_exit_status_increases_score(self):
        anchor = dt.datetime.now().astimezone()
        base = {"command": "sudo apt install foo", "timestamp": None, "source": "session"}
        ok_score, _ = history.score_entry({**base, "exit_status": 0}, "packages", anchor_time=anchor)
        fail_score, _ = history.score_entry({**base, "exit_status": 1}, "packages", anchor_time=anchor)
        self.assertGreater(fail_score, ok_score)

    def test_temporal_proximity_decays_with_distance(self):
        anchor = dt.datetime.now().astimezone()
        near = {"command": "sudo modprobe amdgpu",
                "timestamp": (anchor - dt.timedelta(minutes=5)).isoformat(timespec="seconds"),
                "exit_status": 0, "source": "session"}
        far = {"command": "sudo modprobe amdgpu",
               "timestamp": (anchor - dt.timedelta(hours=40)).isoformat(timespec="seconds"),
               "exit_status": 0, "source": "session"}
        near_score, _ = history.score_entry(near, "gpu", anchor_time=anchor)
        far_score, _ = history.score_entry(far, "gpu", anchor_time=anchor)
        self.assertGreaterEqual(near_score, far_score)

    def test_score_is_bounded_to_one(self):
        anchor = dt.datetime.now().astimezone()
        entry = {"command": "sudo modprobe amdgpu",
                 "timestamp": anchor.isoformat(timespec="seconds"), "exit_status": 1, "source": "session"}
        score, _ = history.score_entry(entry, "gpu", anchor_time=anchor)
        self.assertLessEqual(score, 1.0)


class RelevantHistoryPipelineTests(unittest.TestCase):
    def test_off_mode_returns_nothing(self):
        entries, ignored = history.relevant_history([], "gpu", mode=history.MODE_OFF)
        self.assertEqual(entries, [])
        self.assertEqual(ignored, 0)

    def test_max_context_entries_is_enforced(self):
        session_records = [
            {"command": "sudo modprobe amdgpu", "cwd": "/", "exit_code": 0,
             "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds")}
            for _ in range(50)
        ]
        with mock.patch("sysai.history.read_bash_history", return_value=[]):
            entries, ignored = history.relevant_history(
                session_records, "gpu", mode=history.MODE_RELEVANT, max_context_entries=5)
        self.assertLessEqual(len(entries), 5)

    def test_unrelated_command_is_ignored_in_relevant_mode(self):
        session_records = [
            {"command": "ls -la", "cwd": "/", "exit_code": 0,
             "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds")},
        ]
        with mock.patch("sysai.history.read_bash_history", return_value=[]):
            entries, ignored = history.relevant_history(session_records, "gpu", mode=history.MODE_RELEVANT)
        self.assertEqual(entries, [])
        self.assertEqual(ignored, 1)

    def test_all_mode_ignores_relevance_and_returns_recent(self):
        session_records = [
            {"command": "ls -la", "cwd": "/", "exit_code": 0,
             "timestamp": dt.datetime.now().astimezone().isoformat(timespec="seconds")},
        ]
        with mock.patch("sysai.history.read_bash_history", return_value=[]):
            entries, _ = history.relevant_history(session_records, "gpu", mode=history.MODE_ALL)
        self.assertEqual(len(entries), 1)

    def test_correlation_block_is_labelled_and_bounded(self):
        entries, ignored = [], 3
        block = history.correlation_block(entries, ignored)
        self.assertEqual(block["label"], "HISTORICAL / CORRELATION ONLY")
        self.assertIn("not establish causation", block["note"])
        self.assertEqual(block["ignored_count"], 3)


class SessionSourceTests(unittest.TestCase):
    def test_session_records_are_normalized_with_session_source(self):
        records = [{"command": "sudo modprobe amdgpu", "cwd": "/root", "exit_code": 1,
                   "timestamp": "2026-08-31T10:00:00+05:30"}]
        entries = history.normalize_session_records(records)
        self.assertEqual(entries[0]["source"], history.SOURCE_SESSION)
        self.assertEqual(entries[0]["exit_status"], 1)

    def test_bash_history_entries_have_null_cwd_and_exit_status(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bash_history"
            path.write_text("modprobe amdgpu\n")
            entries = history.read_bash_history(path)
        self.assertIsNone(entries[0]["cwd"])
        self.assertIsNone(entries[0]["exit_status"])
        self.assertEqual(entries[0]["source"], history.SOURCE_BASH_HISTORY)

    def test_concise_history_groups_duplicate_events(self):
        entries = [
            {"command": "sudo apt update", "source": "bash_history", "exit_status": 0,
             "timestamp": "2026-09-01T10:00:00+05:30", "reasons": []},
            {"command": "sudo apt update", "source": "bash_history", "exit_status": 0,
             "timestamp": "2026-09-01T10:05:00+05:30", "reasons": []},
        ]
        grouped = history.summarize_events(entries)
        self.assertEqual(grouped["packages"][0]["count"], 2)

    def test_all_history_keeps_detailed_timestamp_and_source(self):
        text = history.render_history([{
            "command": "dmesg", "source": "session", "exit_status": 0,
            "timestamp": "2026-09-01T10:00:00+05:30",
        }], 0, all_mode=True)
        self.assertIn("2026-09-01T10:00:00+05:30", text)
        self.assertIn("session", text)


if __name__ == "__main__":
    unittest.main()
