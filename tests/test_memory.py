from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import memory


def _isolated(temp: str):
    return mock.patch("sysai.memory.persistent_state_dir", return_value=Path(temp))


class SchemaAndPermissionTests(unittest.TestCase):
    def test_store_is_created_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            memory.remember("test fact")
            db_path = Path(temp) / memory.DB_FILENAME
            self.assertTrue(db_path.exists())
            self.assertEqual(stat.S_IMODE(db_path.stat().st_mode), 0o600)

    def test_schema_creation_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            memory.remember("fact one")
            memory.remember("fact two")
            self.assertEqual(memory.stats()["total"], 2)


class CrudTests(unittest.TestCase):
    def test_remember_is_high_confidence_user_explicit(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("My main GPU is an AMD Radeon RX 7600.")
        self.assertEqual(record["source"], "user_explicit")
        self.assertEqual(record["confidence"], "high")
        self.assertEqual(record["status"], "active")

    def test_get_returns_none_for_missing_id(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            self.assertIsNone(memory.get("999"))

    def test_forget_removes_a_memory(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("temporary fact")
            self.assertTrue(memory.forget(record["id"]))
            self.assertIsNone(memory.get(record["id"]))

    def test_forget_missing_id_returns_false(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            self.assertFalse(memory.forget("999"))

    def test_purge_deletes_everything_and_returns_count(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            memory.remember("a")
            memory.remember("b")
            self.assertEqual(memory.purge(), 2)
            self.assertEqual(memory.stats()["total"], 0)

    def test_unknown_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            with self.assertRaises(memory.MemoryError):
                memory._insert(type="not_a_real_type", subject="x", statement="y", source="user_explicit")

    def test_empty_statement_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            with self.assertRaises(memory.MemoryError):
                memory.remember("   ")


class SearchAndRetrievalTests(unittest.TestCase):
    def test_search_matches_subject_or_statement(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            memory.remember("My main GPU is an AMD Radeon RX 7600.")
            memory.remember("The disk is an NVMe SSD.")
            results = memory.search("GPU")
        self.assertEqual(len(results), 1)
        self.assertIn("GPU", results[0]["statement"])

    def test_search_is_bounded_and_never_touches_raw_logs(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            for i in range(30):
                memory.remember(f"fact number {i} about gpu")
            results = memory.search("gpu", limit=5)
        self.assertLessEqual(len(results), 5)

    def test_retrieve_relevant_is_bounded_to_five(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            for i in range(10):
                memory.record_incident(f"gpu:issue-{i}", f"GPU issue {i}", domain="gpu")
            results = memory.retrieve_relevant(domain="gpu")
        self.assertLessEqual(len(results), memory.MAX_RETRIEVE)

    def test_retrieve_relevant_excludes_contradicted(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.record_incident("gpu:overheat", "GPU overheating suspected", domain="gpu")
            memory.contradict(record["id"], "Telemetry showed max 61C; not supported.")
            results = memory.retrieve_relevant(domain="gpu", keywords=["overheat"])
        self.assertFalse(any(r["id"] == record["id"] for r in results))


class ConfidenceAndConflictTests(unittest.TestCase):
    def test_confirm_increments_times_confirmed(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("fact")
            updated = memory.confirm(record["id"])
        self.assertEqual(updated["times_confirmed"], 1)

    def test_contradict_marks_status_contradicted_not_deleted(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("GPU overheating suspected")
            updated = memory.contradict(record["id"], "Telemetry showed max 61C.")
            self.assertEqual(updated["status"], "contradicted")
            self.assertIsNotNone(memory.get(record["id"]))

    def test_contradict_records_a_diagnostic_lesson(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("GPU overheating suspected")
            memory.contradict(record["id"], "Telemetry showed max 61C; not supported.")
            lessons = memory.list_memories(type="diagnostic_lesson")
        self.assertEqual(len(lessons), 1)

    def test_resolve_sets_status_resolved(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("fact")
            updated = memory.resolve(record["id"])
        self.assertEqual(updated["status"], "resolved")

    def test_repeated_incident_reinforces_instead_of_duplicating(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            first = memory.record_incident("gpu:timeout", "GPU timeout observed", domain="gpu")
            second = memory.record_incident("gpu:timeout", "GPU timeout observed again", domain="gpu")
            self.assertEqual(first["id"], second["id"])
            self.assertEqual(second["times_observed"], 2)
            self.assertEqual(memory.stats()["by_type"].get("incident"), 1)


class PrivacySanitizationTests(unittest.TestCase):
    def test_secrets_are_never_persisted(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("export API_KEY=sk-abcdefghijklmnopqrstuvwx broke things")
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwx", record["statement"])

    def test_home_path_is_sanitized_at_shared_level(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp), \
             mock.patch.dict("os.environ", {"USER": "alice", "LOGNAME": "alice"}), \
             mock.patch("sysai.privacy.os.path.expanduser", return_value="/home/alice"):
            record = memory.remember("Config lives at /home/alice/.config/sysai")
        self.assertNotIn("alice", record["statement"])

    def test_no_raw_logs_are_ever_stored(self):
        with tempfile.TemporaryDirectory() as temp, _isolated(temp):
            record = memory.remember("brief summary of an incident")
        self.assertLess(len(record["statement"]), 2001)


class RenderingTests(unittest.TestCase):
    def test_render_memory_list_handles_empty(self):
        self.assertIn("No memories", memory.render_memory_list([]))

    def test_prior_experience_block_is_labelled(self):
        block = memory.prior_experience_block([])
        self.assertEqual(block["label"], "PRIOR EXPERIENCE")
        self.assertIn("stale", block["note"])


if __name__ == "__main__":
    unittest.main()
