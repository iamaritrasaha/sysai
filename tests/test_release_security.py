from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import sysai
from sysai.config import Config, state_dir
from sysai.display import box
from sysai.ollama import is_owned_ollama_process
from sysai.session import Session
from sysai.web import sanitize_search_query


ROOT = Path(__file__).resolve().parents[1]


class ReleaseSecurityTests(unittest.TestCase):
    def test_version_sources_match(self):
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        self.assertEqual(project["version"], sysai.__version__)

    def test_cli_version(self):
        result = subprocess.run(
            [str(ROOT / "bin/sysai"), "--version"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        self.assertEqual(result.stdout.strip(), "sysai 0.1.0")

    def test_model_terminal_controls_are_removed(self):
        rendered = box("safe\x1b]52;c;ZXZpbA==\x07\x1b[31mred\x1b[0m")
        self.assertNotIn("\x1b", rendered)
        self.assertIn("safered", rendered)

    def test_web_sanitizer_redacts_and_removes_controls(self):
        query = "kernel\nAPI_KEY=super-secret-value\x1b[31m regression"
        cleaned = sanitize_search_query(query)
        self.assertNotIn("super-secret-value", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertLessEqual(len(cleaned), 500)

    def test_web_search_never_receives_terminal_output(self):
        session = Session(Config(web_enabled=True), "/bin/true")
        session.records.append({
            "command": "echo context", "exit_code": 0, "cwd": "/tmp",
            "output": "RAW-TRANSCRIPT-MUST-NOT-LEAVE",
        })
        provider = mock.Mock()
        provider.search.return_value = []
        with mock.patch("sysai.session.OllamaWebSearch", return_value=provider), \
             mock.patch("sysai.session.load_private_env", return_value={"OLLAMA_API_KEY": "fake"}), \
             mock.patch.object(session, "_ask_local", return_value="answer"):
            response = session._control({
                "action": "ask", "question": "release API_KEY=fake-secret", "web": True,
            })
        self.assertTrue(response["ok"])
        sent_query = provider.search.call_args.args[0]
        self.assertNotIn("RAW-TRANSCRIPT", sent_query)
        self.assertNotIn("fake-secret", sent_query)

    def test_runtime_directory_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            target = base / "target"
            target.mkdir()
            (base / "sysai").symlink_to(target, target_is_directory=True)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                with self.assertRaisesRegex(RuntimeError, "Unsafe SysAI runtime path"):
                    state_dir()

    def test_runtime_directory_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                path = state_dir()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_second_session_is_refused_by_runtime_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                first = Session(Config(), "/bin/true")
                second = Session(Config(), "/bin/true")
                first._acquire_session_lock()
                try:
                    with self.assertRaisesRegex(RuntimeError, "already active"):
                        second._acquire_session_lock()
                finally:
                    with mock.patch.object(first.ollama, "cleanup"):
                        first.cleanup()

    def test_state_write_replaces_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime_base = Path(temp) / "runtime"
            runtime_base.mkdir()
            victim = Path(temp) / "victim"
            victim.write_text("unchanged", encoding="utf-8")
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime_base)}):
                session = Session(Config(), "/bin/true")
                session.state_path.symlink_to(victim)
                session._write_state()
                self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
                self.assertFalse(session.state_path.is_symlink())
                self.assertEqual(stat.S_IMODE(session.state_path.stat().st_mode), 0o600)
                state = json.loads(session.state_path.read_text(encoding="utf-8"))
                self.assertNotIn("records", state)
                self.assertNotIn("output", state)
                self.assertNotIn("command", state)

    def test_owned_process_check_requires_all_identity_fields(self):
        with mock.patch("sysai.ollama.Path.read_bytes", return_value=b"/usr/bin/ollama\0serve\0"), \
             mock.patch("sysai.ollama.process_start_time", return_value=777), \
             mock.patch("sysai.ollama.os.getpgid", return_value=123):
            self.assertTrue(is_owned_ollama_process(123, 777, 123))
            self.assertFalse(is_owned_ollama_process(123, 778, 123))
            self.assertFalse(is_owned_ollama_process(123, 777, 124))

    def test_model_output_has_no_execution_sink(self):
        source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src/sysai").glob("*.py"))
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system(", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)

    def test_installer_refuses_symlinked_launcher(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            install_root = base / "install"
            config_root = base / "config"
            (install_root / "bin").mkdir(parents=True)
            victim = base / "victim"
            victim.write_text("unchanged", encoding="utf-8")
            (install_root / "bin/sysai").symlink_to(victim)
            result = subprocess.run(
                [str(ROOT / "install.sh")], text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={**os.environ, "SYSAI_INSTALL_ROOT": str(install_root), "XDG_CONFIG_HOME": str(config_root)},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing symlinked managed path", result.stderr)
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
