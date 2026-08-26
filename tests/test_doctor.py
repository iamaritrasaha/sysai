from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import doctor
from sysai.config import Config


def _status(result: dict, identifier: str) -> str | None:
    return next((item["status"] for item in result["checks"] if item["id"] == identifier), None)


def _detail(result: dict, identifier: str) -> str:
    return next((item["detail"] for item in result["checks"] if item["id"] == identifier), "")


class DoctorTests(unittest.TestCase):
    def test_healthy_setup_reports_no_attention(self):
        config = Config(model="qwen3:8b")
        api = {"/api/version": {"version": "0.33.0"},
               "/api/tags": {"models": [{"name": "qwen3:8b"}]},
               "/api/show": {"capabilities": ["completion", "thinking"]},
               "/api/chat": {"message": {"content": "ready"}}}
        with mock.patch("sysai.doctor._api", side_effect=lambda url, path, body=None, timeout=3: api.get(path)), \
             mock.patch("sysai.doctor.have", return_value=True), \
             mock.patch("sysai.doctor.shutil.which", return_value="/usr/bin/ollama"):
            checks = doctor._ollama_checks(config)
        self.assertTrue(all(item["status"] in (doctor.OK, doctor.INFO) for item in checks), checks)

    def test_missing_ollama_binary_and_api_need_attention(self):
        config = Config()
        with mock.patch("sysai.doctor._api", return_value=None), \
             mock.patch("sysai.doctor.have", return_value=False), \
             mock.patch("sysai.doctor.shutil.which", return_value=None):
            result = {"checks": doctor._ollama_checks(config)}
        self.assertEqual(_status(result, "ollama.binary"), doctor.ATTENTION)
        self.assertEqual(_status(result, "ollama.api"), doctor.ATTENTION)
        # The model cannot be verified, which is unknown rather than broken.
        self.assertEqual(_status(result, "ollama.model"), doctor.UNKNOWN)

    def test_missing_model_is_reported_with_the_pull_command(self):
        config = Config(model="qwen3:8b")
        api = {"/api/version": {"version": "0.33.0"}, "/api/tags": {"models": [{"name": "llama3:8b"}]}}
        with mock.patch("sysai.doctor._api", side_effect=lambda url, path, body=None, timeout=3: api.get(path)), \
             mock.patch("sysai.doctor.have", return_value=True):
            result = {"checks": doctor._ollama_checks(config)}
        self.assertEqual(_status(result, "ollama.model"), doctor.ATTENTION)
        self.assertIn("ollama pull qwen3:8b", _detail(result, "ollama.model"))

    def test_bad_config_permissions_need_attention(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "sysai"
            directory.mkdir()
            config_path = directory / "config.toml"
            config_path.write_text("thinking = true\n", encoding="utf-8")
            config_path.chmod(0o644)
            env_path = directory / "env"
            env_path.write_text("OLLAMA_API_KEY=secret-value\n", encoding="utf-8")
            env_path.chmod(0o644)
            with mock.patch("sysai.doctor.config_dir", return_value=directory), \
                 mock.patch("sysai.doctor.load_private_env", return_value={}):
                result = {"checks": doctor._config_checks(Config())}
        self.assertEqual(_status(result, "config.file"), doctor.ATTENTION)
        self.assertEqual(_status(result, "config.env"), doctor.ATTENTION)

    def test_api_key_presence_is_reported_without_the_value(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "sysai"
            directory.mkdir(mode=0o700)
            with mock.patch("sysai.doctor.config_dir", return_value=directory), \
                 mock.patch("sysai.doctor.load_private_env",
                            return_value={"OLLAMA_API_KEY": "super-secret-value"}):
                checks = doctor._config_checks(Config(web_enabled=True))
        rendered = json.dumps(checks)
        self.assertNotIn("super-secret-value", rendered)
        self.assertIn("API key present", rendered)

    def test_web_enabled_without_a_key_needs_attention(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "sysai"
            directory.mkdir(mode=0o700)
            with mock.patch("sysai.doctor.config_dir", return_value=directory), \
                 mock.patch("sysai.doctor.load_private_env", return_value={}), \
                 mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("OLLAMA_API_KEY", None)
                result = {"checks": doctor._config_checks(Config(web_enabled=True))}
        self.assertEqual(_status(result, "web.key"), doctor.ATTENTION)
        self.assertIn("no API key", _detail(result, "web.key"))

    def test_stale_session_state_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / "sysai"
            runtime.mkdir(mode=0o700)
            (runtime / "active.json").write_text(
                json.dumps({"pid": 2 ** 22 - 1, "socket": str(runtime / "gone.sock")}), encoding="utf-8")
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}), \
                 mock.patch("sysai.doctor.os.kill", side_effect=ProcessLookupError):
                result = {"checks": doctor._runtime_checks()}
        self.assertEqual(_status(result, "session.active"), doctor.ATTENTION)
        self.assertIn("sysai stop", _detail(result, "session.active"))

    def test_corrupt_session_state_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / "sysai"
            runtime.mkdir(mode=0o700)
            (runtime / "active.json").write_text("{not json", encoding="utf-8")
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                result = {"checks": doctor._runtime_checks()}
        self.assertEqual(_status(result, "session.active"), doctor.ATTENTION)

    def test_group_readable_runtime_directory_needs_attention(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / "sysai"
            runtime.mkdir(mode=0o755)
            os.chmod(runtime, 0o755)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": temp}):
                result = {"checks": doctor._runtime_checks()}
        self.assertEqual(_status(result, "runtime.directory"), doctor.ATTENTION)

    def test_installed_copy_mismatch_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = Path(temp) / "repo"
            (repository / "src" / "sysai").mkdir(parents=True)
            (repository / "src" / "sysai" / "cli.py").write_text("current", encoding="utf-8")
            installed = Path(temp) / "installed"
            installed.mkdir()
            (installed / "cli.py").write_text("older", encoding="utf-8")
            with mock.patch("sysai.doctor._repository_root", return_value=repository), \
                 mock.patch("sysai.doctor._installed_package", return_value=installed):
                result = {"checks": doctor._install_checks()}
            self.assertEqual(_status(result, "install.source"), doctor.ATTENTION)
            self.assertIn("re-run ./install.sh", _detail(result, "install.source"))
            (installed / "cli.py").write_text("current", encoding="utf-8")
            with mock.patch("sysai.doctor._repository_root", return_value=repository), \
                 mock.patch("sysai.doctor._installed_package", return_value=installed):
                result = {"checks": doctor._install_checks()}
        self.assertEqual(_status(result, "install.source"), doctor.OK)

    def test_bashrc_modified_by_hand_is_flagged(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            (home / ".bashrc").write_text("source ~/.local/lib/sysai/integration.bash\n", encoding="utf-8")
            with mock.patch("sysai.doctor.Path.home", return_value=home), \
                 mock.patch("sysai.doctor.read_text",
                            return_value="source ~/.local/lib/sysai/integration.bash"):
                result = {"checks": doctor._bash_checks()}
        self.assertEqual(_status(result, "bash.rcfile"), doctor.ATTENTION)
        self.assertIn("SysAI never writes here", _detail(result, "bash.rcfile"))

    def test_json_output_is_machine_readable_and_hides_the_api_key(self):
        captured = io.StringIO()
        result = {"schema_version": 1, "sysai_version": "0.1.0", "attention_count": 0,
                  "overall": "Healthy", "checks": [
                      {"id": "web.key", "label": "Web search", "status": doctor.OK,
                       "detail": "enabled, API key present, provider ollama"}]}
        with mock.patch("sysai.doctor.run_doctor", return_value=result):
            code = doctor.doctor_command(as_json=True, output=captured.write)
        payload = json.loads(captured.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["overall"], "Healthy")
        self.assertNotIn("secret", captured.getvalue().lower())

    def test_attention_produces_a_nonzero_exit_code(self):
        result = {"schema_version": 1, "sysai_version": "0.1.0", "attention_count": 2,
                  "overall": "Attention needed", "checks": []}
        with mock.patch("sysai.doctor.run_doctor", return_value=result):
            self.assertEqual(doctor.doctor_command(output=lambda _text: None), 1)

    def test_doctor_never_asks_the_model_to_decide_a_deterministic_check(self):
        source = Path(doctor.__file__).read_text(encoding="utf-8")
        self.assertNotIn("_ask_local", source)
        self.assertNotIn("stream_chat", source)

    def test_full_run_produces_a_renderable_report(self):
        result = doctor.run_doctor(probe_model=False)
        text = doctor.render_doctor(result)
        self.assertIn("SysAI Doctor", text)
        self.assertIn("Overall", text)
        self.assertTrue(all({"id", "label", "status", "detail"} <= set(item) for item in result["checks"]))


if __name__ == "__main__":
    unittest.main()
