from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import cli
from sysai.config import (Config, ModelProfile, load_config, load_model_profiles,
                          save_model_profiles)
from sysai.ollama import OllamaManager
from sysai.providers import OpenAICompatibleProvider, provider_for


class ModelTests(unittest.TestCase):
    def test_ollama_discovery_and_unavailable(self):
        manager = OllamaManager(Config())
        with mock.patch("sysai.ollama._request", return_value={"models": [{"name": "llama3:8b"}, {"name": "mistral:7b"}]}):
            self.assertEqual(manager.models(), ["llama3:8b", "mistral:7b"])
        with mock.patch("sysai.ollama._request", side_effect=OSError):
            self.assertEqual(manager.models(), [])

    def test_remote_ollama_uses_the_configured_base_url(self):
        manager = OllamaManager(Config(ollama_url="http://192.0.2.10:11434"))
        with mock.patch("sysai.ollama._request") as request:
            request.return_value = {"models": [{"name": "qwen3:8b"}]}
            self.assertEqual(manager.models(), ["qwen3:8b"])
            request.assert_called_once_with("http://192.0.2.10:11434/api/tags", timeout=2, headers={})

    def test_multiple_profiles_are_saved_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "models.toml"
            save_model_profiles([
                ModelProfile("remote-ollama", "ollama", "qwen3:8b", "http://192.0.2.10:11434"),
                ModelProfile("api", "openai_compatible", "remote", "https://example.test/v1", "SYSAI_API_KEY"),
            ], path)
            profiles = load_model_profiles(path)
            self.assertEqual([profile.id for profile in profiles], ["remote-ollama", "api"])
            self.assertNotIn("secret", path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_provider_routing(self):
        self.assertEqual(provider_for(Config()).name, "Ollama")
        self.assertTrue(provider_for(Config(provider="openai-compatible", model_endpoint="http://example")).remote)

    def test_remote_stream_normalizes_sse_and_sanitizes_messages(self):
        class Response:
            def __iter__(self):
                return iter([b'data: {"choices":[{"delta":{"reasoning_content":"think"}}]}\n',
                             b'data: {"choices":[{"delta":{"content":"answer"}}]}\n', b"data: [DONE]\n"])
            def close(self): pass

        config = Config(provider="openai-compatible", model="remote", model_endpoint="http://example", api_key_env="KEY")
        with mock.patch.dict("os.environ", {"KEY": "secret-key"}), \
             mock.patch("sysai.providers.urllib.request.urlopen", return_value=Response()) as urlopen:
            provider = OpenAICompatibleProvider(config)
            thinking, content = [], []
            self.assertEqual(provider.stream_request([{"role": "user", "content": "home /home/alice token=bad"}],
                                                     on_thinking=thinking.append, on_content=content.append), "answer")
        self.assertEqual(thinking, ["think"])
        self.assertEqual(content, ["answer"])
        body = json.loads(urlopen.call_args.args[0].data)
        self.assertNotIn("/home/alice", json.dumps(body))
        self.assertNotIn("bad", json.dumps(body))
        self.assertNotIn("secret-key", json.dumps(body))

    def test_nested_model_configuration_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[model]\nprovider = "openai-compatible"\nname = "remote"\nendpoint = "http://example"\ntimeout = 9\n')
            config = load_config(path)
        self.assertEqual(config.provider, "openai-compatible")
        self.assertEqual(config.model, "remote")
        self.assertEqual(config.model_endpoint, "http://example")
        self.assertEqual(config.request_timeout_seconds, 9)

    def test_cli_model_commands_are_wired_without_inference(self):
        with mock.patch("sysai.cli.models_command", return_value=0) as handler:
            self.assertEqual(cli.main(["models"]), 0)
            handler.assert_called_once_with(None, None)
        with mock.patch("sysai.cli.select_model", return_value=Config()), \
             mock.patch("sysai.cli.Session.run", return_value=0):
            # No active tty is required until Session.run, which is mocked.
            self.assertEqual(cli.main(["--model"]), 0)

    def test_normal_startup_uses_the_selector_and_default(self):
        with mock.patch("sysai.cli.select_model", return_value=Config(model="llama3:3b")), \
             mock.patch("sysai.cli.Session.run", return_value=0) as run:
            self.assertEqual(cli.main([]), 0)
            run.assert_called_once()

    def test_selector_enter_chooses_marked_default_and_explains_remote_setup(self):
        output = io.StringIO()
        with mock.patch("sysai.cli.load_config", return_value=Config(model="qwen3:8b")), \
             mock.patch("sysai.cli._startup_choices", return_value=[("LOCAL", "ollama", "qwen3:8b", "http://127.0.0.1:11434", "")]), \
             mock.patch("builtins.input", return_value=""), \
             mock.patch("sys.stdout", output):
            selected = cli.select_model()
        self.assertEqual(selected.model, "qwen3:8b")
        self.assertIn("sysai models add", output.getvalue())


if __name__ == "__main__":
    unittest.main()
