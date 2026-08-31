from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sysai import cli
from sysai.config import Config, load_config
from sysai.ollama import OllamaManager
from sysai.providers import OpenAICompatibleProvider, provider_for


class ModelTests(unittest.TestCase):
    def test_ollama_discovery_and_unavailable(self):
        manager = OllamaManager(Config())
        with mock.patch("sysai.ollama._request", return_value={"models": [{"name": "llama3:8b"}, {"name": "mistral:7b"}]}):
            self.assertEqual(manager.models(), ["llama3:8b", "mistral:7b"])
        with mock.patch("sysai.ollama._request", side_effect=OSError):
            self.assertEqual(manager.models(), [])

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
        with mock.patch("sysai.cli.select_model", return_value=("ollama", "llama3:8b")), \
             mock.patch("sysai.cli.Session.run", return_value=0):
            # No active tty is required until Session.run, which is mocked.
            self.assertEqual(cli.main(["--model"]), 0)


if __name__ == "__main__":
    unittest.main()
