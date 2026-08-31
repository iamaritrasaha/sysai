"""Provider routing and normalized model interaction."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Protocol

from .config import Config
from .ollama import OllamaCancelled, OllamaError, OllamaManager, StreamHandle
from .privacy import sanitize


class ModelProvider(Protocol):
    name: str
    remote: bool
    def available(self) -> bool: ...
    def request(self, messages: list[dict[str, str]], **kwargs) -> str: ...
    def stream_request(self, messages: list[dict[str, str]], *, on_thinking=None,
                       on_content=None, handle: StreamHandle | None = None) -> str: ...
    def cleanup(self) -> None: ...


class OllamaProvider:
    name = "Ollama"
    remote = False

    def __init__(self, config: Config):
        self.manager = OllamaManager(config)

    def available(self) -> bool:
        return self.manager.available()

    def request(self, messages, **kwargs):
        return self.stream_request(messages, **kwargs)

    def stream_request(self, messages, **kwargs):
        return self.manager.stream_chat(messages, **kwargs)

    def ensure_ready(self, runtime):
        self.manager.ensure_ready(runtime)

    def cleanup(self):
        self.manager.cleanup()


class OpenAICompatibleProvider:
    name = "OpenAI-compatible"
    remote = True

    def __init__(self, config: Config):
        self.config = config
        self.endpoint = (config.model_endpoint or "").rstrip("/")
        self.api_key = os.environ.get(config.api_key_env, "")

    def available(self) -> bool:
        return bool(self.endpoint and self.api_key)

    def _post(self, messages, stream, handle=None):
        if not self.endpoint:
            raise OllamaError("Remote model endpoint is not configured.")
        if not self.api_key:
            raise OllamaError(f"Remote API key environment variable {self.config.api_key_env} is not set.")
        # This is the final cloud boundary: local history/memory and identifiers
        # are removed even if a future caller accidentally includes them.
        safe_messages = sanitize(messages, level="shared")
        body = {"model": self.config.model, "messages": safe_messages, "stream": stream,
                "temperature": 0.2}
        request = urllib.request.Request(
            f"{self.endpoint}/chat/completions", data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        try:
            response = urllib.request.urlopen(request, timeout=self.config.request_timeout_seconds)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise OllamaError("Remote provider authentication failed.") from exc
            raise OllamaError(f"Remote provider returned HTTP {exc.code}.") from exc
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise OllamaError(f"Remote provider unavailable: {exc}") from exc
        return response

    def request(self, messages, **kwargs):
        response = self._post(messages, False)
        try:
            payload = json.loads(response.read())
            return str(payload["choices"][0]["message"]["content"])
        except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise OllamaError("Remote provider returned a malformed response.") from exc
        finally:
            response.close()

    def stream_request(self, messages, *, on_thinking=None, on_content=None, handle=None):
        response = self._post(messages, True, handle)
        if handle is not None:
            handle.attach(response)
        parts = []
        try:
            for raw_line in response:
                if handle is not None and handle.is_cancelled():
                    raise OllamaCancelled("Generation cancelled.")
                line = raw_line.decode("utf-8", "replace").strip()
                if not line or line == "data: [DONE]":
                    continue
                if line.startswith("data:"):
                    line = line[5:].strip()
                try:
                    item = json.loads(line)
                    delta = item["choices"][0].get("delta", {})
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    continue
                thinking = delta.get("reasoning_content") or delta.get("thinking")
                content = delta.get("content")
                if thinking and on_thinking: on_thinking(str(thinking))
                if content:
                    parts.append(str(content))
                    if on_content: on_content(str(content))
        except (OSError, urllib.error.URLError) as exc:
            raise OllamaError(f"Remote provider stream failed: {exc}") from exc
        finally:
            response.close()
        answer = "".join(parts).strip()
        if not answer:
            raise OllamaError("Remote provider returned no answer.")
        return answer

    def cleanup(self):
        pass


def provider_for(config: Config) -> ModelProvider:
    if config.provider.lower() == "ollama":
        return OllamaProvider(config)
    if config.provider.lower() in ("openai", "openai-compatible", "openai_compatible", "remote"):
        return OpenAICompatibleProvider(config)
    raise OllamaError(f"Unknown model provider: {config.provider}")
