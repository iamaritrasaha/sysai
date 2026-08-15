from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Protocol

from .redact import redact


class WebSearchError(RuntimeError):
    pass


class SearchProvider(Protocol):
    def search(self, sanitized_query: str) -> list[dict[str, str]]: ...


class OllamaWebSearch:
    """Optional provider. It receives only a purpose-built sanitized query."""

    endpoint = "https://ollama.com/api/web_search"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY")

    def search(self, sanitized_query: str) -> list[dict[str, str]]:
        if not self.api_key:
            raise WebSearchError("OLLAMA_API_KEY is not configured.")
        body = json.dumps({"query": sanitized_query}).encode()
        request = urllib.request.Request(
            self.endpoint, data=body, method="POST",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read())
            return payload.get("results", [])
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise WebSearchError(f"Web search failed: {exc}") from exc


def sanitize_search_query(query: str) -> str:
    # Queries are accepted explicitly, never derived by forwarding transcript text.
    clean = "".join(ch if ch.isprintable() else " " for ch in redact(query))
    return " ".join(clean.split())[:500]
