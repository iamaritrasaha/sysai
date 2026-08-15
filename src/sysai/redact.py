from __future__ import annotations

import re


REDACTED = "<redacted>"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)
_AUTH = re.compile(r"(?im)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s\r\n]+")
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+\-/=]{12,}")
_ASSIGNMENT = re.compile(
    r"(?i)\b((?:api[_-]?key|token|secret|password|passwd|pwd|access[_-]?key|"
    r"client[_-]?secret|github_token|aws_secret_access_key|ollama_api_key)\s*[=:]\s*)"
    r"(?:'[^']*'|\"[^\"]*\"|[^\s;'\"]+)"
)
_CLI_SECRET = re.compile(
    r"(?i)(--(?:password|passwd|token|api-key|secret|client-secret)(?:=|\s+))"
    r"(?:'[^']*'|\"[^\"]*\"|[^\s;'\"]+)"
)
_COMMON_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|"
    r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,})\b"
)


def redact(text: str) -> str:
    text = _PRIVATE_KEY.sub("<redacted-private-key>", text)
    text = _AUTH.sub(lambda m: m.group(1) + REDACTED, text)
    text = _BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _ASSIGNMENT.sub(lambda m: m.group(1) + REDACTED, text)
    text = _CLI_SECRET.sub(lambda m: m.group(1) + REDACTED, text)
    return _COMMON_TOKEN.sub(REDACTED, text)


def truncate_output(text: str, limit: int) -> str:
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return text
    head_size = max(512, limit // 4)
    tail_size = max(512, limit - head_size)
    head = encoded[:head_size].decode("utf-8", "replace")
    tail = encoded[-tail_size:].decode("utf-8", "replace")
    omitted = len(encoded) - head_size - tail_size
    return f"{head}\n\n... <{omitted} bytes omitted by SysAI> ...\n\n{tail}"
