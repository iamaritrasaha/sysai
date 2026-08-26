"""Canonical sanitization layer for structured diagnostics.

Two levels exist and every diagnostic path uses one of them:

``LOCAL``
    On-screen local diagnostics. Secrets are removed; local identifiers such
    as the hostname stay, because they are already visible on the terminal
    the user is sitting at.

``SHARED``
    Anything that can leave the process or outlive it: reports written to
    disk, baselines, and sanitized web-research queries. Identity and
    network identifiers are removed on top of the secret redaction.

There is deliberately only one implementation. Callers pick a level; they
never write their own regular expressions.
"""
from __future__ import annotations

import os
import re
import socket

from .redact import redact

LOCAL = "local"
SHARED = "shared"
LEVELS = (LOCAL, SHARED)

USER = "<user>"
HOST = "<host>"
IPV4 = "<ipv4>"
IPV6 = "<ipv6>"
MAC = "<mac>"
SERIAL = "<serial>"
UUID = "<uuid>"

# Octet-accurate so ordinary version strings ("1.2.3.4") are not mangled: an
# address must be bounded by non-identifier characters on both sides.
_IPV4 = re.compile(
    r"(?<![\w.-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/\d{1,2})?(?![\w.-])"
)
# Deliberately conservative: an address must be the full eight groups or use
# `::` compression. A looser pattern eats log timestamps (22:35:53) and PCI
# addresses (0000:c5:00.0), which are useful evidence and identify nobody.
_IPV6 = re.compile(
    r"(?<![\w:.])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"
    r")(?:%[A-Za-z0-9._-]{1,16})?(?:/\d{1,3})?(?![\w:.])"
)
# `Aug 26 22:35:53 host program[pid]: ...` and the ISO variant. Journal lines
# always carry the hostname in this position, and a report must not.
_SYSLOG_HOST = re.compile(
    r"(?m)^((?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d"
    r"|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+)"
    r"([A-Za-z0-9][A-Za-z0-9._-]*)(\s)"
)
_MAC = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")
_UUID = re.compile(
    r"(?<![\w-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![\w-])"
)
_SERIAL_FIELD = re.compile(
    r"(?im)^(\s*(?:serial(?:\s*number)?|sn|wwn|world wide name|"
    r"logical unit id|eui-?64)\s*[:=]\s*)\S.*$"
)
_SERIAL_INLINE = re.compile(r"(?i)\b(serial(?:[_-]?number)?\s*[:=]\s*)([^\s,;]+)")
_HOME = re.compile(r"/home/([A-Za-z0-9._-]+)")

# Structured keys whose value is always an identifier rather than prose.
_IDENTIFIER_KEYS = {
    "serial": SERIAL, "serial_number": SERIAL, "serialnumber": SERIAL, "wwn": SERIAL,
    "uuid": UUID, "partuuid": UUID, "machine_id": UUID, "boot_id": UUID,
    "mac": MAC, "mac_address": MAC, "macaddress": MAC, "permanent_address": MAC,
    "hostname": HOST, "host": HOST, "nodename": HOST, "static_hostname": HOST,
    "user": USER, "username": USER, "login": USER, "owner": USER,
    "ipv4": IPV4, "ipv6": IPV6, "ip_address": IPV4, "inet": IPV4, "inet6": IPV6,
}
_SECRET_KEYS = {
    "api_key", "apikey", "token", "access_token", "secret", "client_secret",
    "password", "passwd", "authorization", "ollama_api_key", "private_key",
}


def _identity_terms() -> list[tuple[str, str]]:
    """Concrete local identity strings, longest first so nesting is safe."""
    terms: list[tuple[str, str]] = []
    try:
        home = os.path.expanduser("~")
    except (OSError, KeyError):
        home = ""
    if home and home not in ("/", ""):
        terms.append((home, f"/home/{USER}"))
    for getter in (lambda: os.environ.get("USER"), lambda: os.environ.get("LOGNAME"),
                   lambda: os.path.basename(os.path.expanduser("~"))):
        try:
            name = getter()
        except (OSError, KeyError):
            name = None
        if name and len(name) >= 2 and name not in ("root", "/"):
            terms.append((name, USER))
    try:
        host = socket.gethostname()
    except OSError:
        host = ""
    if host and len(host) >= 2:
        terms.append((host, HOST))
        short = host.split(".")[0]
        if len(short) >= 2:
            terms.append((short, HOST))
    try:
        nodename = os.uname().nodename
    except OSError:
        nodename = ""
    if nodename and len(nodename) >= 2:
        terms.append((nodename, HOST))
    unique: dict[str, str] = {}
    for term, replacement in terms:
        unique.setdefault(term, replacement)
    return sorted(unique.items(), key=lambda item: len(item[0]), reverse=True)


def sanitize_text(text: str, level: str = SHARED) -> str:
    """Redact `text` at the requested level. Secrets are removed at every level."""
    if not isinstance(text, str) or not text:
        return text if isinstance(text, str) else ""
    text = redact(text)
    if level == LOCAL:
        return text
    text = _SYSLOG_HOST.sub(lambda m: m.group(1) + HOST + m.group(3), text)
    text = _SERIAL_FIELD.sub(lambda m: m.group(1) + SERIAL, text)
    text = _SERIAL_INLINE.sub(lambda m: m.group(1) + SERIAL, text)
    text = _UUID.sub(UUID, text)
    text = _MAC.sub(MAC, text)
    text = _IPV6.sub(IPV6, text)
    text = _IPV4.sub(IPV4, text)
    for term, replacement in _identity_terms():
        text = text.replace(term, replacement)
    return _HOME.sub(f"/home/{USER}", text)


def sanitize(value, level: str = SHARED):
    """Recursively sanitize a JSON-shaped structure, key names included."""
    if isinstance(value, str):
        return sanitize_text(value, level)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            name = str(key).lower()
            if name in _SECRET_KEYS:
                result[key] = "<redacted>"
            elif level == SHARED and name in _IDENTIFIER_KEYS and isinstance(item, str):
                result[key] = _IDENTIFIER_KEYS[name]
            else:
                result[key] = sanitize(item, level)
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize(item, level) for item in value]
    return value


def privacy_note(level: str = SHARED) -> dict:
    """Machine-readable description of what a given level removes."""
    removed = ["secrets", "API keys", "authorization headers", "private keys"]
    if level == SHARED:
        removed += ["usernames", "home paths", "hostnames", "IP addresses",
                    "MAC addresses", "serial numbers", "UUIDs"]
    return {
        "level": level,
        "removed": removed,
        "note": ("Local on-screen diagnostics: secrets removed, local identifiers kept."
                 if level == LOCAL else
                 "Sanitized for sharing: identity and network identifiers removed."),
    }
