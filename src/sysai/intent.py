"""Natural-language routing for `sysai check`.

The model is never allowed to invent a diagnostic. Routing is deterministic
keyword matching first; only a genuinely ambiguous question is put to the
local model, and its reply must match one name in a strict enum or it is
discarded. Anything unrecognized falls back to a full-system scan.
"""
from __future__ import annotations

import re

from .domains import DOMAINS, FULL_SYSTEM, SCOPES

# Terms are matched as whole words, so "apt" cannot match inside "laptop".
# A trailing `*` makes a term a prefix match ("throttl*" covers "throttling").
_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("gpu", ("gpu", "graphics", "graphic card", "video card", "vram", "amdgpu", "nvidia",
             "radeon", "nouveau", "rocm", "opengl", "vulkan", "display driver", "screen freez*",
             "screen flicker*", "screen tear*", "artifact*", "monitor goes black",
             "display glitch*", "graphics driver")),
    ("thermal", ("temperature", "thermal", "overheat*", "too hot", "running hot", "fan speed",
                 "fans are loud", "loud fans", "throttl*", "celsius", "degrees")),
    ("memory", ("ram", "memory", "out of memory", "oom", "swap", "memory leak",
                "filling up", "eating memory")),
    ("disk", ("disk*", "hard drive", "ssd", "hdd", "nvme", "storage", "filesystem",
              "file system", "partition", "no space", "out of space", "smart",
              "i/o error*", "read-only", "read only")),
    ("network", ("network", "internet", "wifi", "wi-fi", "wireless", "ethernet", "dns",
                 "disconnect*", "connection drop*", "drops out", "offline", "no connection",
                 "cannot connect", "can't connect", "router", "packet loss", "ping")),
    ("boot", ("boot*", "startup", "start up", "grub", "kernel panic",
              "takes forever to start", "reboot*", "restart the machine")),
    ("services", ("service*", "systemd", "daemon", "unit", "failed to start", "failing unit")),
    ("packages", ("package*", "apt", "dpkg", "upgrade*", "broken install", "held back",
                  "unmet dependencies", "software update")),
)

# Phrases that describe a whole-system symptom rather than one subsystem.
_BROAD = ("slow*", "sluggish", "laggy", "freez*", "hang*", "crash*", "unstable",
          "acting up", "misbehaving", "something wrong", "check my system",
          "system health", "everything", "whole system")


def _matcher(term: str) -> re.Pattern[str]:
    if term.endswith("*"):
        return re.compile(r"\b" + re.escape(term[:-1]))
    return re.compile(r"\b" + re.escape(term) + r"\b")


_PATTERNS: tuple[tuple[str, tuple[tuple[str, re.Pattern[str]], ...]], ...] = tuple(
    (domain, tuple((term.rstrip("*"), _matcher(term)) for term in terms))
    for domain, terms in _KEYWORDS
)
_BROAD_PATTERNS = tuple((term.rstrip("*"), _matcher(term)) for term in _BROAD)

_ENUM_LINE = re.compile(r"[a-z_]+")


def normalize(question: str) -> str:
    return " ".join(str(question).lower().split())


def keyword_route(question: str) -> tuple[str | None, list[str]]:
    """Deterministic first pass. Returns the chosen scope and matched terms."""
    text = normalize(question)
    scores: dict[str, list[str]] = {}
    for domain, terms in _PATTERNS:
        matched = [term for term, pattern in terms if pattern.search(text)]
        if matched:
            scores[domain] = matched
    if len(scores) == 1:
        domain, matched = next(iter(scores.items()))
        return domain, matched
    if len(scores) > 1:
        # Several subsystems named at once is a full-system question.
        return FULL_SYSTEM, sorted(term for terms in scores.values() for term in terms)
    broad = [term for term, pattern in _BROAD_PATTERNS if pattern.search(text)]
    if broad:
        return FULL_SYSTEM, broad
    return None, []


def classification_prompt(question: str) -> str:
    """Prompt asking for one enum name. Commands are never requested or accepted."""
    return (
        "Classify this Linux troubleshooting question into exactly one diagnostic domain.\n"
        "Reply with one word from this list and nothing else: "
        + ", ".join((*DOMAINS, FULL_SYSTEM)) + ".\n"
        "Do not explain. Do not suggest commands. Do not invent a domain name.\n\n"
        f"Question: {normalize(question)}"
    )


def parse_domain(text: str) -> str | None:
    """Accept only an exact enum member; every other reply is discarded."""
    if not isinstance(text, str):
        return None
    for word in _ENUM_LINE.findall(text.lower()):
        if word in SCOPES:
            return word
    return None


def route(question: str, ask_model=None) -> dict:
    """Resolve a question to one approved scope.

    ``ask_model`` is optional and only consulted when keyword routing is
    inconclusive. Its answer is validated against the enum before use.
    """
    scope, matched = keyword_route(question)
    if scope is not None:
        return {"scope": scope, "method": "keywords", "matched": matched, "model_reply": None}
    reply = None
    if ask_model is not None:
        try:
            reply = ask_model(classification_prompt(question))
        except Exception:
            reply = None
        chosen = parse_domain(reply or "")
        if chosen:
            return {"scope": chosen, "method": "model", "matched": [], "model_reply": chosen}
    return {"scope": FULL_SYSTEM, "method": "fallback", "matched": [],
            "model_reply": parse_domain(reply or "") if reply else None}
