from __future__ import annotations

import os
import re


ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[()][0-2A-Z])"
)


def plain_terminal_text(text: str) -> str:
    text = ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return "".join(ch for ch in text if ch in "\n\t" or ord(ch) >= 32)


def box(message: str, title: str = "SysAI") -> str:
    # Never render terminal controls received from a model or remote provider.
    message = plain_terminal_text(message)
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    cyan, reset = ("\033[36m", "\033[0m") if color else ("", "")
    width = 54
    top = f"{cyan}┌─ {title} " + "─" * max(1, width - len(title) - 4) + reset
    bottom = f"{cyan}└" + "─" * (width - 1) + reset
    lines = [top]
    for line in message.strip().splitlines() or [""]:
        lines.append(f"{cyan}│{reset} {line}" if line else f"{cyan}│{reset}")
    lines.append(bottom)
    return "\n".join(lines) + "\n"


def startup(model: str) -> str:
    color = not os.environ.get("NO_COLOR") and os.isatty(1)
    green, bold, reset = ("\033[32m", "\033[1m", "\033[0m") if color else ("", "", "")
    return (
        f"{bold}SysAI{reset}\nLocal Linux assistant\n{model} • Ollama\n\n"
        f"{green}✓{reset} Ollama ready\n{green}✓{reset} Terminal monitoring active\n\n"
    )
