from __future__ import annotations

import os
import re
from typing import Callable

from .redact import redact


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


class StreamBox:
    """Incrementally renders a titled box as text chunks arrive.

    Content is flushed line-by-line (or once a partial line grows past a
    small threshold) rather than character-by-character, so redaction and
    control-sequence stripping apply to whole lines wherever possible while
    still feeling live. This is append-only: no cursor movement or repaint,
    so it is safe on any terminal and never flickers.
    """

    WIDTH = 54

    def __init__(self, write: Callable[[str], None], title: str, *, dim: bool = False):
        self._write = write
        self._title = title
        self._dim = dim
        self._buffer = ""
        self._opened = False

    def _use_color(self) -> bool:
        return not os.environ.get("NO_COLOR") and os.isatty(1)

    def _styles(self) -> tuple[str, str, str]:
        if not self._use_color():
            return "", "", ""
        if self._dim:
            return "\033[2;90m", "\033[2m", "\033[0m"
        return "\033[36m", "", "\033[0m"

    def _open(self) -> None:
        if self._opened:
            return
        border, _, reset = self._styles()
        top = f"{border}┌─ {self._title} " + "─" * max(1, self.WIDTH - len(self._title) - 4) + reset
        self._write(top + "\n")
        self._opened = True

    def _emit_line(self, line: str) -> None:
        self._open()
        border, text_style, reset = self._styles()
        # Reasoning and answer text are model output: never trust it as a
        # command, and never let it carry secrets or terminal control codes.
        line = plain_terminal_text(redact(line))
        if line:
            self._write(f"{border}│{reset} {text_style}{line}{reset}\n")
        else:
            self._write(f"{border}│{reset}\n")

    def feed(self, text: str) -> None:
        text = plain_terminal_text(text)
        if not text:
            return
        self._buffer += text
        while "\n" in self._buffer:
            line, _, self._buffer = self._buffer.partition("\n")
            self._emit_line(line)
        if len(self._buffer) > 120:
            self._emit_line(self._buffer)
            self._buffer = ""

    def close(self) -> None:
        if self._buffer:
            self._emit_line(self._buffer)
            self._buffer = ""
        if not self._opened:
            return
        border, _, reset = self._styles()
        self._write(f"{border}└" + "─" * (self.WIDTH - 1) + f"{reset}\n")


class AnswerRenderer:
    """Renders a live thinking box followed by a live answer box.

    Shared by the in-session auto-analysis path and the external
    ``sysai ask``/``sysai explain`` clients so both present reasoning and
    answers identically. Degrades gracefully: if the model never emits
    reasoning (or ``show_thinking`` is off), no thinking box is drawn and
    only the final answer appears.
    """

    def __init__(self, write: Callable[[str], None], *, show_thinking: bool = True):
        self._write = write
        self._show_thinking = show_thinking
        self._thinking_box: StreamBox | None = None
        self._answer_box: StreamBox | None = None

    def thinking(self, text: str) -> None:
        if not self._show_thinking or not text:
            return
        if self._thinking_box is None:
            self._thinking_box = StreamBox(self._write, "SysAI · thinking", dim=True)
        self._thinking_box.feed(text)

    def content(self, text: str) -> None:
        if not text:
            return
        if self._thinking_box is not None:
            self._thinking_box.close()
            self._thinking_box = None
            self._write("\n")
        if self._answer_box is None:
            self._answer_box = StreamBox(self._write, "SysAI")
        self._answer_box.feed(text)

    def cancelled(self) -> None:
        self._close_boxes()
        self._write("\nSysAI: generation cancelled.\n")

    def error(self, message: str) -> None:
        self._close_boxes()
        self._write(box(f"Analysis unavailable: {message}"))

    def close(self) -> None:
        """Close any box left open (e.g. after a control-level error) without a message."""
        self._close_boxes()

    def finish(self, fallback_answer: str | None = None) -> None:
        if self._thinking_box is not None:
            self._thinking_box.close()
            self._thinking_box = None
        if self._answer_box is None:
            self._answer_box = StreamBox(self._write, "SysAI")
            self._answer_box.feed(fallback_answer or "(no response)")
        self._answer_box.close()
        self._answer_box = None

    def _close_boxes(self) -> None:
        if self._thinking_box is not None:
            self._thinking_box.close()
            self._thinking_box = None
        if self._answer_box is not None:
            self._answer_box.close()
            self._answer_box = None
