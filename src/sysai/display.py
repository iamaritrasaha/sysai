from __future__ import annotations

import os
import re
import shutil
import unicodedata
from typing import Callable

from .redact import redact


ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[P^_X].*?\x1b\\|[()][0-2A-Z])"
)
_REASONING_CONTROL = r"(?:/no_think|/think|</?no_think>|</?think>)"
# ASCII punctuation characters that Markdown allows escaping with a backslash.
_MD_PUNCT = frozenset('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~')


def plain_terminal_text(text: str) -> str:
    text = ANSI_RE.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return "".join(ch for ch in text if ch in "\n\t" or ord(ch) >= 32 and not 127 <= ord(ch) <= 159)


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


# The SYSAI wordmark, hand-drawn on a 5x7 dot-matrix grid so every row is
# provably the same width (see `tests/test_display.py`). Two sizes only:
# a terminal either fits the wide mark, the medium one, or falls back to
# plain text — there is no intermediate scaling.
_WORDMARK_WIDE = (
    "  ████████  ██      ██    ████████      ██      ██████████",
    "██          ██      ██  ██            ██  ██        ██    ",
    "██            ██  ██    ██          ██      ██      ██    ",
    "  ██████        ██        ██████    ██      ██      ██    ",
    "        ██      ██              ██  ██████████      ██    ",
    "        ██      ██              ██  ██      ██      ██    ",
    "████████        ██      ████████    ██      ██  ██████████",
)
_WORDMARK_MEDIUM = (
    " ████ █   █  ████   █   █████",
    "█     █   █ █      █ █    █  ",
    "█      █ █  █     █   █   █  ",
    " ███    █    ███  █   █   █  ",
    "    █   █       █ █████   █  ",
    "    █   █       █ █   █   █  ",
    "████    █   ████  █   █ █████",
)
_WORDMARK_NARROW = "S Y S A I"

# Terminal-width bands the banners adapt to. A terminal narrower than the
# widest of these still gets *something* on-brand: `_wordmark_for` and the
# line-fitting helpers below always degrade gracefully rather than wrap or
# overflow.
WIDE_MIN_COLUMNS = 70
MEDIUM_MIN_COLUMNS = 50

_TAGLINE = "Bash  •  Diagnostics  •  Memory  •  Experience"
_SUBTITLE = "Local Linux Intelligence"


def _columns(width: int | None) -> int:
    if width is not None:
        return max(1, width)
    return shutil.get_terminal_size(fallback=(80, 24)).columns


def _use_color() -> bool:
    return not os.environ.get("NO_COLOR") and os.isatty(1)


def _center(line: str, columns: int) -> str:
    if len(line) >= columns:
        return line
    return " " * ((columns - len(line)) // 2) + line


def _fit(line: str, columns: int) -> str | None:
    """`line` centered, or None when it cannot fit without overflowing."""
    return _center(line, columns) if len(line) <= columns else None


def _status(ok: bool, label: str, short_label: str, columns: int, *, color_on: str, reset: str) -> str:
    """A `✓/✗ label` status line, guaranteed to never exceed `columns`.

    Sized against the plain (uncolored) text so ANSI escape bytes never
    count toward the visible width. Falls back to a shorter label before
    ever truncating raw text, so a genuinely tiny terminal still gets a
    readable (if abbreviated) status rather than a mid-word cut.
    """
    symbol = "✓" if ok else "✗"
    plain = f"{symbol} {label}"
    if len(plain) > columns:
        plain = f"{symbol} {short_label}"
    plain = plain[:columns]
    return f"{color_on}{plain[0]}{reset}{plain[1:]}" if color_on else plain


def _wordmark_lines(columns: int, *, bold: str = "", reset: str = "") -> list[str]:
    """The best-fitting wordmark tier for `columns`, each line bolded and centered.

    Always returns *something*: even a terminal narrower than the plain
    "S Y S A I" fallback gets a truncated-but-safe single line rather than
    an empty banner or an overflow.
    """
    if columns >= WIDE_MIN_COLUMNS and len(_WORDMARK_WIDE[0]) <= columns:
        art = _WORDMARK_WIDE
    elif columns >= MEDIUM_MIN_COLUMNS and len(_WORDMARK_MEDIUM[0]) <= columns:
        art = _WORDMARK_MEDIUM
    elif len(_WORDMARK_NARROW) <= columns:
        art = (_WORDMARK_NARROW,)
    else:
        art = ("SYSAI"[:columns],)
    return [f"{bold}{_center(line, columns)}{reset}" for line in art]


def startup_banner(
    model: str,
    *,
    ollama_ready: bool = True,
    bash_monitoring: bool = True,
    width: int | None = None,
) -> str:
    """The SysAI welcome screen: wordmark, identity, then runtime status.

    Adapts to the terminal width (wide/medium/narrow), stays legible with
    `NO_COLOR` or a non-tty stdout, and only shows status lines that are
    actually true — a status that failed to come up is never silently
    reported as ready.
    """
    columns = _columns(width)
    color = _use_color()
    bold, dim, green, red, reset = (
        ("\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[0m") if color else ("", "", "", "", "")
    )
    lines = [""]
    lines.extend(_wordmark_lines(columns, bold=bold, reset=reset))
    lines.append("")
    for text in (_SUBTITLE, _TAGLINE):
        fitted = _fit(text, columns)
        if fitted is not None:
            lines.append(f"{dim}{fitted}{reset}" if color else fitted)
    lines.append("")
    lines.append(_status(ollama_ready, "Ollama ready" if ollama_ready else "Ollama unavailable",
                        "Ollama ready" if ollama_ready else "Ollama down", columns,
                        color_on=(green if ollama_ready else red), reset=reset))
    lines.append(_status(bash_monitoring, "Bash monitoring active" if bash_monitoring else "Bash monitoring inactive",
                        "Bash monitor active" if bash_monitoring else "Bash monitor off", columns,
                        color_on=(green if bash_monitoring else red), reset=reset))
    model_line = _fit(f"model: {model}", columns)
    if model_line is not None:
        lines.append(f"{dim}{model_line}{reset}" if color else model_line)
    lines.append("")
    return "\n".join(lines) + "\n"


def goodbye_banner(
    *,
    reason: str = "normal",
    model_unloaded: bool = True,
    session_closed: bool = True,
    width: int | None = None,
) -> str:
    """The SysAI farewell screen. Callable exactly once per session exit.

    `reason="normal"` is the only polished, celebratory form — it is meant
    for `sysai stop`, Ctrl+D/EOF, and `exit`, once the child Bash has
    actually finished. Any other reason (an unexpected shutdown, a crash)
    renders a short, plain, non-celebratory line instead: this function
    never claims a clean close it cannot back up.
    """
    columns = _columns(width)
    color = _use_color()
    bold, dim, green, reset = (
        ("\033[1m", "\033[2m", "\033[32m", "\033[0m") if color else ("", "", "", "")
    )
    if reason != "normal":
        text = "SysAI session ended unexpectedly."[:columns]
        return f"{dim}{text}{reset}\n" if color else f"{text}\n"
    lines = [""]
    lines.extend(_wordmark_lines(columns, bold=bold, reset=reset))
    lines.append("")
    fitted = _fit("Session complete.", columns)
    if fitted is not None:
        lines.append(fitted)
    lines.append("")
    if model_unloaded:
        lines.append(_status(True, "Local model unloaded", "Model unloaded", columns, color_on=green, reset=reset))
    if session_closed:
        lines.append(_status(True, "Session closed", "Session closed", columns, color_on=green, reset=reset))
    lines.append("")
    farewell = _fit("Until next time. ── SysAI", columns)
    if farewell is not None:
        lines.append(f"{dim}{farewell}{reset}" if color else farewell)
    lines.append("")
    return "\n".join(lines) + "\n"


class StreamBox:
    """Incrementally renders a titled box as text chunks arrive.

    Content is buffered to complete logical lines before parsing, so syntax,
    redaction, and terminal-control stripping remain correct across arbitrary
    model chunk boundaries. This is append-only: no cursor movement or
    repaint, so it is safe on any terminal and never flickers.
    """

    WIDTH = 78

    def __init__(self, write: Callable[[str], None], title: str, *, dim: bool = False):
        self._write = write
        self._title = title
        self._dim = dim
        self._buffer = ""
        self._opened = False
        self._in_fence = False
        self._last_blank = False
        columns = shutil.get_terminal_size(fallback=(80, 24)).columns
        # Leave one terminal column unused so the terminal never performs an
        # implicit wrap.  The minimum still permits the box prefix.
        self._width = min(self.WIDTH, max(3, columns - 1))

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
        title_room = max(0, self._width - 4)
        title = self._title[:title_room]
        top = f"{border}┌─ {title} " + "─" * max(0, self._width - len(title) - 4) + reset
        self._write(top + "\n")
        self._opened = True

    def _emit_line(self, line: str) -> None:
        # CR and other sanitized line breaks must still pass through the box
        # prefix rather than being embedded inside one physical output line.
        sanitized = plain_terminal_text(redact(line))
        for logical_line in sanitized.split("\n"):
            self._emit_sanitized_line(logical_line)

    def _emit_sanitized_line(self, line: str) -> None:
        self._open()
        border, text_style, reset = self._styles()
        literal_code = self._in_fence
        for rendered in self._render_markdown(line):
            if not literal_code and not rendered:
                if self._last_blank:
                    continue
                self._last_blank = True
            elif rendered:
                self._last_blank = False
            for physical in self._wrap(rendered):
                if physical:
                    self._write(f"{border}│{reset} {text_style}{physical}{reset}\n")
                else:
                    self._write(f"{border}│{reset}\n")

    def _render_markdown(self, line: str) -> list[str]:
        """Deliberately small Markdown presentation layer for untrusted model text."""
        if re.match(r"^\s*```", line):
            self._in_fence = not self._in_fence
            return [""]
        if self._in_fence:
            return [line]
        line = self._normalize_markdown_escapes(line)
        # Qwen can occasionally put a reasoning-mode transport token in
        # `message.content` even though reasoning otherwise arrives in
        # `message.thinking`. Ignore only known standalone/trailing control
        # tokens, and leave inline code untouched.
        line, removed_control = self._without_reasoning_control(line)
        if removed_control and not line.strip():
            return []
        if re.match(r"^\s*(?:---|\*\*\*|___)\s*$", line):
            return [""]
        heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            title = self._render_inline(heading.group(1))
            return [title, "─" * max(3, min(40, len(title)))]
        # Models commonly use a whole bold line as a section heading. Handle
        # it before generic inline parsing so delimiters can never leak.
        bold_heading = re.match(r"^(\s*)\*\*([^*]+)\*\*\s*$", line) or re.match(r"^(\s*)__([^_]+)__\s*$", line)
        if bold_heading:
            title = bold_heading.group(1) + self._render_inline(bold_heading.group(2))
            return [title, bold_heading.group(1) + "─" * max(3, min(40, len(title.strip())))]
        line = re.sub(r"^(\s*)[-*+]\s+", r"\1• ", line)
        line = re.sub(r"^(\s*)(\d+)\.\s+", r"\1\2. ", line)
        return [self._render_inline(line)]

    @staticmethod
    def _render_inline(line: str) -> str:
        """Render supported inline spans while treating code contents literally."""
        rendered, index = [], 0
        while index < len(line):
            if line[index] == "`":
                end = line.find("`", index + 1)
                if end >= 0:
                    rendered.append(line[index + 1:end])
                    index = end + 1
                    continue
            if line[index] == "[":
                label_end = line.find("](", index + 1)
                url_end = line.find(")", label_end + 2) if label_end >= 0 else -1
                if label_end >= 0 and url_end >= 0:
                    label = StreamBox._render_inline(line[index + 1:label_end])
                    url = line[label_end + 2:url_end]
                    rendered.append(f"{label} ({url})")
                    index = url_end + 1
                    continue
            matched = False
            for marker in ("**", "__", "*", "_"):
                if not line.startswith(marker, index):
                    continue
                # CommonMark: _ and __ cannot open emphasis when right-flanking
                # (i.e., preceded by a word character). This prevents
                # package names like ubuntu_pro_esm_cache from being
                # mis-interpreted as italic spans.
                if "_" in marker and index > 0 and (line[index - 1].isalnum() or line[index - 1] == "_"):
                    break
                end = line.find(marker, index + len(marker))
                if end > index + len(marker):
                    rendered.append(StreamBox._render_inline(line[index + len(marker):end]))
                    index = end + len(marker)
                    matched = True
                    break
            if matched:
                continue
            rendered.append(line[index])
            index += 1
        return "".join(rendered)

    @staticmethod
    def _normalize_markdown_escapes(line: str) -> str:
        """Unescape the small Markdown subset we render, outside inline code."""
        if re.match(r"^\s*\\---\s*$", line):
            return line.replace("\\---", "---", 1)
        line = re.sub(r"^(\s*\d+)\\\.", r"\1.", line)
        result, index, in_code = [], 0, False
        while index < len(line):
            if line[index] == "`":
                in_code = not in_code
                result.append("`")
                index += 1
            elif not in_code and line.startswith(r"\*\*", index):
                result.append("**")
                index += 4
            elif not in_code and line.startswith(r"\**", index):
                result.append("**")
                index += 3
            elif not in_code and line.startswith(r"\_\_", index):
                result.append("__")
                index += 4
            elif not in_code and line.startswith(r"\__", index):
                result.append("__")
                index += 3
            elif not in_code and line.startswith(r"\`", index):
                result.append("`")
                index += 2
            elif not in_code and line[index] == "\\" and index + 1 < len(line) and line[index + 1] in _MD_PUNCT:
                # General Markdown punctuation unescape: \X → X for any
                # escapable ASCII punctuation not already handled above.
                result.append(line[index + 1])
                index += 2
            else:
                result.append(line[index])
                index += 1
        return "".join(result)

    @staticmethod
    def _without_reasoning_control(line: str) -> tuple[str, bool]:
        pieces = re.split(r"(`[^`]*`)", line)
        removed = False
        for index in range(0, len(pieces), 2):
            piece = pieces[index]
            clean = re.sub(
                rf"(?:^\s*{_REASONING_CONTROL}\s*$|(?:[ \t]+{_REASONING_CONTROL})+[ \t]*$)",
                "", piece, flags=re.IGNORECASE,
            )
            if clean != piece:
                removed = True
            pieces[index] = clean
        return "".join(pieces), removed

    @staticmethod
    def _visible_width(text: str) -> int:
        return sum(0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in "WF" else 1) for char in text)

    def _wrap(self, line: str) -> list[str]:
        if not line:
            return [""]
        limit = max(1, self._width - 2)  # `│ ` is visible content prefix.
        leading = re.match(r"\s*", line).group(0).replace("\t", "    ")
        text = line.replace("\t", "    ")
        bullet = re.match(r"\s*(?:•|[-*+]|\d+\.)\s+", text)
        continuation = leading + ("  " if bullet else "")
        lines, remaining, prefix = [], text, ""
        while remaining:
            available = max(1, limit - self._visible_width(prefix))
            if self._visible_width(remaining) <= available:
                lines.append(prefix + remaining)
                break
            width = cut = 0
            last_space = -1
            for index, char in enumerate(remaining):
                width += self._visible_width(char)
                if char.isspace(): last_space = index
                if width > available:
                    cut = last_space + 1 if last_space >= 0 else index
                    break
            cut = max(1, cut)
            piece = remaining[:cut].rstrip()
            lines.append(prefix + piece)
            remaining = remaining[cut:].lstrip()
            prefix = continuation
        return lines

    def feed(self, text: str) -> None:
        if not text:
            return
        self._buffer += text.replace("\r\n", "\n").replace("\r", "\n")
        while "\n" in self._buffer:
            line, _, self._buffer = self._buffer.partition("\n")
            self._emit_line(line)

    def close(self) -> None:
        if self._buffer:
            self._emit_line(self._buffer)
            self._buffer = ""
        if not self._opened:
            return
        border, _, reset = self._styles()
        self._write(f"{border}└" + "─" * max(0, self._width - 1) + f"{reset}\n")


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
