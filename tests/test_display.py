from __future__ import annotations

import unittest
from unittest import mock

from sysai.display import (
    ANSI_RE,
    MEDIUM_MIN_COLUMNS,
    WIDE_MIN_COLUMNS,
    _WORDMARK_MEDIUM,
    _WORDMARK_NARROW,
    _WORDMARK_WIDE,
    goodbye_banner,
    startup_banner,
)


def _plain_lines(banner: str) -> list[str]:
    return [ANSI_RE.sub("", line) for line in banner.splitlines()]


class WordmarkShapeTests(unittest.TestCase):
    def test_wide_wordmark_rows_are_all_the_same_width(self):
        self.assertEqual(len({len(row) for row in _WORDMARK_WIDE}), 1)

    def test_medium_wordmark_rows_are_all_the_same_width(self):
        self.assertEqual(len({len(row) for row in _WORDMARK_MEDIUM}), 1)

    def test_medium_wordmark_is_narrower_than_wide(self):
        self.assertLess(len(_WORDMARK_MEDIUM[0]), len(_WORDMARK_WIDE[0]))

    def test_narrow_fallback_fits_under_the_medium_threshold(self):
        self.assertLess(len(_WORDMARK_NARROW), MEDIUM_MIN_COLUMNS)


class StartupBannerTests(unittest.TestCase):
    def test_wide_terminal_uses_the_wide_wordmark(self):
        banner = startup_banner("qwen3:8b", width=WIDE_MIN_COLUMNS + 10)
        self.assertIn(_WORDMARK_WIDE[0].strip(), banner)

    def test_medium_terminal_uses_the_medium_wordmark(self):
        banner = startup_banner("qwen3:8b", width=MEDIUM_MIN_COLUMNS + 5)
        self.assertNotIn(_WORDMARK_WIDE[0].strip(), banner)
        self.assertIn(_WORDMARK_MEDIUM[0].strip(), banner)

    def test_narrow_terminal_falls_back_to_plain_text(self):
        banner = startup_banner("qwen3:8b", width=MEDIUM_MIN_COLUMNS - 5)
        self.assertNotIn(_WORDMARK_WIDE[0].strip(), banner)
        self.assertNotIn(_WORDMARK_MEDIUM[0].strip(), banner)
        self.assertIn("S Y S A I", banner)

    def test_no_color_still_shows_full_structure(self):
        with mock.patch.dict("os.environ", {"NO_COLOR": "1"}):
            banner = startup_banner("qwen3:8b", width=80)
        self.assertNotIn("\033[", banner)
        self.assertIn("Local Linux Intelligence", banner)
        self.assertIn("Ollama ready", banner)

    def test_no_line_exceeds_the_requested_width(self):
        for width in (10, 30, 49, 50, 69, 70, 80, 120):
            banner = startup_banner("qwen3:8b", width=width)
            for line in _plain_lines(banner):
                self.assertLessEqual(len(line), width, msg=f"width={width} line={line!r}")

    def test_status_lines_reflect_actual_readiness(self):
        banner = startup_banner("qwen3:8b", ollama_ready=False, bash_monitoring=True, width=80)
        self.assertIn("Ollama unavailable", banner)
        self.assertNotIn("Ollama ready", banner)
        self.assertIn("Bash monitoring active", banner)

    def test_model_name_is_a_subtle_secondary_line_not_the_headline(self):
        banner = startup_banner("qwen3:8b", width=80)
        lines = banner.splitlines()
        model_index = next(i for i, line in enumerate(lines) if "qwen3:8b" in line)
        wordmark_index = next(i for i, line in enumerate(lines) if "████" in line or "S Y S A I" in line)
        self.assertGreater(model_index, wordmark_index)

    def test_banner_appears_exactly_once_in_its_own_output(self):
        banner = startup_banner("qwen3:8b", width=80)
        self.assertEqual(banner.count("Local Linux Intelligence"), 1)


class GoodbyeBannerTests(unittest.TestCase):
    def test_normal_exit_gets_the_polished_banner(self):
        banner = goodbye_banner(width=80)
        self.assertIn("Session complete.", banner)
        self.assertIn("Until next time", banner)
        self.assertIn("Local model unloaded", banner)
        self.assertIn("Session closed", banner)

    def test_fatal_reason_never_shows_the_normal_goodbye(self):
        for reason in ("error", "crash", "interrupted"):
            banner = goodbye_banner(reason=reason, width=80)
            self.assertNotIn("Session complete.", banner)
            self.assertNotIn("Until next time", banner)
            self.assertNotIn("Local model unloaded", banner)

    def test_goodbye_visually_relates_to_the_startup_wordmark(self):
        startup = startup_banner("qwen3:8b", width=80)
        goodbye = goodbye_banner(width=80)
        self.assertEqual(
            [l for l in _plain_lines(startup) if "████" in l],
            [l for l in _plain_lines(goodbye) if "████" in l],
        )

    def test_no_line_exceeds_the_requested_width(self):
        for width in range(1, 90):
            for reason in ("normal", "error"):
                banner = goodbye_banner(reason=reason, width=width)
                for line in _plain_lines(banner):
                    self.assertLessEqual(len(line), width, msg=f"width={width} line={line!r}")

    def test_unloaded_and_closed_status_are_independently_optional(self):
        banner = goodbye_banner(model_unloaded=False, session_closed=True, width=80)
        self.assertNotIn("model unloaded", banner)
        self.assertIn("Session closed", banner)

    def test_banner_appears_exactly_once(self):
        banner = goodbye_banner(width=80)
        self.assertEqual(banner.count("Session complete."), 1)
        self.assertEqual(banner.count("Until next time"), 1)


if __name__ == "__main__":
    unittest.main()
