from __future__ import annotations

import json
import socket
import threading
import unittest
from unittest import mock

from sysai.config import Config
from sysai.display import AnswerRenderer, StreamBox
from sysai.ollama import OllamaCancelled, OllamaError, OllamaManager, StreamHandle
from sysai.session import Session


def _line(**fields) -> bytes:
    return (json.dumps(fields) + "\n").encode()


class FakeStreamResponse:
    """Minimal stand-in for the object returned by urllib.request.urlopen."""

    def __init__(self, lines, *, fail_after: int | None = None):
        self._lines = list(lines)
        self._index = 0
        self._fail_after = fail_after
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        if self._fail_after is not None and self._index >= self._fail_after:
            raise OSError("connection reset by peer")
        if self._index >= len(self._lines):
            raise StopIteration
        line = self._lines[self._index]
        self._index += 1
        return line

    def close(self):
        self.closed = True


class StreamChatTests(unittest.TestCase):
    """Ollama's native streaming NDJSON protocol: thinking then content chunks."""

    def _manager(self, thinking=True):
        return OllamaManager(Config(thinking=thinking))

    def test_streamed_thinking_chunks_arrive_incrementally(self):
        lines = [
            _line(message={"thinking": "Examining the exit status"}),
            _line(message={"thinking": "...looks like a missing binary"}),
            _line(message={"content": "It failed because "}),
            _line(message={"content": "the binary is missing."}, done=True),
        ]
        thoughts, content = [], []
        with mock.patch("sysai.ollama.urllib.request.urlopen", return_value=FakeStreamResponse(lines)):
            answer = self._manager().stream_chat(
                [{"role": "user", "content": "hi"}],
                on_thinking=thoughts.append, on_content=content.append,
            )
        self.assertEqual(thoughts, ["Examining the exit status", "...looks like a missing binary"])
        self.assertEqual(content, ["It failed because ", "the binary is missing."])
        self.assertEqual(answer, "It failed because the binary is missing.")

    def test_thinking_disabled_is_not_requested_or_shown(self):
        captured = {}

        def fake_urlopen(request, timeout=None):
            captured["body"] = json.loads(request.data)
            return FakeStreamResponse([_line(message={"content": "ok"}, done=True)])

        with mock.patch("sysai.ollama.urllib.request.urlopen", side_effect=fake_urlopen):
            self._manager(thinking=False).stream_chat([{"role": "user", "content": "hi"}])
        self.assertFalse(captured["body"]["think"])

    def test_model_without_thinking_support_degrades_gracefully(self):
        lines = [
            _line(message={"content": "plain "}),
            _line(message={"content": "answer"}, done=True),
        ]
        thoughts = []
        with mock.patch("sysai.ollama.urllib.request.urlopen", return_value=FakeStreamResponse(lines)):
            answer = self._manager().stream_chat(
                [{"role": "user", "content": "hi"}], on_thinking=thoughts.append,
            )
        self.assertEqual(thoughts, [])
        self.assertEqual(answer, "plain answer")

    def test_ollama_failure_during_stream_raises_ollama_error(self):
        lines = [_line(message={"content": "partial"})]
        with mock.patch(
            "sysai.ollama.urllib.request.urlopen",
            return_value=FakeStreamResponse(lines, fail_after=1),
        ):
            with self.assertRaises(OllamaError):
                self._manager().stream_chat([{"role": "user", "content": "hi"}])

    def test_malformed_line_is_skipped_not_fatal(self):
        lines = [
            b"not json at all\n",
            _line(message={"content": "still "}),
            _line(message={"content": "works"}, done=True),
        ]
        with mock.patch("sysai.ollama.urllib.request.urlopen", return_value=FakeStreamResponse(lines)):
            answer = self._manager().stream_chat([{"role": "user", "content": "hi"}])
        self.assertEqual(answer, "still works")

    def test_partial_stream_with_content_returns_what_arrived(self):
        # Connection ends (iterator exhausted) without a `done: true` chunk.
        lines = [_line(message={"content": "cut off"})]
        with mock.patch("sysai.ollama.urllib.request.urlopen", return_value=FakeStreamResponse(lines)):
            answer = self._manager().stream_chat([{"role": "user", "content": "hi"}])
        self.assertEqual(answer, "cut off")

    def test_empty_partial_stream_raises_ollama_error(self):
        with mock.patch("sysai.ollama.urllib.request.urlopen", return_value=FakeStreamResponse([])):
            with self.assertRaises(OllamaError):
                self._manager().stream_chat([{"role": "user", "content": "hi"}])

    def test_cancel_mid_stream_raises_cancelled_and_stops_reading(self):
        handle = StreamHandle()
        seen = []

        def cancel_after_first(text):
            seen.append(text)
            handle.cancel()

        lines = [
            _line(message={"thinking": "first"}),
            _line(message={"thinking": "second-should-not-be-seen"}),
            _line(message={"content": "answer"}, done=True),
        ]
        with mock.patch("sysai.ollama.urllib.request.urlopen", return_value=FakeStreamResponse(lines)):
            with self.assertRaises(OllamaCancelled):
                self._manager().stream_chat(
                    [{"role": "user", "content": "hi"}], on_thinking=cancel_after_first, handle=handle,
                )
        self.assertEqual(seen, ["first"])

    def test_cancel_before_start_short_circuits(self):
        handle = StreamHandle()
        handle.cancel()
        with mock.patch("sysai.ollama.urllib.request.urlopen") as urlopen:
            with self.assertRaises(OllamaCancelled):
                self._manager().stream_chat([{"role": "user", "content": "hi"}], handle=handle)
        urlopen.assert_not_called()


class AnswerRendererTests(unittest.TestCase):
    def _renderer(self, **kwargs):
        written = []
        return AnswerRenderer(written.append, **kwargs), written

    def test_thinking_then_content_transition(self):
        renderer, written = self._renderer()
        renderer.thinking("Looking at the error...\n")
        renderer.content("It failed because X.")
        renderer.finish("It failed because X.")
        text = "".join(written)
        think_open = text.index("SysAI · thinking")
        think_close = text.index("└", think_open)
        answer_open = text.index("┌─ SysAI ", think_close)
        self.assertLess(think_open, think_close)
        self.assertLess(think_close, answer_open)
        self.assertIn("It failed because X.", text)

    def test_thinking_disabled_shows_only_final_answer(self):
        renderer, written = self._renderer(show_thinking=False)
        renderer.thinking("secret reasoning\n")
        renderer.content("final answer")
        renderer.finish("final answer")
        text = "".join(written)
        self.assertNotIn("thinking", text)
        self.assertIn("final answer", text)

    def test_control_characters_in_thinking_are_stripped(self):
        renderer, written = self._renderer()
        renderer.thinking("safe\x1b[31mred\x1b[0m text\n")
        renderer.content("done")
        renderer.finish("done")
        text = "".join(written)
        self.assertNotIn("\x1b", text)
        self.assertIn("safered text", text)

    def test_secrets_in_thinking_are_redacted(self):
        renderer, written = self._renderer()
        renderer.thinking("export API_KEY=super-secret-value\n")
        renderer.content("done")
        renderer.finish("done")
        text = "".join(written)
        self.assertNotIn("super-secret-value", text)

    def test_unsupported_model_never_shows_fake_reasoning(self):
        renderer, written = self._renderer()
        # on_thinking is simply never called for a model without reasoning.
        renderer.content("plain final answer")
        renderer.finish("plain final answer")
        text = "".join(written)
        self.assertNotIn("thinking", text)
        self.assertIn("plain final answer", text)

    def test_normal_final_response_streams_incrementally(self):
        renderer, written = self._renderer()
        renderer.content("First line.\n")
        # The first line is flushed to the sink as soon as its newline
        # arrives -- before the second chunk (and before finish()) exists.
        first_flush_count = len(written)
        self.assertGreater(first_flush_count, 0)
        self.assertIn("First line.", "".join(written))
        renderer.content("Second line.")
        renderer.finish("First line.\nSecond line.")
        text = "".join(written)
        self.assertTrue(text.strip().startswith("┌─ SysAI"))
        self.assertIn("First line.", text)
        self.assertIn("Second line.", text)
        self.assertIn("└", text)

    def test_cancelled_closes_any_open_box(self):
        renderer, written = self._renderer()
        renderer.thinking("partial thought\n")
        renderer.cancelled()
        text = "".join(written)
        self.assertIn("cancelled", text)
        self.assertIn("└", text)


class StreamBoxTests(unittest.TestCase):
    def test_long_line_without_newline_still_flushes_live(self):
        written = []
        box_stream = StreamBox(written.append, "SysAI · thinking", dim=True)
        box_stream.feed("x" * 200)
        # Flushed before close() because it exceeded the live-flush threshold.
        self.assertTrue(any("x" * 100 in chunk for chunk in written))
        box_stream.close()


class SessionThinkingIntegrationTests(unittest.TestCase):
    def _session(self, **config_kwargs):
        return Session(Config(**config_kwargs), "/bin/true")

    def test_successful_commands_cause_zero_qwen_calls(self):
        session = self._session()
        session.current = {"command": "echo hi", "cwd": "/tmp", "timestamp": "now"}
        with mock.patch.object(session, "_ask_local") as ask, \
             mock.patch("sysai.session._safe_write"):
            session._handle_event({"event": "complete", "status": 0, "cwd": "/tmp"}, 42)
        ask.assert_not_called()
        self.assertIsNone(session._analysis_thread)

    def test_failed_commands_still_trigger_diagnosis(self):
        session = self._session()
        session.current = {"command": "false", "cwd": "/tmp", "timestamp": "now"}
        with mock.patch.object(session, "_ask_local", return_value="diagnosis") as ask, \
             mock.patch("sysai.session._safe_write"):
            session._handle_event({"event": "complete", "status": 1, "cwd": "/tmp"}, 42)
            session._analysis_thread.join(timeout=5)
        ask.assert_called_once()

    def test_reasoning_is_not_persisted_in_discussion(self):
        session = self._session()
        session.current = {"command": "false", "cwd": "/tmp", "timestamp": "now"}

        def fake_stream_chat(messages, *, on_thinking=None, on_content=None, handle=None):
            if on_thinking:
                on_thinking("MARKER-THINKING-TEXT")
            if on_content:
                on_content("final answer")
            return "final answer"

        with mock.patch.object(session.ollama, "stream_chat", side_effect=fake_stream_chat), \
             mock.patch("sysai.session._safe_write"):
            session._handle_event({"event": "complete", "status": 1, "cwd": "/tmp"}, 42)
            session._analysis_thread.join(timeout=5)
        combined_discussion = json.dumps(list(session.discussion))
        self.assertNotIn("MARKER-THINKING-TEXT", combined_discussion)
        # Auto-analysis answers are not added to the long-lived discussion at all.
        self.assertEqual(list(session.discussion), [])

    def test_reasoning_never_written_to_a_non_display_fd(self):
        session = self._session()
        session.current = {"command": "false", "cwd": "/tmp", "timestamp": "now"}

        def fake_stream_chat(messages, *, on_thinking=None, on_content=None, handle=None):
            if on_thinking:
                on_thinking("rm -rf / # not a real command, just reasoning text\n")
            if on_content:
                on_content("answer")
            return "answer"

        with mock.patch.object(session.ollama, "stream_chat", side_effect=fake_stream_chat), \
             mock.patch("sysai.session._safe_write") as write:
            session._handle_event({"event": "complete", "status": 1, "cwd": "/tmp"}, 42)
            session._analysis_thread.join(timeout=5)
        used_fds = {call.args[0] for call in write.call_args_list}
        # Only the real terminal (1) and the shell's response pipe (42) are
        # ever targeted; reasoning text never reaches a PTY input fd.
        self.assertEqual(used_fds, {1, 42})

    def test_reasoning_never_enters_web_search_queries(self):
        session = self._session(web_enabled=True)
        provider = mock.Mock()
        provider.search.return_value = []

        def fake_ask_local(prompt, *, on_thinking=None, on_content=None, handle=None):
            if on_thinking:
                on_thinking("MARKER-REASONING-TEXT")
            return "answer"

        server_end, client_end = socket.socketpair()
        with mock.patch("sysai.session.OllamaWebSearch", return_value=provider), \
             mock.patch("sysai.session.load_private_env", return_value={"OLLAMA_API_KEY": "fake"}), \
             mock.patch.object(session, "_ask_local", side_effect=fake_ask_local):
            session._control_stream({"action": "ask", "question": "why did it fail?", "web": True}, server_end)
        server_end.close()
        client_end.settimeout(2)
        raw = client_end.recv(65536)
        client_end.close()
        # Reasoning legitimately streams to the `ask` client for display...
        self.assertIn(b"MARKER-REASONING-TEXT", raw)
        # ...but must never be part of what gets sent to the search provider.
        sent_query = provider.search.call_args.args[0]
        self.assertNotIn("MARKER-REASONING-TEXT", sent_query)

    def test_ctrl_c_cancels_active_generation_and_is_not_forwarded(self):
        session = self._session()
        handle = mock.Mock()
        session.active_generation = handle
        forwarded = session._handle_stdin(b"\x03")
        handle.cancel.assert_called_once()
        self.assertEqual(forwarded, b"")

    def test_ctrl_c_without_active_generation_marks_command_interrupted(self):
        session = self._session()
        session.current = {"command": "sleep 30", "cwd": "/tmp", "timestamp": "now"}
        forwarded = session._handle_stdin(b"\x03")
        self.assertTrue(session.current["interrupted"])
        self.assertEqual(forwarded, b"\x03")

    def test_ctrl_c_mixed_with_other_bytes_only_strips_the_interrupt(self):
        session = self._session()
        session.active_generation = mock.Mock()
        forwarded = session._handle_stdin(b"a\x03b")
        self.assertEqual(forwarded, b"ab")


if __name__ == "__main__":
    unittest.main()
