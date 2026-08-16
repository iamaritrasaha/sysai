from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys

from . import __version__
from .config import load_config, set_config_value, state_dir
from .display import AnswerRenderer, box
from .ollama import OllamaError, is_owned_ollama_process
from .session import Session


def _active_socket() -> str | None:
    socket_name = os.environ.get("SYSAI_SOCKET")
    if not socket_name:
        state = state_dir() / "active.json"
        if state.exists():
            try:
                socket_name = json.loads(state.read_text()).get("socket")
            except (OSError, json.JSONDecodeError):
                pass
    return socket_name


def _session_request(action: str, **values) -> dict:
    socket_name = _active_socket()
    if not socket_name:
        return {"ok": False, "error": "No active SysAI session was found."}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(180)
            client.connect(socket_name)
            client.sendall(json.dumps({"action": action, **values}).encode())
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"Could not contact the active SysAI session: {exc}"}


def _stream_session_request(action: str, **values) -> int:
    """Send `explain`/`ask` and render the session's streamed thinking/answer live."""
    socket_name = _active_socket()
    if not socket_name:
        print("SysAI: No active SysAI session was found.", file=sys.stderr)
        return 1
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(180)
        client.connect(socket_name)
        client.sendall(json.dumps({"action": action, **values}).encode())
        client.shutdown(socket.SHUT_WR)
    except OSError as exc:
        print(f"SysAI: Could not contact the active SysAI session: {exc}", file=sys.stderr)
        return 1

    def write(text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    renderer = AnswerRenderer(write)
    buffer = b""
    error: str | None = None
    ok = False
    saw_done = False
    try:
        with client:
            while True:
                try:
                    chunk = client.recv(65536)
                except socket.timeout:
                    error = "Timed out waiting for a response."
                    break
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, _, buffer = buffer.partition(b"\n")
                    if not line:
                        continue
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    kind = message.get("type")
                    if kind == "thinking":
                        renderer.thinking(str(message.get("text", "")))
                    elif kind == "content":
                        renderer.content(str(message.get("text", "")))
                    elif kind == "error":
                        error = str(message.get("error", "unknown error"))
                    elif kind == "done":
                        ok = bool(message.get("ok"))
                        saw_done = True
    except KeyboardInterrupt:
        # Cancel cleanly: drop the connection (the session detects this and
        # stops generating) and return control to the shell prompt.
        renderer.cancelled()
        try:
            client.close()
        except OSError:
            pass
        return 130
    if error:
        renderer.close()
        print(f"SysAI: {error}", file=sys.stderr)
        return 1
    if not saw_done:
        print("SysAI: Connection to the active session was lost.", file=sys.stderr)
        return 1
    renderer.finish()
    return 0 if ok else 1


def hook(args: list[str]) -> int:
    try:
        event_fd = int(os.environ["SYSAI_EVENT_FD"])
        response_fd = int(os.environ["SYSAI_RESPONSE_FD"])
    except (KeyError, ValueError):
        return 0
    if args[0] == "begin":
        payload = {"event": "begin", "command": args[1], "cwd": args[2]}
    else:
        payload = {"event": "complete", "status": int(args[1]), "cwd": args[2]}
    os.write(event_fd, json.dumps(payload).encode() + b"\n")
    if payload["event"] == "complete":
        try:
            os.read(response_fd, 1)
        except OSError:
            pass
    return 0


def _print_response(response: dict) -> int:
    if response.get("ok"):
        if response.get("answer"):
            print(box(response["answer"]), end="")
        elif response.get("message"):
            print(response["message"])
        return 0
    print(f"SysAI: {response.get('error', 'unknown error')}", file=sys.stderr)
    return 1


def stop_outside() -> int:
    response = _session_request("stop")
    if response.get("ok"):
        print("SysAI stopped.\nQwen unloaded; SysAI-owned Ollama will shut down.\nGoodbye 👋")
        return 0
    # Recover a server left behind by an abnormally terminated SysAI process.
    state_path = state_dir() / "active.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
            pid = state.get("ollama_pid")
            start_time = state.get("ollama_start_time")
            pgid = state.get("ollama_pgid")
            if (
                state.get("ollama_started_by_sysai")
                and all(isinstance(value, int) for value in (pid, start_time, pgid))
            ):
                if is_owned_ollama_process(pid, start_time, pgid):
                    os.killpg(pid, signal.SIGTERM)
                    state_path.unlink(missing_ok=True)
                    print("Stopped the orphaned SysAI-owned Ollama server.")
                    return 0
        except (OSError, json.JSONDecodeError):
            pass
    return _print_response(response)


def thinking_command(state: str) -> int:
    if state == "status":
        response = _session_request("get_thinking")
        if response.get("ok"):
            print(f"Thinking display: {'on' if response['thinking'] else 'off'} (active session)")
            return 0
        value = load_config().thinking
        print(f"Thinking display: {'on' if value else 'off'} (from config; no active session)")
        return 0
    value = state == "on"
    set_config_value("thinking", value)
    response = _session_request("set_thinking", value=value)
    if response.get("ok"):
        print(f"Thinking display turned {state} for the active session and saved for future sessions.")
    else:
        print(f"Thinking display turned {state}. It will take effect the next time SysAI starts.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "__hook":
        return hook(argv[1:])
    if argv[:2] == ["__session", "stop"]:
        return _print_response(_session_request("leave"))

    parser = argparse.ArgumentParser(prog="sysai", description="Local AI-aware Zsh session")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("explain", help="analyze the most recently completed command")
    ask_parser = sub.add_parser("ask", help="ask a local Ubuntu/Linux question")
    ask_parser.add_argument("--web", action="store_true", help="research this sanitized question online")
    ask_parser.add_argument("question", nargs="+")
    sub.add_parser("stop", help="stop an active SysAI session")
    thinking_parser = sub.add_parser("thinking", help="control the live reasoning display")
    thinking_parser.add_argument("state", choices=["on", "off", "status"])
    args = parser.parse_args(argv)
    if args.command == "explain":
        return _stream_session_request("explain")
    if args.command == "ask":
        return _stream_session_request("ask", question=" ".join(args.question), web=args.web)
    if args.command == "stop":
        return stop_outside()
    if args.command == "thinking":
        return thinking_command(args.state)
    if os.environ.get("SYSAI_SESSION"):
        parser.print_help()
        return 0
    config = load_config()
    executable = os.environ.get("SYSAI_EXECUTABLE", os.path.abspath(sys.argv[0]))
    session = Session(config, executable)
    try:
        return session.run()
    except (OllamaError, RuntimeError) as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        session.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
