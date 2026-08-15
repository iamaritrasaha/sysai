from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys

from . import __version__
from .config import load_config, state_dir
from .display import box
from .ollama import OllamaError, is_owned_ollama_process
from .session import Session


def _session_request(action: str, **values) -> dict:
    socket_name = os.environ.get("SYSAI_SOCKET")
    if not socket_name:
        state = state_dir() / "active.json"
        if state.exists():
            try:
                socket_name = json.loads(state.read_text()).get("socket")
            except (OSError, json.JSONDecodeError):
                pass
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
    args = parser.parse_args(argv)
    if args.command == "explain":
        return _print_response(_session_request("explain"))
    if args.command == "ask":
        return _print_response(_session_request("ask", question=" ".join(args.question), web=args.web))
    if args.command == "stop":
        return stop_outside()
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
