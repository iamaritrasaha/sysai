# SysAI

SysAI is a local AI-aware Zsh session for Linux. It watches commands you run, notices failures, and uses a local Ollama model to explain what went wrong and suggest what to try next. **SysAI advises; it does not autonomously execute LLM-suggested commands.**

It is a terminal assistant, not a coding agent. Successful commands are recorded as lightweight, bounded context without invoking the model. Unexpected non-zero exits trigger concise local analysis.

## Demo

```console
$ sysai
SysAI
Local Linux assistant
qwen3:8b • Ollama

✓ Ollama ready
✓ Terminal monitoring active

$ apt update
...
E: The repository ... does not have a Release file.

┌─ SysAI ─────────────────────────────────────────────
│ What failed: APT rejected a configured repository.
│ Evidence: the repository has no Release file.
│
│ Safest next diagnostic:
│   grep -R "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/
│
│ This only reads repository configuration.
└─────────────────────────────────────────────────────
```

The diagnostic is displayed for review. SysAI never runs it.

## Architecture

```text
Terminal emulator
      ↓
SysAI PTY supervisor ───────────────┐
      ↓                             │
real interactive Zsh               │
      ├─ preexec: command + cwd     │
      ├─ PTY: combined output       ├─ bounded in-memory context
      └─ precmd: exit status        │
                                    ↓
                         redaction + safety prompt
                                    ↓
                         local Ollama → configured model

Explicit `ask --web` only → sanitized question → optional search provider
```

SysAI creates a temporary `ZDOTDIR` whose `.zshrc` safely sources the user's normal `.zshrc` and then session-only monitoring hooks. It does not permanently modify `.zshrc` or replace Zsh with a command parser.

## Features

- Real PTY-backed interactive Zsh with prompts, colors, history, completion, signals, sudo prompts, job control, and TUI support.
- Automatic local analysis of unexpected non-zero command exits.
- `sysai explain` for the most recently completed command, including successful commands.
- `sysai ask` for general Linux questions with bounded recent context.
- Explicit, optional `sysai ask --web` research with sanitized queries only.
- Common credential, authorization header, private-key, and secret-argument redaction.
- Bounded in-memory transcripts with head-and-tail truncation for large output.
- Ownership-aware Ollama startup and shutdown; no boot-time service changes.
- Conservative ANSI output and `NO_COLOR` support.
- Standard-library-only Python implementation with no package dependencies.

## Requirements

Required at runtime:

- Linux with PTY, Unix socket, `/proc`, and POSIX terminal support.
- Python 3.11 or newer.
- Zsh 5.x.
- Native Ollama available on `PATH` or already reachable at the configured URL.
- The configured local model installed in Ollama; the default is `qwen3:8b`.
- An interactive terminal emulator.

“Dependency-free Python” means the Python implementation uses only Python's standard library. Zsh, Ollama, a local model, and Linux are still external runtime requirements.

SysAI does not require Ghostty, AMD hardware, ROCm, systemd, or a particular GPU vendor. CPU inference and other Ollama-supported accelerators can work. It has been developed and manually tested on Ubuntu 24.04.4, Zsh 5.9, Ghostty, native Ollama, and AMD Radeon/ROCm; that is a tested setup, not a hard-coded requirement.

## Installation

From a checked-out release:

```sh
./install.sh
```

By default this installs:

- launcher: `~/.local/bin/sysai`
- Python source: `~/.local/lib/sysai-terminal`
- configuration: `~/.config/sysai`

Ensure `~/.local/bin` is in `PATH`. The installer refuses symlinked managed targets and does not edit `.zshrc`.

Check the release:

```sh
sysai --version
sysai --help
```

## Usage

Start an AI-aware child Zsh:

```sh
sysai
```

Run terminal commands normally. Successful commands do not call the model. A failed command normally triggers analysis unless its non-zero status is likely routine control flow, such as `test`, `grep -q`, `command -v`, `||`, or an interrupt status.

### Explain the last command

```sh
sysai explain
```

This explicitly analyzes the most recently completed command, even if it succeeded.

### Ask a local question

```sh
sysai ask "what does exit status 127 mean?"
```

The question, safety prompt, and a short redacted summary of recent commands go only to the configured local Ollama endpoint.

### Request web research

Web access is disabled by default. Enable it in `~/.config/sysai/config.toml`:

```toml
web_enabled = true
```

Place the Ollama web-search key in the private file created with mode `0600`:

```text
# ~/.config/sysai/env
OLLAMA_API_KEY=your-key
```

Then explicitly request research:

```sh
sysai ask --web "current Ubuntu kernel regression affecting suspend"
```

Only the explicit question is normalized, redacted, stripped of control characters, and limited to 500 characters before web search. Raw terminal output and recent terminal context are never sent to the provider.

### Stop SysAI

Inside the session:

```sh
sysai stop
```

From a parent terminal, `sysai stop` asks an active SysAI session to exit. It may recover an orphaned Ollama process only when private state, exact argv, Linux process start time, and process-group identity all confirm that SysAI created it.

## Ollama lifecycle

On startup SysAI probes the configured local API, defaulting to `http://127.0.0.1:11434`. If it is unavailable, SysAI launches `ollama serve` with fixed argv and waits for readiness. The model is not preloaded.

On exit:

- the configured model is unloaded with `keep_alive: 0`;
- an Ollama server started by that SysAI session is stopped;
- an Ollama server that was already running is left alone;
- no service is enabled, disabled, installed, or reconfigured at boot.

`sysai stop` does not kill an unowned Ollama service.

## Configuration

Defaults are in [`config/default.toml`](config/default.toml):

```toml
model = "qwen3:8b"
ollama_url = "http://127.0.0.1:11434"
auto_analyze_failures = true
output_capture_bytes = 48000
context_commands = 8
verbosity = "concise"
thinking = false
web_enabled = false
web_provider = "ollama"
request_timeout_seconds = 120
startup_timeout_seconds = 20
```

Edit `~/.config/sysai/config.toml` and restart SysAI. The model and API URL are configurable; no GPU name, username, or home path is embedded in the program.

## Privacy and security model

- Model output is display-only and control characters are removed before display. It is never parsed as a command or passed to a shell.
- Fixed executable argv is used to start Zsh and Ollama; observed command text is data, never interpolated for execution.
- Command text and output are redacted before local model context where practical.
- Recent command/output context exists only in bounded process memory and is not persisted by default.
- Runtime sockets and ownership state live in a mode-`0700`, user-owned runtime directory; state is mode `0600` and written atomically.
- PTY output and hook events travel over separate file descriptors, preventing ordinary terminal output from becoming internal protocol data.
- Web search is disabled by default and never receives a raw terminal transcript.
- Secret redaction is defense in depth, not a guarantee. Avoid printing secrets and revoke any credential that may have appeared in a terminal.
- Qwen can be mistaken. Review every suggested command, especially commands involving `sudo`, deletion, permissions, disks, packages, services, boot, `/etc`, or networking.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.

## Troubleshooting

### `sysai` is not found

Add the user binary directory to `PATH`, then start a new shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

### Ollama does not become ready

Check that `ollama` is on `PATH` and that the configured address is free. If SysAI started Ollama, its server log is in the private runtime directory, normally `$XDG_RUNTIME_DIR/sysai/ollama.log` or `/tmp/sysai-$UID/ollama.log`.

### The model is unavailable

Confirm the configured model already exists:

```sh
ollama list
```

SysAI does not install or pull models automatically.

### A routine failure triggered analysis

Expected-failure detection is heuristic. Disable automatic analysis with `auto_analyze_failures = false`, or ignore the advice. Use `sysai explain` when an important failure was suppressed.

### Web research is unavailable

Confirm `web_enabled = true` and that `~/.config/sysai/env` contains a valid `OLLAMA_API_KEY`. Ordinary local analysis does not need this key.

## Limitations

- PTYs combine stdout and stderr, so SysAI captures their ordered combined terminal presentation rather than falsely claiming stream separation.
- Full-screen applications and background processes may produce output whose semantic ownership cannot be determined perfectly.
- The recorded exit status is Zsh's status for the complete top-level command or pipeline.
- Expected-failure suppression is heuristic.
- Redaction cannot identify every proprietary or newly invented credential format.
- A local process running as the same user can generally inspect or interfere with that user's processes; SysAI does not claim to sandbox manually executed commands.
- v0.1.0 supports one active SysAI session per user. A private runtime lock rejects a second session to keep stop and Ollama ownership unambiguous.
- Linux is currently required. macOS, BSD, and Windows are not supported in v0.1.0.

## Development and testing

Normal CI requires no Ollama account, GPU, ROCm, model, or API key:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
sh -n bin/sysai install.sh uninstall.sh scripts/manual-integration-test.sh
zsh -n src/sysai/integration.zsh
git diff --check
```

The live integration test is deliberately separate because it requires a reachable Ollama server and configured model:

```sh
./scripts/manual-integration-test.sh
```

## Uninstall

```sh
./uninstall.sh
```

The uninstaller stops an active SysAI session, removes only the managed launcher and library directory, and preserves `~/.config/sysai`. It refuses symlinked managed paths. Remove the configuration directory manually if desired.

## License

[MIT](LICENSE)
