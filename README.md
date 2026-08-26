# SysAI

SysAI is a local AI-aware Bash session for Linux. It watches commands you run, notices failures, and uses a local Ollama model to explain what went wrong and suggest what to try next. **SysAI advises; it does not autonomously execute LLM-suggested commands.**

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
real interactive Bash               │
      ├─ DEBUG trap: command + cwd  │
      ├─ PTY: combined output       ├─ bounded in-memory context
      └─ PROMPT_COMMAND: exit code  │
                                    ↓
                         redaction + safety prompt
                                    ↓
                         local Ollama → configured model

Explicit `ask --web` only → sanitized question → optional search provider
```

SysAI writes a temporary, session-only rcfile and starts Bash with `bash --rcfile <temporary-file> -i`. That rcfile sources the user's normal `~/.bashrc` first and then SysAI's session-only monitoring hooks, and it is removed when the session ends. SysAI never modifies `~/.bashrc`, `~/.profile`, or `~/.bash_profile`, and never replaces Bash with a command parser.

### Bash integration

Bash has no `preexec`/`precmd` hooks, so SysAI builds the equivalent lifecycle from Bash's own mechanisms, entirely inside the session:

- **Command start.** A `DEBUG` trap detects that a command is beginning. Bash raises `DEBUG` before *every* simple command, so SysAI arms the trap once per prompt and disarms it on the first firing. `dmesg | grep amdgpu` and `sudo apt update && echo done` therefore each produce exactly one record, and the internal commands of a shell function do not become separate records. The recorded text is the complete top-level line taken from `history`, not the fragment Bash is about to run.
- **Command completion.** `PROMPT_COMMAND` reports the real exit status of the finished top-level command or pipeline, together with the current directory.
- **Your `PROMPT_COMMAND` is preserved.** SysAI prepends its completion hook and appends its arming hook around whatever was already there, keeping the existing form: an array stays an array (Bash 5.1+), a string stays a string, and an unset `PROMPT_COMMAND` becomes a string. Registration is idempotent, and if a prompt framework later replaces `PROMPT_COMMAND` outright, SysAI reinstalls its hooks rather than silently stopping.
- **`DEBUG` trap policy.** SysAI needs the `DEBUG` trap and cannot chain onto an existing one, because re-running a saved trap body would mean evaluating stored shell text — something SysAI never does. If your shell startup already installed a `DEBUG` trap, SysAI takes it over **for the session only** and says so on stderr, keeping the original definition in `$SYSAI_REPLACED_DEBUG_TRAP`. Your `~/.bashrc` is untouched, and any new shell gets the original trap back.
- **Nothing recursive.** SysAI's own hook and `sysai` wrapper functions are excluded from monitoring, so internal bookkeeping never becomes a recorded command or triggers analysis.

## Features

- Real PTY-backed interactive Bash with prompts, colors, history, readline, completion, signals, sudo prompts, job control, and TUI support.
- Automatic local analysis of unexpected non-zero command exits.
- `sysai explain` for the most recently completed command, including successful commands.
- `sysai ask` for general Linux questions with bounded recent context.
- `sysai health` for a bounded, read-only local Linux health assessment; `sysai health --web` optionally researches sanitized detected issue labels.
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
- Bash 5.x.
- Native Ollama available on `PATH` or already reachable at the configured URL.
- The configured local model installed in Ollama; the default is `qwen3:8b`.
- An interactive terminal emulator.

“Dependency-free Python” means the Python implementation uses only Python's standard library. Bash, Ollama, a local model, and Linux are still external runtime requirements.

SysAI does not require Ghostty, AMD hardware, ROCm, systemd, or a particular GPU vendor. CPU inference and other Ollama-supported accelerators can work. It has been developed and manually tested on Ubuntu 24.04.4, Bash 5.2, Ghostty, native Ollama, and AMD Radeon/ROCm; that is a tested setup, not a hard-coded requirement.

## Installation

From a checked-out release:

```sh
./install.sh
```

By default this installs:

- launcher: `~/.local/bin/sysai`
- Python source: `~/.local/lib/sysai-terminal`
- configuration: `~/.config/sysai`

Ensure `~/.local/bin` is in `PATH`. The installer refuses symlinked managed targets and does not edit `~/.bashrc`, `~/.profile`, or `~/.bash_profile`. It does not install a shell, and it never runs `chsh` or changes your login shell.

Check the release:

```sh
sysai --version
sysai --help
```

## Usage

Start an AI-aware child Bash:

```sh
sysai
```

Run terminal commands normally. Successful commands do not call the model. A failed command normally triggers analysis unless its non-zero status is likely routine control flow, such as `test`, `grep -q`, `command -v`, `||`, or an interrupt status.

### Live reasoning ("thinking")

When the configured model exposes reasoning (Ollama's `think` field, supported by `qwen3:8b`), SysAI streams it live in a dim, subdued box before the final answer:

```console
┌─ SysAI · thinking ─────────────────────────
│ Examining the exit status...
│ This resembles a missing executable rather
│ than a permissions problem...
└─────────────────────────────────────────────

┌─ SysAI ────────────────────────────────────
│ The command failed because ...
└─────────────────────────────────────────────
```

This applies to automatic failure analysis, `sysai explain`, and `sysai ask`. Reasoning is real model output streamed as it is generated, never simulated. It is **display-only**: it is redacted and control-character-sanitized exactly like the final answer, is never written to disk, never added to SysAI's short-lived conversation context, never sent to web search, and can never become shell input. Reasoning text is model-generated and can itself be wrong; treat it the same way you treat the final answer, as a hint to verify rather than a fact.

If the model does not expose reasoning, SysAI shows only the final answer, with no fake "thinking" text and no error.

Control it with:

```sh
sysai thinking on       # show live reasoning (default)
sysai thinking off      # show only the final answer
sysai thinking status   # report the current setting
```

`on`/`off` update `~/.config/sysai/config.toml` for future sessions and, if a SysAI session is currently running, take effect immediately. `status` reports the active session's live setting if one exists, otherwise the saved configuration.

**Cancelling a generation:** press Ctrl+C while SysAI is streaming thinking or an answer to cancel that generation cleanly. It stops the local model request and returns you to the normal prompt; it never kills the monitored Bash session, corrupts the terminal, or stops Ollama.

### Explain the last command

```sh
sysai explain
```

This explicitly analyzes the most recently completed command, even if it succeeded.

### Command Insight Mode

```sh
sysai dmesg
sysai journalctl -b
sysai --web dmesg
sysai --raw dmesg
sysai sudo dmesg
```

An explicitly requested, allowlisted read-only inspection command is captured privately and analyzed without dumping its raw output. SysAI reduces long logs into bounded anomaly context, repetition counts, and useful tail evidence, then reports findings before recommendations. `--raw` additionally shows the sanitized bounded capture without Markdown rendering. `--web` pre-authorizes research using a query built only from normalized technical facts; raw logs and identifiers never enter that query. Without `--web`, SysAI may offer a one-time `[y/N]` research prompt when a concrete finding would benefit from current information.

SysAI may ask the local model which audited diagnostic action IDs would resolve remaining uncertainty. IDs map to fixed read-only argv builders with strict parameter validation, timeouts, and output limits; arbitrary model commands are rejected. Unprivileged actions may run automatically within a maximum of three follow-up rounds. Elevated read-only actions show their purpose, exact audited command, and privilege level and require one-time approval. A user-typed `sysai sudo dmesg` is already explicit privilege authorization, while destructive or mutating commands remain rejected. Repairs are recommendations only.

### Ask a local question

```sh
sysai ask "what does exit status 127 mean?"
```

The question, safety prompt, and a short redacted summary of recent commands go only to the configured local Ollama endpoint.
Broad or focused inspection requests such as “check my system,” “check my GPU,” or “check my disk” collect actual safe telemetry through the shared health/diagnostic engine. Recent terminal context is labelled as potentially unrelated and is never treated as an inspection result by itself.

### Check system health

```sh
sysai health
sysai health --web
```

Health concurrently collects bounded, read-only local evidence (OS/kernel, CPU/load, memory/swap, storage/inodes/mount state, services, kernel errors/OOM, packages, network/DNS/routes, time, processes, GPU/AMD/ROCm where available, and thermal sensors) before asking the local model to explain it. Missing utilities become NOT CHECKED. Health never applies a fix. `--web` remains optional and only sends generic, sanitized issue descriptions—not logs, paths, hostnames, addresses, serials, or terminal context.

When deeper evidence is needed, SysAI's small diagnostic-action catalogue validates the action and collector-derived parameters before it can run. Elevated read-only actions (for example SMART inspection) require an explicit one-time `[y/N]` approval; refusal leaves the assessment at reduced confidence. Repairs are always suggestions for you to run manually.

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
thinking = true
web_enabled = false
web_provider = "ollama"
request_timeout_seconds = 120
startup_timeout_seconds = 20
```

Edit `~/.config/sysai/config.toml` and restart SysAI, or use `sysai thinking on|off` to toggle `thinking` without hand-editing the file. `thinking` controls both requesting reasoning tokens from Ollama and displaying the live "SysAI · thinking" box; there is no separate display-only flag, since requesting reasoning SysAI would then throw away is wasted latency. The model and API URL are configurable; no GPU name, username, or home path is embedded in the program.

## Privacy and security model

- Model output — including reasoning ("thinking") text — is display-only and control characters are removed before display. It is never parsed as a command, never passed to a shell, and can never become terminal input.
- Fixed executable argv is used to start Bash and Ollama; observed command text is data, never interpolated for execution. Bash is resolved to `/bin/bash`, or to `bash` on `PATH`; the user's arbitrary `$SHELL` is never launched, and SysAI never uses `bash -c`, `eval`, or a shell interpreter for observed or model-generated text.
- Command text, output, and model reasoning are redacted before display or use as context, where practical.
- Recent command/output context and reasoning text exist only in bounded process memory. Reasoning is never persisted to disk and is never added to SysAI's short-lived conversation context; only final answers are kept there, and only for explicit `sysai ask` follow-ups.
- Runtime sockets and ownership state live in a mode-`0700`, user-owned runtime directory; state is mode `0600` and written atomically. `~/.config/sysai/config.toml` is written mode `0600`.
- PTY output and hook events travel over separate file descriptors, preventing ordinary terminal output from becoming internal protocol data.
- Web search is disabled by default and never receives a raw terminal transcript or model reasoning text — only an explicit, sanitized user question.
- Health diagnostics use an audited fixed read-only allowlist with bounded timeouts; model suggestions, including repairs, are never executed.
- Secret redaction is defense in depth, not a guarantee. Avoid printing secrets and revoke any credential that may have appeared in a terminal.
- Qwen can be mistaken, in its reasoning as well as its final answer. Review every suggested command, especially commands involving `sudo`, deletion, permissions, disks, packages, services, boot, `/etc`, or networking.

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
- The recorded exit status is Bash's status for the complete top-level command or pipeline.
- Expected-failure suppression is heuristic.
- SysAI takes over the `DEBUG` trap for the session. A `DEBUG` trap installed by your shell startup is reported and preserved in `$SYSAI_REPLACED_DEBUG_TRAP`, but it is not active inside a SysAI session.
- A command hidden from history by `HISTCONTROL=ignorespace` or `HISTIGNORE` is recorded as its leading simple command rather than the full line.
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
bash -n src/sysai/integration.bash
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
