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
- Deterministic read-only diagnostics for eight domains, a full-system summary, plain-language questions, sanitized reports, baselines, change analysis, command explanation, deeper failure investigation, and bounded monitoring.
- `sysai doctor` for SysAI's own installation, model, and runtime health.
- Explicit, optional `--web` research with sanitized queries only.
- Common credential, authorization header, private-key, and secret-argument redaction, plus stricter identity sanitization for anything written to disk.
- Bounded in-memory transcripts with head-and-tail truncation for large output.
- Ownership-aware Ollama startup and shutdown; no boot-time service changes.
- Conservative ANSI output and `NO_COLOR` support.
- Standard-library-only Python implementation with no package dependencies.

**SysAI may autonomously collect ONLY validated read-only diagnostics. SysAI never autonomously applies repairs.**

## CLI reference

| Command | What it does |
| --- | --- |
| `sysai` | Start the AI-aware Bash session |
| `sysai explain` | Explain the most recently completed command |
| `sysai investigate [--web]` | Gather more safe evidence about the last failure, then explain it |
| `sysai ask [--web] QUESTION` | Ask a local Linux question |
| `sysai check [--web] QUESTION` | Answer a plain-language question about this machine |
| `sysai health [--web]` | Every diagnostic domain, summarized |
| `sysai doctor [--json]` | Diagnose SysAI itself |
| `sysai gpu\|memory\|disk\|network\|boot\|services\|packages\|thermal [--web]` | One domain in depth |
| `sysai what COMMAND` | Explain a command without running it |
| `sysai report [SCOPE] [--last] [--json] [--output PATH]` | Sanitized diagnostic report |
| `sysai baseline create\|compare\|show\|delete` | Record and compare deterministic system facts |
| `sysai changes [--since VALUE] [--web]` | What changed on this machine, and when |
| `sysai watch DOMAIN [--duration SEC] [--interval SEC] [--web]` | Bounded foreground sampling |
| `sysai update check\|update` | Check for, or install, a checksum-verified SysAI release |
| `sysai thinking on\|off\|status` | Control the live reasoning display |
| `sysai stop` | Stop an active SysAI session |
| `sysai <read-only command>` | Command Insight Mode (`sysai dmesg`, `sysai --raw journalctl -b`, `sysai sudo dmesg`) |

Commands that display model prose (`health`, the domain commands, `check`, `changes`, `watch`, `investigate`, `report --last`) use the active SysAI session's local model. The deterministic evidence is collected and rendered either way; without a session, SysAI prints the facts and says the assessment is unavailable.

## Diagnostic architecture

```text
deterministic collectors      fixed argv, no shell, bounded output
          ↓
audited diagnostic engine     action IDs only, validated parameters, consent for elevated
          ↓
local Qwen reasoning          explains evidence; never invents or executes commands
          ↓
manual repair recommendation  shown for you to run yourself
```

Every diagnostic produces one canonical evidence document: request, system summary, normalized sections, findings, diagnostics performed, checks that were not available, timestamp, and a privacy note. Findings are computed in Python — severity, counts, thresholds — so the model is never asked to derive a fact that can be calculated. Each finding carries an id, domain, severity, classification (CONFIRMED, PROBABLE, POSSIBLE, INFORMATIONAL, NOT CHECKED), evidence, count, confidence, probable cause, what remains unverified, and a suggested next diagnostic.

The model may be asked which audited action **IDs** would reduce uncertainty. It can never supply argv. Unknown IDs and parameters that did not come from a collector are rejected.

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

Health runs every domain collector concurrently and summarizes them: OS/kernel, GPU/driver, memory/swap/OOM, storage/inodes/mount state and I/O errors, services, boot, packages, network/DNS/routes, and thermal sensors. Missing utilities become NOT CHECKED. Health never applies a fix. `--web` sends only generic, sanitized issue labels — not logs, paths, hostnames, addresses, serials, or terminal context.

### Diagnose one domain

```sh
sysai gpu
sysai memory --web
sysai disk
sysai network
sysai boot
sysai services
sysai packages
sysai thermal
```

Each command runs its domain's deterministic collectors, prints the facts directly, and then asks the local model to explain them. GPU collection is vendor-neutral: it consults only the tooling matching the hardware actually present, and never suggests NVIDIA utilities for an AMD or Intel GPU. SMART inspection stays elevated and approval-gated, and `fsck` is never run. Services are never restarted, enabled, or disabled; packages are never installed, upgraded, or removed. Sensors that a machine does not expose are NOT CHECKED, not a failure.

### Ask in plain language

```sh
sysai check "why is my PC slow?"
sysai check "why does my internet disconnect?"
sysai check "is my GPU okay?"
sysai check why is boot slow
```

`check` routes a question to one approved scope. Routing is deterministic keyword matching first; only a genuinely ambiguous question is put to the local model, and its reply must be one name from a strict enum (`gpu`, `memory`, `disk`, `network`, `boot`, `services`, `packages`, `thermal`, `full_system`) or it is discarded and the question falls back to a full-system scan. The model cannot invent a diagnostic or name a command.

### Explain a command without running it

```sh
sysai what "sudo apt autoremove"
sysai what "find /var -type f -size +1G"
```

`what` is explanation only: the command is tokenized with `shlex` for analysis and display and is **never executed**. It reports the program and its significant arguments, what is read, what is changed, privilege level, risk, reversibility, any dangerous parts, and a safer preview or dry-run alternative where one exists. Model-suggested alternatives, when shown, remain suggestions.

### Investigate a failure

```sh
sysai investigate
sysai investigate --web
```

`sysai explain` reasons about evidence that already exists. `sysai investigate` first gathers **additional safe read-only evidence** through the audited action catalogue — bounded rounds, the same privilege rules, one-time approval for elevated read-only checks — and only then produces an assessment. No repair action exists in the catalogue. With no recent failure or serious finding, SysAI says so and stops.

### Watch a domain for a bounded window

```sh
sysai watch gpu
sysai watch memory --duration 60 --interval 2
sysai watch thermal --duration 30
```

Watch samples `gpu`, `memory`, `network`, `thermal`, or `system` in the foreground for a bounded window: 30 seconds by default, 300 seconds maximum, minimum interval one second. Ctrl+C stops cleanly and still produces a summary. There is no daemon, background service, timer, or startup unit. Samples stay in memory, Python computes the minimum/maximum/change summary and correlates kernel events occurring during the window, and the local model is called exactly once at the end. With `--web`, a single sanitized research pass runs after sampling finishes, never during it.

### Reports

```sh
sysai report
sysai report gpu
sysai report --last
sysai report network --json
sysai report gpu --output report.md
```

Reports render the canonical evidence as Markdown (or `--json`) with sections for generation time, scope, system summary, findings, evidence, diagnostics performed, what was **not** checked, confidence, recommended next steps, and a privacy note. Every report is re-sanitized at the strict level first: usernames, home paths, hostnames, IP and MAC addresses, serial numbers, UUIDs, tokens, and keys are removed. `--last` uses the last completed diagnostic from the running SysAI session. Nothing is written to disk unless `--output` names a path, and files are created mode `0600`.

### Baselines

```sh
sysai baseline create
sysai baseline compare
sysai baseline show
sysai baseline delete
```

A baseline is a single sanitized snapshot of deterministic facts — kernel, OS, GPU/driver identity, memory size, filesystems, interface names and types, failed-service summary, boot health, selected package versions, installed count, and the SysAI version. It never contains terminal history, model reasoning, raw `dmesg` or journal text, secrets, addresses, MACs, or serials. It is written atomically, mode `0600`, to `$XDG_STATE_HOME/sysai/baseline.json` (default `~/.local/state/sysai/`); a corrupt or schema-mismatched file is reported rather than misread.

`compare` computes the differences in Python, and the model may explain them afterwards:

```text
Changed since baseline

Kernel
  7.0.0-29-generic -> 7.0.0-30-generic

mesa-vulkan-drivers
  26.0.7 -> 26.0.8

Failed services
  0 -> 1
```

### What changed

```sh
sysai changes
sysai changes --since last-boot
sysai changes --since yesterday
sysai changes --since "2026-08-20"
sysai changes --web
```

`changes` answers "what changed before my machine started behaving differently?". It parses APT history, the dpkg log, kernel and driver package changes, reboot history, current service failures, and the modification times of files directly under `/etc`. It does not scan the filesystem and does not read private document contents. The default window is the current boot. Timestamps are parsed deterministically, and correlation is reported as correlation: "this changed shortly before the first observed failure", never as cause.

### Diagnose SysAI itself

```sh
sysai doctor
sysai doctor --json
```

`doctor` checks SysAI rather than the machine: Python and Bash versions, install location and version, whether an installed copy still matches the repository checkout, config and private-env readability and permissions, web configuration and whether an API key exists (never its value), the Ollama binary, local API reachability, the configured model and whether it responds, reasoning support, session and runtime state including stale `active.json`, Bash integration syntax, `~/.bashrc` readability and whether anything added a SysAI reference to it, free disk space, GPU visibility as information only, and renderer sanity. It exits non-zero when a check needs attention.

### Update SysAI

```sh
sysai update check
sysai update
```

This updates SysAI only. It never runs `apt upgrade`, never updates Ubuntu, Ollama, or the local model, never pulls from a branch, and never pipes a download into a shell. `update check` reads published release metadata and reports the version and summary without changing anything. `sysai update` installs a release only when it can verify it: the release must publish both an artifact and a `SHA256SUMS` (or equivalent) manifest, the download must match the recorded digest, and the archive must contain no traversal or link entries. Otherwise SysAI reports:

```text
SysAI: A newer release exists, but automatic update is unavailable
because no verifiable release artifact/checksum is published.
```

and prints manual instructions. A development checkout is never updated in place, and a checkout with uncommitted changes is refused explicitly.

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

`--web` is accepted by `ask`, `health`, the eight domain commands, `check`, `changes`, `investigate`, and `watch` (post-sampling only). For diagnostics, the query is built from generic finding labels and normalized facts — never from raw telemetry, hostnames, usernames, paths, terminal logs, IP or MAC addresses, serial numbers, or model reasoning. Online results are labelled secondary and untrusted and can never establish local system state.

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
- One canonical sanitization layer serves every structured diagnostic. On-screen local output removes secrets; anything written to disk or sent to a search provider additionally removes usernames, home paths, hostnames, IP and MAC addresses, serial numbers, and UUIDs.
- Findings are computed in Python. The model explains evidence; it never derives a deterministic fact, contributes a finding, or supplies an executable command. Diagnostic action IDs are validated against a fixed argv table, and their parameters must come from a collector.
- Repairs are never executed. No mutating action exists in the diagnostic catalogue: services are not restarted, enabled, or disabled, packages are not installed, upgraded, or removed, and `fsck` is never run.
- Self-update installs only a release whose artifact matches a published checksum manifest. It never pulls a branch, never pipes a download into a shell, and never updates a development checkout in place.
- `sysai watch` is foreground and bounded. There is no daemon, background service, timer, or startup unit, and samples are discarded once the summary is produced.
- Secret redaction is defense in depth, not a guarantee. Avoid printing secrets and revoke any credential that may have appeared in a terminal.
- Qwen can be mistaken, in its reasoning as well as its final answer. Review every suggested command, especially commands involving `sudo`, deletion, permissions, disks, packages, services, boot, `/etc`, or networking.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.

## What SysAI keeps

SysAI is memory-only by default. Recent command context, captured output, diagnostic evidence, model reasoning, and watch samples exist only in bounded process memory and disappear when the session ends. Nothing writes a shell-history copy, a command transcript, reasoning text, raw health logs, or retained telemetry.

Only these files are ever written, and only for the reasons given:

| Path | Written by | Contents |
| --- | --- | --- |
| `~/.config/sysai/config.toml` | installer, `sysai thinking on\|off` | settings, mode `0600` |
| `~/.config/sysai/env` | you | the optional web-search key, mode `0600` |
| `$XDG_STATE_HOME/sysai/baseline.json` | `sysai baseline create` | sanitized deterministic facts, mode `0600`, atomic |
| the path you pass to `--output` | `sysai report --output PATH` | a sanitized report, mode `0600`, atomic |
| `$XDG_RUNTIME_DIR/sysai/` | an active session | control socket and ownership state, mode `0700`/`0600` |

`sysai report` prints to the terminal unless `--output` names a path; no file is created silently.

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
- Model-backed assessment needs a running SysAI session. Deterministic diagnostics, `sysai doctor`, `sysai what`, `sysai report`, `sysai baseline`, and `sysai update check` work without one.
- `sysai changes` reads package and boot history, not arbitrary file contents, so a change made outside a package manager and outside `/etc` is not visible to it.
- Automatic self-update requires the release to publish a checksum manifest. Until one exists, `sysai update` reports that and gives manual instructions.
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
