# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- History intelligence and local experience memory. `sysai history [--all] [--json]` shows SysAI's interpretation of recent relevant activity; `sysai memories [list|search|show|forget|purge|stats]`, `sysai remember "..."`, and `sysai feedback ...` manage a local, structured, dependency-free SQLite memory store at `$XDG_STATE_HOME/sysai/memory.db` (mode `0600`); `sysai context` summarizes what SysAI currently knows without dumping data. Every diagnostic assessment (`health`, a domain command, `check`, `changes`, `investigate`, `baseline compare`, `watch`), `sysai ask`, Command Insight Mode, and automatic failure analysis are enriched with a bounded, sanitized `history_correlation` section (labelled HISTORICAL / CORRELATION ONLY, never causation) and a `prior_experience` section (labelled PRIOR EXPERIENCE, at most five memories), computed deterministically before the model ever sees them, and always after evidence reduction so raw history never reaches a web-search query. `sysai ask` and automatic failure analysis only consult history/memory when the question or failed command matches a recognizable diagnostic domain, so a trivial question or an unrecognized program never triggers a lookup. Bash history is read from a bounded tail of `HISTFILE` (or `~/.bash_history`), parsed as inert text and never executed, and relevance is scored with word-boundary domain matching (so `apt` never matches inside `laptop`). Confirmed critical/warning findings are recorded as incidents automatically, with repeat findings reinforcing the same record instead of duplicating it; contradicting evidence marks a memory `contradicted` rather than deleting it. An ordinary completed shell command never touches the history file or the memory database — only an explicit diagnostic command, question, or qualifying failure does. See `history.py`, `memory.py`, and the History intelligence / Memory sections of `SECURITY.md`.

- `sysai doctor` (and `sysai doctor --json`): a deterministic self-diagnosis of SysAI itself — Python and Bash versions, install location and version, installed-copy vs repository drift, config and private-env readability and permissions, web configuration and API-key presence (never its value), Ollama binary and API reachability, configured model presence and response, reasoning support, session and runtime state including stale `active.json`, Bash integration syntax, `~/.bashrc` readability and whether anything added a SysAI reference to it, free disk space, GPU visibility as information only, and renderer sanity.
- Domain diagnostics: `sysai gpu`, `sysai memory`, `sysai disk`, `sysai network`, `sysai boot`, `sysai services`, `sysai packages`, and `sysai thermal`, each with optional `--web`. GPU collection is vendor-neutral and never suggests another vendor's tooling. SMART inspection stays elevated and approval-gated; `fsck` is never run; services are never restarted, enabled, or disabled; packages are never installed, upgraded, or removed. Unavailable sensors and utilities are NOT CHECKED, not failures.
- `sysai check "..."`: plain-language routing to one approved diagnostic scope. Deterministic word-boundary keyword matching decides first; a genuinely ambiguous question may be classified by the local model, whose reply must match a strict enum or be discarded in favour of a full-system scan. The model can never invent a diagnostic or name a command.
- `sysai report [SCOPE] [--last] [--json] [--output PATH]`: sanitized Markdown or JSON reports covering generation time, scope, system summary, findings, evidence, diagnostics performed, what was not checked, confidence, recommended next steps, and a privacy note. Nothing is written unless `--output` names a path; files are created mode `0600` and atomically.
- `sysai baseline create|compare|show|delete`: a sanitized snapshot of deterministic system facts in `$XDG_STATE_HOME/sysai/baseline.json`, written atomically with mode `0600`, with schema versioning and corruption handling. Differences are computed in Python; the model may explain them afterwards.
- `sysai changes [--since VALUE] [--web]`: APT history, dpkg log, kernel and driver package changes, reboot history, current service failures, and `/etc` modification times over a bounded window (default: the current boot). Timestamps are parsed deterministically and temporal ordering is reported as correlation, never as cause.
- `sysai what COMMAND`: explanation only. The command is tokenized with `shlex` for analysis and display and is never executed. Reports the program, significant arguments, what is read and changed, privilege, risk, reversibility, dangerous parts, and a safer preview or dry-run alternative.
- `sysai investigate [--web]`: gathers additional safe read-only evidence through the audited action catalogue before explaining the most recent failure or serious finding, with bounded rounds and unchanged privilege rules. Reports plainly when nothing recent requires investigation.
- `sysai watch DOMAIN [--duration SEC] [--interval SEC] [--web]`: bounded foreground sampling of `gpu`, `memory`, `network`, `thermal`, or `system` — 30 seconds by default, 300 maximum, minimum interval one second, Ctrl+C stops cleanly. No daemon, background service, timer, or startup unit. Samples stay in memory, Python computes the summary and correlates kernel events during the window, and the local model is called exactly once afterwards.
- `sysai update check` and `sysai update`: SysAI self-update only. Never touches the operating system, APT, Ollama, or the local model. An update installs only from a release artifact that matches a published checksum manifest, with archive traversal and link entries rejected; without a verifiable artifact SysAI says so and prints manual instructions. It never pulls a branch, never pipes a download into a shell, and never updates a development checkout in place.
- One canonical evidence document shared by every diagnostic: schema version, request, system summary, sections, findings, diagnostics, unavailable checks, timestamp, and privacy note. Findings carry id, domain, severity, classification, evidence, count, confidence, probable cause, what remains unverified, and a suggested next diagnostic.
- One canonical sanitization layer with two levels: on-screen local output removes secrets, while anything written to disk or sent to a search provider additionally removes usernames, home paths, hostnames, IP and MAC addresses, serial numbers, and UUIDs. Log timestamps and PCI addresses are deliberately preserved as useful, non-identifying evidence.
- Additional audited diagnostic action IDs covering memory, filesystem capacity and inodes, block layout, listening sockets, boot timing and blame, failed-unit listing, held packages, and vendor-appropriate GPU tooling.

### Changed

- README rewritten around SysAI's current identity as a local Linux intelligence and diagnostic companion (Bash session + diagnostics + history intelligence + local experience memory), rather than describing it primarily as an "AI-aware Bash session". No behavior changed; this is a documentation/positioning update.
- `sysai health` is now every domain summarized, sharing the collectors, findings engine, evidence schema, and audited action catalogue with the individual domain commands. The command and its `--web` flag are unchanged.
- Diagnostic collection is split into reusable modules — `collect`, `domains`, `diagnostics`, `evidence`, `privacy`, `render`, `intent`, `doctor`, `reports`, `baseline`, `changes`, `monitor`, `updater`, `whatis` — and `health.py` is now the facade over them rather than a separate implementation.
- Findings, severities, and thresholds are computed in Python rather than inferred by the model; the model explains evidence and never derives a deterministic fact.
- Growing log files (`dpkg.log`, APT history) are read from the end, so history parsing sees the newest entries rather than the oldest.
- Every new command word is reserved in the CLI, so `sysai disk` is the disk diagnostic rather than an attempt to inspect a program called `disk`. Existing Command Insight forms (`sysai dmesg`, `sysai --web dmesg`, `sysai --raw dmesg`, `sysai sudo dmesg`) are unchanged.

### Fixed

- `test_stream_box_output_remains_prefixed_through_a_pty` was flaky: it performed a single read of a PTY master, which can return only the first chunk. It now drains the master until EOF on a reader thread, making the captured output deterministic without retries or sleeps.

### Changed (Bash migration)

- SysAI is now Bash-native. The monitored session is a real interactive Bash started with fixed argv as `bash --rcfile <temporary-file> -i`, replacing the previous Zsh session. Bash 5.x is the runtime requirement; Zsh is no longer required, installed, or supported.
- Command lifecycle metadata now comes from a guarded Bash `DEBUG` trap (command start) and `PROMPT_COMMAND` (completion and real exit status), replacing Zsh's `preexec`/`precmd`. One top-level entry produces exactly one record: pipelines, `&&`/`||` lists, multi-line compound commands, and shell functions are not split, and SysAI's own hooks never record themselves.
- An existing `PROMPT_COMMAND` is preserved in its existing form (array on Bash 5.1+, string, or unset), registration is idempotent, and the hooks are reinstalled if a prompt framework replaces `PROMPT_COMMAND`.
- Session setup uses a temporary rcfile that sources the user's `~/.bashrc`, instead of a temporary `ZDOTDIR` and `.zshrc`. `~/.bashrc`, `~/.profile`, and `~/.bash_profile` are never modified, and the installer no longer touches or checks for a shell startup file beyond requiring Bash 5.x.

### Removed

- `src/sysai/integration.zsh`, `ZDOTDIR` handling, and every Zsh runtime path, requirement, and CI dependency.

## [0.1.0] - 2026-08-15

### Added

- Command Insight Mode for explicit allowlisted read-only commands such as `sysai dmesg`, with private bounded capture, optional sanitized raw output and web research.
- Findings-first Command Insight evidence reduction for logs and common status commands, with explicit SysAI truncation metadata, normalized anomaly counts, and safeguards against treating normal enumeration as failure.
- Bounded adaptive diagnostics through audited action IDs only, including strict parameters, fixed argv, per-action limits, three-round maximum, and one-time consent for elevated read-only checks.

- `sysai health` and optional `sysai health --web`: bounded, read-only Linux evidence collection with local health explanation and sanitized issue-only web research.
- Stateful safe terminal Markdown presentation shared by every model-output path, including chunked block/inline syntax, escaped Markdown, literal code, links, bounded wrapping, blank-line collapse, and terminal-control stripping.
- End-to-end streamed renderer golden tests covering ask, explain, health, Command Insight, automatic analysis, native Ollama events, PTY output, and an isolated installed copy.

- PTY-backed interactive Zsh monitoring with `preexec` and `precmd` metadata.
- Automatic local Qwen diagnosis for unexpected non-zero command exits.
- Manual `sysai explain`, `sysai ask`, optional `sysai ask --web`, and graceful `sysai stop` commands.
- Bounded ephemeral context, output truncation, credential redaction, and a safety-focused system prompt.
- Ownership-aware native Ollama startup, model unload, and shutdown behavior.
- Standard-library test suite, live integration script, secure installer, and uninstaller.
- Live streamed model reasoning ("thinking") for automatic failure analysis, `sysai explain`, and `sysai ask`, using Ollama's native `stream`/`think` protocol. Reasoning is display-only: redacted and control-sanitized like the final answer, never persisted, never added to long-lived context, and never sent to web search. Models without reasoning support degrade to a normal streamed answer with no fake "thinking" output.
- `sysai thinking on|off|status` to control the live reasoning display, backed by a single `thinking` config key (default `true`) that also controls whether reasoning is requested from Ollama at all.
- Ctrl+C now cancels an in-progress model generation (auto-analysis or `sysai ask`/`explain`) cleanly, without affecting the monitored Zsh session, without corrupting the terminal, and without stopping Ollama.
