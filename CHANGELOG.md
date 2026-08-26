# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
