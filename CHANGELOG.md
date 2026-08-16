# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-15

### Added

- PTY-backed interactive Zsh monitoring with `preexec` and `precmd` metadata.
- Automatic local Qwen diagnosis for unexpected non-zero command exits.
- Manual `sysai explain`, `sysai ask`, optional `sysai ask --web`, and graceful `sysai stop` commands.
- Bounded ephemeral context, output truncation, credential redaction, and a safety-focused system prompt.
- Ownership-aware native Ollama startup, model unload, and shutdown behavior.
- Standard-library test suite, live integration script, secure installer, and uninstaller.
- Live streamed model reasoning ("thinking") for automatic failure analysis, `sysai explain`, and `sysai ask`, using Ollama's native `stream`/`think` protocol. Reasoning is display-only: redacted and control-sanitized like the final answer, never persisted, never added to long-lived context, and never sent to web search. Models without reasoning support degrade to a normal streamed answer with no fake "thinking" output.
- `sysai thinking on|off|status` to control the live reasoning display, backed by a single `thinking` config key (default `true`) that also controls whether reasoning is requested from Ollama at all.
- Ctrl+C now cancels an in-progress model generation (auto-analysis or `sysai ask`/`explain`) cleanly, without affecting the monitored Zsh session, without corrupting the terminal, and without stopping Ollama.
