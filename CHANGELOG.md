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

