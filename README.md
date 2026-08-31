# SysAI — Local Linux Intelligence

SysAI is a Bash-native Linux intelligence and diagnostic environment. It
inspects system evidence, correlates relevant history, remembers local
incidents, investigates failures, and explains what it finds through a model
you choose at startup.

It provides:

- deterministic, read-only diagnostics, health, doctor, and investigation
- safe Command Insight for allowlisted commands
- bounded Bash-history correlation and local experience memory
- startup selection for local Ollama, remote Ollama, hosted Ollama models,
  and optional compatible remote APIs
- explicit remote consent, shared privacy filtering, and no provider fallback

## Quick start

```sh
./install.sh
sysai
```

The startup screen discovers available models, marks the saved default, and
lets Enter accept it. With one model, Enter continues immediately.

```text
SysAI
Local Linux Intelligence

Select a model

LOCAL
  1. ✓ qwen3:8b
      Ollama · Local

Select [1]:
```

Use `sysai --model` to reopen the selector or `sysai --model MODEL` for a
non-interactive launch. Local Ollama is the default. Configure additional
remote entries with `sysai models add`; keys are represented only by their
environment-variable names. Remote/cloud models are never selected or used
without explicit consent.

Provider setup is provider-aware: local Ollama needs no form, hosted Ollama
uses its supported authentication/discovery, remote Ollama asks for an
endpoint and only asks for credentials after an authentication challenge,
and compatible APIs ask for the fields they need.

## Everyday commands

```sh
sysai health
sysai check "why is my network slow?"
sysai investigate
sysai dmesg
sysai watch gpu
sysai what "sudo apt autoremove"
```

Advanced configuration inspection is available through `sysai models`.
Useful local data commands include `sysai history`, `sysai memories`,
`sysai remember`, `sysai baseline`, and `sysai report`.

## Safety and privacy

SysAI supervises a real interactive Bash session but never executes model
output. Diagnostics use fixed audited action IDs; privileged read-only checks
require approval. Remote requests pass through the existing shared privacy
layer. Raw Bash history, raw memory, credentials, tokens, private identifiers,
and unsanitized logs do not leave the machine. History and memory remain local.

The terminal welcome and exit screens adapt to width and respect `NO_COLOR`.
SysAI requires Linux, Bash 5.x, Python 3.11+, and Ollama for local models.

See [SECURITY.md](SECURITY.md) for the threat model and [CONTRIBUTING.md](CONTRIBUTING.md)
for development guidance.

## Configuration

Settings live in `~/.config/sysai/config.toml`; provider profiles are managed
there by SysAI and written with restrictive permissions. API keys are read
from environment variables, never stored in configuration.

```toml
provider = "ollama"
model = "qwen3:8b"
ollama_url = "http://127.0.0.1:11434"
api_key_env = "SYSAI_API_KEY"
```

## License

[MIT](LICENSE) © 2026 Aritra Saha and contributors
