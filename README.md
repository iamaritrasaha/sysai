# SysAI — Local Linux Intelligence

SysAI is a local Linux intelligence and diagnostic companion. It observes a real interactive Bash session, understands system evidence, investigates problems through bounded read-only diagnostics, correlates relevant Bash history, and remembers useful machine-specific experience — all locally.

**SysAI can inspect; it does not autonomously repair your system.**

- 🐧 Real interactive Bash — prompts, colors, readline, job control, sudo, TUIs
- 🔍 Deterministic, read-only diagnostics across eight system domains
- 🕘 History intelligence — relevant, sanitized, bounded — never a bulk dump
- 🧠 Local experience memory — durable machine facts, incidents, corrections
- 🔒 Local-first — multiple local models, optional remote providers, no cloud memory
- 🧩 Standard-library-only Python; no package dependencies

## Why SysAI?

Most terminal AI tools either paste your shell history into a prompt or bolt a chatbot onto your terminal. SysAI does neither. It watches your session the way a careful sysadmin would: noticing what failed, gathering only the evidence needed to explain it, remembering what turned out to matter, and always leaving the fix to you.

```console
$ sysai

           ████ █   █  ████   █   █████
          █     █   █ █      █ █    █
          █      █ █  █     █   █   █
           ███    █    ███  █   █   █
              █   █       █ █████   █
              █   █       █ █   █   █
          ████    █   ████  █   █ █████

             Local Linux Intelligence
  Bash  •  Diagnostics  •  Memory  •  Experience

✓ Ollama ready
✓ Bash monitoring active

$ sysai gpu
✓ Driver
  amdgpu
! Findings
  3 GPU timeout events in this boot
Assessment
  Further read-only diagnostics recommended.
```

The welcome and goodbye screens adapt to your terminal width and stay clean under `NO_COLOR`.

## What it can do

| Understand | Investigate | Learn from experience | Track change | Work safely |
| --- | --- | --- | --- | --- |
| `health`, `doctor` | `explain`, `investigate` | `history` | `changes` | `what` |
| `gpu`, `memory`, `disk` | `check "..."` | `memories` | `baseline` | `report` |
| `network`, `boot` | Command Insight (`dmesg`, ...) | `remember "..."` | | `update check` |
| `services`, `packages`, `thermal` | `watch` | `feedback`, `context` | | |

| Command | What it does |
| --- | --- |
| `sysai` | Start the Bash session SysAI supervises |
| `sysai health` / `sysai gpu` \| `memory` \| `disk` \| `network` \| `boot` \| `services` \| `packages` \| `thermal` | Diagnose everything, or one domain |
| `sysai doctor` | Diagnose SysAI's own installation |
| `sysai check "why is my PC slow?"` | Plain-language question, routed automatically |
| `sysai investigate` | Gather more evidence, then explain the last failure |
| `sysai history` / `sysai memories` | Relevant recent activity / local experience memory |
| `sysai what "sudo apt autoremove"` | Explain a command — never runs it |
| `sysai report` / `sysai baseline` | Sanitized report / deterministic snapshot & diff |
| `sysai changes` | What changed on this machine, and when |
| `sysai watch gpu` | Bounded foreground sampling |
| `sysai update check` | Check for a verified SysAI release |
| `sysai stop` | End the session cleanly |
| `sysai --model [MODEL]` | Select a discovered model for this launch (interactive when omitted) |
| `sysai models` / `sysai models use MODEL` | List models/providers / save the default |
| `sysai models add` / `sysai models remove ID` | Configure or remove a provider profile |
| `sysai dmesg`, `sysai --web dmesg` | Command Insight: inspect an allowlisted read-only command |

Run `sysai --help` or `sysai <command> --help` for full options.

## Quick start

```sh
git clone https://github.com/iamaritrasaha/sysai.git
cd sysai
./install.sh
sysai
```

Requires Linux, Bash 5.x, Python 3.11+, and [Ollama](https://ollama.com) with a local model installed. Local Ollama models are discovered automatically and local is the default. SysAI also supports configured remote Ollama servers and generic OpenAI-compatible APIs: use `sysai models add`, then `sysai --model` or `sysai models use <id>`. Remote use requires explicit endpoint/API-key-environment configuration and consent; privacy controls run before remote requests, and history and memory remain local.

```sh
sysai health
sysai check "why is my internet flaky?"
sysai memories search "GPU"
sysai baseline create
```

## How it works

```text
Bash session
     ↓
System evidence
     +
Relevant history        ← recent operational context, bounded & sanitized
     +
Local experience        ← durable memory: facts, incidents, corrections
     ↓
Read-only diagnostics    ← audited action IDs only, never raw commands
     ↓
Local reasoning
     ↓
Assessment
     ↓
Human-reviewed action
```

**History is not memory.** History is what just happened; memory is what SysAI has learned persists. Neither is sent to web search — history is locally filtered and sanitized before it ever reaches the model, and memory never leaves your machine unless you explicitly ask for a report.

## Safety & privacy

- Bash runs for real; SysAI observes it — it never parses or replaces your shell.
- Model output is advice only. It is never executed, and no memory or history entry can become a command.
- Diagnostics use a fixed, audited catalogue of read-only actions; privileged checks require your explicit one-time approval.
- Repairs are recommendations you run yourself — SysAI never applies one.
- Web research is off by default, explicit when used, and never carries raw history, logs, or memory.
- Reports and baselines are written only when you ask, always sanitized, always mode `0600`.

Full guarantees, threat model, and vulnerability reporting: [SECURITY.md](SECURITY.md).

## Configuration

Edit `~/.config/sysai/config.toml` (defaults in [`config/default.toml`](config/default.toml)):

```toml
provider = "ollama"
model = "qwen3:8b"
model_endpoint = ""
api_key_env = "SYSAI_API_KEY"
web_enabled = false
history_enabled = true
history_mode = "relevant"      # off | relevant | recent | all
history_lookback_hours = 48
```

`sysai thinking on|off` toggles the live reasoning display without editing the file.

## Documentation

- [SECURITY.md](SECURITY.md) — privacy model, threat boundaries, vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and architectural rules
- [CHANGELOG.md](CHANGELOG.md) — release history

## License

[MIT](LICENSE) © 2026 Aritra Saha and contributors
