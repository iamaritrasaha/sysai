# Contributing

Contributions are welcome through issues and pull requests.

## Development setup

SysAI requires Linux, Python 3.11 or newer, and Bash 5.x. Unit tests do not require Ollama, a GPU, ROCm, an account, or API keys.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
sh -n bin/sysai install.sh uninstall.sh scripts/manual-integration-test.sh
bash -n src/sysai/integration.bash
```

Run `scripts/manual-integration-test.sh` separately when a local Ollama server and the configured model are available.

## Diagnostic layering

New diagnostics belong in the shared engine, not in a new one-off collector:

- `collect.py` holds read-only primitives. Every process starts from a fixed argv resolved through `shutil.which` — no shell, no `bash -c`, no string interpolation of user or model text.
- `domains.py` holds per-domain collectors and the findings they support. A domain returns `(sections, unavailable)`; anything that could not run becomes an `unavailable` entry (NOT CHECKED), never an invented failure.
- `evidence.py` defines the one document shape every diagnostic produces, and `privacy.py` is the one sanitization layer. Do not add a second redactor.
- `diagnostics.py` owns the audited action catalogue. A new follow-up diagnostic is a new fixed argv entry with a purpose, timeout, and output limit — never a way for the model to supply a command.
- `render.py` prints deterministic facts directly; `AnswerRenderer` is for model prose only.

Findings are computed in Python. If a fact can be calculated, calculate it rather than asking the model to infer it.

## History and memory

`history.py` (relevance-filtered, privacy-sanitized recent activity) and `memory.py` (local structured experience) are the two shared layers for anything involving Bash history or durable machine facts. New behavior that touches either belongs there, not in a new one-off implementation:

- History is data, never executed and never interpreted as shell syntax; a change here must never add a way for a history entry to reach a shell.
- Memory writes go through `memory.py`'s narrow functions (`remember`, `record_incident`, `record_outcome`, ...), never free-form model text turned directly into a stored record.
- Both stay bounded (safety limits apply regardless of mode) and privacy-sanitized before persistence or use as model context, reusing `privacy.py` rather than a new redactor.
- Anything reaching a prompt or evidence document from history or memory must stay clearly labelled (`HISTORICAL / CORRELATION ONLY`, `PRIOR EXPERIENCE`) and must never be presented as causation.
- An ordinary, successful completed shell command must never touch the history file or the memory database — only an explicit diagnostic command, question, or qualifying failure does. Preserve this in any new call site.

Keep changes focused, add tests for behavior changes, and never add captured transcripts, credentials, local configuration, or runtime state. Changes must preserve the rule that model output is advice only and is never executed, that SysAI applies no repairs autonomously, that history/memory content can never supply an action ID or argv, that SysAI stays local-first with no cloud dependency for memory, and that nothing is written to disk unless the user asked for it.
