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

Keep changes focused, add tests for behavior changes, and never add captured transcripts, credentials, local configuration, or runtime state. Changes must preserve the rule that model output is advice only and is never executed, that SysAI applies no repairs autonomously, and that nothing is written to disk unless the user asked for it.
