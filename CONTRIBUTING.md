# Contributing

Contributions are welcome through issues and pull requests.

## Development setup

SysAI requires Linux, Python 3.11 or newer, and Zsh. Unit tests do not require Ollama, a GPU, ROCm, an account, or API keys.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
sh -n bin/sysai install.sh uninstall.sh scripts/manual-integration-test.sh
zsh -n src/sysai/integration.zsh
```

Run `scripts/manual-integration-test.sh` separately when a local Ollama server and the configured model are available.

Keep changes focused, add tests for behavior changes, and never add captured transcripts, credentials, local configuration, or runtime state. Changes must preserve the rule that model output is advice only and is never executed.

