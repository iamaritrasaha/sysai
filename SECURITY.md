# Security Policy

## Supported versions

Security fixes are provided for the latest released version of SysAI.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature rather than opening a public issue. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation. Do not include real credentials or private terminal transcripts.

If private reporting is unavailable, open a minimal issue asking the maintainers for a private contact channel without disclosing exploit details.

## Security boundary

SysAI supervises a real interactive Bash started with fixed argv (`bash --rcfile <temporary-file> -i`) and a resolved Bash path; it never launches the user's arbitrary `$SHELL`, never uses `bash -c`, `eval`, `shell=True`, or `os.system`, and never parses or re-executes shell text itself. Shell text the user types is interpreted only by that Bash process, and observed command text is data. The session-only rcfile and monitoring hooks are removed when the session ends; `~/.bashrc`, `~/.profile`, and `~/.bash_profile` are never modified. SysAI takes over the Bash `DEBUG` trap for the session and reports any trap it replaces rather than replacing it silently, because re-running a saved trap body would require evaluating stored shell text.

SysAI displays model advice but never executes model-generated commands. The user remains responsible for reviewing and manually running suggestions. Terminal content is processed locally by default; explicit web searches send only a sanitized query to the configured provider.

## Diagnostic engine

SysAI has three layers, and they are not interchangeable:

```text
deterministic collectors  →  audited diagnostic engine  →  local model reasoning
```

Collectors run fixed argv resolved through `shutil.which`, with no shell, no `bash -c`, no `eval`, and bounded timeouts and output. Findings — severity, counts, thresholds, classification — are computed in Python. The local model explains the resulting evidence; it never derives a deterministic fact, contributes a finding, or supplies an executable command.

The model may request additional evidence by **action ID only**. Every ID maps to a fixed argv builder in an internal table; parameters must both match a strict pattern and appear in the collector-derived trusted inventory. Unknown IDs, unexpected parameters, and untrusted values are rejected. Model text is never used as argv, and the CLI independently revalidates any privileged action message before execution.

No mutating action exists in the catalogue. Services are never restarted, enabled, disabled, or masked; packages are never installed, upgraded, removed, or purged; `fsck` and `mkfs` are never run. Elevated read-only actions such as SMART inspection require an explicit one-time approval, and refusal performs no privileged execution.

`sysai check` routes a plain-language question to one approved scope. Routing is deterministic keyword matching first; a model classification is accepted only when it matches a strict enum, and anything else falls back to a full-system scan. The model cannot name a diagnostic that does not exist.

`sysai what` never executes. It tokenizes the supplied text with `shlex` for analysis and display only; the module imports no process-spawning library and calls no `eval`, `exec`, or `os.system`. A hostile command string remains inert data.

`sysai watch` is foreground and bounded: 300 seconds maximum, minimum one-second interval, Ctrl+C stops cleanly. There is no daemon, background service, timer, or startup unit, samples are held in memory only and discarded after the summary, and the model is called exactly once after sampling finishes. With `--web`, a single sanitized research pass runs after sampling, never during it.

`sysai update` updates SysAI only. It never runs `apt upgrade`, never updates the operating system, Ollama, or the local model, never pulls from a branch, and never pipes a download into a shell. An automatic update proceeds only when the release publishes both an artifact and a checksum manifest, the download's SHA-256 matches the manifest entry for that exact filename, and the archive contains no path-traversal or link entries. Otherwise SysAI refuses and prints manual instructions. A development checkout is never updated in place.

Adaptive diagnostic actions have per-action timeouts and output limits, duplicate suppression, and at most three follow-up rounds. Model text and thinking can never supply executable argv or authorize an action.

Command Insight Mode executes only the user-provided argv after a fixed read-only policy check. It does not interpret shell syntax; captured output stays local by default. Web queries are derived only from normalized command family and finding kinds, never raw output. Online results are labelled untrusted and cannot establish local system state.

## Privacy layer

One sanitization implementation serves every structured diagnostic, at two levels. Local on-screen output removes secrets: authorization headers, bearer tokens, API keys, secret assignments and CLI arguments, and private-key blocks. Anything written to disk or sent to a search provider additionally removes usernames, home paths, hostnames (including the syslog hostname field of journal lines), IP and MAC addresses, serial-number fields, and UUIDs. Log timestamps and PCI addresses are deliberately preserved: they are useful evidence and identify nobody.

Reports and baselines always use the strict level. Reports print to the terminal unless `--output` names a path, and any file SysAI writes is created atomically with mode `0600`. Baselines contain only deterministic sanitized facts — never terminal history, model reasoning, raw `dmesg` or journal text, secrets, addresses, MACs, or serials.

Web research receives only generic issue labels derived from finding identifiers and normalized system facts. Raw telemetry, evidence values, terminal output, paths, hostnames, addresses, hardware identifiers, and model reasoning are never sent. Online results are labelled secondary and untrusted and cannot establish local system state.

When enabled, SysAI streams the model's reasoning ("thinking") live alongside its answer. Reasoning is display-only: it goes through the same redaction and terminal-control-sequence sanitization as the final answer, is never persisted to disk, is never added to SysAI's short-lived conversation context, and is never sent to web search. It can never be interpreted as a command or fed back into the monitored shell. Reasoning is real model output, not a scripted narration, and like the final answer it can be wrong.

## Persistence

SysAI is memory-only by default. Recent command context, captured output, diagnostic evidence, model reasoning, and watch samples exist only in bounded process memory. SysAI never writes a shell-history copy, a command transcript, reasoning text, raw health logs, or retained telemetry. The only files it writes are the config file, the private env file you create, an explicit baseline, an explicit report, and per-session runtime state in a mode-`0700` user-owned directory.

Secret redaction is defense in depth and cannot recognize every possible credential format. Avoid printing secrets in terminal sessions and revoke any credential that may have been exposed.
