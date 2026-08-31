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

## History intelligence

Bash history is treated as untrusted, sensitive data, not as free-form model input. `sysai history`, every diagnostic command that calls `sysai investigate`, `sysai health`, a domain command, `sysai check`, `sysai changes`, `sysai baseline compare`, or `sysai watch` internally, `sysai ask`, Command Insight Mode, and automatic failure analysis may correlate recent activity with the current evidence — but this never means "send the shell history to the model" in bulk. Bash history is read from a bounded tail of the resolved `HISTFILE` (or `~/.bash_history`), parsed as inert text — **it is never executed and never interpreted as shell syntax, here or anywhere downstream** — redacted, sanitized through the same privacy layer as everything else, scored deterministically against the current diagnostic domain (temporal proximity, domain vocabulary, privilege, exit status — word-boundary matched, so `apt` never matches inside `laptop`), and only a small top-N slice — labelled `HISTORICAL / CORRELATION ONLY` in the evidence document or prompt — is ever included. Ordering in time is never presented as causation.

`sysai ask` and automatic failure analysis only consult history/memory when the question or the failed command matches a recognizable diagnostic domain; a trivial question or an unrecognized program triggers no lookup at all. Command Insight attaches history/memory only after its own evidence reduction, and the web-research query builder reads only normalized finding labels — never the `history_correlation`/`prior_experience` content — so history is never sent to web search, in raw or sanitized form. `history_mode = "off"` in `config.toml` disables the feature entirely. Reading history or querying memory happens only for these explicit diagnostic/question/failure paths, never for an ordinary successful completed shell command.

## Memory (experience store)

`memory.py` is a local, structured store of durable facts, incidents, patterns, outcomes, and corrections about this machine, at `$XDG_STATE_HOME/sysai/memory.db` (mode `0600`, directory mode `0700`), read back as bounded `PRIOR EXPERIENCE` context (at most five records) for future diagnoses. It never stores raw logs, terminal transcripts, or model reasoning; every string is redacted and sanitized before being written. Automatic writes happen only from a `CONFIRMED` `critical`/`warning` finding that Python's deterministic collectors already computed — never from free model text — and a repeated finding reinforces the existing record instead of duplicating it. Explicit memory (`sysai remember "..."`, `sysai feedback ...`) is user-sourced and marked as such. Memory is data: nothing in `memory.py` executes a stored string, no memory can supply an action ID, argv, or path to the audited diagnostic engine, and a memory record can never become shell input. Memory is never sent to web search. There is no optional Mem0 or other network dependency; SysAI ships one local, dependency-free backend, and the memory interface is designed so another local backend could be added later without changing callers.

## Persistence

SysAI is otherwise memory-only by default. Recent command context, captured output, model reasoning, and watch samples exist only in bounded process memory. SysAI never writes a shell-history copy, a command transcript, reasoning text, raw health logs, or retained telemetry. The only files it writes are the config file, the private env file you create, an explicit baseline, an explicit report, the local memory database described above, and per-session runtime state in a mode-`0700` user-owned directory.

Secret redaction is defense in depth and cannot recognize every possible credential format. Avoid printing secrets in terminal sessions and revoke any credential that may have been exposed.
