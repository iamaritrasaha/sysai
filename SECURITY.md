# Security Policy

## Supported versions

Security fixes are provided for the latest released version of SysAI.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature rather than opening a public issue. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation. Do not include real credentials or private terminal transcripts.

If private reporting is unavailable, open a minimal issue asking the maintainers for a private contact channel without disclosing exploit details.

## Security boundary

SysAI supervises a real interactive Bash started with fixed argv (`bash --rcfile <temporary-file> -i`) and a resolved Bash path; it never launches the user's arbitrary `$SHELL`, never uses `bash -c`, `eval`, `shell=True`, or `os.system`, and never parses or re-executes shell text itself. Shell text the user types is interpreted only by that Bash process, and observed command text is data. The session-only rcfile and monitoring hooks are removed when the session ends; `~/.bashrc`, `~/.profile`, and `~/.bash_profile` are never modified. SysAI takes over the Bash `DEBUG` trap for the session and reports any trap it replaces rather than replacing it silently, because re-running a saved trap body would require evaluating stored shell text.

SysAI displays model advice but never executes model-generated commands. The user remains responsible for reviewing and manually running suggestions. Terminal content is processed locally by default; explicit web searches send only a sanitized query to the configured provider.

`sysai health` runs an audited allowlist of fixed, read-only diagnostics with argv execution, no shell, and bounded output/timeouts. It never executes a model-proposed command or repair. Additional elevated read-only actions require explicit one-time approval; rejection performs no privileged execution. Optional health web research receives only generic sanitized issue labels; it never receives local logs, terminal output, hostnames, paths, usernames, addresses, hardware identifiers, or model reasoning.

Adaptive diagnostic actions have fixed IDs, fixed argv builders, strict collector-derived parameter validation, per-action timeouts/output limits, duplicate suppression, and at most three follow-up rounds. One-time consent is required for elevated read-only access. The CLI independently revalidates privileged action messages before execution. Model text and thinking can never supply executable argv or authorize an action.

Command Insight Mode executes only the user-provided argv after a fixed read-only policy check. It does not interpret shell syntax; captured output stays local by default. Web queries are derived only from normalized command family and finding kinds, never raw output. Online results are labelled untrusted and cannot establish local system state.

When enabled, SysAI streams the model's reasoning ("thinking") live alongside its answer. Reasoning is display-only: it goes through the same redaction and terminal-control-sequence sanitization as the final answer, is never persisted to disk, is never added to SysAI's short-lived conversation context, and is never sent to web search. It can never be interpreted as a command or fed back into the monitored shell. Reasoning is real model output, not a scripted narration, and like the final answer it can be wrong.

Secret redaction is defense in depth and cannot recognize every possible credential format. Avoid printing secrets in terminal sessions and revoke any credential that may have been exposed.
