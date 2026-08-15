# Security Policy

## Supported versions

Security fixes are provided for the latest released version of SysAI.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature rather than opening a public issue. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation. Do not include real credentials or private terminal transcripts.

If private reporting is unavailable, open a minimal issue asking the maintainers for a private contact channel without disclosing exploit details.

## Security boundary

SysAI displays model advice but never executes model-generated commands. The user remains responsible for reviewing and manually running suggestions. Terminal content is processed locally by default; explicit web searches send only a sanitized query to the configured provider.

Secret redaction is defense in depth and cannot recognize every possible credential format. Avoid printing secrets in terminal sessions and revoke any credential that may have been exposed.

