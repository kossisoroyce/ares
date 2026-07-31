# Security Policy

Ares is a security tool, so we hold its own security to a high bar.

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Report privately via GitHub Security Advisories:
<https://github.com/kossisoroyce/ares/security/advisories/new>

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept if possible).
- Affected version(s) and environment.

We aim to acknowledge reports within **72 hours** and to provide a remediation
timeline after triage. Coordinated disclosure is appreciated; we will credit
reporters who wish to be named.

## Scope

In scope:

- The `ares-agent` package and its components (daemon, sensors, investigator,
  response engine, notifications, storage).
- Privilege-escalation, secret-leakage, or injection issues in Ares itself.
- Weaknesses that let an attacker evade detection by exploiting Ares' own logic
  (e.g. baseline poisoning beyond documented limits, redaction bypass).

Out of scope:

- Vulnerabilities in third-party models/providers reached via OpenRouter/OpenAI.
- Findings that require pre-existing root on the monitored host.

## Handling of sensitive data

- Ares does **not** send raw telemetry to AI providers by default; case packages
  are summarized and secret-redacted (see [docs/security-model.md](docs/security-model.md)).
- Secrets (API keys, webhooks, SMTP/PagerDuty credentials) are read from the
  environment, never stored in the repository or config by default.
- The language model never receives shell access; `execute_generated_shell_command`
  and `delete_file` are prohibited actions and cannot be enabled via config.

## Supported versions

Until 1.0, security fixes are applied to the latest released version.
