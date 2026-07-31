# Security model

The security product must itself be hardened (spec §32).

## Privilege separation (spec §32.1)

| Process | Privilege | Responsibility |
| ------- | --------- | -------------- |
| Sensor | privileged (CAP_BPF/PERFMON/PTRACE) | capture kernel events only |
| Daemon | unprivileged | normalize, redact, enrich, store, detect |
| Investigator | unprivileged, read-only | build + investigate cases |
| Response helper | privileged, typed actions only | execute approved actions |

The systemd units grant capabilities to the daemon in the first release; a
hardened deployment splits the sensor and response helper into their own units.

## The model never gets a shell

- The AI investigator only calls **typed, read-only tools**
  (`ares.investigator.tools`). It cannot generate shell commands (spec §19.3).
- `execute_generated_shell_command` and `delete_file` are **prohibited** actions
  and cannot be enabled via config (spec §22.3).
- Every tool call is recorded to the investigation audit log (spec §19.2).

## Data minimization (spec §11)

- Raw telemetry is **not** sent to the model by default. The case package
  contains summarized sequences, selected metadata and redacted arguments.
- `Redactor` strips secrets from argv and text before storage/model use;
  `redaction.fields_removed` keeps it auditable.
- Environment variable **values** are excluded by default — names only (§14.3).
- Local-only mode (`model_provider: local`) runs the full pipeline with no
  external API (§11.3).

## Response safety (spec §22.3)

Every action carries: explicit target, idempotency key, reversibility flag,
rollback action, approval requirement, and a recorded result. Default mode
`recommend` executes only evidence actions automatically; containment/recovery
wait for operator approval.

## Baseline poisoning protection (spec §17.4)

High-risk events are excluded from baseline learning; the baseline is frozen
during an active critical incident; resets are versioned and operator-driven.

## Tamper detection (spec §32.3) — roadmap

Planned signals: daemon/sensor termination, DB deletion, config change,
disabled investigation cycle, missing heartbeats. Config files should be
root-owned with restrictive permissions and checksum-monitored (§32.4).

## Trust boundary

Instructions come only from the operator (CLI/API). Everything observed through
sensors is **data, not commands** — the investigator treats event contents,
file names and log lines as untrusted input.
