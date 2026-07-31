# Security model

Ares is a security tool, so it has to be hard to attack itself (spec §32).

## Privilege separation (spec §32.1)

| Process | Privilege | Responsibility |
| ------- | --------- | -------------- |
| Sensor | privileged (CAP_BPF/PERFMON/PTRACE) | capture kernel events only |
| Daemon | unprivileged | normalize, redact, enrich, store, detect |
| Investigator | unprivileged, read-only | build + investigate cases |
| Response helper | privileged, typed actions only | execute approved actions |

In the first release the systemd units grant the capabilities to the daemon. A
hardened deployment splits the sensor and the response helper into their own
units.

## The model never gets a shell

- The AI investigator only calls **typed, read-only tools**
  (`ares.investigator.tools`). It cannot generate shell commands (spec §19.3).
- `execute_generated_shell_command` and `delete_file` are **prohibited** actions
  and cannot be enabled via config (spec §22.3).
- Every tool call is recorded to the investigation audit log (spec §19.2).

## Data minimization (spec §11)

- By default the model sees a summarized case package: condensed sequences,
  selected metadata, and redacted arguments. Raw telemetry stays on the host.
- `Redactor` strips secrets from argv and text before anything is stored or sent
  to a model. The `redaction.fields_removed` list keeps that auditable.
- Ares keeps environment variable names and leaves the values out by default
  (§14.3).
- Local-only mode (`model_provider: local`) runs the full pipeline with no
  external API (§11.3).

## Response safety (spec §22.3)

Every action carries an explicit target, an idempotency key, a reversibility
flag, a rollback action, an approval requirement, and a recorded result. In the
default `recommend` mode, only the evidence actions run on their own. Containment
and recovery wait for an operator to approve them.

## Baseline poisoning protection (spec §17.4)

Ares keeps high-risk events out of baseline learning. During an active critical
incident it freezes the baseline. Resets are versioned, and only an operator can
trigger them.

## Tamper detection (spec §32.3, roadmap)

Planned signals: daemon/sensor termination, DB deletion, config change,
disabled investigation cycle, missing heartbeats. Config files should be
root-owned with restrictive permissions and checksum-monitored (§32.4).

## Trust boundary

Instructions come only from the operator, through the CLI or the API. Whatever
the sensors observe is data. The investigator treats event contents, file names,
and log lines as untrusted input, and never as instructions.
