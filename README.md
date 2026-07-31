<h1 align="center">Ares</h1>

<p align="center">
  <strong>AI-native host security investigator for Linux.</strong><br>
  Continuous eBPF telemetry with minute-by-minute AI investigation.
</p>

<p align="center">
  <a href="https://github.com/kossisoroyce/ares/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/kossisoroyce/ares/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/ares-agent/"><img alt="PyPI" src="https://img.shields.io/pypi/v/ares-agent.svg"></a>
  <a href="https://pypi.org/project/ares-agent/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/ares-agent.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://github.com/astral-sh/ruff"><img alt="Ruff" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json"></a>
</p>

> An AI-native host investigation and response layer for production Linux infrastructure.

Ares continuously records process, network, filesystem, identity and
persistence events, runs deterministic detection in real time, and every minute
runs an AI investigation cycle that reconstructs suspicious activity into an
evidence-backed verdict.

The design principle (spec §1):

> The daemon records what happened. The detection engine decides what deserves
> attention. The AI investigator determines what the evidence means.

## Architecture

```
kernel/OS ──► sensors ──► redaction + enrichment ──► SQLite store
                                     │
                          streaming detector ──► immediate critical path
                                     │                 (evidence capture)
                                     ▼
              one-minute scheduler ──► correlation ──► cases ──► AI investigator
                                     │
                          policy + response ──► notifications / approved actions
```

| Layer | Module | Spec |
| ----- | ------ | ---- |
| Continuous daemon | `ares.daemon` | §6.1 |
| Sensors (eBPF + procfs/psutil fallback) | `ares.sensors` | §8 |
| Event schema | `ares.events` | §9 |
| Redaction | `ares.redaction` | §11 |
| Enrichment | `ares.enrichment` | §10 |
| Streaming detection | `ares.detection` | §12 |
| Correlation | `ares.correlation` | §16 |
| Baseline | `ares.baseline` | §17 |
| Cases | `ares.cases` | §18 |
| AI investigator | `ares.investigator` | §19 |
| Policy + response | `ares.policy`, `ares.response` | §22 |
| Scheduler | `ares.scheduler` | §15 |
| Storage | `ares.storage` | §23 |
| CLI | `ares.cli` | §29 |

## Platform support

The first release targets Linux (Ubuntu/Debian/Amazon Linux/Rocky/Alma). The
sensor layer is abstracted: eBPF is preferred on Linux, with an automatic
procfs/psutil/inotify fallback (spec §8.2) that also lets the full pipeline run
on macOS for development.

## Install

```bash
pip install -e ".[dev,fs]"       # from source
```

Optional extras: `ai` (Anthropic-native provider), `api` (local HTTP API),
`fs` (watchdog filesystem watcher). The OpenAI SDK (used for OpenRouter) is a
core dependency.

## Quick start (dev, no root)

```bash
export ARES_STATE_DIR="$HOME/.ares"      # dev state dir
ares init
ares daemon run            # terminal 1: collect + detect
ares investigator run      # terminal 2: one-minute investigation cycle
ares status
ares cases list
```

## AI investigation (OpenRouter by default)

The default provider is **OpenRouter**, so you can run *any* model with two
environment variables — no code or config changes:

```bash
export OPENROUTER_API_KEY=sk-or-...
export OPENROUTER_MODEL=anthropic/claude-3.5-sonnet   # any OpenRouter model id
```

Other backends (set `investigation.model_provider` to match):

| Provider | Env vars |
| -------- | -------- |
| `openrouter` (default) | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |
| `openai` / self-hosted gateway | `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL` |
| `anthropic` | `ANTHROPIC_API_KEY` (`pip install -e ".[ai]"`) |
| `local` | none — deterministic, no external model (spec §11.3) |

If no credentials are present the investigator automatically **falls back to
`local`**, so a fresh install runs with zero configuration and lights up the
moment you set the env vars. Secrets are read from the environment, never stored
in config. See [`examples/ares.env.example`](examples/ares.env.example).

## Notifications

Ares pushes incidents out over **outbound-only** channels — nothing inbound has
to be exposed on the host. Configure any subset via env vars:

```bash
export ARES_NOTIFY_MIN_SEVERITY=high                    # global floor
export ARES_SLACK_WEBHOOK=https://hooks.slack.com/...   # recommended default
export ARES_PAGERDUTY_ROUTING_KEY=...                   # pages on-call (critical)
export ARES_NOTIFY_WEBHOOK=https://ops.internal/ares    # route anywhere
export ARES_SMTP_HOST=smtp.example.com ARES_SMTP_TO=secops@example.com  # email
```

```bash
ares notify channels     # show what's active
ares notify test         # send a test alert through every channel
```

| Channel | Best for | Threshold |
| ------- | -------- | --------- |
| Slack | team visibility, rich formatting | global `min_severity` |
| Generic webhook | routing into your own tooling | global `min_severity` |
| Email / SMTP | universal fallback | global `min_severity` |
| PagerDuty | waking on-call for real incidents | own `min_severity` (default `critical`) |

Alert fatigue is controlled by the global severity floor, PagerDuty's separate
higher threshold, and case deduplication (repeat activity updates one case /
one PagerDuty incident rather than paging repeatedly).

## Response safety

- Default mode is `recommend`: nothing destructive runs automatically.
- Only allow-listed **evidence** actions (hash/capture/preserve) run without
  approval. Containment/recovery actions require explicit operator approval and
  carry rollback metadata (spec §22.3).
- `delete_file` and `execute_generated_shell_command` are **prohibited**; the
  language model never receives shell access (spec §22.3).

## Python API

```python
from ares import Ares

client = Ares.from_config("examples/config.yaml")
print(client.status())
for case in client.cases.list(status="open"):
    print(case["title"], case["risk_score"])
```

## Testing

```bash
pytest            # unit + integration + attack simulations (safe fixtures)
```

## Status

This repository implements Phase 1 and the core of Phase 2 (spec §36). The
eBPF programs (`bpf/`) and privileged response helper are Linux integration
steps; see `docs/` for the roadmap and security model.

Licensed under Apache-2.0.
