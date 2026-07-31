# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Codex, Copilot, and the rest)
working with Ares, a security agent that watches a Linux host and investigates
what looks wrong. This file has two audiences:

1. Agents helping a user integrate or deploy Ares into their own stack.
2. Agents contributing to the Ares codebase itself.

---

## 1. Helping someone integrate Ares

**What Ares is.** It records what processes, network connections, and files are
doing on a host. Cheap rules flag anything odd as it happens. Once a minute a
model reviews the recent activity and returns a verdict, along with responses
that stay gated behind policy.

**Key fact for integration.** Ares watches the host and its kernel, so the
user's backend can be written in anything: Python, Rust, Go, Node, Java. It
ships as a Python package (`pip install ares-agent`), so the packaging only
affects where you install it.

### The decision you should drive

Ask the user two things, then point them at the right recipe in [`docs/deploy/`](docs/deploy/README.md):

1. **How much of the host do they control?**
   - Full VM or their own K8s nodes → **host-level** deploy with eBPF
     ([`docs/deploy/kubernetes.md`](docs/deploy/kubernetes.md) DaemonSet,
     [`docs/deploy/fly-io.md`](docs/deploy/fly-io.md), [`docs/deployment.md`](docs/deployment.md) VM).
   - Managed container PaaS (Railway, Render, and the like) → **in-container
     companion** with the procfs fallback ([`docs/deploy/railway.md`](docs/deploy/railway.md),
     [`docs/deploy/docker.md`](docs/deploy/docker.md)).
2. **What language is their backend?**
   - Python → install `ares-agent` into the same image.
   - Anything else → run Ares as a **sidecar** and **share the PID namespace**
     (`shareProcessNamespace: true` in K8s, `pid: "service:app"` in Compose).
     On its own the sidecar only sees itself.

### Things to get right (common mistakes)

- **eBPF might not be available.** Managed PaaS usually can't load it, and Ares
  falls back to procfs on its own. Be honest with the user about that, and have
  them check `ares status`.
- **Both processes must run:** `ares daemon run` (collector) and
  `ares investigator run` (the minute cycle). In containers, background both from
  an entrypoint, then `exec` the app as PID 1.
- **Persist state:** point `ARES_STATE_DIR` (or `storage.path`) at a mounted
  volume so events, baselines, and the watermark survive redeploys.
- **Secrets come from the environment:** `OPENROUTER_API_KEY`,
  `OPENROUTER_MODEL`, `ARES_SLACK_WEBHOOK`, `ARES_PAGERDUTY_ROUTING_KEY`,
  `ARES_SMTP_*`. See [`examples/ares.env.example`](examples/ares.env.example).
- **OpenRouter is the default provider**, and it takes any model through env
  vars. It also supports `openai`, `anthropic`, and a no-key `local` mode. When
  creds are missing, Ares falls back to `local` and keeps running.

### Verify an integration

```bash
ares status          # sensors active, AI provider, notification channels
ares notify test     # sends a synthetic alert through every configured channel
ares doctor          # storage + integrity checks
```

### Safety limits

- Keep destructive response actions behind approval. `delete_file` and
  `execute_generated_shell_command` are prohibited by design.
- Keep real secrets out of `config.yaml`, commits, issues, and logs.
- Raw host telemetry should stay away from the model. Ares redacts and
  summarizes before anything gets sent.

---

## 2. Contributing to the Ares codebase

### Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,fs]"
export ARES_STATE_DIR="$HOME/.ares"   # dev state dir, no root needed
```

Ares runs on macOS for development through the procfs/psutil fallback. eBPF and
systemd only work on Linux.

### Commands (see the Makefile)

```bash
make test     # pytest
make lint     # ruff check
make format   # ruff format + ruff check --fix
make build    # python -m build && twine check dist/*
make check    # lint + test (what CI gates on)
```

Everything must pass `ruff check`, `ruff format --check`, and `pytest` before a
PR. CI runs on Python 3.10 to 3.13 (Ubuntu) plus 3.12 (macOS).

### Architecture map

| Area | Module | Spec |
| ---- | ------ | ---- |
| Continuous daemon | `src/ares/daemon/` | §6.1 |
| Sensors (eBPF + procfs/audit fallback) | `src/ares/sensors/` | §8 |
| Event schema | `src/ares/events/` | §9 |
| Redaction | `src/ares/redaction/` | §11 |
| Enrichment | `src/ares/enrichment/` | §10 |
| Detection rules | `src/ares/detection/` | §12 |
| Correlation | `src/ares/correlation/` | §16 |
| Baseline | `src/ares/baseline/` | §17 |
| Cases | `src/ares/cases/` | §18 |
| AI investigator + providers | `src/ares/investigator/` | §19 |
| Policy + response | `src/ares/policy/`, `src/ares/response/` | §22 |
| Notifications | `src/ares/notifications/` | §27 |
| Scheduler | `src/ares/scheduler/` | §15 |
| Storage (SQLite) | `src/ares/storage/` | §23 |
| CLI | `src/ares/cli/` | §29 |

Module docstrings cite spec section numbers (for example "spec §12"). Follow them.

### Extending

| To add… | Edit | Guide |
| ------- | ---- | ----- |
| A detection rule | `src/ares/detection/builtin.py` | [`docs/rule-authoring.md`](docs/rule-authoring.md) |
| A sensor | `src/ares/sensors/` | [`docs/architecture.md`](docs/architecture.md) |
| An AI provider | `src/ares/investigator/providers.py` | keep the local fallback |
| A notifier | `src/ares/notifications/channels.py` | push-only, fail soft |
| A response action | `src/ares/response/actions.py` | [`docs/security-model.md`](docs/security-model.md) |

Every change in behaviour needs a test. Use `tests/fixtures/factory.py` to build
event sequences. Attack simulations live in `tests/simulations/` and use
controlled fixtures only.

### Conventions

- Match the surrounding code's style, comment density, and spec-citation idiom.
- Rules and providers must fail soft. If a rule breaks or a model is unavailable,
  log it and carry on so the pipeline keeps running.
- Keep detection cheap. The expensive reasoning belongs in the investigator.

### Commit & PR rules

- Write plain, human commit messages with no AI or co-author attribution. Leave
  out `Co-Authored-By: Claude` and any similar trailer. This one is deliberate
  project policy.
- Conventional-ish messages preferred: `feat:`, `fix:`, `docs:`, `chore:`.
- Never commit secrets, tokens, or real host telemetry.
- CI must be green (lint, format, types, tests, build).

### Release (maintainers)

Bump `__version__` in `src/ares/__init__.py`, update `CHANGELOG.md`, then:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```

The Release workflow builds the package, verifies it, and publishes to PyPI via
Trusted Publishing with no tokens, then opens a GitHub Release with the artifacts
and their attestations.
