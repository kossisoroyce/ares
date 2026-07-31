# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Codex, Copilot, etc.) working
with **Ares** — an AI-native host security investigator for Linux. This file has
two audiences:

1. Agents **helping a user integrate/deploy Ares** into their own stack.
2. Agents **contributing to the Ares codebase** itself.

---

## 1. Helping someone integrate Ares

**What Ares is:** a lightweight agent that continuously records process, network,
and filesystem activity on a host, runs deterministic detection in real time, and
every minute runs an AI investigation cycle that turns suspicious activity into an
evidence-backed verdict with recommended, policy-gated responses.

**Key fact for integration:** Ares is **language-agnostic** — it watches the
host/kernel, not the app. A user's backend can be Python, Rust, Go, Node, Java,
etc. Ares is shipped as a **Python package** (`pip install ares-agent`), which
affects *where* it runs, not *what* it monitors.

### The decision you should drive

Ask the user two things, then point them at the right recipe in [`docs/deploy/`](docs/deploy/README.md):

1. **How much of the host do they control?**
   - Full VM / their own K8s nodes → **host-level** deploy with eBPF
     ([`docs/deploy/kubernetes.md`](docs/deploy/kubernetes.md) DaemonSet,
     [`docs/deploy/fly-io.md`](docs/deploy/fly-io.md), [`docs/deployment.md`](docs/deployment.md) VM).
   - Managed container PaaS (Railway/Render/etc.) → **in-container companion**
     with the procfs fallback ([`docs/deploy/railway.md`](docs/deploy/railway.md),
     [`docs/deploy/docker.md`](docs/deploy/docker.md)).
2. **What language is their backend?**
   - Python → install `ares-agent` into the same image.
   - Anything else → run Ares as a **sidecar** and **share the PID namespace**
     (`shareProcessNamespace: true` in K8s, `pid: "service:app"` in Compose),
     otherwise Ares only sees itself.

### Things to get right (common mistakes)

- **eBPF is not guaranteed.** Managed PaaS usually can't load eBPF; Ares falls
  back to procfs automatically. Set expectations — don't promise kernel-level
  capture where it can't run. Tell users to check `ares status`.
- **Both processes must run:** `ares daemon run` (collector) **and**
  `ares investigator run` (the minute cycle). In containers, background both from
  an entrypoint, then `exec` the app as PID 1.
- **Persist state:** point `ARES_STATE_DIR` (or `storage.path`) at a mounted
  volume so events/baselines/watermark survive redeploys.
- **Secrets via env, never in config files:** `OPENROUTER_API_KEY`,
  `OPENROUTER_MODEL`, `ARES_SLACK_WEBHOOK`, `ARES_PAGERDUTY_ROUTING_KEY`,
  `ARES_SMTP_*`. See [`examples/ares.env.example`](examples/ares.env.example).
- **Default AI provider is OpenRouter** (any model via env). Also supports
  `openai`, `anthropic`, and a no-key `local` mode. Missing creds → auto-fallback
  to `local`; never hard-fail the pipeline over a missing key.

### Verify an integration

```bash
ares status          # sensors active, AI provider, notification channels
ares notify test     # sends a synthetic alert through every configured channel
ares doctor          # storage + integrity checks
```

### Never do (safety)

- Do not enable destructive response actions to bypass approval. `delete_file`
  and `execute_generated_shell_command` are prohibited by design.
- Do not put real secrets in `config.yaml`, commits, issues, or logs.
- Do not send raw host telemetry to a model; Ares redacts + summarizes by design.

---

## 2. Contributing to the Ares codebase

### Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,fs]"
export ARES_STATE_DIR="$HOME/.ares"   # dev state dir, no root needed
```

Ares runs on macOS for development via the procfs/psutil fallback; eBPF and
systemd are Linux-only.

### Commands (see the Makefile)

```bash
make test     # pytest
make lint     # ruff check
make format   # ruff format + ruff check --fix
make build    # python -m build && twine check dist/*
make check    # lint + test (what CI gates on)
```

Everything must pass `ruff check`, `ruff format --check`, and `pytest` before a
PR. CI runs on Python 3.10–3.13 (Ubuntu) + 3.12 (macOS).

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

Module docstrings cite spec section numbers (e.g. "spec §12"). Follow them.

### Extending

| To add… | Edit | Guide |
| ------- | ---- | ----- |
| A detection rule | `src/ares/detection/builtin.py` | [`docs/rule-authoring.md`](docs/rule-authoring.md) |
| A sensor | `src/ares/sensors/` | [`docs/architecture.md`](docs/architecture.md) |
| An AI provider | `src/ares/investigator/providers.py` | keep the local fallback |
| A notifier | `src/ares/notifications/channels.py` | push-only, fail soft |
| A response action | `src/ares/response/actions.py` | [`docs/security-model.md`](docs/security-model.md) |

Every behavioural change needs a test. Use `tests/fixtures/factory.py` to build
event sequences. Attack simulations live in `tests/simulations/` and must use
controlled fixtures — never real/dangerous payloads.

### Conventions

- Match the surrounding code's style, comment density, and spec-citation idiom.
- Rules and providers must **fail soft** — a broken rule or an unavailable model
  must never crash the pipeline (log and continue).
- Keep detection cheap; expensive reasoning belongs in the investigator.

### Commit & PR rules

- **Do not add AI/co-author attribution to commits** (no `Co-Authored-By: Claude`
  or similar trailers). This is a deliberate project policy — write normal,
  human-authored commit messages.
- Conventional-ish messages preferred: `feat:`, `fix:`, `docs:`, `chore:`.
- Never commit secrets, tokens, or real host telemetry.
- CI must be green (lint, format, types, tests, build).

### Release (maintainers)

Bump `__version__` in `src/ares/__init__.py`, update `CHANGELOG.md`, then:

```bash
git tag vX.Y.Z && git push origin vX.Y.Z
```

The Release workflow builds, verifies, and publishes to PyPI via Trusted
Publishing (no tokens), then cuts a GitHub Release with artifacts + attestations.
