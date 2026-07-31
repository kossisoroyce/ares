<h1 align="center">Ares</h1>

<p align="center">
  Ares runs on your Linux servers and works out what an attacker did.
</p>

<p align="center">
  <a href="https://github.com/kossisoroyce/ares/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/kossisoroyce/ares/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/ares-agent/"><img alt="PyPI" src="https://img.shields.io/pypi/v/ares-agent?color=blue"></a>
  <a href="https://pypi.org/project/ares-agent/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/ares-agent"></a>
  <a href="https://pepy.tech/project/ares-agent"><img alt="Downloads" src="https://img.shields.io/pypi/dm/ares-agent?color=blue"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://github.com/astral-sh/ruff"><img alt="Ruff" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json"></a>
</p>

Ares records what programs do on a machine: process activity, network
connections, file changes, logins, and the tricks attackers use to stick around
after a reboot. Cheap rules run over those events as they arrive and flag
anything that looks off. Once a minute a model reads back over the recent
activity and works out a story for it, so you find out what ran and whether any
of it lines up with a real attack.

The three parts stay separate on purpose. Collecting events is cheap, so that
part runs constantly in the background. A model is the expensive bit, both in
money and in the second or two it takes to answer, which is why it only sees the
cases that are hard enough to need judgment. The plain rules in the middle
decide which cases those are.

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

Ares is built for Linux. It has been run on Ubuntu, Debian, Amazon Linux, Rocky,
and Alma. On those machines it reads events straight from the kernel using eBPF.
When the kernel won't allow that, it falls back to reading `/proc` and watching
the filesystem. The fallback path is slower. It also runs on a Mac, which helps
while you're writing code against it.

## Install

```bash
pip install ares-agent
```

From source, if you want to hack on it:

```bash
git clone https://github.com/kossisoroyce/ares
cd ares
pip install -e ".[dev,fs]"
```

A few extras are optional. `ai` pulls in the Anthropic client for talking to
Anthropic directly. `api` gives you a local HTTP server. `fs` adds a filesystem
watcher that mostly helps during development. None of them matter for the
default OpenRouter setup, since the OpenAI client is already a core dependency.

## Quick start (dev, no root)

```bash
export ARES_STATE_DIR="$HOME/.ares"      # dev state dir
ares init
ares daemon run            # terminal 1: collect + detect
ares investigator run      # terminal 2: one-minute investigation cycle
ares status
ares cases list
```

## Deploy alongside your backend

Ares watches the host, so it doesn't care what your app is written in. Python,
Rust, Go, Node, Java: it treats them all the same. Run it next to your app
wherever that app already lives.

| Platform | Guide |
| -------- | ----- |
| Docker / Compose | [docs/deploy/docker.md](docs/deploy/docker.md) |
| Fly.io | [docs/deploy/fly-io.md](docs/deploy/fly-io.md) |
| Railway | [docs/deploy/railway.md](docs/deploy/railway.md) |
| Kubernetes (DaemonSet or sidecar) | [docs/deploy/kubernetes.md](docs/deploy/kubernetes.md) |
| Bare VM / systemd | [docs/deployment.md](docs/deployment.md) |

The [deployment hub](docs/deploy/README.md) walks through the one real choice you
have to make, which is whether Ares runs on the host or inside your container,
and what that means for eBPF on a managed platform. If you're using an AI coding
agent to wire it in, point the agent at [`AGENTS.md`](AGENTS.md).

## AI investigation (OpenRouter by default)

OpenRouter is the default, so you can point Ares at almost any model by setting
two environment variables. You leave the code and the config file alone.

```bash
export OPENROUTER_API_KEY=sk-or-...
export OPENROUTER_MODEL=anthropic/claude-3.5-sonnet   # any OpenRouter model id
```

Other backends work too. Set `investigation.model_provider` to match.

| Provider | Env vars |
| -------- | -------- |
| `openrouter` (default) | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |
| `openai` / self-hosted gateway | `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL` |
| `anthropic` | `ANTHROPIC_API_KEY` (`pip install -e ".[ai]"`) |
| `local` | none, deterministic, no external model (spec §11.3) |

When there's no key set, Ares uses the built-in `local` analyzer, so a fresh
install still works before you've configured anything. Add the env vars and it
switches over to the model on the next cycle. Keys come from the environment, so
they stay out of your config file. See
[`examples/ares.env.example`](examples/ares.env.example).

## Notifications

When something fires, Ares sends the alert out to you. Every channel makes an
outbound connection, so you don't have to open a port on the box. Turn on
whatever your team already uses:

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

A few things keep the noise down. There's a severity floor, and anything under
it stays quiet. PagerDuty sits behind a higher bar of its own, so on-call only
hears about the serious incidents. When the same activity keeps happening, it
folds into the case that's already open, so it pages you once and then goes quiet.

## Response safety

By default Ares only recommends. It won't change anything on the host on its own.

The harmless evidence steps run by themselves, like hashing a suspect file or
grabbing a snapshot of a process. Anything with real consequences, such as
isolating a container or killing a process, waits for you to approve it, and Ares
records how to undo it. Two things stay off the table completely: deleting files,
and running shell commands the model wrote. The model never gets a shell
(spec §22.3).

## Python API

Everything the CLI does is available from Python.

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

What's here covers Phase 1 and most of Phase 2 from the spec (§36). The eBPF
programs under `bpf/` and the privileged response helper still need wiring up on
a real Linux host. The `docs/` folder has the roadmap and the security model if
you want the detail.

Licensed under Apache-2.0.
