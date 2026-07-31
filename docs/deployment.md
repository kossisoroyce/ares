# Deployment

## Supported targets (spec §3.2)

Ubuntu, Debian, Amazon Linux, Rocky, AlmaLinux; cloud VMs, bare metal, Docker
hosts, Kubernetes worker nodes. macOS is supported for **development only** via
the procfs/psutil fallback sensors.

## Linux install (production)

```bash
pip install ares-agent          # or install the signed artifact
sudo ares init                  # create /var/lib/ares, config
sudo cp examples/config.yaml /etc/ares/config.yaml
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ares-daemon.service
sudo systemctl enable --now ares-investigator.timer
ares status
```

### eBPF prerequisites

You need kernel 5.8 or newer with BTF, plus `clang` and `libbpf`. Build the
programs from `bpf/` (see `bpf/README.md`). When eBPF can't load, the daemon
falls back to the procfs, psutil, and audit collectors (spec §8.2), and
`ares status` shows you which capabilities came up. That fallback misses
processes that begin and end between polls, so eBPF is what you want for full
coverage of short-lived processes.

## Development (macOS / no root)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,fs]"
export ARES_STATE_DIR="$HOME/.ares"   # dev state dir, no root needed
ares init
ares daemon run        # terminal 1
ares investigator run  # terminal 2
```

`load_config()` with no file falls back to dev defaults writing under
`ARES_STATE_DIR`.

## Configuration

Full reference: [../examples/config.yaml](../examples/config.yaml) (spec §27).
Key knobs:

- `response.mode`: `observe|alert|recommend|approve|automatic` (default `recommend`).
- `investigation.model_provider`: `openrouter` (default), `openai`, `anthropic`, `local`.
- `detection.*_threshold`: retain / investigate / immediate cut-offs.
- `storage.*_retention_*`: per-band retention (spec §23.3).
- `privacy.*`: redaction and what may reach the model.
- `notifications.*`: channels + severity routing (see below).

Keep secrets in the environment and out of the config file. The systemd units
already read `EnvironmentFile=/etc/ares/ares.env`, so drop them there. There's a
template at [../examples/ares.env.example](../examples/ares.env.example).

## AI investigation (OpenRouter default)

```bash
export OPENROUTER_API_KEY=sk-or-...
export OPENROUTER_MODEL=anthropic/claude-3.5-sonnet   # any OpenRouter model id
```

Switch backends with `investigation.model_provider`:

- `openrouter` (default): `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`.
- `openai` or a self-hosted gateway: `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`.
- `anthropic`: `ANTHROPIC_API_KEY` (`pip install ares-agent[ai]`).
- `local`: deterministic, runs with no external model.

When the provider or key isn't there, the investigator drops back to `local`, so
the pipeline keeps producing verdicts (spec §25.2).

## Notifications

Enable channels via env (or the `notifications:` config block):

```bash
export ARES_NOTIFY_MIN_SEVERITY=high
export ARES_SLACK_WEBHOOK=https://hooks.slack.com/services/...
export ARES_PAGERDUTY_ROUTING_KEY=...          # pages on-call (critical only)
export ARES_NOTIFY_WEBHOOK=https://ops.internal/ares
export ARES_SMTP_HOST=smtp.example.com ARES_SMTP_FROM=ares@ex.com ARES_SMTP_TO=secops@ex.com
```

Verify delivery before you rely on it:

```bash
ares notify channels     # what's active
ares notify test         # send a synthetic alert through every channel
```

Every channel is push-only over outbound HTTPS or SMTP. If one fails, Ares logs
it and the investigation cycle carries on (spec §25.2).

## Operations

```bash
ares status                 # host status, capabilities, open cases
ares doctor                 # self-checks
ares findings --severity high
ares cases list
ares cases show <id>
ares cases feedback <id> --label false_positive
ares actions list
ares actions approve <id>
ares actions rollback <id>
ares baseline status
```

## Backpressure & health

Under load the daemon keeps collecting. It only drops events when the buffer
fills, and it counts those in `events_dropped`. The scheduler tracks its own lag.
You can watch all of this through `ares status` or the `sensor_health` table.
