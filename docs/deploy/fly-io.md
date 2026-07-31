# Fly.io

Fly runs your app in a **Firecracker microVM**, so you have more of the machine
than a typical managed container — a good fit for running Ares next to your
backend. Use the [Docker patterns](docker.md) to build the image, then wire Fly.

## fly.toml

```toml
app = "my-backend"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"        # your app image, with Ares installed (Pattern A)

[env]
  ARES_STATE_DIR = "/data/ares"
  OPENROUTER_MODEL = "anthropic/claude-3.5-sonnet"
  ARES_NOTIFY_MIN_SEVERITY = "high"

# Persist the Ares event store across deploys/restarts.
[mounts]
  source = "ares_data"
  destination = "/data"

[http_service]
  internal_port = 8080
  force_https = true
```

## Secrets (never put these in fly.toml)

```bash
fly secrets set \
  OPENROUTER_API_KEY=sk-or-... \
  ARES_SLACK_WEBHOOK=https://hooks.slack.com/services/... \
  ARES_PAGERDUTY_ROUTING_KEY=...        # optional, pages on critical
```

## Create the volume

```bash
fly volumes create ares_data --size 1 --region iad
fly deploy
```

## About eBPF on Fly

Firecracker gives you a real Linux kernel, but the default capability set may
not permit loading eBPF programs. Check after deploy:

```bash
fly ssh console -C "ares status"
```

If `ebpf_process_events` is `false`, Ares is using the procfs fallback — still
useful, just without kernel-level short-lived-process capture. Treat eBPF as a
bonus on Fly, not a guarantee.

## Non-Python backends on Fly

Fly runs one image per Machine. For a Rust/Go/Node app, either:

- add a minimal Python layer to your image and install `ares-agent` there
  (multi-stage: copy your compiled binary into a `python:3.12-slim` base), or
- run a **second Fly Machine / process group** for Ares. Note that separate
  Machines don't share a PID namespace, so an in-VM companion (same image) is
  the way to see your app's own processes.
