# Docker & Docker Compose

The container patterns here are the building block for Fly.io, Railway, Render,
and any container platform.

## Pattern A: Python backend, Ares in the same image

Install `ares-agent` next to your app and start both from an entrypoint.

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "ares-agent"

COPY . .

ENV ARES_STATE_DIR=/data/ares
VOLUME ["/data"]

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

```bash
#!/usr/bin/env sh
# entrypoint.sh: start Ares in the background, then exec your app as PID 1.
set -e

mkdir -p "${ARES_STATE_DIR:-/data/ares}"
ares init || true
ares daemon run &                 # continuous collection + detection
( while true; do ares investigator run --once; sleep 60; done ) &   # AI cycle

# Replace with your real backend (any Python server):
exec gunicorn app:app --bind 0.0.0.0:8080
```

> Prefer a tiny supervisor (e.g. `tini` + a process manager, `s6-overlay`, or
> `honcho`) if you want proper signal handling and restart-on-crash for the
> background processes. The `&` approach is fine to start.

## Pattern B: sidecar for a non-Python backend (Rust/Go/Node) {#sidecar}

Your compiled app image has no Python in it. Run Ares as a second service that
shares the app's process namespace, which lets it see the app's processes.

```yaml
# docker-compose.yml
services:
  app:
    build: .                       # your Rust/Go/Node backend
    ports: ["8080:8080"]

  ares:
    image: python:3.12-slim
    command: >
      sh -c "pip install --no-cache-dir ares-agent &&
             ares init &&
             ares daemon run &
             while true; do ares investigator run --once; sleep 60; done"
    pid: "service:app"             # <-- share the app's PID namespace
    environment:
      ARES_STATE_DIR: /data/ares
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
      OPENROUTER_MODEL: anthropic/claude-3.5-sonnet
      ARES_SLACK_WEBHOOK: ${ARES_SLACK_WEBHOOK}
    volumes:
      - ares-data:/data

volumes:
  ares-data:
```

For faster, repeatable starts, bake a dedicated Ares image so you skip the
boot-time `pip install`:

```dockerfile
# Dockerfile.ares
FROM python:3.12-slim
RUN pip install --no-cache-dir ares-agent
ENV ARES_STATE_DIR=/data/ares
ENTRYPOINT ["sh","-c","ares init; ares daemon run & while true; do ares investigator run --once; sleep 60; done"]
```

## Enabling eBPF in a container (optional)

On a host you control (your own Docker host / VM), grant the kernel access so
Ares uses eBPF instead of the fallback:

```bash
docker run --rm \
  --pid=host \
  --cap-add=CAP_BPF --cap-add=CAP_PERFMON --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -e OPENROUTER_API_KEY -e OPENROUTER_MODEL \
  ghcr.io/kossisoroyce/ares:latest    # or your own image
```

> Managed PaaS won't grant these, which is normal. Ares falls back to procfs,
> and `ares status` will show `ebpf_process_events: false`.

## Persistence

Point `ARES_STATE_DIR` (or `storage.path` in config) at a mounted volume so the
event store, baselines, and watermark survive restarts and redeploys.
