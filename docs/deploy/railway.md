# Railway

Railway runs your service in a managed container without host privileges, so
Ares runs as an **in-container companion** using the procfs fallback (spec §8.2).
It monitors your service's own processes — exactly what you want for a single
app service.

## Recommended: a Dockerfile service

Railway will build and run a `Dockerfile` if present. Use
[Docker Pattern A](docker.md) (Python backend) or a multi-stage image that adds
a Python layer for non-Python apps.

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt ares-agent
COPY . .
ENV ARES_STATE_DIR=/data/ares
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

`entrypoint.sh` (same as the Docker guide): start `ares daemon run` and the
investigator loop in the background, then `exec` your server.

## Variables

Set these in the Railway service **Variables** tab (they become env vars):

```
ARES_STATE_DIR=/data/ares
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet
ARES_SLACK_WEBHOOK=https://hooks.slack.com/services/...
ARES_NOTIFY_MIN_SEVERITY=high
```

## Persistence

Add a **Railway Volume** mounted at `/data` so the Ares event store, baselines,
and processing watermark survive redeploys.

## Nixpacks (no Dockerfile)

If you deploy with Nixpacks instead of a Dockerfile, add Ares to your app's
Python dependencies and use a start command that launches Ares in the background
before your server, e.g. in `railway.json`:

```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "deploy": {
    "startCommand": "ares init; ares daemon run & (while true; do ares investigator run --once; sleep 60; done) & gunicorn app:app --bind 0.0.0.0:$PORT"
  }
}
```

## Expectations on Railway

- `ares status` will show `ebpf_process_events: false` (no privileged kernel
  access) — the procfs fallback is active. This is normal for managed PaaS.
- Ares sees the processes in **this** container, which for a typical single-app
  Railway service is precisely your backend.
