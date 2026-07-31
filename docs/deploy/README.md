# Deploying Ares alongside your backend

Ares watches the **host and kernel**, not your application code — so it is
**language-agnostic**. Whether your backend is Python, Rust, Go, Node, Java, or
Elixir, Ares monitors process, network, and filesystem activity the same way.

This guide is for teams shipping backends to platforms like **Fly.io**,
**Railway**, **Render**, **Kubernetes**, or a plain **VM**, who want runtime
security monitoring next to their app.

## Pick a deployment model

There are two ways to run Ares. Choose based on how much of the host you control.

| Model | You get | Sensor backend | Best on |
| ----- | ------- | -------------- | ------- |
| **Host-level** | full visibility into every workload on the machine/node | **eBPF** (kernel-level) with procfs fallback | bare VMs, Fly.io microVMs, K8s nodes you own, EC2/GCE/Hetzner |
| **In-container companion** | visibility into your app container's processes | **procfs/psutil fallback** (no privileges) | Railway, Render, managed containers, constrained PaaS |

```
Host-level (privileged)                In-container companion (unprivileged)
┌───────────────────────────┐          ┌───────────────────────────┐
│ VM / node                 │          │ container                 │
│  ├─ your app (any lang)   │          │  ├─ your app (any lang)   │
│  ├─ other workloads       │          │  └─ ares (procfs fallback)│
│  └─ ares (eBPF) ──────────┼─ sees    └───────────────────────────┘
│        everything on host │            sees this container's procs
└───────────────────────────┘
```

> **Reality check on eBPF.** eBPF needs a real kernel and elevated capabilities
> (`CAP_BPF`/`CAP_PERFMON`, or privileged). Many managed PaaS run your code in a
> locked-down container where eBPF is unavailable — there Ares automatically
> uses the **procfs fallback** (spec §8.2). The fallback can miss processes that
> start and exit between polls; for full short-lived-process coverage you need a
> host where eBPF can load. `ares status` always shows which sensors are active.

## Language notes (important)

Ares is distributed as a **Python package** (`ares-agent`). That affects *where*
it runs, not *what* it can watch:

- **Python backends** — install `ares-agent` into the same image/venv and run it
  next to your app. See [docker.md](docker.md).
- **Rust / Go / Node / other** — your app image usually has no Python runtime, so
  run Ares as a **sidecar** (a separate container in the same pod, or a second
  service sharing the process namespace) rather than installing it into your app
  image. See [kubernetes.md](kubernetes.md) and [docker.md](docker.md#sidecar).

> **To see your app's processes from a sidecar, share the PID namespace.**
> Without it, the sidecar only sees itself. In Kubernetes set
> `shareProcessNamespace: true`; in Docker Compose set `pid: "service:app"`.

## What actually needs to run

Ares is two processes over one SQLite store (see [../architecture.md](../architecture.md)):

1. **daemon** — `ares daemon run` (continuous collection + detection)
2. **investigator** — `ares investigator run` (the one-minute AI cycle)

In a container you typically start both in the background from an entrypoint and
then exec your app as PID 1. Platform recipes below show the exact wiring.

## Minimum configuration for any platform

Set these as environment variables (12-factor; see
[../../examples/ares.env.example](../../examples/ares.env.example)):

```bash
# State dir Ares can write to (must be writable by the app user).
ARES_STATE_DIR=/data/ares            # or a mounted volume

# AI investigator (default provider is OpenRouter — any model).
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet

# Where incidents go (see ../deployment.md#notifications).
ARES_SLACK_WEBHOOK=https://hooks.slack.com/services/...
ARES_NOTIFY_MIN_SEVERITY=high
```

No API key? Ares still runs — the investigator falls back to the deterministic
`local` provider and detection/notifications keep working.

## Platform recipes

- [Docker & Docker Compose](docker.md) — the building block for everything below
- [Fly.io](fly-io.md) — microVMs (host-level eBPF possible)
- [Railway](railway.md) — managed containers (in-container companion)
- [Kubernetes](kubernetes.md) — DaemonSet (node-level) or sidecar (per-pod)
- [Bare VM / systemd](../deployment.md) — the classic host install

## Verify it works anywhere

```bash
ares status            # shows sensors, AI provider, notification channels
ares notify test       # sends a synthetic alert through every channel
ares doctor            # storage + integrity self-checks
```
