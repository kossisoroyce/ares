# Deploying Ares alongside your backend

Ares watches the host and its kernel. It never reads your application code, so
the language your backend is written in makes no difference to it. Python, Rust,
Go, Node, Java, Elixir: underneath all of them Ares sees the same activity, which
is process starts, network connections, and file changes.

This guide is for anyone running a backend on Fly.io, Railway, Render,
Kubernetes, or a plain VM who wants Ares watching alongside it.

## Pick a deployment model

There are two ways to run Ares, and which one fits depends on how much of the
host you control.

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

> **Reality check on eBPF.** eBPF needs a real kernel and elevated privileges
> (`CAP_BPF`/`CAP_PERFMON`, or a privileged container). Plenty of managed
> platforms run your code locked down, and there Ares uses the procfs fallback
> instead (spec §8.2). The fallback can miss a process that starts and exits
> between two polls, so full coverage of short-lived processes needs a host where
> eBPF can load. `ares status` always tells you which sensors are live.

## Language notes

Ares ships as a Python package (`ares-agent`). That changes where you run it. It
has no bearing on what it can see.

- **Python backends.** Install `ares-agent` into the same image or venv and run
  it next to your app. See [docker.md](docker.md).
- **Rust, Go, Node, and everything else.** Those images usually have no Python in
  them, so run Ares as a sidecar: a separate container in the same pod, or a
  second service that shares the process namespace. See
  [kubernetes.md](kubernetes.md) and [docker.md](docker.md#sidecar).

> **A sidecar needs the shared PID namespace to see your app.** On its own it
> only sees itself. Set `shareProcessNamespace: true` in Kubernetes, or
> `pid: "service:app"` in Docker Compose.

## What needs to run

Ares is two processes over one SQLite store (see
[../architecture.md](../architecture.md)):

1. **daemon** (`ares daemon run`) collects events and runs detection.
2. **investigator** (`ares investigator run`) runs the one-minute cycle.

In a container you start both in the background from your entrypoint, then hand
off to your app as PID 1. The platform pages below have the exact wiring.

## Minimum configuration for any platform

Set these as environment variables (12-factor; see
[../../examples/ares.env.example](../../examples/ares.env.example)):

```bash
# State dir Ares can write to (must be writable by the app user).
ARES_STATE_DIR=/data/ares            # or a mounted volume

# AI investigator. OpenRouter is the default and takes any model.
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=anthropic/claude-3.5-sonnet

# Where incidents go (see ../deployment.md#notifications).
ARES_SLACK_WEBHOOK=https://hooks.slack.com/services/...
ARES_NOTIFY_MIN_SEVERITY=high
```

No API key yet? Ares still runs. The investigator uses the built-in `local`
analyzer, and detection and alerting carry on as normal.

## Platform recipes

- [Docker & Docker Compose](docker.md), the building block for the rest
- [Fly.io](fly-io.md), microVMs where host-level eBPF can work
- [Railway](railway.md), managed containers running the in-container companion
- [Kubernetes](kubernetes.md), a DaemonSet across nodes or a sidecar per pod
- [Bare VM / systemd](../deployment.md), the plain host install

## Verify it works anywhere

```bash
ares status            # shows sensors, AI provider, notification channels
ares notify test       # sends a synthetic alert through every channel
ares doctor            # storage + integrity self-checks
```
