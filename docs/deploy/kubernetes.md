# Kubernetes

Two patterns, depending on whether you want to protect **whole nodes** or a
**single app**.

## Pattern A — DaemonSet (node-level, eBPF) — recommended for clusters you own

One Ares pod per node, with the privileges to load eBPF and see every workload
on that node. This is the strongest posture and matches how EDRs deploy.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ares
  namespace: security
spec:
  selector:
    matchLabels: { app: ares }
  template:
    metadata:
      labels: { app: ares }
    spec:
      hostPID: true                     # see all processes on the node
      containers:
        - name: ares
          image: ghcr.io/kossisoroyce/ares:latest   # or your own image
          args: ["sh","-c","ares init; ares daemon run & while true; do ares investigator run --once; sleep 60; done"]
          securityContext:
            privileged: true            # or capabilities: add [BPF, PERFMON, SYS_PTRACE]
          env:
            - name: ARES_STATE_DIR
              value: /data/ares
            - name: OPENROUTER_MODEL
              value: anthropic/claude-3.5-sonnet
          envFrom:
            - secretRef: { name: ares-secrets }
          volumeMounts:
            - { name: data, mountPath: /data }
            - { name: debugfs, mountPath: /sys/kernel/debug }
      volumes:
        - name: data
          hostPath: { path: /var/lib/ares, type: DirectoryOrCreate }
        - name: debugfs
          hostPath: { path: /sys/kernel/debug }
```

```bash
kubectl create namespace security
kubectl -n security create secret generic ares-secrets \
  --from-literal=OPENROUTER_API_KEY=sk-or-... \
  --from-literal=ARES_SLACK_WEBHOOK=https://hooks.slack.com/services/...
kubectl apply -f ares-daemonset.yaml
```

> Managed control planes (GKE Autopilot, some EKS/Fargate setups) restrict
> `privileged`/`hostPID`. If the DaemonSet can't get them, use the sidecar
> pattern below (procfs fallback).

## Pattern B — Sidecar (per-pod, works anywhere)

Run Ares as an extra container in your app's pod. **Share the process namespace**
so Ares can see the app container's processes.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-backend
spec:
  replicas: 2
  selector:
    matchLabels: { app: my-backend }
  template:
    metadata:
      labels: { app: my-backend }
    spec:
      shareProcessNamespace: true       # <-- required for the sidecar to see the app
      containers:
        - name: app
          image: my-backend:latest      # any language
          ports: [{ containerPort: 8080 }]
        - name: ares
          image: ghcr.io/kossisoroyce/ares:latest
          args: ["sh","-c","ares init; ares daemon run & while true; do ares investigator run --once; sleep 60; done"]
          env:
            - name: ARES_STATE_DIR
              value: /data/ares
            - name: OPENROUTER_MODEL
              value: anthropic/claude-3.5-sonnet
          envFrom:
            - secretRef: { name: ares-secrets }
          volumeMounts:
            - { name: ares-data, mountPath: /data }
      volumes:
        - name: ares-data
          emptyDir: {}                  # or a PVC to persist across restarts
```

- Sidecar uses the **procfs fallback** (no node privileges needed).
- `shareProcessNamespace: true` is what lets Ares observe the app; without it the
  sidecar only sees itself.

## Which to choose

| Want to… | Use |
| -------- | --- |
| Protect the whole node / all pods, with eBPF | **DaemonSet** |
| Protect one app, on any (even restricted) cluster | **Sidecar** |

## Notifications & AI provider

Both patterns read the same env vars (`OPENROUTER_API_KEY`, `ARES_SLACK_WEBHOOK`,
`ARES_PAGERDUTY_ROUTING_KEY`, …) from the `ares-secrets` Secret. See
[../deployment.md#notifications](../deployment.md).
