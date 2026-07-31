# Architecture

Ares is two long-running components over one local SQLite store.

## Components

### Continuous telemetry daemon (`ares.daemon.Daemon`, spec §6.1)

Runs sensors on their own threads. Each event flows:

```
sensor.emit(event)
  → EnrichmentPipeline.enrich   (host context always; hashes lazily on severity)
  → bounded queue               (backpressure: full queue increments events_dropped)
  → writer thread               (batched writes, flush by size or interval)
      → Store.write_events
      → DetectionEngine.evaluate (every rule, per event)
      → BaselineEngine.observe   (skips high-risk events → poisoning protection)
```

Immediate findings (spec §13) trigger `_handle_immediate`: capture volatile
process state, hash the executable, freeze the baseline, and notify — all before
the one-minute cycle, so evidence survives short-lived processes.

### Investigation scheduler (`ares.scheduler.InvestigationScheduler`, spec §15)

Every 60s (systemd timer or `ares investigator run`):

1. Acquire the lease lock (`scheduler_state` row with expiry) — prevents overlap.
2. Read unprocessed events.
3. Correlate into sequences (host + time-proximity sessionization).
4. Score sequences (§16.3).
5. Build/dedupe cases above `retain_threshold`.
6. Investigate cases above `investigation_threshold`, up to `max_cases_per_cycle`.
7. Plan responses from each verdict; notify.
8. Advance the durable watermark; mark events processed; release the lock.

## Data flow diagram

```
kernel/OS ─► sensors ─► redaction+enrichment ─► SQLite
                              │
                    DetectionEngine ─► immediate path ─► evidence capture
                              │
        scheduler ─► Correlator ─► CaseBuilder ─► Investigator ─► verdict
                              │
                    PolicyEngine ─► ResponseEngine ─► actions
                              │
                       Notifications
```

## Why SQLite

Single-host first release (spec §23). WAL mode gives concurrent reads while a
process-wide lock serializes writes. The lease lock and durable watermark live
in the same DB, so a daemon restart resumes exactly where it left off (§25.2).

## Sensor abstraction

`Sensor` (base) → eBPF collectors (preferred on Linux) or procfs/psutil/audit
fallbacks. `build_sensors()` selects the available set and each reports
`SensorCapabilities`, surfaced by `ares status` so missing coverage is
visible (§8.3). See [deployment.md](deployment.md).
