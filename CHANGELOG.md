# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-31

Initial public release. Covers Phase 1 and the core of Phase 2.

### Added

- **Continuous telemetry daemon** with process, network, and filesystem sensors
  (eBPF sources for Linux; procfs/psutil/audit fallbacks that run everywhere).
- **Shared event schema** with reuse-safe process identity and secret redaction.
- **Streaming detection engine** with 11 high-value rules and an immediate
  critical path that captures volatile evidence before short-lived processes exit.
- **Correlation engine** that groups events into scored behavioural sequences,
  recognising multi-step attack chains (write → execute → connect → delete).
- **Baseline engine** with novelty scoring and poisoning protection.
- **Case construction & deduplication** producing bounded investigator packages.
- **AI investigator** with typed read-only tools, budgets, and a structured
  verdict. Default provider is **OpenRouter** (any model via env vars); also
  supports OpenAI-compatible endpoints, Anthropic, and a no-API `local` mode.
- **Policy & response engine.** Evidence actions run on their own. Containment
  and recovery need approval and carry rollback metadata. Destructive actions are
  prohibited.
- **Multi-channel notifications:** Slack, generic webhook, email/SMTP, and
  PagerDuty, with global and per-channel severity routing (all env-configurable).
- **One-minute investigation scheduler** with a lease lock and durable watermark.
- **SQLite storage** (WAL) with per-band retention.
- **CLI** (`ares`) and a Python API (`from ares import Ares`).
- systemd units, example config, `.env` template, and full docs.

[Unreleased]: https://github.com/kossisoroyce/ares/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kossisoroyce/ares/releases/tag/v0.1.0
