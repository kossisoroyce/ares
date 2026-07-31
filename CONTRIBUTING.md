# Contributing to Ares

Thanks for your interest in improving Ares! This guide gets you productive fast.

## Ground rules

- Be respectful — see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Never include secrets, tokens, or real host telemetry in issues, PRs, or tests.
- Security issues go through a [private advisory](SECURITY.md), never a public issue.

## Development setup

```bash
git clone https://github.com/kossisoroyce/ares
cd ares
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,fs]"
pre-commit install            # optional but recommended
export ARES_STATE_DIR="$HOME/.ares"   # dev state dir, no root needed
```

Ares runs on macOS for development via the procfs/psutil fallback sensors; eBPF
and systemd are Linux-only (see [docs/deployment.md](docs/deployment.md)).

## Everyday commands

```bash
make test        # pytest
make lint        # ruff check
make format      # ruff format
make cov         # tests with coverage
make build       # build sdist + wheel and twine check
```

(or run the underlying tools directly — see the [Makefile](Makefile).)

## Making a change

1. Create a branch: `git checkout -b feat/my-change`.
2. Write code **and tests** — every behavioural change needs a test.
3. Keep the pipeline honest: `ruff check`, `ruff format`, `pytest` all green.
4. Update docs and `CHANGELOG.md` (Unreleased section) where relevant.
5. Open a PR using the template. Small, focused PRs merge fastest.

## Where things live

| I want to add… | Look at | Guide |
| -------------- | ------- | ----- |
| A detection rule | `src/ares/detection/builtin.py` | [docs/rule-authoring.md](docs/rule-authoring.md) |
| A sensor | `src/ares/sensors/` | [docs/architecture.md](docs/architecture.md) |
| An AI provider | `src/ares/investigator/providers.py` | — |
| A notifier | `src/ares/notifications/channels.py` | — |
| A response action | `src/ares/response/actions.py` | [docs/security-model.md](docs/security-model.md) |

## Testing conventions

- Unit tests in `tests/unit/`, integration in `tests/integration/`, and safe
  attack simulations in `tests/simulations/` (controlled fixtures only — never
  dangerous payloads).
- Use the helpers in `tests/fixtures/factory.py` to build event sequences.

## Commit & PR style

- Conventional-ish messages are appreciated (`feat:`, `fix:`, `docs:`, `chore:`).
- CI must pass (lint, types, tests on Python 3.10–3.13, package build).

## Releasing (maintainers)

Releases publish to PyPI via Trusted Publishing on tag push:

```bash
# bump __version__ in src/ares/__init__.py, update CHANGELOG.md
git tag v0.1.0 && git push origin v0.1.0
```

The `Release` workflow builds, verifies, publishes to PyPI, and creates a GitHub
Release with artifacts and attestations.
