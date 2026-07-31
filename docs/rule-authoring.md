# Authoring detection rules

Rules are the deterministic layer (spec §12). They run on every event and return
a `Finding` or `None`. Keep them cheap. The expensive reasoning belongs in the
investigator.

## Minimal rule

```python
from ares.rules import Rule, Finding, RuleContext
from ares.events import Event

class UnexpectedShellRule(Rule):
    rule_id = "CUSTOM_SHELL_001"
    title = "Network service spawned a shell"
    severity = "high"

    def evaluate(self, event: Event, context: RuleContext) -> Finding | None:
        if (event.type == "process.exec"
                and event.get("executable") in {"/bin/sh", "/bin/bash"}
                and event.get("parent_is_network_service")):
            return self._finding(event, risk_score=0.88, confidence=0.9,
                                 immediate=True,
                                 reasons=["Shell spawned by a network service"])
        return None
```

`self._finding(event, ...)` fills in `rule_id`, `host_id`, `primary_process_id`
and `event_ids` for you.

## RuleContext

- `context.store`: read-only lookups (`get_process`, `process_ancestry`,
  `observe_destination`, `baseline_count`).
- `context.parent_process(event)`: the parent process row, when it's known.
- `context.host_role`, `context.environment`.

## Registering rules

```python
from ares.detection import DetectionEngine, BUILTIN_RULES
engine = DetectionEngine(store, rules=[*BUILTIN_RULES, UnexpectedShellRule()])
```

## Severity, scoring and the immediate path

- `severity`: one of `info|low|medium|high|critical`, which feeds sequence
  scoring (§16.3).
- `risk_score` ≥ `immediate_alert_threshold` (default 0.90) **or** `immediate=True`
  routes the finding to the critical path (§13), which captures evidence and
  alerts right away.
- Stateful rules like failed-login bursts keep state on the instance, so create a
  fresh instance per engine.

## Suppressions

Findings are dropped when an active suppression matches on `rule_id`, `host_id`,
`path_glob`, or `executable` (spec §21). Suppressions carry an `expires_at`.

## Tips for precision

- Combine signals where you can. Look at `EncodedCommandArguments`, which fires
  on an interpreter together with decoded code, because a bare base64 blob on its
  own throws far too many false positives.
- Use the baseline (`context.store.baseline_count`) to gate "new or rare" rules.
