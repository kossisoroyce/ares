"""Public custom-rule API (spec 28.1).

Re-exports the rule primitives so integrators can write::

    from ares.rules import Rule, Finding, RuleContext

    class UnexpectedShellRule(Rule):
        rule_id = "CUSTOM_SHELL_001"
        def evaluate(self, event, context):
            if (event.type == "process.exec"
                    and event.get("executable") in {"/bin/sh", "/bin/bash"}
                    and event.get("parent_is_network_service")):
                return Finding(title="Network service spawned a shell",
                               severity="high", risk_score=0.88)
            return None
"""

from ares.detection.rule import Finding, Rule, RuleContext

__all__ = ["Rule", "Finding", "RuleContext"]
