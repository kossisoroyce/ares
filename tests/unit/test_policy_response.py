"""Policy and response engine tests (spec 22, 35.1)."""

import pytest

from ares.config import Config
from ares.investigator.verdict import RecommendedAction, Verdict
from ares.policy import PolicyEngine
from ares.policy.engine import Disposition
from ares.response import ResponseEngine


@pytest.fixture
def cfg():
    return Config()


def test_prohibited_action(cfg):
    d = PolicyEngine(cfg).evaluate("delete_file")
    assert d.disposition is Disposition.PROHIBITED
    assert d.allowed is False


def test_evidence_action_automatic_in_recommend_mode(cfg):
    d = PolicyEngine(cfg).evaluate("hash_file")
    assert d.disposition is Disposition.AUTOMATIC


def test_containment_requires_approval(cfg):
    d = PolicyEngine(cfg).evaluate("isolate_container")
    assert d.disposition is Disposition.REQUIRES_APPROVAL


def test_plan_from_verdict_executes_evidence_and_holds_containment(store, tmp_path):
    cfg = Config.model_validate({"storage": {"path": str(tmp_path / "db")}})
    engine = ResponseEngine(store, cfg, str(tmp_path / "evidence"))
    verdict = Verdict(
        classification="likely_malicious",
        recommended_actions=[
            RecommendedAction(action="capture_forensic_bundle", urgency="immediate"),
            RecommendedAction(
                action="isolate_workload", urgency="immediate", requires_approval=True
            ),
        ],
    )
    planned = engine.plan_from_verdict("case_1", verdict)
    by_type = {a["type"]: a for a in planned}
    # Evidence action ran automatically.
    assert store.get_action(by_type["capture_forensic_bundle"]["action_id"])["status"] == "executed"
    # Containment awaits approval.
    assert by_type["isolate_workload"]["requires_approval"] is True
    assert store.get_action(by_type["isolate_workload"]["action_id"])["status"] == "proposed"


def test_approval_flow(store, tmp_path):
    cfg = Config.model_validate({"storage": {"path": str(tmp_path / "db")}})
    engine = ResponseEngine(store, cfg, str(tmp_path / "evidence"))
    verdict = Verdict(
        classification="malicious",
        recommended_actions=[RecommendedAction(action="isolate_container", requires_approval=True)],
    )
    planned = engine.plan_from_verdict("case_2", verdict)
    action_id = planned[0]["action_id"]
    result = engine.approve(action_id)
    # Containment is not implemented in the first release -> not_implemented, not executed.
    assert result["status"] == "not_implemented"
    # Reversible action carries a rollback.
    assert store.get_action(action_id)["rollback_action"] == "restore_container_network"
