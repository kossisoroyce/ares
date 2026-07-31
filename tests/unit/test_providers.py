"""Investigator provider selection + fallback tests (spec §19, §34.2)."""

from ares.investigator.providers import (
    LocalProvider,
    OpenAICompatibleProvider,
    get_provider,
)
from ares.investigator.tools import InvestigatorTools
from ares.investigator.verdict import Verdict


def test_default_provider_is_openrouter():
    p = get_provider("openrouter", "")
    assert isinstance(p, OpenAICompatibleProvider)
    assert p.name == "openrouter"


def test_unknown_provider_defaults_to_openrouter():
    assert isinstance(get_provider("wat", ""), OpenAICompatibleProvider)


def test_local_provider_explicit():
    assert isinstance(get_provider("local", ""), LocalProvider)


def test_openrouter_without_key_falls_back_to_local(monkeypatch, store):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    p = OpenAICompatibleProvider(flavor="openrouter", model="")
    assert p.available() is False
    tools = InvestigatorTools(store=store, host_id="h")
    package = {
        "sequence": [
            {
                "event_type": "process.exec",
                "label": "sh",
                "event_id": "e1",
                "payload": {"executable": "/bin/sh"},
            }
        ],
        "supporting_findings": [],
        "risk_score": 0.7,
        "host": {},
        "title": "t",
        "summary": "s",
    }
    verdict, usage = p.investigate(package, tools, {"max_tool_calls": 12})
    # Fell back to the local provider and still produced a valid verdict.
    assert isinstance(verdict, Verdict)
    assert verdict.classification in {
        "suspicious",
        "likely_malicious",
        "malicious",
        "likely_benign",
    }


def test_openrouter_reads_env(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    monkeypatch.setenv("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet")
    p = OpenAICompatibleProvider(flavor="openrouter")
    assert p.available() is True
    assert p._model == "anthropic/claude-3.5-sonnet"
