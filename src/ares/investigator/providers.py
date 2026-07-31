"""Investigator provider backends (spec 19, 34.2 model routing).

A provider takes a bounded case package and the tool surface and returns a
structured :class:`Verdict`. The ``LocalProvider`` needs no external model and
implements the local-only mode (spec 11.3): it reasons over the sequence and
findings with deterministic heuristics and templates. AI providers
(Anthropic/OpenAI) run a bounded tool-use loop and are used only when
configured.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Protocol

from ares.investigator.tools import InvestigatorTools
from ares.investigator.verdict import (
    BenignExplanation,
    Evidence,
    RecommendedAction,
    Verdict,
)

log = logging.getLogger("ares.investigator")

SYSTEM_PROMPT = """You are a host security investigator. You receive a bounded \
case package describing a correlated sequence of events on one Linux host. Use \
the read-only tools to gather evidence. Build benign and malicious hypotheses, \
weigh them against the evidence, and return a single structured verdict. Be \
conservative: cite event ids for every claim, and recommend the smallest safe \
response. Never request shell access or destructive actions."""


class Provider(Protocol):
    name: str

    def investigate(
        self, package: dict, tools: InvestigatorTools, budget: dict
    ) -> tuple[Verdict, dict]:
        """Return (verdict, usage) where usage has token/tool-call counts."""
        ...


class LocalProvider:
    """Deterministic, no-network investigator (spec 11.3 local-only mode)."""

    name = "local"

    def investigate(
        self, package: dict, tools: InvestigatorTools, budget: dict
    ) -> tuple[Verdict, dict]:
        seq = package.get("sequence", [])
        findings = package.get("supporting_findings", [])
        score = package.get("risk_score", 0.0)

        types = {n.get("event_type") for n in seq}
        reasons: list[str] = []
        for f in findings:
            reasons.extend(f.get("reasons", []))
        reasons.extend(package.get("summary", "").split("; "))
        reasons = [r for r in dict.fromkeys(reasons) if r]

        # Evidence: one claim per supporting finding, citing its events.
        evidence: list[Evidence] = []
        for n in seq:
            if n.get("event_type", "").startswith(("process.exec", "network.connect", "file.")):
                evidence.append(
                    Evidence(
                        claim=n.get("label", n.get("event_type", "")),
                        supporting_event_ids=[n.get("event_id")] if n.get("event_id") else [],
                        strength="strong" if score >= 0.8 else "moderate",
                    )
                )

        # Enrich with a file hash for temp executables when policy allows.
        for n in seq:
            exe = (n.get("payload") or {}).get("executable", "")
            if exe.startswith(("/tmp/", "/dev/shm/")) and tools.call_count < budget.get(
                "max_tool_calls", 12
            ):
                res = tools.dispatch("hash_file", {"path": exe})
                if res.ok:
                    evidence.append(
                        Evidence(
                            claim=f"Temporary executable {exe} hashes to {res.data['sha256'][:16]}…",
                            strength="strong",
                        )
                    )

        classification, confidence, severity = self._classify(score, types)

        benign = self._benign_explanations(types, package)

        actions = self._actions(classification, severity)

        missing = []
        if any(n.get("event_type") == "network.connect" for n in seq):
            missing.append("External destination ownership could not be confirmed")

        verdict = Verdict(
            classification=classification,
            confidence=confidence,
            severity=severity,
            title=package.get("title") or "Investigated activity sequence",
            summary=self._summary(package, classification, reasons),
            evidence=evidence,
            benign_explanations=benign,
            recommended_actions=actions,
            missing_information=missing,
        )
        usage = {"tool_calls": tools.call_count, "input_tokens": 0, "output_tokens": 0}
        return verdict, usage

    def _classify(self, score: float, types: set[str]) -> tuple[str, float, str]:
        if score >= 0.9:
            return "likely_malicious", min(0.95, score), "critical"
        if score >= 0.75:
            return "likely_malicious", score, "high"
        if score >= 0.6:
            return "suspicious", score, "high"
        if score >= 0.4:
            return "suspicious", score, "medium"
        return "likely_benign", 1 - score, "low"

    def _summary(self, package: dict, classification: str, reasons: list[str]) -> str:
        base = package.get("summary") or "Correlated activity observed."
        verdict_line = {
            "likely_malicious": "The evidence best fits malicious activity.",
            "malicious": "The evidence indicates malicious activity.",
            "suspicious": "The activity is anomalous and warrants review.",
            "likely_benign": "No malicious pattern was confirmed.",
        }.get(classification, "")
        return f"{base}. {verdict_line}".strip()

    def _benign_explanations(self, types: set[str], package: dict) -> list[BenignExplanation]:
        out = []
        if "process.exec" in types:
            out.append(
                BenignExplanation(
                    explanation="A deployment or maintenance script introduced a helper binary.",
                    likelihood=0.15,
                    contradictions=[
                        "No active deployment recorded in the case window",
                    ],
                )
            )
        return out

    def _actions(self, classification: str, severity: str) -> list[RecommendedAction]:
        actions = [
            RecommendedAction(
                action="capture_forensic_bundle", urgency="immediate", reversible=True
            )
        ]
        if classification in {"likely_malicious", "malicious"}:
            actions.append(
                RecommendedAction(
                    action="isolate_workload",
                    urgency="immediate",
                    reversible=True,
                    requires_approval=True,
                )
            )
        return actions


class AnthropicProvider:
    """Anthropic-backed investigator running a bounded tool-use loop.

    Only used when configured and the ``anthropic`` package + API key are
    available. Falls back to :class:`LocalProvider` on any error so the pipeline
    keeps producing verdicts when the provider is unavailable (spec 25.2).
    """

    name = "anthropic"

    def __init__(self, model: str = "claude-opus-4-8", api_key: str | None = None) -> None:
        self._model = model
        self._api_key = api_key
        self._fallback = LocalProvider()

    def investigate(
        self, package: dict, tools: InvestigatorTools, budget: dict
    ) -> tuple[Verdict, dict]:
        try:
            import anthropic  # type: ignore
        except Exception:
            log.warning("anthropic package unavailable; using local provider")
            return self._fallback.investigate(package, tools, budget)

        try:
            client = (
                anthropic.Anthropic(api_key=self._api_key)
                if self._api_key
                else anthropic.Anthropic()
            )
        except Exception as exc:
            log.warning("anthropic client init failed (%s); using local provider", exc)
            return self._fallback.investigate(package, tools, budget)

        verdict_tool = {
            "name": "submit_verdict",
            "description": "Submit the final structured verdict.",
            "input_schema": Verdict.model_json_schema(),
        }
        messages = [
            {
                "role": "user",
                "content": (
                    "Investigate this case package and submit a verdict.\n\n"
                    + json.dumps(package, indent=2, default=str)
                ),
            }
        ]
        tool_defs = tools.schemas() + [verdict_tool]
        max_calls = budget.get("max_tool_calls", 12)
        input_tokens = output_tokens = 0

        try:
            while tools.call_count <= max_calls:
                resp = client.messages.create(
                    model=self._model,
                    max_tokens=budget.get("max_output_tokens", 4000),
                    system=SYSTEM_PROMPT,
                    tools=tool_defs,
                    messages=messages,
                )
                input_tokens += getattr(resp.usage, "input_tokens", 0)
                output_tokens += getattr(resp.usage, "output_tokens", 0)
                messages.append({"role": "assistant", "content": resp.content})

                tool_results = []
                submitted = None
                for block in resp.content:
                    if getattr(block, "type", None) != "tool_use":
                        continue
                    if block.name == "submit_verdict":
                        submitted = block.input
                        break
                    result = tools.dispatch(block.name, dict(block.input))
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(
                                {"ok": result.ok, "data": result.data, "error": result.error},
                                default=str,
                            ),
                        }
                    )
                if submitted is not None:
                    verdict = Verdict.model_validate(submitted)
                    return verdict, {
                        "tool_calls": tools.call_count,
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                    }
                if not tool_results:
                    break
                messages.append({"role": "user", "content": tool_results})
        except Exception as exc:
            log.warning("anthropic investigation failed (%s); using local provider", exc)

        return self._fallback.investigate(package, tools, budget)


class OpenAICompatibleProvider:
    """Investigator backed by any OpenAI-compatible chat API (spec §19, §34.2).

    This is the default backend, configured for **OpenRouter** so operators can
    run *any* model with two env vars::

        OPENROUTER_API_KEY=sk-or-...
        OPENROUTER_MODEL=anthropic/claude-3.5-sonnet   # or any OpenRouter model

    It also works against OpenAI itself or a self-hosted gateway by pointing
    ``base_url``/``api_key``/``model`` at them (env: ``OPENAI_API_KEY``,
    ``OPENAI_BASE_URL``, ``OPENAI_MODEL``). It runs a bounded function-calling
    loop and asks the model to call ``submit_verdict`` with the structured
    result. On any error — missing key, unsupported model, network — it falls
    back to the local provider so verdicts keep flowing (spec §25.2).
    """

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        *,
        flavor: str = "openrouter",
        model: str = "",
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.name = flavor
        self._flavor = flavor
        self._fallback = LocalProvider()
        if flavor == "openrouter":
            self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
            self._base_url = base_url or os.environ.get(
                "OPENROUTER_BASE_URL", self.OPENROUTER_BASE_URL
            )
            self._model = model or os.environ.get("OPENROUTER_MODEL", "")
        else:  # generic "openai" / self-hosted gateway
            self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
            self._base_url = base_url or os.environ.get("OPENAI_BASE_URL")
            self._model = model or os.environ.get("OPENAI_MODEL", "")

    def available(self) -> bool:
        return bool(self._api_key and self._model)

    def investigate(
        self, package: dict, tools: InvestigatorTools, budget: dict
    ) -> tuple[Verdict, dict]:
        if not self.available():
            log.warning(
                "%s provider missing API key or model; using local provider "
                "(set %s_API_KEY and %s_MODEL)",
                self._flavor,
                self._flavor.upper(),
                self._flavor.upper(),
            )
            return self._fallback.investigate(package, tools, budget)
        try:
            import openai  # type: ignore
        except Exception:
            log.warning("openai package unavailable; using local provider")
            return self._fallback.investigate(package, tools, budget)

        try:
            client = openai.OpenAI(api_key=self._api_key, base_url=self._base_url)
        except Exception as exc:
            log.warning("%s client init failed (%s); using local provider", self._flavor, exc)
            return self._fallback.investigate(package, tools, budget)

        oai_tools = [
            {
                "type": "function",
                "function": {
                    "name": s["name"],
                    "description": s["description"],
                    "parameters": s["input_schema"],
                },
            }
            for s in tools.schemas()
        ]
        oai_tools.append(
            {
                "type": "function",
                "function": {
                    "name": "submit_verdict",
                    "description": "Submit the final structured verdict.",
                    "parameters": Verdict.model_json_schema(),
                },
            }
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Investigate this case package and, when done, call submit_verdict.\n\n"
                    + json.dumps(package, indent=2, default=str)
                ),
            },
        ]
        max_calls = budget.get("max_tool_calls", 12)
        input_tokens = output_tokens = 0

        try:
            while tools.call_count <= max_calls:
                resp = client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    tools=oai_tools,
                    tool_choice="auto",
                    max_tokens=budget.get("max_output_tokens", 4000),
                )
                usage = getattr(resp, "usage", None)
                if usage:
                    input_tokens += getattr(usage, "prompt_tokens", 0) or 0
                    output_tokens += getattr(usage, "completion_tokens", 0) or 0

                msg = resp.choices[0].message
                calls = msg.tool_calls or []
                if not calls:
                    break
                messages.append(
                    {
                        "role": "assistant",
                        "content": msg.content or "",
                        "tool_calls": [
                            {
                                "id": c.id,
                                "type": "function",
                                "function": {
                                    "name": c.function.name,
                                    "arguments": c.function.arguments,
                                },
                            }
                            for c in calls
                        ],
                    }
                )
                for c in calls:
                    try:
                        args = json.loads(c.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    if c.function.name == "submit_verdict":
                        return Verdict.model_validate(args), {
                            "tool_calls": tools.call_count,
                            "input_tokens": input_tokens,
                            "output_tokens": output_tokens,
                        }
                    result = tools.dispatch(c.function.name, args)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": c.id,
                            "content": json.dumps(
                                {"ok": result.ok, "data": result.data, "error": result.error},
                                default=str,
                            ),
                        }
                    )
        except Exception as exc:
            log.warning("%s investigation failed (%s); using local provider", self._flavor, exc)

        return self._fallback.investigate(package, tools, budget)


def get_provider(provider: str, model: str) -> Provider:
    """Resolve the configured provider, defaulting to env-driven OpenRouter.

    Unknown provider names fall through to OpenRouter, which itself degrades to
    the local provider when no credentials are present — so a fresh install runs
    with zero configuration and lights up the moment env vars are set.
    """
    provider = (provider or "openrouter").lower()
    if provider == "local":
        return LocalProvider()
    if provider == "anthropic":
        return AnthropicProvider(model=model or "claude-opus-4-8")
    if provider in {"openai", "openai-compatible"}:
        return OpenAICompatibleProvider(flavor="openai", model=model)
    # Default: OpenRouter (or any unrecognised name → OpenRouter).
    return OpenAICompatibleProvider(flavor="openrouter", model=model)
