from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from nifra.graph.builder import AttackSurfaceGraph
from nifra.reasoning.confidence import ConfidenceComponents, compute_hybrid_confidence


@dataclass
class ExploitChain:
    case_id: str
    finding_rule_id: str
    severity: str
    attack_chain_steps: list[str]
    reasoning: str
    impact: str
    adversarial_payload: Optional[str]
    exploit_reproducible: bool
    confidence: float
    cvss_ai: float
    remediation: list[dict]

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "finding_rule_id": self.finding_rule_id,
            "severity": self.severity,
            "attack_chain_steps": self.attack_chain_steps,
            "reasoning": self.reasoning,
            "impact": self.impact,
            "adversarial_payload": self.adversarial_payload,
            "exploit_reproducible": self.exploit_reproducible,
            "confidence": self.confidence,
            "cvss_ai": self.cvss_ai,
            "remediation": self.remediation,
        }


@dataclass
class ReasoningResult:
    exploit_chains: list[ExploitChain] = field(default_factory=list)
    reasoning_model: str = "unknown"
    token_usage: int = 0

    @property
    def critical_chains(self) -> list[ExploitChain]:
        return [c for c in self.exploit_chains if c.severity == "critical"]

    @property
    def risk_level(self) -> str:
        if any(c.severity == "critical" for c in self.exploit_chains):
            return "CRITICAL"
        if any(c.severity == "high" for c in self.exploit_chains):
            return "HIGH"
        if any(c.severity == "medium" for c in self.exploit_chains):
            return "MEDIUM"
        return "LOW"


_PROMPT_PATH = Path(__file__).parent / "prompts" / "exploit_chain.txt"

_FALLBACK_CHAIN_STEPS = [
    "1. Attacker identifies the vulnerable entry point",
    "2. Crafts adversarial payload targeting the detected weakness",
    "3. Payload is processed by the LLM without validation",
    "4. LLM follows attacker instructions overriding original intent",
    "5. Attacker achieves the described impact",
]


class ReasoningEngine:
    """Orchestrates LLM-based exploit chain reasoning."""

    def __init__(
        self,
        model: str = "gpt-4o",
        temperature: float = 0.2,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self._client = None

    def reason(self, attack_surface: AttackSurfaceGraph) -> ReasoningResult:
        if not attack_surface.findings:
            return ReasoningResult()

        result = ReasoningResult(reasoning_model=self.model)

        for i, finding in enumerate(attack_surface.findings):
            chain = self._reason_single_finding(
                finding=finding,
                graph_context=attack_surface.to_dict(),
                case_id=f"{(i + 1):03d}",
            )
            result.exploit_chains.append(chain)

        return result

    def _reason_single_finding(self, finding, graph_context: dict, case_id: str) -> ExploitChain:
        # Try LLM reasoning; fall back to deterministic chain on any error
        try:
            return self._llm_reason(finding, graph_context, case_id)
        except Exception:
            return self._deterministic_chain(finding, case_id)

    def _llm_reason(self, finding, graph_context: dict, case_id: str) -> ExploitChain:
        client = self._get_client()

        # Load and fill prompt template
        try:
            prompt_template = _PROMPT_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            prompt_template = _DEFAULT_PROMPT

        graph_summary = json.dumps({
            "node_count": len(graph_context.get("nodes", [])),
            "edge_count": len(graph_context.get("edges", [])),
            "nodes": graph_context.get("nodes", [])[:20],  # Cap for token budget
            "edges": graph_context.get("edges", [])[:30],
        }, indent=2)

        finding_json = json.dumps(finding.to_dict(), indent=2)

        prompt = (
            prompt_template
            .replace("{{GRAPH_JSON}}", graph_summary)
            .replace("{{FINDING_JSON}}", finding_json)
        )

        response = client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior AI security researcher. "
                        "Respond ONLY with a valid JSON object matching the requested schema. "
                        "Do not add any text outside the JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        )

        raw = response.choices[0].message.content or "{}"
        data = json.loads(raw)

        # NIFRA-006: clamp LLM-provided numeric fields to valid ranges
        llm_confidence = max(0.0, min(1.0, float(data.get("confidence", 0.7))))
        cvss_ai_raw = float(data.get("cvss_ai", _severity_to_cvss(finding.severity)))
        cvss_ai = max(0.0, min(10.0, cvss_ai_raw))
        final_confidence = compute_hybrid_confidence(ConfidenceComponents(
            rule_confidence=finding.confidence,
            llm_confidence=llm_confidence,
            evidence_count=len(finding.evidence),
            exploit_validated=finding.exploit_reproducible,
        ))

        return ExploitChain(
            case_id=case_id,
            finding_rule_id=finding.rule_id,
            severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            attack_chain_steps=data.get("attack_chain_steps", _FALLBACK_CHAIN_STEPS),
            reasoning=data.get("reasoning", finding.description),
            impact=data.get("impact", "Impact assessment pending"),
            adversarial_payload=data.get("adversarial_payload"),
            exploit_reproducible=finding.exploit_reproducible,
            confidence=final_confidence,
            cvss_ai=cvss_ai,
            remediation=[
                {"priority": "HIGH", "action": r}
                for r in (data.get("remediation") or finding.remediation)
            ],
        )

    def _deterministic_chain(self, finding, case_id: str) -> ExploitChain:
        """Fallback exploit chain built from deterministic rule output (no LLM)."""
        severity_str = (
            finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity)
        )
        return ExploitChain(
            case_id=case_id,
            finding_rule_id=finding.rule_id,
            severity=severity_str,
            attack_chain_steps=_FALLBACK_CHAIN_STEPS,
            reasoning=finding.description,
            impact=f"{finding.rule_name} — potential high-impact exploitation path",
            adversarial_payload=None,
            exploit_reproducible=finding.exploit_reproducible,
            confidence=compute_hybrid_confidence(ConfidenceComponents(
                rule_confidence=finding.confidence,
                llm_confidence=0.6,
                evidence_count=len(finding.evidence),
                exploit_validated=False,
            )),
            cvss_ai=_severity_to_cvss(finding.severity),
            remediation=[{"priority": "HIGH", "action": r} for r in finding.remediation],
        )

    def _build_deterministic_result(self, attack_surface: AttackSurfaceGraph) -> "ReasoningResult":
        """Build a full ReasoningResult using only deterministic rule output (no LLM)."""
        result = ReasoningResult(reasoning_model="deterministic")
        for i, finding in enumerate(attack_surface.findings):
            result.exploit_chains.append(
                self._deterministic_chain(finding, f"{i + 1:03d}")
            )
        return result

    def _get_client(self):
        if self._client is None:
            import openai
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise EnvironmentError(
                    "OPENAI_API_KEY not set. Set it to enable AI reasoning, "
                    "or use --no-ai for deterministic-only mode."
                )
            self._client = openai.OpenAI(api_key=api_key)
        return self._client


def _severity_to_cvss(severity) -> float:
    val = severity.value if hasattr(severity, "value") else str(severity)
    return {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.5, "info": 0.0}.get(val, 5.0)


_DEFAULT_PROMPT = """
You are analyzing an AI application security finding. Based on the attack surface graph and finding below,
generate a detailed exploit chain.

## Attack Surface Graph
{{GRAPH_JSON}}

## Finding
{{FINDING_JSON}}

Respond with JSON matching this schema:
{
  "attack_chain_steps": ["1. ...", "2. ...", "3. ...", "4. ...", "5. ..."],
  "reasoning": "Full paragraph explanation of the exploit",
  "impact": "Concrete description of what the attacker achieves",
  "adversarial_payload": "Example malicious input string (safe, non-destructive)",
  "confidence": 0.0,
  "cvss_ai": 0.0,
  "remediation": ["Fix 1", "Fix 2", "Fix 3"]
}
"""
