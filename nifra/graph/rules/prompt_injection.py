from __future__ import annotations

from typing import TYPE_CHECKING

from nifra.graph.nodes import NodeType
from nifra.graph.rules import BaseRiskRule, RiskFinding, Severity

if TYPE_CHECKING:
    import networkx as nx


class PromptInjectionRule(BaseRiskRule):
    """
    RAG Indirect Prompt Injection

    Fires when: ExternalDocument → RAGLoader → PromptTemplate path exists
    without content validation at the RAGLoader node.

    OWASP LLM01 — Prompt Injection
    """

    rule_id = "PI-001"
    rule_name = "RAG Indirect Prompt Injection"
    severity = Severity.CRITICAL
    owasp_ref = "LLM01"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []

        ext_docs = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.EXTERNAL_DOCUMENT.value
        ]
        vuln_loaders = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.RAG_LOADER.value
            and not d.get("has_content_validation", False)
        ]

        if not ext_docs or not vuln_loaders:
            return findings

        evidence: list[str] = []
        for _, d in ext_docs:
            loc = d.get("source_file", "unknown")
            evidence.append(f"ExternalDocument source at {loc}")
        for _, d in vuln_loaders:
            loc = d.get("source_file", "unknown")
            label = d.get("label", "RAGLoader")
            evidence.append(f"{label} at {loc} — has_content_validation=False")

        findings.append(RiskFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            owasp_ref=self.owasp_ref,
            description=(
                f"{len(ext_docs)} external document source(s) feed into "
                f"{len(vuln_loaders)} unvalidated RAG loader(s). "
                "An attacker-controlled document can embed instructions that override "
                "the system prompt (indirect prompt injection)."
            ),
            evidence=evidence,
            confidence=0.85,
            exploit_reproducible=True,
            remediation=[
                "Sanitize and validate retrieved document content before inserting into prompts",
                "Use a trust-scoring layer (e.g. NeMo Guardrails) on RAG-retrieved content",
                "Separate untrusted content from instructions using structured delimiters",
                "Monitor LLM output for instruction-following from unexpected sources",
            ],
        ))
        return findings


class DirectInjectionRule(BaseRiskRule):
    """
    Direct Prompt Injection via User Input

    Fires when: UserInput flows directly into PromptTemplate
    without sanitization, and PromptTemplate includes system instructions
    in the same context window.

    OWASP LLM01 — Prompt Injection
    """

    rule_id = "PI-002"
    rule_name = "Direct Prompt Injection via User Input"
    severity = Severity.HIGH
    owasp_ref = "LLM01"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []

        user_inputs = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.USER_INPUT.value
        ]
        sys_prompts = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.PROMPT_TEMPLATE.value
            and d.get("is_system_prompt", False)
        ]

        if not user_inputs or not sys_prompts:
            return findings

        evidence = [
            f"UserInput flows into system prompt template at {d.get('source_file', '?')}"
            for _, d in sys_prompts
        ]
        findings.append(RiskFinding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            owasp_ref=self.owasp_ref,
            description=(
                "User-controlled input reaches a system prompt template without sanitization. "
                "An attacker can craft input to override system instructions or exfiltrate context."
            ),
            evidence=evidence,
            confidence=0.80,
            exploit_reproducible=True,
            remediation=[
                "Never interpolate raw user input directly into system prompts",
                "Validate and sanitize user input before prompt construction",
                "Use separate context windows for system instructions and user content",
            ],
        ))
        return findings
