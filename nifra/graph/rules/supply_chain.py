from __future__ import annotations

from typing import TYPE_CHECKING

from nifra.graph.nodes import NodeType
from nifra.graph.rules import BaseRiskRule, RiskFinding, Severity

if TYPE_CHECKING:
    import networkx as nx


class SupplyChainRule(BaseRiskRule):
    """
    Unverified Third-Party LLM Plugin or Tool

    Fires when: AgentTool wraps an external package from community sources
    without integrity verification or sandboxing.

    OWASP LLM05 — Supply Chain Vulnerabilities
    """

    rule_id = "SC-001"
    rule_name = "Unverified Third-Party LLM Plugin"
    severity = Severity.HIGH
    owasp_ref = "LLM05"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []

        community_tools = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.AGENT_TOOL.value
            and "community" in d.get("label", "").lower()
        ]

        if community_tools:
            evidence = [
                f"Community tool '{d.get('label', n)}' at {d.get('source_file', '?')}"
                for n, d in community_tools
            ]
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                owasp_ref=self.owasp_ref,
                description=(
                    f"Found {len(community_tools)} community tool(s) without integrity verification. "
                    "Third-party plugins can introduce malicious code, backdoors, or data exfiltration."
                ),
                evidence=evidence,
                confidence=0.70,
                exploit_reproducible=False,
                remediation=[
                    "Pin all community tool versions to specific hashes in requirements.txt",
                    "Review community tool source code before adding to production agents",
                    "Use a private PyPI mirror with pre-approved packages",
                    "Enable dependency scanning in CI (pip-audit, safety)",
                ],
            ))
        return findings


class LLMOutputCodeExecRule(BaseRiskRule):
    """
    LLM Output Used in Dynamic Code Execution

    Fires when: LLM response is passed directly to eval(), exec(),
    subprocess, or similar execution primitives.

    OWASP LLM02 — Insecure Output Handling
    """

    rule_id = "SC-002"
    rule_name = "LLM Output Passed to Code Execution"
    severity = Severity.CRITICAL
    owasp_ref = "LLM02, LLM05"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []

        code_exec_sinks = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.DATA_SINK.value
            and d.get("sink_type", "") == "code_exec"
        ]

        llm_clients = [
            n for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.LLM_CLIENT.value
        ]

        if not code_exec_sinks or not llm_clients:
            return findings

        for sink_id, sink_data in code_exec_sinks:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                owasp_ref=self.owasp_ref,
                description=(
                    f"Dynamic code execution sink '{sink_data.get('label', sink_id)}' detected "
                    "in the same codebase as an LLM client. "
                    "If LLM output is passed to eval()/exec()/subprocess without validation, "
                    "an attacker can achieve arbitrary code execution via prompt injection."
                ),
                evidence=[
                    f"Code exec sink at {sink_data.get('source_file', '?')} line {sink_data.get('line_number', '?')}",
                    f"LLM client at {graph.nodes[llm_clients[0]].get('source_file', '?')}",
                ],
                confidence=0.88,
                exploit_reproducible=True,
                remediation=[
                    "Never pass raw LLM output to eval(), exec(), or subprocess",
                    "Parse LLM output as structured data (JSON schema) before using it",
                    "Run any LLM-generated code in an isolated sandbox environment",
                    "Use allow-listed code templates instead of free-form code generation",
                ],
            ))
        return findings
