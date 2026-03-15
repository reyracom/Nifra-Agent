from __future__ import annotations

from typing import TYPE_CHECKING

from nifra.graph.nodes import DataSinkNode, NodeType
from nifra.graph.rules import BaseRiskRule, RiskFinding, Severity

if TYPE_CHECKING:
    import networkx as nx


class DataExfiltrationRule(BaseRiskRule):
    """
    PII Exposure via LLM Output

    Fires when: DataSink with contains_pii=True is reachable by an agent tool,
    and the output path lacks a PII filter before returning to the user.

    OWASP LLM02 — Insecure Output Handling
    OWASP LLM06 — Sensitive Information Disclosure
    """

    rule_id = "DE-001"
    rule_name = "PII Exposure via LLM Output"
    severity = Severity.CRITICAL
    owasp_ref = "LLM02, LLM06"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []

        pii_sinks = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.DATA_SINK.value
            and d.get("contains_pii", False)
            and not d.get("has_output_filter", False)
        ]

        if not pii_sinks:
            return findings

        agent_tools = [
            n for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.AGENT_TOOL.value
        ]

        for sink_id, sink_data in pii_sinks:
            # Check if any agent tool can reach this sink
            tool_can_reach = any(
                graph.has_edge(tool, sink_id) or graph.has_edge(sink_id, tool)
                for tool in agent_tools
            ) if agent_tools else True  # If no tools mapped, assume risk

            if tool_can_reach or not agent_tools:
                findings.append(RiskFinding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    owasp_ref=self.owasp_ref,
                    description=(
                        f"Data sink '{sink_data.get('label', sink_id)}' contains PII "
                        "and has no output filter. An adversarial prompt could instruct "
                        "the LLM to summarise or forward sensitive records to the attacker."
                    ),
                    evidence=[
                        f"DataSink '{sink_data.get('label', sink_id)}' at {sink_data.get('source_file', '?')}",
                        f"contains_pii=True, has_output_filter=False",
                    ],
                    confidence=0.85,
                    exploit_reproducible=True,
                    remediation=[
                        "Add a PII redaction layer before LLM responses are returned to users",
                        "Implement output scanning with tools like Microsoft Presidio or Amazon Comprehend",
                        "Restrict DB queries to non-PII fields when used via agent tools",
                        "Log all agent data-access operations for audit purposes",
                    ],
                ))
        return findings


class CredentialLeakRule(BaseRiskRule):
    """
    Credential or API Key Leakage in LLM Context

    Fires when: environment variables or config files with credentials
    are accessible in the same context as LLM prompt construction.

    OWASP LLM06 — Sensitive Information Disclosure
    """

    rule_id = "DE-002"
    rule_name = "Credential Leakage in LLM Context"
    severity = Severity.HIGH
    owasp_ref = "LLM06"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []

        # Detect credential-containing sinks near LLM clients
        cred_sinks = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.DATA_SINK.value
            and d.get("sink_type", "") in {"env", "config", "secrets"}
        ]

        llm_clients = [
            n for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.LLM_CLIENT.value
        ]

        if not cred_sinks or not llm_clients:
            return findings

        for sink_id, sink_data in cred_sinks:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                owasp_ref=self.owasp_ref,
                description=(
                    "Credentials or API keys are accessible in the same context as LLM calls. "
                    "A prompt injection attack could exfiltrate these secrets via the LLM response."
                ),
                evidence=[
                    f"Credential source at {sink_data.get('source_file', '?')}",
                    f"LLM client at {graph.nodes[llm_clients[0]].get('source_file', '?')}",
                ],
                confidence=0.75,
                exploit_reproducible=False,
                remediation=[
                    "Never expose API keys or secrets in the LLM context window",
                    "Use secret management services (AWS Secrets Manager, Vault)",
                    "Rotate all API keys if a prompt injection vulnerability exists",
                ],
            ))
        return findings
