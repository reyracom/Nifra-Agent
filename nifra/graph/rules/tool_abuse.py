from __future__ import annotations

from typing import TYPE_CHECKING

from nifra.graph.nodes import AgentToolNode, NodeType
from nifra.graph.rules import BaseRiskRule, RiskFinding, Severity

if TYPE_CHECKING:
    import networkx as nx


class ToolAbuseRule(BaseRiskRule):
    """
    Over-Permissioned Agent Tools

    Fires when: AgentExecutor has registered tools with critical capabilities
    (code_exec, filesystem, shell) and lacks tool-level validation.

    OWASP LLM07 — Insecure Plugin Design
    OWASP LLM08 — Excessive Agency
    """

    rule_id = "TA-001"
    rule_name = "Over-Permissioned Agent Tools"
    severity = Severity.CRITICAL
    owasp_ref = "LLM07, LLM08"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []
        critical_caps = {"code_exec", "filesystem", "shell"}

        dangerous_tools = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.AGENT_TOOL.value
            and d.get("capability", "unknown") in critical_caps
            and not d.get("has_scope_restriction", False)
        ]

        if not dangerous_tools:
            return findings

        for nid, d in dangerous_tools:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                owasp_ref=self.owasp_ref,
                description=(
                    f"Agent tool '{d.get('tool_name', d.get('label', nid))}' has "
                    f"{d.get('capability', 'unknown')} capability with no scope restriction. "
                    "If the agent is compromised via prompt injection, the attacker gains "
                    f"{d.get('capability', 'unknown')} access on the host system."
                ),
                evidence=[
                    f"Tool '{d.get('label', nid)}' at {d.get('source_file', '?')} line {d.get('line_number', '?')}",
                    f"capability={d.get('capability')}, has_scope_restriction=False",
                ],
                confidence=0.90,
                exploit_reproducible=True,
                remediation=[
                    f"Restrict the {d.get('capability')} tool to an allowlist of safe operations",
                    "Add human-in-the-loop confirmation before destructive tool calls",
                    "Run tool execution in an isolated sandbox (Docker, gVisor)",
                    "Implement tool call rate limiting and audit logging",
                ],
            ))
        return findings


class SSRFViaAgentRule(BaseRiskRule):
    """
    Server-Side Request Forgery via Agent HTTP Tool

    Fires when: AgentTool with http capability lacks URL allowlist
    and is reachable from untrusted input.

    OWASP LLM07 — Insecure Plugin Design
    """

    rule_id = "TA-002"
    rule_name = "SSRF via Agent HTTP Tool"
    severity = Severity.HIGH
    owasp_ref = "LLM07"

    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        findings = []

        http_tools = [
            (n, d) for n, d in graph.nodes(data=True)
            if d.get("node_type") == NodeType.AGENT_TOOL.value
            and d.get("capability", "") in {"http", "web", "requests"}
            and not d.get("has_scope_restriction", False)
        ]

        for nid, d in http_tools:
            findings.append(RiskFinding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                owasp_ref=self.owasp_ref,
                description=(
                    f"Agent HTTP tool '{d.get('tool_name', d.get('label', nid))}' has no URL allowlist. "
                    "An attacker can inject instructions causing the agent to issue requests "
                    "to internal services (SSRF), cloud metadata APIs, or data exfiltration endpoints."
                ),
                evidence=[
                    f"HTTP tool '{d.get('label', nid)}' at {d.get('source_file', '?')}",
                    "No URL restriction found (has_scope_restriction=False)",
                ],
                confidence=0.80,
                exploit_reproducible=True,
                remediation=[
                    "Implement a URL allowlist for all agent HTTP tools",
                    "Block requests to RFC1918 addresses and cloud metadata endpoints (169.254.169.254)",
                    "Use an outgoing HTTP proxy with URL filtering",
                ],
            ))
        return findings
