from __future__ import annotations

import json
from pathlib import Path

from nifra.graph.builder import AttackSurfaceGraph
from nifra.reasoning.engine import ExploitChain, ReasoningResult

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_OWASP_RULE_URLS: dict[str, str] = {
    "PI-001": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01",
    "PI-002": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01",
    "PI-003": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01",
    "PI-004": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01",
    "PI-005": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01",
    "PI-006": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm01",
    "TA-001": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm07",
    "TA-002": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm07",
    "TA-003": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm07",
    "TA-004": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm07",
    "TA-005": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm07",
    "TA-006": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm08",
    "DE-001": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02",
    "DE-002": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02",
    "DE-003": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm06",
    "DE-004": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm06",
    "DE-005": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm06",
    "SC-001": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm05",
    "SC-002": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm05",
    "SC-003": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm05",
    "SC-004": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm05",
    "EA-001": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm08",
    "EA-002": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm08",
    "EA-003": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm08",
    "EA-004": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm08",
    "IO-001": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02",
    "IO-002": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02",
    "IO-003": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02",
    "IO-004": "https://owasp.org/www-project-top-10-for-large-language-model-applications/#llm02",
}


class SARIFReporter:
    """
    Generate SARIF 2.1.0 output for GitHub Security tab integration.

    SARIF (Static Analysis Results Interchange Format) is the standard
    format consumed by GitHub Code Scanning, VS Code, and IDEs.

    Usage:
        reporter = SARIFReporter()
        sarif = reporter.render(attack_surface, reasoning_result, "my-agent")
        reporter.write(attack_surface, reasoning_result, "my-agent", Path("results.sarif"))
    """

    NIFRA_VERSION = "0.2.0"

    def render(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
    ) -> dict:
        chains = reasoning_result.exploit_chains
        rules = self._build_rules(chains)
        results = self._build_results(chains)

        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "NIfra",
                            "version": self.NIFRA_VERSION,
                            "semanticVersion": self.NIFRA_VERSION,
                            "informationUri": "https://github.com/reyracom/Nifra-Agent",
                            "organization": "ReyraLabs",
                            "fullDescription": {
                                "text": (
                                    "AI Application Security Autopilot — automated exploit simulation, "
                                    "attack surface mapping and pipeline protection for LLM apps and AI agents."
                                )
                            },
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                        }
                    ],
                    "properties": {
                        "project": project_name,
                        "nodeCount": attack_surface.node_count,
                        "edgeCount": attack_surface.edge_count,
                        "riskLevel": reasoning_result.risk_level,
                        "totalFindings": len(chains),
                        "criticalFindings": sum(
                            1 for c in chains if c.severity == "critical"
                        ),
                        "highFindings": sum(1 for c in chains if c.severity == "high"),
                    },
                }
            ],
        }

    def render_json(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
    ) -> str:
        return json.dumps(
            self.render(attack_surface, reasoning_result, project_name),
            indent=2,
            ensure_ascii=False,
        )

    def write(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
        output: Path,
    ) -> None:
        content = self.render_json(attack_surface, reasoning_result, project_name)
        output.write_text(content, encoding="utf-8")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_rules(self, chains: list[ExploitChain]) -> list[dict]:
        seen: set[str] = set()
        rules: list[dict] = []

        for chain in chains:
            rule_id = chain.finding_rule_id
            if rule_id in seen:
                continue
            seen.add(rule_id)

            rule: dict = {
                "id": rule_id,
                "name": f"NIfraAI/{rule_id}",
                "shortDescription": {
                    "text": f"AI Security Finding: {rule_id}"
                },
                "fullDescription": {
                    "text": chain.reasoning or f"AI security vulnerability detected: {rule_id}"
                },
                "defaultConfiguration": {
                    "level": _SEVERITY_LEVEL.get(chain.severity, "warning")
                },
                "properties": {
                    "tags": ["ai-security", "owasp-llm", chain.severity],
                    "severity": chain.severity,
                    "precision": "high" if chain.confidence >= 0.8 else "medium",
                    "problem.severity": chain.severity,
                },
            }

            help_url = _OWASP_RULE_URLS.get(rule_id)
            if help_url:
                rule["helpUri"] = help_url
                rule["help"] = {
                    "text": f"See OWASP LLM Top 10: {help_url}",
                    "markdown": f"See [OWASP LLM Top 10]({help_url}) for remediation guidance.",
                }

            # Add remediation as a fix in the rule definition
            if chain.remediation:
                fix_text = "\n".join(
                    f"- {r.get('action', str(r))}" for r in chain.remediation
                )
                rule["properties"]["remediation"] = fix_text

            rules.append(rule)

        return rules

    def _build_results(self, chains: list[ExploitChain]) -> list[dict]:
        results: list[dict] = []

        for chain in chains:
            attack_chain_text = " → ".join(chain.attack_chain_steps)
            message_text = (
                f"{chain.reasoning}\n\n"
                f"**Impact:** {chain.impact}\n\n"
                f"**Attack Chain:** {attack_chain_text}\n\n"
                f"**CVSS-AI Score:** {chain.cvss_ai}/10  |  "
                f"**Confidence:** {chain.confidence:.0%}"
            )

            result: dict = {
                "ruleId": chain.finding_rule_id,
                "level": _SEVERITY_LEVEL.get(chain.severity, "warning"),
                "message": {
                    "text": message_text,
                },
                "properties": {
                    "caseId": chain.case_id,
                    "severity": chain.severity,
                    "confidence": chain.confidence,
                    "cvssAi": chain.cvss_ai,
                    "exploitReproducible": chain.exploit_reproducible,
                    "attackChain": chain.attack_chain_steps,
                    "impact": chain.impact,
                    "remediation": [
                        r.get("action", str(r)) for r in chain.remediation
                    ],
                },
            }

            # Include adversarial payload only if reproducible (not just a hypothesis)
            if chain.exploit_reproducible and chain.adversarial_payload:
                result["properties"]["adversarialPayload"] = chain.adversarial_payload

            # SARIF fix suggestions
            if chain.remediation:
                result["fixes"] = [
                    {
                        "description": {
                            "text": r.get("action", str(r))
                        }
                    }
                    for r in chain.remediation[:3]  # top 3 fixes
                ]

            results.append(result)

        return results
