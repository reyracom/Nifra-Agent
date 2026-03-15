"""
Risk Rule Engine — Step 2c of NIfra pipeline.

Evaluates the attack surface graph against a set of risk rules to
identify dangerous patterns and produce findings.

Rules are purely deterministic — they don't use LLM reasoning.
The output feeds into the AI reasoning engine (Step 3) along with
the full graph for exploit chain generation.

Adding a new rule: create a subclass of BaseRiskRule and register it
in RISK_RULES at the bottom of this file.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import networkx as nx


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskFinding:
    """A single risk finding produced by a rule evaluation."""
    rule_id: str
    rule_name: str
    severity: Severity
    owasp_ref: str
    description: str
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.8
    exploit_reproducible: bool = False
    remediation: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "owasp_ref": self.owasp_ref,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "exploit_reproducible": self.exploit_reproducible,
            "remediation": self.remediation,
        }


class BaseRiskRule(ABC):
    """
    Abstract base class for all NIfra risk rules.

    Subclass this and implement `evaluate()` to add a new rule.
    Register the class in RISK_RULES at the bottom of this file.
    """

    rule_id: str
    rule_name: str
    severity: Severity
    owasp_ref: str

    @abstractmethod
    def evaluate(self, graph: "nx.DiGraph") -> list[RiskFinding]:
        """
        Evaluate this rule against the attack surface graph.

        Returns a list of findings (empty if no issues found).
        """
        ...


# Rules are imported from sub-modules and registered here
# Import each rule module to trigger class registration
from nifra.graph.rules.prompt_injection import DirectInjectionRule, PromptInjectionRule
from nifra.graph.rules.tool_abuse import SSRFViaAgentRule, ToolAbuseRule
from nifra.graph.rules.data_exfiltration import CredentialLeakRule, DataExfiltrationRule
from nifra.graph.rules.supply_chain import LLMOutputCodeExecRule, SupplyChainRule

RISK_RULES: list[type[BaseRiskRule]] = [
    PromptInjectionRule,
    DirectInjectionRule,
    ToolAbuseRule,
    SSRFViaAgentRule,
    DataExfiltrationRule,
    CredentialLeakRule,
    SupplyChainRule,
    LLMOutputCodeExecRule,
]
