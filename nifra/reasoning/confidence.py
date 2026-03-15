from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfidenceComponents:
    rule_confidence: float      # 0.0-1.0 from rule engine
    llm_confidence: float       # 0.0-1.0 from LLM self-report
    evidence_count: int         # number of graph paths that triggered the rule
    exploit_validated: bool     # True if reproduce --case confirmed it


def compute_hybrid_confidence(components: ConfidenceComponents) -> float:
    """
    Compute the final hybrid confidence score.

    Caps at 0.97 — NIfra never claims 100% certainty.
    Floor at 0.05 — if we report it, there's at least some basis.
    """
    base = components.rule_confidence * components.llm_confidence

    # Boost for multiple evidence paths
    evidence_boost = min(0.1 * (components.evidence_count - 1), 0.15)

    # Boost if exploit has been reproduced (empirically confirmed)
    validation_boost = 0.10 if components.exploit_validated else 0.0

    score = base + evidence_boost + validation_boost
    return round(min(max(score, 0.05), 0.97), 2)
