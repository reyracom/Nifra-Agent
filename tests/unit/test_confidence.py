from nifra.reasoning.confidence import ConfidenceComponents, compute_hybrid_confidence


def test_compute_hybrid_confidence_basic():
    c = ConfidenceComponents(
        rule_confidence=0.9,
        llm_confidence=0.8,
        evidence_count=2,
        exploit_validated=False,
    )
    result = compute_hybrid_confidence(c)
    # base = 0.72, evidence_boost = 0.10, final = 0.82
    assert 0.80 <= result <= 0.85


def test_confidence_caps_at_097():
    c = ConfidenceComponents(1.0, 1.0, 10, True)
    result = compute_hybrid_confidence(c)
    assert result <= 0.97


def test_confidence_floor_at_005():
    c = ConfidenceComponents(0.0, 0.0, 0, False)
    result = compute_hybrid_confidence(c)
    assert result >= 0.05


def test_validation_boost():
    c1 = ConfidenceComponents(0.7, 0.7, 1, False)
    c2 = ConfidenceComponents(0.7, 0.7, 1, True)
    assert compute_hybrid_confidence(c2) > compute_hybrid_confidence(c1)
