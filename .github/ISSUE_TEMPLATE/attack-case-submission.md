---
name: "🎯 New Attack Case"
about: "Submit a new AI application attack scenario for the community library"
title: "[ATTACK CASE] "
labels: ["attack-case", "community"]
---

## Attack Case Submission

Before submitting, check `attacks/README.md` for the YAML schema.

## YAML Draft

```yaml
id: PI-XXX  # Use the next available ID in the relevant category
name: ""
owasp_ref:  # LLM01 / LLM02 / etc.
severity:   # critical | high | medium | low
description: |
  
conditions:
  requires:
    - key: value

exploit_template: |
  # Do NOT include fully weaponized payloads.
  # Show the structure/pattern, not a ready-to-use weapon.

expected_behavior: ""
impact: ""
remediation:
  - ""
references:
  - ""
```

## Evidence / References

Please provide at least one public reference (CVE, paper, blog post, OWASP entry) that backs this attack scenario.

## Checklist

- [ ] No fully weaponized payloads
- [ ] Public reference provided
- [ ] Tested against a real application (or clear theoretical basis)
- [ ] Remediation steps are actionable
