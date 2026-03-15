# NIfra Attack Case Library

A community-maintained library of AI application attack cases in YAML format.

Each YAML file defines one attack scenario with conditions, exploit template,
expected behavior, and remediation guidance.

## Structure

```
attacks/
├── prompt-injection/       # OWASP LLM01
├── tool-abuse/             # OWASP LLM07, LLM08
├── data-exfiltration/      # OWASP LLM02, LLM06
├── supply-chain/           # OWASP LLM05
├── excessive-agency/       # OWASP LLM08
└── sensitive-disclosure/   # OWASP LLM06
```

## Contributing a New Attack Case

You don't need to know Python. Just create a YAML file following the schema below.

### Case ID Format

- `PI-NNN` — Prompt Injection
- `TA-NNN` — Tool Abuse
- `DE-NNN` — Data Exfiltration
- `SC-NNN` — Supply Chain
- `EA-NNN` — Excessive Agency
- `SD-NNN` — Sensitive Disclosure

### YAML Schema

```yaml
id: PI-XXX
name: "Short descriptive name"
owasp_ref: LLM01
severity: critical | high | medium | low
description: |
  Multi-line description of the vulnerability and attack scenario.
conditions:
  requires:
    - key: value   # application characteristics required for this attack
exploit_template: |
  The attacker input or payload structure.
  Use placeholders like {TARGET} where appropriate.
  Do NOT include fully weaponized payloads.
expected_behavior: "What the vulnerable app does when attacked"
impact: "Real-world consequence"
remediation:
  - "Specific fix action 1"
  - "Specific fix action 2"
references:
  - "URL to relevant research or OWASP entry"
```

See existing files for examples.
