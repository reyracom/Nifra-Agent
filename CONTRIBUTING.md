# Contributing to NIfra

Thank you for contributing to NIfra. Security tooling is a community effort.

## Ways to Contribute

### 1. Attack Cases (Highest Impact — No Python Required)

Submit YAML files to `attacks/`. Security researchers, pentesters, and AI security
practitioners can contribute expertise without needing to understand the codebase.

See [`attacks/README.md`](../attacks/README.md) for the YAML schema.

**Good first contribution:** If you've found an interesting AI vulnerability pattern
that isn't covered yet, write it up as a YAML case.

### 2. Detection Rules

Add new risk rules to `nifra/graph/rules/`. Each rule is a Python class:

```python
from nifra.graph.rules import BaseRiskRule, RiskFinding, Severity

class MyNewRule(BaseRiskRule):
    rule_id = "XX-001"
    rule_name = "Short descriptive name"
    severity = Severity.HIGH
    owasp_ref = "LLM01"

    def evaluate(self, graph: nx.DiGraph) -> list[RiskFinding]:
        findings = []
        # traverse the graph, return RiskFinding objects
        return findings
```

Then register it in `nifra/graph/rules/__init__.py`.

### 3. Framework Patterns

Add new LLM framework patterns to `nifra/detectors/pattern_registry.py`.
If a new framework (e.g., a new agent library) isn't detected, this is the place to add it.

### 4. Core Engine

Contribution areas:
- Improve AST pattern detection accuracy
- Add JavaScript/TypeScript support
- Improve graph edge inference
- Add new report formats

## Development Setup

```bash
git clone https://github.com/reyracom/Nifra-Agent.git
cd Nifra-Agent
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Lint:

```bash
ruff check .
```

## Pull Request Guidelines

1. **One PR = one concern.** Don't mix attack cases with code changes.
2. **Test your changes.** Every code change needs a test.
3. **Attack cases need evidence.** Link to a CVE, paper, or public disclosure.
4. **No weaponized payloads.** Attack case payloads must show structure, not full weapons.
5. **Follow the code style.** Run `ruff check .` before submitting.

## Code of Conduct

NIfra follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

---

## Supporting the Project

NIfra is built and maintained by **[ReyraLabs](https://reyralabs.com)** — a security research lab from Surabaya, Indonesia 🇮🇩.

If this project has been valuable to you or your organization, consider sponsoring its development:

**💠 USDC (Base Network):** `0xace4ac1f6ccf9782fd8ec45b2bfeca265392a154`

All funds go directly toward research, new attack cases, and framework support.
