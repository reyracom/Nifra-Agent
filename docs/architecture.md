# NIfra Architecture

## Overview

NIfra uses a 4-step hybrid pipeline that separates deterministic analysis from AI reasoning. This design keeps false positive rates low while still producing human-readable exploit narratives.

```
Codebase Static Analysis (Steps 1-2)    │    AI Reasoning (Step 3)
                                         │
Step 1: DETECT ──► Step 2: GRAPH BUILD ──┼──► Step 3: REASON ──► Step 4: REPORT
                                         │
Deterministic, fast, high precision      │    LLM-augmented, narrative quality
```

---

## Step 1 — Deterministic Detection

**Module:** `nifra/detectors/`

Two complementary approaches:

### 1a. Dependency Scanner (`dependency_scanner.py`)

Scans project dependency files for AI/LLM library usage:
- `requirements.txt`
- `pyproject.toml`
- `package.json`

Outputs a `DependencyScanResult` with detected libraries, their vendor, type, and risk weight.

### 1b. AST Parser (`ast_parser.py`)

Traverses Python Abstract Syntax Trees to find usage patterns that dependency scanning misses:
- Dynamic instantiation: `get_llm_from_env()`
- Factory patterns: `factory.create("gpt")`
- Config-driven: `model = config["model_class"]`

Uses Python's built-in `ast` module. Zero additional dependencies. Handles syntax errors gracefully.

### 1c. Pattern Registry (`pattern_registry.py`)

Central catalogue of known AI framework class names, decorators, and patterns. Community can add entries here to support new frameworks without touching parser logic.

---

## Step 2 — Attack Surface Graph

**Module:** `nifra/graph/`

### Graph Model

Uses NetworkX `DiGraph`. Nodes represent security-relevant components; edges represent data flow and trust relationships.

**Node Types:**

| Node | represents | OWASP relevance |
|---|---|---|
| `UserInput` | Direct user-controlled input | LLM01 |
| `ExternalDocument` | File, URL, email (untrusted) | LLM01 |
| `RAGLoader` | Document ingestion / retrieval | LLM01, LLM06 |
| `PromptTemplate` | System/human prompt construction | LLM01 |
| `LLMClient` | The actual LLM API call | LLM01, LLM02 |
| `AgentExecutor` | Agent loop controller | LLM07, LLM08 |
| `AgentTool` | Tool the agent can invoke | LLM07, LLM08 |
| `DataSink` | Database, file, API write | LLM02, LLM06 |

### Risk Rule Engine

Rules are pure Python classes that evaluate graph structure and return findings.

```python
class MyNewRule(BaseRiskRule):
    rule_id = "XX-001"
    severity = Severity.HIGH
    
    def evaluate(self, graph: nx.DiGraph) -> list[RiskFinding]:
        # traverse graph, return findings
        ...
```

Rules are registered in `nifra/graph/rules/__init__.py`.

---

## Step 3 — AI Reasoning Engine

**Module:** `nifra/reasoning/`

The LLM reasoning layer receives:
1. Full attack surface graph as JSON
2. Each confirmed risk finding from Step 2
3. A structured prompt template (`prompts/exploit_chain.txt`)

And outputs:
- Exploit chain narrative (step-by-step)
- Adversarial payload example
- Impact analysis
- Confidence score (hybrid, see below)
- Remediation recommendations

### Hybrid Confidence Scoring

```
final_confidence = rule_confidence × llm_confidence + evidence_boost + validation_boost
```

- `rule_confidence`: how certain the deterministic rule is
- `llm_confidence`: LLM's self-reported certainty
- `evidence_boost`: +0.05 per additional confirming graph path (max +0.15)
- `validation_boost`: +0.10 if exploit was confirmed by `nifra reproduce`

Caps at 0.97 — NIfra never claims 100% certainty.

---

## Step 4 — Reporters

**Module:** `nifra/reporters/`

| Reporter | Format | Use case |
|---|---|---|
| `CLIReporter` | Terminal (Rich) | Default scan output |
| `JSONReporter` | JSON | CI/CD machine-readable |
| `HTMLReporter` | HTML + JS | Interactive attack graph |
| `MarkdownReporter` | Markdown | GitHub PR comments |

---

## Data Flow Diagram

```
requirements.txt ──┐
pyproject.toml   ──┤
package.json     ──┤
                   ▼
             DependencyScanner
                   │
                   ▼
Python .py files ──► ASTParser
                   │
                   ▼
          AttackSurfaceGraphBuilder
                   │
                   ├── nodes (typed)
                   ├── edges (inferred)
                   └── risk rules
                   │
                   ▼
          AttackSurfaceGraph (NetworkX DAG)
                   │
                   ▼
          ReasoningEngine (LLM)
                   │
                   ├── exploit chains
                   ├── payloads
                   └── recommendations
                   │
                   ▼
              Reporters
          (CLI / JSON / HTML / MD)
```

---

## Design Decisions

### Why NetworkX?

- Pure Python, well-maintained, battle-tested
- Exports to JSON, GraphML, DOT with one call
- Enables path algorithms (shortest path between untrusted source → sensitive sink)
- No graph database setup required for users

### Why Separate Detection from Reasoning?

Feeding raw code to an LLM for vulnerability detection produces too many false positives and is computationally expensive. Deterministic detection provides high-precision signal; LLM reasoning adds explainability and exploit narrative.

### Why YAML for Attack Cases?

Security researchers are comfortable with YAML (Nuclei, Sigma). It lowers the barrier to contribution significantly versus Python. A researcher can submit an attack case without needing to understand the NIfra codebase.
