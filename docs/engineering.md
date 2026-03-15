# Engineering Reference

> Internal reference for contributors. Not required reading for users.

---

## Test Suite

```
337 passed in 5.04s  ·  94% total coverage  ·  Python 3.12
```

### Coverage by layer

| Layer | Modules | Coverage |
|---|---|---|
| CLI commands | `scan`, `report`, `reproduce` | 94 – 100% |
| Graph | `builder`, `edges`, `nodes`, `rules/*` | 91 – 100% |
| Reporters | `cli`, `json`, `html`, `markdown` | 97 – 100% |
| Reasoning | `engine`, `confidence` | 97 – 100% |
| Detectors | `ast_parser`, `pattern_registry` | 88 – 100% |
| Detectors | `dependency_scanner` | 79% |

The only meaningful gap is `dependency_scanner` — several branches handle less common manifest formats (Pipfile, pyproject.toml extras) that are tricky to exercise in unit tests without real file fixtures.

---

## Test layout

```
tests/
├── unit/
│   ├── test_ast_parser.py         # ASTParser + PatternRegistry
│   ├── test_dependency_scanner.py # DependencyScanner, pyproject, package.json
│   ├── test_graph_builder.py      # AttackSurfaceGraph, EdgeInferrer, nodes
│   ├── test_reasoning_engine.py   # ExploitChain, ReasoningResult, deterministic
│   ├── test_reporters.py          # JSON / Markdown / HTML / CLI reporters
│   ├── test_risk_rules.py         # All 8 risk rules (PI, TA, SC, DE, ...)
│   ├── test_cli_scan.py           # `nifra scan` via CliRunner
│   ├── test_cli_report.py         # `nifra report` formats via CliRunner
│   └── test_cli_reproduce.py      # `nifra reproduce` dry-run + mock HTTP
└── e2e/
    └── test_full_pipeline.py      # Full pipeline against playground fixtures
```

### E2E scope

`tests/e2e/test_full_pipeline.py` runs the complete deterministic pipeline
(`DependencyScanner → ASTParser → AttackSurfaceGraphBuilder → ReasoningEngine`)
against `playground/vulnerable-rag-agent` and `playground/vulnerable-tool-agent`.

Assertions:
- Graph node / edge minimums
- Expected rule IDs present (`PI-001`, `DE-001`)
- Confidence range `0.0 – 1.0`
- CVSS-AI range `0.0 – 10.0`
- `scan → report` CLI round-trip
- `--fail-on critical` exit code
- Deterministic reproducibility (two runs → identical rule IDs)

---

## Running tests locally

```bash
# All tests with coverage
pytest

# New tests only
pytest tests/unit/test_cli_scan.py tests/unit/test_cli_report.py \
       tests/unit/test_cli_reproduce.py tests/e2e/test_full_pipeline.py -v

# Single module
pytest tests/unit/test_reasoning_engine.py -v
```

---

## Modules missing coverage (details)

| File | Missing lines | Reason |
|---|---|---|
| `cli/commands/scan.py` | 118-121 | `chains = []` dead variable block inside `--no-ai` branch |
| `cli/commands/report.py` | 53 | `Path("./nifra-results.json")` candidate never resolves in tests |
| `cli/main.py` | 19, 23 | `if __name__ == "__main__"` guard |
| `detectors/dependency_scanner.py` | 139-191 | Pipfile / conda / poetry lock parsers, need dedicated fixtures |
| `detectors/ast_parser.py` | various | Edge-case node visitors for less common call patterns |
| `reasoning/engine.py` | 116-117, 226 | OpenAI streaming path (requires live API key) |

---

## Security Audit (pre-publish)

A full audit was performed against OWASP Top 10 before the first public release.
16 issues were found and fixed. All critical and high issues were resolved.

| ID | Severity | File | Issue | Fixed |
|---|---|---|---|---|
| NIFRA-001 | HIGH | `reproduce.py` | SSRF via unvalidated `--target` URL | ✅ `_validate_target()` blocks private IPs + non-https |
| NIFRA-002 | HIGH | `html_reporter.py` | XSS — `chain.severity` unescaped in HTML | ✅ Wrapped with `_esc()` |
| NIFRA-003 | HIGH | `markdown_reporter.py` | HTML/Markdown injection via LLM-sourced fields in PR comments | ✅ `_md_text()` / `_md_inline()` helpers |
| NIFRA-004 | HIGH | `reproduce.py` | Plain HTTP allowed — payload sent in cleartext | ✅ `https://` enforced in `_validate_target()` |
| NIFRA-005 | HIGH | `reproduce.py` | Unvalidated JSON deserialization from external results file | ✅ Schema check + 64 KB payload size limit |
| NIFRA-006 | MEDIUM | `engine.py` | LLM-provided `confidence`/`cvss_ai` not clamped to valid range | ✅ `max(0, min(1, ...))` applied |
| NIFRA-007 | MEDIUM | `reproduce.py` | ANSI escape injection from server response reflected to terminal | ✅ `_ANSI_ESCAPE.sub()` strip before print |
| NIFRA-008 | MEDIUM | `exploit_chain.txt` | Scanned project data injected raw into LLM system prompt | ✅ `<DATA>` boundary delimiters added |
| NIFRA-009 | MEDIUM | `ast_parser.py` | `ast.parse()` crashes on `RecursionError`/`MemoryError` cause DoS | ✅ Caught in except clause + 5 MB file limit |
| NIFRA-010 | MEDIUM | `scan.py` | Default output written inside target dir — risk of accidental git commit of payloads | ✅ Default output now goes to `cwd` |
| NIFRA-011 | LOW | `dependency_scanner.py` | No size guard before reading manifest files | ✅ 10 MB limit added |
| NIFRA-012 | LOW | `report.py` | `node.pop()` mutates deserialized data in-place | ✅ Changed to `node.get()` |
| NIFRA-013 | LOW | `report.py` | Raw `OSError`/`JSONDecodeError` messages leak filesystem paths | ✅ Generic user-facing messages |
| NIFRA-014 | LOW | `reproduce.py` | No confirmation before auto-sending adversarial payload | ✅ `typer.confirm()` gate added |
| NIFRA-015 | LOW | `html_reporter.py` | `_esc()` missing `&#x27;` + no CSP meta tag | ✅ Both added |
| NIFRA-016 | LOW | `ast_parser.py` | No file-size limit before reading source files for AST parse | ✅ Same 5 MB guard as NIFRA-009 |
