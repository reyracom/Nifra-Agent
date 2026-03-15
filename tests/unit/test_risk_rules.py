import networkx as nx
from nifra.graph.rules.prompt_injection import PromptInjectionRule, DirectInjectionRule
from nifra.graph.rules.tool_abuse import ToolAbuseRule, SSRFViaAgentRule
from nifra.graph.rules.supply_chain import LLMOutputCodeExecRule, SupplyChainRule
from nifra.graph.rules.data_exfiltration import DataExfiltrationRule, CredentialLeakRule
from nifra.graph.nodes import NodeType, TrustLevel


def _make_graph_with_nodes(*node_specs):
    g = nx.DiGraph()
    for nid, attrs in node_specs:
        g.add_node(nid, **attrs)
    return g


def test_prompt_injection_fires():
    g = _make_graph_with_nodes(
        ("doc1", {"node_type": NodeType.EXTERNAL_DOCUMENT.value}),
        ("rag1", {"node_type": NodeType.RAG_LOADER.value, "has_content_validation": False, "label": "RetrievalQA", "source_file": "app.py"}),
    )
    findings = PromptInjectionRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "PI-001"


def test_prompt_injection_no_fire_when_validated():
    g = _make_graph_with_nodes(
        ("doc1", {"node_type": NodeType.EXTERNAL_DOCUMENT.value}),
        ("rag1", {"node_type": NodeType.RAG_LOADER.value, "has_content_validation": True}),
    )
    findings = PromptInjectionRule().evaluate(g)
    assert findings == []


def test_tool_abuse_fires():
    g = _make_graph_with_nodes(
        ("tool1", {
            "node_type": NodeType.AGENT_TOOL.value,
            "capability": "code_exec",
            "has_scope_restriction": False,
            "tool_name": "python_repl",
            "label": "python_repl",
            "source_file": "agent.py",
            "line_number": 42,
        }),
    )
    findings = ToolAbuseRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "TA-001"
    assert findings[0].severity.value == "critical"


def test_tool_abuse_no_fire_when_restricted():
    g = _make_graph_with_nodes(
        ("tool1", {
            "node_type": NodeType.AGENT_TOOL.value,
            "capability": "code_exec",
            "has_scope_restriction": True,
        }),
    )
    assert ToolAbuseRule().evaluate(g) == []


def test_code_exec_rule_fires():
    g = _make_graph_with_nodes(
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "sink_type": "code_exec",
            "label": "eval",
            "source_file": "app.py",
            "line_number": 10,
        }),
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value, "source_file": "app.py"}),
    )
    findings = LLMOutputCodeExecRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-002"


# ---------------------------------------------------------------------------
# DirectInjectionRule (PI-002)
# ---------------------------------------------------------------------------

def test_direct_injection_fires_when_user_input_and_system_prompt_coexist():
    """PI-002 fires when UserInput node AND a system PromptTemplate are both present."""
    g = _make_graph_with_nodes(
        ("ui1", {"node_type": NodeType.USER_INPUT.value, "trust_level": TrustLevel.UNTRUSTED.value}),
        ("pt1", {
            "node_type": NodeType.PROMPT_TEMPLATE.value,
            "is_system_prompt": True,
            "label": "SystemPrompt",
            "source_file": "app.py",
        }),
    )
    findings = DirectInjectionRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "PI-002"


def test_direct_injection_no_fire_without_system_prompt():
    """No system prompt template → rule should not fire."""
    g = _make_graph_with_nodes(
        ("ui1", {"node_type": NodeType.USER_INPUT.value}),
        ("pt1", {"node_type": NodeType.PROMPT_TEMPLATE.value, "is_system_prompt": False}),
    )
    findings = DirectInjectionRule().evaluate(g)
    assert findings == []


def test_direct_injection_no_fire_when_no_user_input():
    g = _make_graph_with_nodes(
        ("pt1", {"node_type": NodeType.PROMPT_TEMPLATE.value, "is_system_prompt": True}),
    )
    findings = DirectInjectionRule().evaluate(g)
    assert findings == []


# ---------------------------------------------------------------------------
# SSRFViaAgentRule (TA-002)
# ---------------------------------------------------------------------------

def test_ssrf_rule_fires_for_http_tool_without_restriction():
    g = _make_graph_with_nodes(
        ("tool1", {
            "node_type": NodeType.AGENT_TOOL.value,
            "capability": "http",
            "has_scope_restriction": False,
            "tool_name": "web_browser",
            "label": "web_browser",
            "source_file": "agent.py",
        }),
    )
    findings = SSRFViaAgentRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "TA-002"
    assert findings[0].severity.value == "high"


def test_ssrf_rule_no_fire_when_restricted():
    g = _make_graph_with_nodes(
        ("tool1", {
            "node_type": NodeType.AGENT_TOOL.value,
            "capability": "http",
            "has_scope_restriction": True,
        }),
    )
    assert SSRFViaAgentRule().evaluate(g) == []


def test_ssrf_rule_no_fire_for_non_http_tool():
    g = _make_graph_with_nodes(
        ("tool1", {
            "node_type": NodeType.AGENT_TOOL.value,
            "capability": "search",
            "has_scope_restriction": False,
        }),
    )
    assert SSRFViaAgentRule().evaluate(g) == []


# ---------------------------------------------------------------------------
# SupplyChainRule (SC-001)
# ---------------------------------------------------------------------------

def test_supply_chain_rule_fires_for_untrusted_package():
    g = _make_graph_with_nodes(
        ("pkg1", {
            "node_type": NodeType.AGENT_TOOL.value,
            "trust_level": TrustLevel.UNTRUSTED.value,
            "label": "langchain-community-tool",
            "source_file": "requirements.txt",
        }),
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value}),
    )
    findings = SupplyChainRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "SC-001"


def test_supply_chain_rule_no_fire_when_no_community_tools():
    g = _make_graph_with_nodes(
        ("tool1", {
            "node_type": NodeType.AGENT_TOOL.value,
            "label": "my_trusted_tool",
            "source_file": "tools.py",
        }),
    )
    assert SupplyChainRule().evaluate(g) == []


# ---------------------------------------------------------------------------
# DataExfiltrationRule (DE-001) — full branch coverage
# ---------------------------------------------------------------------------

def test_data_exfiltration_fires_with_pii_sink_no_filter():
    g = _make_graph_with_nodes(
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "contains_pii": True,
            "has_output_filter": False,
            "label": "CustomerDB",
            "source_file": "db.py",
        }),
    )
    findings = DataExfiltrationRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "DE-001"
    assert findings[0].severity.value == "critical"


def test_data_exfiltration_no_fire_when_output_filter_present():
    g = _make_graph_with_nodes(
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "contains_pii": True,
            "has_output_filter": True,
        }),
    )
    assert DataExfiltrationRule().evaluate(g) == []


def test_data_exfiltration_no_fire_when_no_pii():
    g = _make_graph_with_nodes(
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "contains_pii": False,
            "has_output_filter": False,
        }),
    )
    assert DataExfiltrationRule().evaluate(g) == []


def test_data_exfiltration_fires_when_agent_tool_reaches_pii_sink():
    g = _make_graph_with_nodes(
        ("tool1", {"node_type": NodeType.AGENT_TOOL.value}),
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "contains_pii": True,
            "has_output_filter": False,
            "label": "UserDB",
            "source_file": "db.py",
        }),
    )
    g.add_edge("tool1", "sink1")
    findings = DataExfiltrationRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "DE-001"


def test_data_exfiltration_no_fire_when_tool_not_connected_to_sink():
    """Tool exists but has no edge to the sink — should not fire."""
    g = _make_graph_with_nodes(
        ("tool1", {"node_type": NodeType.AGENT_TOOL.value}),
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "contains_pii": True,
            "has_output_filter": False,
        }),
    )
    # No edge between tool and sink
    findings = DataExfiltrationRule().evaluate(g)
    assert findings == []


def test_data_exfiltration_evidence_contains_sink_label():
    g = _make_graph_with_nodes(
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "contains_pii": True,
            "has_output_filter": False,
            "label": "MySuperSecretDB",
            "source_file": "models.py",
        }),
    )
    findings = DataExfiltrationRule().evaluate(g)
    assert any("MySuperSecretDB" in e for f in findings for e in f.evidence)


def test_data_exfiltration_exploit_is_reproducible():
    g = _make_graph_with_nodes(
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "contains_pii": True,
            "has_output_filter": False,
            "label": "DB",
            "source_file": "app.py",
        }),
    )
    findings = DataExfiltrationRule().evaluate(g)
    assert findings[0].exploit_reproducible is True


def test_data_exfiltration_multiple_pii_sinks_multiple_findings():
    g = _make_graph_with_nodes(
        ("sink1", {"node_type": NodeType.DATA_SINK.value, "contains_pii": True, "has_output_filter": False,
                   "label": "DB1", "source_file": "a.py"}),
        ("sink2", {"node_type": NodeType.DATA_SINK.value, "contains_pii": True, "has_output_filter": False,
                   "label": "DB2", "source_file": "b.py"}),
    )
    findings = DataExfiltrationRule().evaluate(g)
    assert len(findings) == 2


def test_data_exfiltration_no_fire_when_no_sinks():
    g = _make_graph_with_nodes(
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value}),
    )
    assert DataExfiltrationRule().evaluate(g) == []


# ---------------------------------------------------------------------------
# CredentialLeakRule (DE-002) — full branch coverage
# ---------------------------------------------------------------------------

def test_credential_leak_fires_with_env_sink_and_llm_client():
    g = _make_graph_with_nodes(
        ("sink1", {
            "node_type": NodeType.DATA_SINK.value,
            "sink_type": "env",
            "source_file": "config.py",
        }),
        ("llm1", {
            "node_type": NodeType.LLM_CLIENT.value,
            "source_file": "app.py",
        }),
    )
    findings = CredentialLeakRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "DE-002"
    assert findings[0].severity.value == "high"


def test_credential_leak_fires_for_config_sink_type():
    g = _make_graph_with_nodes(
        ("sink1", {"node_type": NodeType.DATA_SINK.value, "sink_type": "config", "source_file": "cfg.py"}),
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value, "source_file": "app.py"}),
    )
    findings = CredentialLeakRule().evaluate(g)
    assert len(findings) == 1
    assert findings[0].rule_id == "DE-002"


def test_credential_leak_fires_for_secrets_sink_type():
    g = _make_graph_with_nodes(
        ("sink1", {"node_type": NodeType.DATA_SINK.value, "sink_type": "secrets", "source_file": "vault.py"}),
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value, "source_file": "app.py"}),
    )
    findings = CredentialLeakRule().evaluate(g)
    assert len(findings) == 1


def test_credential_leak_no_fire_when_no_llm_client():
    g = _make_graph_with_nodes(
        ("sink1", {"node_type": NodeType.DATA_SINK.value, "sink_type": "env", "source_file": "cfg.py"}),
    )
    assert CredentialLeakRule().evaluate(g) == []


def test_credential_leak_no_fire_when_no_credential_sinks():
    g = _make_graph_with_nodes(
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value}),
        ("sink1", {"node_type": NodeType.DATA_SINK.value, "sink_type": "vector_db", "source_file": "a.py"}),
    )
    assert CredentialLeakRule().evaluate(g) == []


def test_credential_leak_no_fire_with_empty_graph():
    g = _make_graph_with_nodes()
    assert CredentialLeakRule().evaluate(g) == []


def test_credential_leak_exploit_not_reproducible():
    """Credential leak is harder to reproduce — should be False."""
    g = _make_graph_with_nodes(
        ("sink1", {"node_type": NodeType.DATA_SINK.value, "sink_type": "env", "source_file": "cfg.py"}),
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value, "source_file": "app.py"}),
    )
    findings = CredentialLeakRule().evaluate(g)
    assert findings[0].exploit_reproducible is False


def test_credential_leak_evidence_references_source_files():
    g = _make_graph_with_nodes(
        ("sink1", {"node_type": NodeType.DATA_SINK.value, "sink_type": "env", "source_file": "secrets_loader.py"}),
        ("llm1", {"node_type": NodeType.LLM_CLIENT.value, "source_file": "main.py"}),
    )
    findings = CredentialLeakRule().evaluate(g)
    evidence_text = " ".join(findings[0].evidence)
    assert "secrets_loader.py" in evidence_text or "main.py" in evidence_text
