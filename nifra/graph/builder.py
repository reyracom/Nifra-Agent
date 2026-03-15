from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import networkx as nx

from nifra.detectors.ast_parser import ASTScanResult
from nifra.detectors.dependency_scanner import DependencyScanResult
from nifra.graph.edges import EdgeInferrer
from nifra.graph.nodes import (
    AgentExecutorNode,
    AgentToolNode,
    BaseNode,
    DataSinkNode,
    ExternalDocumentNode,
    LLMClientNode,
    NodeType,
    PromptTemplateNode,
    RAGLoaderNode,
    TrustLevel,
    UserInputNode,
)
from nifra.graph.rules import RISK_RULES, RiskFinding


class AttackSurfaceGraph:
    """The attack surface DAG for an AI application."""

    def __init__(self, graph: nx.DiGraph, project_path: Path) -> None:
        self._graph = graph
        self.project_path = project_path
        self.findings: list[RiskFinding] = []

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def get_nodes_by_type(self, node_type: NodeType) -> list[dict]:
        return [
            data for _, data in self._graph.nodes(data=True)
            if data.get("node_type") == node_type.value
        ]

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n, **data}
                for n, data in self._graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **data}
                for u, v, data in self._graph.edges(data=True)
            ],
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# Vendor name mapping (class_name → vendor string)
_VENDOR_MAP = {
    "OpenAI": "openai", "AsyncOpenAI": "openai", "AzureOpenAI": "openai",
    "ChatOpenAI": "openai",
    "ChatAnthropic": "anthropic", "Anthropic": "anthropic", "AsyncAnthropic": "anthropic",
    "ChatGoogleGenerativeAI": "google", "GoogleGenerativeAI": "google",
    "ChatVertexAI": "google", "VertexAI": "google",
    "ChatCohere": "cohere", "ChatGroq": "groq", "ChatMistralAI": "mistral",
    "OpenAIChatCompletion": "openai", "AzureChatCompletion": "openai",
}

# Tool keyword → capability mapping
_TOOL_CAPABILITY_KEYWORDS = {
    ("shell", "bash", "terminal", "subprocess", "run_command"): "shell",
    ("exec", "python_repl", "code", "execute"): "code_exec",
    ("filesystem", "file", "read_file", "write_file", "open"): "filesystem",
    ("database", "db", "sql", "query", "sqlite", "postgres"): "db",
    ("http", "requests", "web", "scrape", "fetch", "url", "browse"): "http",
    ("email", "send_email", "mail", "smtp"): "email",
    ("search", "google", "serp", "bing", "ddg", "tavily"): "search",
}


def _infer_vendor(class_name: str) -> str:
    return _VENDOR_MAP.get(class_name, "unknown")


def _infer_tool_capability(tool_name: str) -> str:
    lower = tool_name.lower()
    for keywords, cap in _TOOL_CAPABILITY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return cap
    return "unknown"


def _infer_source_type(source_path: str) -> str:
    if not source_path:
        return "unknown"
    lower = source_path.lower()
    if lower.startswith(("http://", "https://")):
        return "url"
    if lower.startswith(("s3://", "gs://", "azure://")):
        return "cloud_storage"
    if any(ext in lower for ext in (".pdf", ".docx", ".html", ".txt", ".md")):
        return "file"
    return "unknown"


class AttackSurfaceGraphBuilder:
    """Build an attack surface graph from static analysis results."""

    def __init__(
        self,
        dep_result: DependencyScanResult,
        ast_result: ASTScanResult,
    ) -> None:
        self.dep_result = dep_result
        self.ast_result = ast_result
        self._graph = nx.DiGraph()
        self._node_counter = 0

    def build(self) -> AttackSurfaceGraph:
        self._infer_nodes()
        self._infer_edges()
        attack_surface = AttackSurfaceGraph(
            graph=self._graph,
            project_path=self.dep_result.project_path,
        )
        attack_surface.findings = self._apply_risk_rules()
        return attack_surface

    def _infer_nodes(self) -> None:
        has_llm = False
        has_agent = False

        for pattern in self.ast_result.patterns:
            ptype = pattern.pattern_type
            cls = pattern.class_or_func
            sf = pattern.file_path
            ln = pattern.line_number

            if ptype == "llm_init":
                node = LLMClientNode(
                    id=self._next_id("llm"),
                    label=cls,
                    source_file=sf,
                    line_number=ln,
                    vendor=_infer_vendor(cls),
                    risk_weight=1.0,
                )
                self._add_node(node)
                has_llm = True

            elif ptype == "agent_init":
                tools = pattern.extra.get("tools", [])
                node = AgentExecutorNode(
                    id=self._next_id("agent"),
                    label=cls,
                    source_file=sf,
                    line_number=ln,
                    tool_count=len(tools),
                    has_tool_validation=False,
                )
                self._add_node(node)
                has_agent = True

            elif ptype == "tool_registration":
                tool_name = pattern.extra.get("tool_name", cls)
                cap = _infer_tool_capability(tool_name)
                node = AgentToolNode(
                    id=self._next_id("tool"),
                    label=tool_name,
                    source_file=sf,
                    line_number=ln,
                    tool_name=tool_name,
                    capability=cap,
                    is_destructive=cap in {"code_exec", "filesystem", "shell"},
                    has_scope_restriction=False,
                )
                self._add_node(node)

            elif ptype == "rag_chain":
                node = RAGLoaderNode(
                    id=self._next_id("rag"),
                    label=cls,
                    source_file=sf,
                    line_number=ln,
                    has_content_validation=False,
                    has_trust_scoring=False,
                )
                self._add_node(node)

            elif ptype == "document_loader":
                src = pattern.extra.get("source", "")
                node = ExternalDocumentNode(
                    id=self._next_id("doc"),
                    label=cls,
                    source_file=sf,
                    line_number=ln,
                    source_type=_infer_source_type(src),
                    trust_level=TrustLevel.UNTRUSTED,
                )
                self._add_node(node)

            elif ptype == "prompt_template":
                is_sys = pattern.extra.get("is_system", "System" in cls)
                node = PromptTemplateNode(
                    id=self._next_id("prompt"),
                    label=cls,
                    source_file=sf,
                    line_number=ln,
                    is_system_prompt=bool(is_sys),
                    uses_user_content=True,
                    uses_document_content=True,
                )
                self._add_node(node)

            elif ptype == "dangerous_sink":
                node = DataSinkNode(
                    id=self._next_id("sink"),
                    label=cls,
                    source_file=sf,
                    line_number=ln,
                    sink_type="code_exec",
                    contains_pii=False,
                    has_output_filter=False,
                )
                self._add_node(node)

            elif ptype == "vector_store_init":
                node = DataSinkNode(
                    id=self._next_id("vstore"),
                    label=cls,
                    source_file=sf,
                    line_number=ln,
                    sink_type="vector_db",
                    contains_pii=True,
                    has_output_filter=False,
                )
                self._add_node(node)

        # If any LLM/agent usage found, add a generic UserInput entry point
        if has_llm or has_agent:
            user_node = UserInputNode(
                id=self._next_id("input"),
                label="User Input",
                source_file=None,
                trust_level=TrustLevel.UNTRUSTED,
                risk_weight=1.5,
            )
            self._add_node(user_node)

    def _infer_edges(self) -> None:
        inferrer = EdgeInferrer(self._graph)
        inferrer.infer_edges()

    def _apply_risk_rules(self) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        for RuleClass in RISK_RULES:
            rule = RuleClass()
            findings.extend(rule.evaluate(self._graph))
        return findings

    def _add_node(self, node: BaseNode) -> None:
        from dataclasses import fields as dc_fields
        attrs: dict = {}
        for f in dc_fields(node):
            val = getattr(node, f.name)
            if hasattr(val, "value") and not isinstance(val, bool):  # Enum
                attrs[f.name] = val.value
            else:
                attrs[f.name] = val
        self._graph.add_node(node.id, **attrs)

    def _next_id(self, prefix: str = "node") -> str:
        self._node_counter += 1
        return f"{prefix}_{self._node_counter:03d}"
