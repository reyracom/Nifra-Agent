from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NodeType(str, Enum):
    USER_INPUT = "user_input"               # Direct user-controlled input
    EXTERNAL_DOCUMENT = "external_document" # File, URL, email, webhook (untrusted)
    RAG_LOADER = "rag_loader"               # Document ingestion / retrieval
    PROMPT_TEMPLATE = "prompt_template"     # System/human prompt construction
    LLM_CLIENT = "llm_client"              # LLM API call
    AGENT_EXECUTOR = "agent_executor"       # Agent loop controller
    AGENT_TOOL = "agent_tool"              # Tool the agent can invoke
    DATA_SINK = "data_sink"                # Database, filesystem, API write
    EXTERNAL_API = "external_api"           # Outbound HTTP call
    MEMORY = "memory"                       # Persistent memory store


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


@dataclass
class BaseNode:
    id: str
    label: str
    node_type: NodeType
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    risk_weight: float = 1.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "node_type": self.node_type.value,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "trust_level": self.trust_level.value,
            "risk_weight": self.risk_weight,
        }


@dataclass
class UserInputNode(BaseNode):
    """
    Direct user-controlled input to the AI application.

    Risk: Primary injection entry point.
    OWASP: LLM01 (Prompt Injection)
    """
    node_type: NodeType = field(default=NodeType.USER_INPUT, init=False)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED


@dataclass
class ExternalDocumentNode(BaseNode):
    """
    External document ingested by the application (file, URL, email, feed).

    Risk: Indirect prompt injection via malicious document content.
    OWASP: LLM01 (Indirect Prompt Injection)
    """
    node_type: NodeType = field(default=NodeType.EXTERNAL_DOCUMENT, init=False)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    source_type: str = "unknown"  # file | url | email | api | webhook


@dataclass
class RAGLoaderNode(BaseNode):
    """
    RAG document loader and retriever.

    Risk: Untrusted content enters prompt context without validation.
    OWASP: LLM01, LLM06
    """
    node_type: NodeType = field(default=NodeType.RAG_LOADER, init=False)
    has_content_validation: bool = False
    has_trust_scoring: bool = False


@dataclass
class PromptTemplateNode(BaseNode):
    """
    Prompt template (system prompt, human message template).

    Risk: Template injection, system prompt override.
    OWASP: LLM01
    """
    node_type: NodeType = field(default=NodeType.PROMPT_TEMPLATE, init=False)
    is_system_prompt: bool = False
    uses_user_content: bool = False
    uses_document_content: bool = False


@dataclass
class LLMClientNode(BaseNode):
    """
    LLM API client (the actual model call).

    Risk: Processes untrusted content from upstream nodes.
    OWASP: LLM01, LLM02, LLM04
    """
    node_type: NodeType = field(default=NodeType.LLM_CLIENT, init=False)
    vendor: str = "unknown"
    model: str = "unknown"


@dataclass
class AgentExecutorNode(BaseNode):
    """
    Agent executor — the component that runs the agent loop and decides tool calls.

    Risk: High. Can be instructed by injected content to invoke tools with
    attacker-controlled arguments.
    OWASP: LLM07, LLM08
    """
    node_type: NodeType = field(default=NodeType.AGENT_EXECUTOR, init=False)
    tool_count: int = 0
    has_tool_validation: bool = False


@dataclass
class AgentToolNode(BaseNode):
    """
    A tool registered with the agent (database, filesystem, HTTP, code_exec, etc.)

    Risk: Varies dramatically by tool capability. code_exec = critical.
    OWASP: LLM07, LLM08
    """
    node_type: NodeType = field(default=NodeType.AGENT_TOOL, init=False)
    tool_name: str = ""
    capability: str = "unknown"  # db | filesystem | http | email | code_exec | search
    is_destructive: bool = False
    has_scope_restriction: bool = False

    @property
    def risk_category(self) -> str:
        critical_caps = {"code_exec", "filesystem", "shell"}
        high_caps = {"db", "email", "http"}
        if self.capability in critical_caps:
            return "critical"
        if self.capability in high_caps:
            return "high"
        return "medium"


@dataclass
class DataSinkNode(BaseNode):
    """
    Data storage or external write destination (database, file, API write).

    Risk: Attacker-influenced LLM can exfiltrate data through this node.
    OWASP: LLM02, LLM06
    """
    node_type: NodeType = field(default=NodeType.DATA_SINK, init=False)
    sink_type: str = "unknown"  # database | filesystem | external_api | email
    contains_pii: bool = False
    has_output_filter: bool = False
