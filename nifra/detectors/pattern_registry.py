from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PatternCategory(str, Enum):
    LLM_CLIENT = "llm_client"
    AGENT_FRAMEWORK = "agent_framework"
    RAG_FRAMEWORK = "rag_framework"
    VECTOR_STORE = "vector_store"
    TOOL_SYSTEM = "tool_system"
    MEMORY_SYSTEM = "memory_system"
    PROMPT_TEMPLATE = "prompt_template"
    OUTPUT_PARSER = "output_parser"


@dataclass(frozen=True)
class FrameworkPattern:
    name: str
    category: PatternCategory
    vendor: str
    risk_multiplier: float  # 1.0 = baseline; >1.0 = higher risk surface
    notes: str = ""


# Master pattern registry
# Community can add new patterns by adding entries here
PATTERN_REGISTRY: list[FrameworkPattern] = [
    # ── LLM Clients ──────────────────────────────────────────────────
    FrameworkPattern("OpenAI", PatternCategory.LLM_CLIENT, "openai", 1.0),
    FrameworkPattern("AsyncOpenAI", PatternCategory.LLM_CLIENT, "openai", 1.0),
    FrameworkPattern("AzureOpenAI", PatternCategory.LLM_CLIENT, "openai", 1.0),
    FrameworkPattern("Anthropic", PatternCategory.LLM_CLIENT, "anthropic", 1.0),
    FrameworkPattern("AsyncAnthropic", PatternCategory.LLM_CLIENT, "anthropic", 1.0),
    FrameworkPattern("ChatOpenAI", PatternCategory.LLM_CLIENT, "langchain/openai", 1.0),
    FrameworkPattern("ChatAnthropic", PatternCategory.LLM_CLIENT, "langchain/anthropic", 1.0),
    FrameworkPattern("ChatGoogleGenerativeAI", PatternCategory.LLM_CLIENT, "langchain/google", 1.0),

    # ── Agent Frameworks ─────────────────────────────────────────────
    FrameworkPattern("AgentExecutor", PatternCategory.AGENT_FRAMEWORK, "langchain", 1.5,
                     notes="Tool invocation attack surface is high — review all registered tools"),
    FrameworkPattern("create_react_agent", PatternCategory.AGENT_FRAMEWORK, "langchain", 1.5),
    FrameworkPattern("create_openai_tools_agent", PatternCategory.AGENT_FRAMEWORK, "langchain", 1.5),
    FrameworkPattern("initialize_agent", PatternCategory.AGENT_FRAMEWORK, "langchain", 1.5),
    FrameworkPattern("AssistantAgent", PatternCategory.AGENT_FRAMEWORK, "autogen", 1.6,
                     notes="AutoGen agents have high autonomous action surface"),
    FrameworkPattern("UserProxyAgent", PatternCategory.AGENT_FRAMEWORK, "autogen", 1.6),
    FrameworkPattern("Agent", PatternCategory.AGENT_FRAMEWORK, "crewai", 1.5),
    FrameworkPattern("Crew", PatternCategory.AGENT_FRAMEWORK, "crewai", 1.6,
                     notes="Multi-agent setups increase privilege escalation risk"),

    # ── RAG Frameworks ────────────────────────────────────────────────
    FrameworkPattern("RetrievalQA", PatternCategory.RAG_FRAMEWORK, "langchain", 1.3,
                     notes="Verify document trust validation before ingestion"),
    FrameworkPattern("ConversationalRetrievalChain", PatternCategory.RAG_FRAMEWORK, "langchain", 1.3),
    FrameworkPattern("VectorStoreRetriever", PatternCategory.RAG_FRAMEWORK, "langchain", 1.2),
    FrameworkPattern("RAGStringQueryEngine", PatternCategory.RAG_FRAMEWORK, "llamaindex", 1.3),
    FrameworkPattern("VectorIndexRetriever", PatternCategory.RAG_FRAMEWORK, "llamaindex", 1.2),

    # ── Vector Stores ─────────────────────────────────────────────────
    FrameworkPattern("Chroma", PatternCategory.VECTOR_STORE, "chromadb", 0.8),
    FrameworkPattern("PineconeVectorStore", PatternCategory.VECTOR_STORE, "pinecone", 0.8),
    FrameworkPattern("QdrantVectorStore", PatternCategory.VECTOR_STORE, "qdrant", 0.8),
    FrameworkPattern("FAISS", PatternCategory.VECTOR_STORE, "meta/faiss", 0.7),
    FrameworkPattern("Weaviate", PatternCategory.VECTOR_STORE, "weaviate", 0.8),

    # ── Tool Systems ──────────────────────────────────────────────────
    FrameworkPattern("Tool", PatternCategory.TOOL_SYSTEM, "langchain", 1.4),
    FrameworkPattern("StructuredTool", PatternCategory.TOOL_SYSTEM, "langchain", 1.4),
    FrameworkPattern("BaseTool", PatternCategory.TOOL_SYSTEM, "langchain", 1.4),
    FrameworkPattern("FunctionTool", PatternCategory.TOOL_SYSTEM, "llamaindex", 1.4),
    FrameworkPattern("tool", PatternCategory.TOOL_SYSTEM, "langchain", 1.4,
                     notes="@tool decorator — check for over-permissioned tool scope"),

    # ── Memory Systems ────────────────────────────────────────────────
    FrameworkPattern("ConversationBufferMemory", PatternCategory.MEMORY_SYSTEM, "langchain", 1.2,
                     notes="Memory poisoning attack surface — validate memory entries"),
    FrameworkPattern("VectorStoreRetrieverMemory", PatternCategory.MEMORY_SYSTEM, "langchain", 1.3),
    FrameworkPattern("ConversationSummaryMemory", PatternCategory.MEMORY_SYSTEM, "langchain", 1.2),

    # ── Prompt Templates ─────────────────────────────────────────────
    FrameworkPattern("PromptTemplate", PatternCategory.PROMPT_TEMPLATE, "langchain", 1.1),
    FrameworkPattern("ChatPromptTemplate", PatternCategory.PROMPT_TEMPLATE, "langchain", 1.1),
    FrameworkPattern("SystemMessagePromptTemplate", PatternCategory.PROMPT_TEMPLATE, "langchain", 1.2,
                     notes="System prompt injection risk — ensure template is hardened"),
]

# Fast lookup index by name
PATTERN_BY_NAME: dict[str, FrameworkPattern] = {p.name: p for p in PATTERN_REGISTRY}

HIGH_RISK_PATTERNS = frozenset(p.name for p in PATTERN_REGISTRY if p.risk_multiplier >= 1.4)
