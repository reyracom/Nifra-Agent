from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_MAX_JS_FILE_BYTES = 5 * 1024 * 1024  

_JS_PATTERNS: list[dict] = [
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']openai["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "OpenAI",
        "vendor": "openai",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(
            r'(?:new\s+OpenAI\s*\(|openai\.chat\.completions\.create|'
            r'client\.chat\.completions\.create)'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "OpenAI.chat.completions",
        "vendor": "openai",
        "risk_weight": 1.1,
    },
    {
        "pattern": re.compile(r'openai\.beta\.assistants|openai\.beta\.threads'),
        "pattern_type": "agent_framework",
        "class_or_func": "OpenAI.Assistants",
        "vendor": "openai",
        "risk_weight": 1.4,
        "notes": "OpenAI Assistants API — tool calls and code interpreter active",
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']@anthropic-ai/sdk["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "Anthropic",
        "vendor": "anthropic",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(
            r'(?:new\s+Anthropic\s*\(|anthropic\.messages\.create|client\.messages\.create)'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "Anthropic.messages",
        "vendor": "anthropic",
        "risk_weight": 1.1,
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']ai["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "ai",
        "vendor": "vercel",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(
            r'\b(?:generateText|streamText|generateObject|streamObject)\s*\('
        ),
        "pattern_type": "llm_client",
        "class_or_func": "vercel/generateText",
        "vendor": "vercel",
        "risk_weight": 1.1,
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']@langchain/(?:core|openai|anthropic|'
            r'community|langgraph|google-genai|groq|mistralai)["\']'
        ),
        "pattern_type": "agent_framework",
        "class_or_func": "LangChain",
        "vendor": "langchain",
        "risk_weight": 1.2,
    },
    {
        "pattern": re.compile(
            r'\b(?:AgentExecutor|createReactAgent|createOpenAIToolsAgent|'
            r'createToolCallingAgent|initializeAgentExecutorWithOptions)\s*[({]'
        ),
        "pattern_type": "agent_framework",
        "class_or_func": "AgentExecutor",
        "vendor": "langchain",
        "risk_weight": 1.5,
        "notes": "Agent with tool invocation — review all registered tools for over-permission",
    },
    {
        "pattern": re.compile(
            r'\b(?:RetrievalQAChain|ConversationalRetrievalQAChain|'
            r'createRetrievalChain|createStuffDocumentsChain)\b'
        ),
        "pattern_type": "rag_framework",
        "class_or_func": "RetrievalQAChain",
        "vendor": "langchain",
        "risk_weight": 1.3,
        "notes": "RAG chain — verify content validation before ingestion",
    },
    {
        "pattern": re.compile(r'\bStateGraph\s*[({]|\bAnnotation\.Root\b'),
        "pattern_type": "agent_framework",
        "class_or_func": "LangGraph.StateGraph",
        "vendor": "langchain",
        "risk_weight": 1.6,
        "notes": "LangGraph stateful agent — multi-step autonomous execution surface",
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']llamaindex["\']'
        ),
        "pattern_type": "rag_framework",
        "class_or_func": "LlamaIndex",
        "vendor": "llamaindex",
        "risk_weight": 1.2,
    },
    {
        "pattern": re.compile(
            r'\b(?:VectorStoreIndex|SimpleDirectoryReader|QueryEngine)\b'
        ),
        "pattern_type": "rag_framework",
        "class_or_func": "LlamaIndex.VectorStore",
        "vendor": "llamaindex",
        "risk_weight": 1.3,
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']@google/generative-ai["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "GoogleGenerativeAI",
        "vendor": "google",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']@google-cloud/vertexai["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "VertexAI",
        "vendor": "google",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']@huggingface/inference["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "HfInference",
        "vendor": "huggingface",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']cohere-ai["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "CohereClient",
        "vendor": "cohere",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']groq-sdk["\']'
        ),
        "pattern_type": "llm_client",
        "class_or_func": "Groq",
        "vendor": "groq",
        "risk_weight": 1.0,
    },
    {
        "pattern": re.compile(r'\btools\s*:\s*\['),
        "pattern_type": "tool_system",
        "class_or_func": "tools_array",
        "vendor": "openai",
        "risk_weight": 1.4,
        "notes": "Tool registration — verify each tool scope for over-permission",
    },
    {
        "pattern": re.compile(r'\bfunctions\s*:\s*\['),
        "pattern_type": "tool_system",
        "class_or_func": "functions_array",
        "vendor": "openai",
        "risk_weight": 1.4,
        "notes": "Function calling — check for SSRF or code execution in handlers",
    },
    {
        "pattern": re.compile(r'\btool_choice\s*:\s*["\']auto["\']'),
        "pattern_type": "tool_system",
        "class_or_func": "tool_choice_auto",
        "vendor": "openai",
        "risk_weight": 1.5,
        "notes": "Automatic tool selection — agent chooses tools autonomously",
    },
    {
        "pattern": re.compile(r'\brole\s*:\s*["\']system["\']'),
        "pattern_type": "prompt_template",
        "class_or_func": "system_prompt",
        "vendor": "openai",
        "risk_weight": 1.1,
        "notes": "System prompt — ensure injection-resistant template",
    },
    {
        "pattern": re.compile(
            r'\b(?:similaritySearch|maxMarginalRelevanceSearch|'
            r'asRetriever|retrieve)\s*\('
        ),
        "pattern_type": "rag_framework",
        "class_or_func": "vectorSearch",
        "vendor": "vector_store",
        "risk_weight": 1.2,
        "notes": "Vector similarity search — retrieved content fed to LLM context",
    },
    {
        "pattern": re.compile(
            r'\b(?:CheerioWebBaseLoader|RecursiveUrlLoader|SitemapLoader|'
            r'WebBaseLoader|GithubRepoLoader)\b'
        ),
        "pattern_type": "rag_framework",
        "class_or_func": "WebLoader",
        "vendor": "langchain",
        "risk_weight": 1.4,
        "notes": "Web content loader — ingests untrusted external content into RAG",
    },
    {
        "pattern": re.compile(
            r'\b(?:BufferMemory|ConversationSummaryMemory|VectorStoreRetrieverMemory|'
            r'MemorySaver)\b'
        ),
        "pattern_type": "memory_system",
        "class_or_func": "MemorySystem",
        "vendor": "langchain",
        "risk_weight": 1.2,
        "notes": "Persistent memory — validate entries to prevent memory poisoning",
    },
    {
        "pattern": re.compile(
            r'(?:from|require)\s*\(?\s*["\']@modelcontextprotocol/sdk["\']'
        ),
        "pattern_type": "agent_framework",
        "class_or_func": "MCP.Server",
        "vendor": "anthropic",
        "risk_weight": 1.6,
        "notes": "MCP server — exposes tools/resources to AI agents, high attack surface",
    },
]


@dataclass
class JSPatternMatch:
    """A detected AI framework pattern in a JS/TS source file."""

    file_path: str
    line_number: int
    pattern_type: str
    class_or_func: str
    vendor: str
    risk_weight: float = 1.0
    notes: str = ""
    language: str = "javascript"


@dataclass
class JSParseResult:
    """Result of scanning a directory for JS/TS AI framework patterns."""

    scanned_files: int = 0
    patterns: list[JSPatternMatch] = field(default_factory=list)

    @property
    def has_llm(self) -> bool:
        return any(p.pattern_type == "llm_client" for p in self.patterns)

    @property
    def has_agent(self) -> bool:
        return any(p.pattern_type == "agent_framework" for p in self.patterns)

    @property
    def has_rag(self) -> bool:
        return any(p.pattern_type == "rag_framework" for p in self.patterns)

    @property
    def has_tools(self) -> bool:
        return any(p.pattern_type == "tool_system" for p in self.patterns)

    @property
    def has_memory(self) -> bool:
        return any(p.pattern_type == "memory_system" for p in self.patterns)


class JSParser:
    """
    Regex-based JavaScript/TypeScript source code parser for AI framework detection.

    Supports: .js .ts .jsx .tsx .mjs .cjs

    Does NOT require a Node.js runtime — purely static regex analysis.
    Designed to complement Python ASTParser for polyglot AI applications.

    Architecture:
      - Pattern matching is file-level deduped (same pattern type + class_or_func
        is only reported once per file to avoid noise from repeated imports)
      - Files > 5 MB are skipped (DoS protection)
      - node_modules, dist, build directories are skipped
    """

    _JS_EXTENSIONS = frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"})
    _SKIP_DIRS = frozenset({
        "node_modules", ".next", "dist", "build", ".nuxt", ".output",
        "coverage", ".venv", "venv", "__pycache__", ".git",
    })

    def __init__(self, project_path: Path) -> None:
        self.project_path = project_path

    def scan(self) -> JSParseResult:
        result = JSParseResult()
        js_files = [
            f for f in self.project_path.rglob("*")
            if f.suffix in self._JS_EXTENSIONS
            and not any(skip in f.parts for skip in self._SKIP_DIRS)
        ]

        for js_file in js_files:
            try:
                if js_file.stat().st_size > _MAX_JS_FILE_BYTES:
                    continue
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                result.scanned_files += 1
                matches = self._scan_file(js_file, content)
                result.patterns.extend(matches)
            except (OSError, PermissionError):
                continue

        return result

    def _scan_file(self, file_path: Path, content: str) -> list[JSPatternMatch]:
        matches: list[JSPatternMatch] = []
        lines = content.splitlines()
        # Dedup within a single file: same (pattern_type, class_or_func) reported once
        seen: set[tuple[str, str]] = set()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip single-line comments
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pat in _JS_PATTERNS:
                key = (pat["pattern_type"], pat["class_or_func"])
                if key in seen:
                    continue
                if pat["pattern"].search(line):
                    seen.add(key)
                    lang = (
                        "typescript"
                        if file_path.suffix in {".ts", ".tsx"}
                        else "javascript"
                    )
                    try:
                        rel_path = str(file_path.relative_to(self.project_path))
                    except ValueError:
                        rel_path = str(file_path)

                    matches.append(
                        JSPatternMatch(
                            file_path=rel_path,
                            line_number=line_num,
                            pattern_type=pat["pattern_type"],
                            class_or_func=pat["class_or_func"],
                            vendor=pat["vendor"],
                            risk_weight=pat.get("risk_weight", 1.0),
                            notes=pat.get("notes", ""),
                            language=lang,
                        )
                    )

        return matches
