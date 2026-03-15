from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AICodePattern:
    pattern_type: str
    class_or_func: str
    file_path: str
    line_number: int
    context_snippet: str
    confidence: float = 1.0
    extra: dict = field(default_factory=dict)


@dataclass
class ASTScanResult:
    project_path: Path
    patterns: list[AICodePattern] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0

    @property
    def entry_points(self) -> list[AICodePattern]:
        return [p for p in self.patterns if p.pattern_type in ("llm_init", "agent_init")]

    @property
    def tool_registrations(self) -> list[AICodePattern]:
        return [p for p in self.patterns if p.pattern_type == "tool_registration"]

    @property
    def rag_patterns(self) -> list[AICodePattern]:
        return [p for p in self.patterns if p.pattern_type == "rag_chain"]

    @property
    def dangerous_sinks(self) -> list[AICodePattern]:
        return [p for p in self.patterns if p.pattern_type == "dangerous_sink"]


LLM_INIT_CLASSES = frozenset([
    "OpenAI", "AsyncOpenAI", "AzureOpenAI",
    "ChatOpenAI", "ChatAnthropic", "ChatGoogleGenerativeAI",
    "ChatVertexAI", "ChatCohere", "ChatGroq", "ChatMistralAI",
    "Anthropic", "AsyncAnthropic",
    "GoogleGenerativeAI", "VertexAI",
    "OpenAIChatCompletion", "AzureChatCompletion",
])

AGENT_INIT_FUNCS = frozenset([
    "AgentExecutor", "initialize_agent",
    "create_react_agent", "create_openai_tools_agent",
    "create_openai_functions_agent", "create_structured_chat_agent",
    "ConversationalAgent", "ZeroShotAgent",
    "AssistantAgent", "UserProxyAgent",
    "Agent", "Crew",
])

TOOL_DECORATORS = frozenset(["tool", "structured_tool"])
TOOL_CLASSES = frozenset(["Tool", "StructuredTool", "BaseTool", "FunctionTool"])

RAG_CLASSES = frozenset([
    "RetrievalQA", "ConversationalRetrievalChain",
    "VectorStoreRetriever", "MultiQueryRetriever",
    "RAGStringQueryEngine", "VectorIndexRetriever",
    "ContextualCompressionRetriever",
])

MEMORY_CLASSES = frozenset([
    "ConversationBufferMemory", "ConversationBufferWindowMemory",
    "ConversationSummaryMemory", "VectorStoreRetrieverMemory",
    "ConversationTokenBufferMemory",
])

VECTOR_STORE_CLASSES = frozenset([
    "Chroma", "PineconeVectorStore", "QdrantVectorStore",
    "FAISS", "Weaviate", "Milvus", "ElasticsearchStore",
    "OpenSearchVectorSearch",
])

DANGEROUS_SINK_FUNCS = frozenset(["eval", "exec", "compile"])

PROMPT_TEMPLATE_CLASSES = frozenset([
    "PromptTemplate", "ChatPromptTemplate",
    "SystemMessagePromptTemplate", "HumanMessagePromptTemplate",
    "FewShotPromptTemplate",
])

DOCUMENT_LOADER_CLASSES = frozenset([
    "DirectoryLoader", "TextLoader", "PyPDFLoader", "UnstructuredFileLoader",
    "WebBaseLoader", "SeleniumURLLoader", "PlaywrightURLLoader",
    "SlackDirectoryLoader", "OutlookMessageLoader",
    "SimpleDirectoryReader",
])


class ASTParser:
    def __init__(self, project_path: Path) -> None:
        self.project_path = project_path

    def scan(self) -> ASTScanResult:
        result = ASTScanResult(project_path=self.project_path)
        for py_file in self.project_path.rglob("*.py"):
            if self._should_skip(py_file):
                result.skipped_files += 1
                continue
            patterns = self._parse_file(py_file)
            result.patterns.extend(patterns)
            result.scanned_files += 1
        return result

    def _should_skip(self, path: Path) -> bool:
        skip_dirs = {".venv", "venv", "env", "node_modules", "__pycache__",
                     ".git", "site-packages", "dist", "build"}
        return any(part in skip_dirs for part in path.parts)

    def _parse_file(self, file_path: Path) -> list[AICodePattern]:
        _MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB — skip oversized generated files
        try:
            if file_path.stat().st_size > _MAX_FILE_BYTES:
                return []
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(file_path))
        except (SyntaxError, RecursionError, MemoryError, OSError, ValueError):
            return []
        try:
            rel_path = str(file_path.relative_to(self.project_path))
        except ValueError:
            rel_path = str(file_path)
        visitor = _AIPatternVisitor(file_path=rel_path, source_lines=source.splitlines())
        visitor.visit(tree)
        return visitor.patterns


class _AIPatternVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: list[str]) -> None:
        self.file_path = file_path
        self.source_lines = source_lines
        self.patterns: list[AICodePattern] = []
        self._assignments: dict[str, str] = {}

    def visit_Call(self, node: ast.Call) -> None:
        name = self._get_call_name(node)
        # For class method calls like Foo.from_xxx(), also check the class name
        parent_class = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            parent_class = node.func.value.id

        # Prefer parent_class when the method name is a factory (from_*, create_*, build_*)
        effective_name = (
            parent_class
            if parent_class and (
                name.startswith("from_") or name.startswith("create_") or name.startswith("build_")
            )
            else name
        )

        if effective_name in LLM_INIT_CLASSES or name in LLM_INIT_CLASSES:
            self._add("llm_init", effective_name or name, node.lineno)
        elif effective_name in AGENT_INIT_FUNCS or name in AGENT_INIT_FUNCS:
            tools = self._extract_tools_arg(node)
            self._add("agent_init", effective_name or name, node.lineno, extra={"tools": tools})
        elif effective_name in TOOL_CLASSES or name in TOOL_CLASSES:
            tname = self._extract_kwarg(node, "name") or ""
            self._add("tool_registration", effective_name or name, node.lineno, extra={"tool_name": tname})
        elif effective_name in RAG_CLASSES or name in RAG_CLASSES:
            self._add("rag_chain", effective_name or name, node.lineno)
        elif effective_name in MEMORY_CLASSES or name in MEMORY_CLASSES:
            self._add("memory_init", effective_name or name, node.lineno)
        elif effective_name in VECTOR_STORE_CLASSES or name in VECTOR_STORE_CLASSES:
            self._add("vector_store_init", effective_name or name, node.lineno)
        elif effective_name in DOCUMENT_LOADER_CLASSES or name in DOCUMENT_LOADER_CLASSES:
            src = self._extract_first_arg_str(node)
            self._add("document_loader", effective_name or name, node.lineno, extra={"source": src or ""})
        elif effective_name in PROMPT_TEMPLATE_CLASSES or name in PROMPT_TEMPLATE_CLASSES:
            self._add("prompt_template", effective_name or name, node.lineno, extra={"is_system": "System" in (effective_name or name)})
        elif name in DANGEROUS_SINK_FUNCS:
            self._add("dangerous_sink", name, node.lineno, confidence=0.9)

        if isinstance(node.func, ast.Attribute) and node.func.attr in (
            "invoke", "run", "predict", "apredict", "ainvoke", "acall"
        ):
            self._add("llm_call", node.func.attr, node.lineno, confidence=0.7)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            deco_name = self._get_call_name(decorator)
            if deco_name in TOOL_DECORATORS:
                self._add("tool_registration", f"@{deco_name}:{node.name}", node.lineno,
                          extra={"tool_name": node.name, "decorated": True})
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            call_name = self._get_call_name(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._assignments[target.id] = call_name
        self.generic_visit(node)

    def _get_call_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        return ""

    def _extract_tools_arg(self, node: ast.Call) -> list[str]:
        for kw in node.keywords:
            if kw.arg == "tools" and isinstance(kw.value, ast.List):
                return [self._get_call_name(e) for e in kw.value.elts]
        return []

    def _extract_kwarg(self, node: ast.Call, key: str) -> Optional[str]:
        for kw in node.keywords:
            if kw.arg == key and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        return None

    def _extract_first_arg_str(self, node: ast.Call) -> Optional[str]:
        if node.args and isinstance(node.args[0], ast.Constant):
            return str(node.args[0].value)
        return None

    def _add(self, pattern_type: str, name: str, line: int,
             confidence: float = 1.0, extra: Optional[dict] = None) -> None:
        snippet = ""
        if 0 < line <= len(self.source_lines):
            snippet = self.source_lines[line - 1].strip()
        self.patterns.append(AICodePattern(
            pattern_type=pattern_type,
            class_or_func=name,
            file_path=self.file_path,
            line_number=line,
            context_snippet=snippet,
            confidence=confidence,
            extra=extra or {},
        ))
