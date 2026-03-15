from __future__ import annotations

from pathlib import Path

import pytest

from nifra.detectors.js_parser import (
    JSParser,
    JSParseResult,
    JSPatternMatch,
    _JS_PATTERNS,
    _MAX_JS_FILE_BYTES,
)


def _write(tmp_path: Path, filename: str, content: str) -> Path:
    """Write content to a file inside tmp_path and return its path."""
    p = tmp_path / filename
    p.write_text(content, encoding="utf-8")
    return p

class TestJSPatternMatch:
    def test_defaults(self):
        m = JSPatternMatch(
            file_path="index.js",
            line_number=1,
            pattern_type="llm_client",
            class_or_func="OpenAI",
            vendor="openai",
        )
        assert m.risk_weight == 1.0
        assert m.notes == ""
        assert m.language == "javascript"

    def test_custom_fields(self):
        m = JSPatternMatch(
            file_path="src/agent.ts",
            line_number=42,
            pattern_type="agent_framework",
            class_or_func="AgentExecutor",
            vendor="langchain",
            risk_weight=1.5,
            notes="Watch out",
            language="typescript",
        )
        assert m.line_number == 42
        assert m.language == "typescript"
        assert m.risk_weight == 1.5

class TestJSParseResult:
    def test_empty_result_all_false(self):
        r = JSParseResult()
        assert not r.has_llm
        assert not r.has_agent
        assert not r.has_rag
        assert not r.has_tools
        assert not r.has_memory

    def test_has_llm_true(self):
        match = JSPatternMatch("f.js", 1, "llm_client", "OpenAI", "openai")
        r = JSParseResult(scanned_files=1, patterns=[match])
        assert r.has_llm

    def test_has_agent_true(self):
        match = JSPatternMatch("f.js", 1, "agent_framework", "AgentExecutor", "langchain")
        r = JSParseResult(scanned_files=1, patterns=[match])
        assert r.has_agent

    def test_has_rag_true(self):
        match = JSPatternMatch("f.js", 1, "rag_framework", "RetrievalQAChain", "langchain")
        r = JSParseResult(scanned_files=1, patterns=[match])
        assert r.has_rag

    def test_has_tools_true(self):
        match = JSPatternMatch("f.js", 1, "tool_system", "tools_array", "openai")
        r = JSParseResult(scanned_files=1, patterns=[match])
        assert r.has_tools

    def test_has_memory_true(self):
        match = JSPatternMatch("f.js", 1, "memory_system", "MemorySystem", "langchain")
        r = JSParseResult(scanned_files=1, patterns=[match])
        assert r.has_memory


class TestOpenAIDetection:
    def test_import_openai(self, tmp_path: Path):
        _write(tmp_path, "index.js", 'import OpenAI from "openai";\n')
        result = JSParser(tmp_path).scan()
        vendors = [p.vendor for p in result.patterns]
        assert "openai" in vendors

    def test_require_openai(self, tmp_path: Path):
        _write(tmp_path, "index.js", "const OpenAI = require('openai');\n")
        result = JSParser(tmp_path).scan()
        vendors = [p.vendor for p in result.patterns]
        assert "openai" in vendors

    def test_chat_completions_create(self, tmp_path: Path):
        _write(tmp_path, "app.js", "const resp = await openai.chat.completions.create({")
        result = JSParser(tmp_path).scan()
        types = [p.pattern_type for p in result.patterns]
        assert "llm_client" in types

    def test_openai_assistants_api(self, tmp_path: Path):
        _write(tmp_path, "agent.js", "await openai.beta.assistants.create({})")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "OpenAI.Assistants" in funcs

    def test_no_false_positive_without_openai(self, tmp_path: Path):
        _write(tmp_path, "utils.js", 'const x = "hello world";\nconsole.log(x);\n')
        result = JSParser(tmp_path).scan()
        vendors = [p.vendor for p in result.patterns]
        assert "openai" not in vendors


class TestAnthropicDetection:
    def test_import_anthropic(self, tmp_path: Path):
        _write(tmp_path, "claude.ts", 'import Anthropic from "@anthropic-ai/sdk";')
        result = JSParser(tmp_path).scan()
        vendors = [p.vendor for p in result.patterns]
        assert "anthropic" in vendors

    def test_messages_create(self, tmp_path: Path):
        _write(tmp_path, "chat.ts", "const msg = await anthropic.messages.create({")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "Anthropic.messages" in funcs


class TestVercelAIDetection:
    def test_import_ai(self, tmp_path: Path):
        _write(tmp_path, "api.ts", 'import { generateText } from "ai";')
        result = JSParser(tmp_path).scan()
        types = [p.pattern_type for p in result.patterns]
        assert "llm_client" in types

    def test_generate_text_call(self, tmp_path: Path):
        _write(tmp_path, "route.ts", 'const { text } = await generateText({')
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "vercel/generateText" in funcs

class TestLangChainDetection:
    def test_langchain_import(self, tmp_path: Path):
        _write(tmp_path, "chain.ts", 'import { ChatOpenAI } from "@langchain/openai";')
        result = JSParser(tmp_path).scan()
        vendors = [p.vendor for p in result.patterns]
        assert "langchain" in vendors

    def test_agent_executor(self, tmp_path: Path):
        # Pattern requires AgentExecutor followed by ( or {
        _write(tmp_path, "agent.ts", "const agent = new AgentExecutor({\n  tools,\n  llm,\n});")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "AgentExecutor" in funcs

    def test_retrieval_qa_chain(self, tmp_path: Path):
        _write(tmp_path, "rag.ts", "const chain = RetrievalQAChain.fromLLM(llm, retriever);")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "RetrievalQAChain" in funcs

    def test_state_graph(self, tmp_path: Path):
        _write(tmp_path, "graph.ts", "const workflow = new StateGraph(GraphState);")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "LangGraph.StateGraph" in funcs

    def test_buffer_memory(self, tmp_path: Path):
        _write(tmp_path, "mem.ts", "const memory = new BufferMemory({});")
        result = JSParser(tmp_path).scan()
        types = [p.pattern_type for p in result.patterns]
        assert "memory_system" in types

class TestToolSystemDetection:
    def test_tools_array(self, tmp_path: Path):
        _write(tmp_path, "tools.js", "const config = { tools: [searchTool, calcTool] };")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "tools_array" in funcs

    def test_tool_choice_auto(self, tmp_path: Path):
        _write(tmp_path, "call.js", "tool_choice: 'auto',")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "tool_choice_auto" in funcs

    def test_system_prompt_role(self, tmp_path: Path):
        _write(tmp_path, "prompt.js", '{ role: "system", content: systemPrompt }')
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "system_prompt" in funcs


class TestVectorStoreDetection:
    def test_similarity_search(self, tmp_path: Path):
        _write(tmp_path, "search.ts", "const docs = await vectorStore.similaritySearch(query, 4);")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "vectorSearch" in funcs

    def test_as_retriever(self, tmp_path: Path):
        _write(tmp_path, "ret.ts", "const retriever = vectorStore.asRetriever();")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "vectorSearch" in funcs


class TestWebLoaderDetection:
    def test_cheerio_web_loader(self, tmp_path: Path):
        _write(tmp_path, "loader.ts", "const loader = new CheerioWebBaseLoader(url);")
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "WebLoader" in funcs


class TestMCPDetection:
    def test_mcp_sdk_import(self, tmp_path: Path):
        _write(tmp_path, "server.ts", 'import { Server } from "@modelcontextprotocol/sdk";')
        result = JSParser(tmp_path).scan()
        funcs = [p.class_or_func for p in result.patterns]
        assert "MCP.Server" in funcs

class TestLanguageClassification:
    def test_ts_file_classified_as_typescript(self, tmp_path: Path):
        _write(tmp_path, "app.ts", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        langs = [p.language for p in result.patterns]
        assert "typescript" in langs

    def test_tsx_file_classified_as_typescript(self, tmp_path: Path):
        _write(tmp_path, "App.tsx", 'import { generateText } from "ai";')
        result = JSParser(tmp_path).scan()
        langs = [p.language for p in result.patterns]
        assert "typescript" in langs

    def test_js_file_classified_as_javascript(self, tmp_path: Path):
        _write(tmp_path, "app.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        langs = [p.language for p in result.patterns]
        assert "javascript" in langs

    def test_mjs_file_classified_as_javascript(self, tmp_path: Path):
        _write(tmp_path, "module.mjs", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        langs = [p.language for p in result.patterns]
        assert "javascript" in langs

class TestSkipDirectories:
    def test_skips_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules" / "openai"
        nm.mkdir(parents=True)
        _write(nm, "index.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

    def test_skips_next_dir(self, tmp_path: Path):
        nd = tmp_path / ".next"
        nd.mkdir()
        _write(nd, "main.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

    def test_skips_dist_dir(self, tmp_path: Path):
        d = tmp_path / "dist"
        d.mkdir()
        _write(d, "bundle.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

    def test_skips_build_dir(self, tmp_path: Path):
        d = tmp_path / "build"
        d.mkdir()
        _write(d, "app.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

    def test_skips_coverage_dir(self, tmp_path: Path):
        d = tmp_path / "coverage"
        d.mkdir()
        _write(d, "app.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

    def test_src_dir_not_skipped(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        _write(src, "agent.ts", 'import { AgentExecutor } from "@langchain/core";')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 1

class TestCommentSkipping:
    def test_single_line_comment_not_detected(self, tmp_path: Path):
        _write(tmp_path, "app.js", '// import OpenAI from "openai";\n')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 1
        openai_patterns = [p for p in result.patterns if p.vendor == "openai"]
        assert len(openai_patterns) == 0

    def test_jsdoc_star_line_not_detected(self, tmp_path: Path):
        _write(tmp_path, "app.js", ' * import OpenAI from "openai";\n')
        result = JSParser(tmp_path).scan()
        openai_patterns = [p for p in result.patterns if p.vendor == "openai"]
        assert len(openai_patterns) == 0

    def test_actual_import_is_detected(self, tmp_path: Path):
        content = (
            '// this is a comment about openai\n'
            'import OpenAI from "openai";\n'  # actual import on its own line
        )
        _write(tmp_path, "app.js", content)
        result = JSParser(tmp_path).scan()
        openai_patterns = [p for p in result.patterns if p.vendor == "openai"]
        assert len(openai_patterns) >= 1

class TestDeduplication:
    def test_same_pattern_deduped_within_single_file(self, tmp_path: Path):
        content = (
            'import OpenAI from "openai";\n'
            'const client = new OpenAI();\n'
            'import OpenAI from "openai";  // duplicate\n'
        )
        _write(tmp_path, "app.js", content)
        result = JSParser(tmp_path).scan()
        # The (llm_client, OpenAI) key should appear only once even with 3 lines
        openai_import_matches = [
            p for p in result.patterns
            if p.class_or_func == "OpenAI" and p.pattern_type == "llm_client"
        ]
        assert len(openai_import_matches) == 1

    def test_same_pattern_detected_in_different_files(self, tmp_path: Path):
        _write(tmp_path, "file1.js", 'import OpenAI from "openai";')
        _write(tmp_path, "file2.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        openai_matches = [p for p in result.patterns if p.class_or_func == "OpenAI"]
        # Each file gets its own dedup — so two matches total is acceptable
        assert len(openai_matches) <= 2
        assert result.scanned_files == 2

class TestFileSizeGuard:
    def test_oversized_file_skipped(self, tmp_path: Path):
        large_file = tmp_path / "large.js"
        # Write a file just over the 5 MB limit
        large_file.write_bytes(b'import OpenAI from "openai";\n' + b"x" * (_MAX_JS_FILE_BYTES + 1))
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

    def test_normal_file_scanned(self, tmp_path: Path):
        _write(tmp_path, "small.js", 'import OpenAI from "openai";')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 1

class TestNonJSFiles:
    def test_python_file_not_scanned(self, tmp_path: Path):
        _write(tmp_path, "agent.py", 'from openai import OpenAI')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

    def test_json_file_not_scanned(self, tmp_path: Path):
        _write(tmp_path, "package.json", '{"name": "test", "dependencies": {"openai": "^4"}}')
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 0

class TestMultiplePatternsInFile:
    def test_full_ai_app_file(self, tmp_path: Path):
        content = """\
import OpenAI from "openai";
import { AgentExecutor } from "@langchain/core";
import { RetrievalQAChain } from "@langchain/core";

const config = { tools: [searchTool, calendarTool] };
const messages = [{ role: "system", content: systemPrompt }];
const docs = await vectorStore.similaritySearch(query, 4);
const memory = new BufferMemory({});
"""
        _write(tmp_path, "full_agent.ts", content)
        result = JSParser(tmp_path).scan()
        assert result.has_llm
        assert result.has_agent
        assert result.has_rag
        assert result.has_tools
        assert result.has_memory
        assert result.scanned_files == 1

    def test_scanned_files_count_is_accurate(self, tmp_path: Path):
        _write(tmp_path, "a.ts", 'import OpenAI from "openai";')
        _write(tmp_path, "b.ts", 'import Anthropic from "@anthropic-ai/sdk";')
        _write(tmp_path, "c.py", "# python file — should not count")
        result = JSParser(tmp_path).scan()
        assert result.scanned_files == 2


# ── Pattern registry sanity ───────────────────────────────────────────────────

class TestPatternRegistry:
    def test_all_patterns_have_required_keys(self):
        required_keys = {"pattern", "pattern_type", "class_or_func", "vendor", "risk_weight"}
        for pat in _JS_PATTERNS:
            missing = required_keys - set(pat.keys())
            assert not missing, f"Pattern {pat.get('class_or_func')} missing: {missing}"

    def test_all_risk_weights_are_positive(self):
        for pat in _JS_PATTERNS:
            assert pat["risk_weight"] > 0, f"{pat['class_or_func']} has non-positive risk_weight"

    def test_at_least_20_patterns_registered(self):
        assert len(_JS_PATTERNS) >= 20

    def test_no_duplicate_class_or_func_same_vendor(self):
        seen: set[tuple[str, str]] = set()
        duplicates: list[str] = []
        for pat in _JS_PATTERNS:
            key = (pat["class_or_func"], pat["vendor"])
            if key in seen:
                duplicates.append(f"{pat['vendor']}/{pat['class_or_func']}")
            seen.add(key)
        assert not duplicates, f"Duplicate pattern entries: {duplicates}"
