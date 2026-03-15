# NIfra Playground

Intentionally vulnerable AI applications for testing and demonstrating NIfra.

> **WARNING:** These applications contain real security vulnerabilities by design.
> Do NOT deploy them to production or expose them to the internet.
> For local testing only.

## Available Playgrounds

### 1. `vulnerable-rag-agent/`

A RAG-powered Q&A agent with intentional vulnerabilities:
- No document content validation (RAG poisoning)
- Unfiltered system prompt construction
- PII in knowledge base without output filter

**Vulnerabilities demonstrated:** PI-001, DE-001

```bash
cd vulnerable-rag-agent
pip install -r requirements.txt
python app.py
# App runs on http://localhost:8000

# Scan it with NIfra
nifra scan ./vulnerable-rag-agent
```

### 2. `vulnerable-tool-agent/`

A LangChain agent with over-permissioned tools:
- HTTP tool without URL allowlist (SSRF risk)
- Filesystem tool without path restriction
- Database tool with full table access

**Vulnerabilities demonstrated:** TA-001, TA-002, DE-001

```bash
cd vulnerable-tool-agent
pip install -r requirements.txt
python app.py

nifra scan ./vulnerable-tool-agent
```

## Why These Exist

They serve three purposes:
1. **Test NIfra** — verify detection works correctly
2. **Learn** — see what vulnerable AI code looks like
3. **Demo** — reproducible demo for talks, blog posts, and onboarding

## Adding a New Playground

Each playground should:
- Have exactly 1-3 specific, documented vulnerabilities
- Be simple enough to understand in 10 minutes
- Have a `README.md` explaining the vulnerabilities
- Include a `requirements.txt`
