import os

# ── Intentional vulnerability: API key read from env without validation
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# ── Simulated "customer" knowledge base with PII (vulnerability: DE-001)
CUSTOMER_KNOWLEDGE_BASE = [
    "Customer ID 1001: Alice Johnson, alice@example.com, Card ending 4242",
    "Customer ID 1002: Bob Smith, bob@example.com, Card ending 8888",
    "Customer ID 1003: Carol White, carol@example.com, Card ending 1234",
]

# ── Intentional vulnerability: documents loaded without trust validation (PI-001)
DOCUMENT_SOURCES = [
    "./docs/",          # local docs
    "https://example.com/feed",  # external URL — untrusted source, no validation
]


def build_rag_chain():
    """
    Vulnerable RAG chain setup.

    Vulnerabilities:
     1. Documents from external URL loaded without content validation
     2. Retrieved context inserted directly into prompt with no filtering
     3. PII in vector store accessible by any query
    """
    from langchain_community.document_loaders import DirectoryLoader
    from langchain_openai import ChatOpenAI, OpenAIEmbeddings
    from langchain_community.vectorstores import Chroma
    from langchain.chains import RetrievalQA
    from langchain.prompts import PromptTemplate

    # VULNERABILITY: No content validation on loaded documents
    # A malicious document in ./docs/ can override LLM behavior
    loader = DirectoryLoader("./docs/", glob="**/*.txt")
    documents = loader.load()

    embeddings = OpenAIEmbeddings()

    # VULNERABILITY: PII customer data stored in vector store
    # Any query can potentially retrieve customer PII
    vectorstore = Chroma.from_documents(
        documents=documents + [
            # Simulating PII in knowledge base
        ],
        embedding=embeddings,
    )

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

    # VULNERABILITY: System prompt directly includes retrieved context
    # without any sanitization or trust scoring
    prompt_template = PromptTemplate(
        input_variables=["context", "question"],
        template="""You are a helpful customer service assistant.

Context information:
{context}

Question: {question}

Answer:""",
        # MISSING: no instruction to ignore conflicting instructions in context
        # MISSING: no output filter for PII in response
    )

    chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=vectorstore.as_retriever(),
        chain_type_kwargs={"prompt": prompt_template},
    )
    return chain


def main():
    print("⚠  VULNERABLE RAG AGENT — FOR SECURITY TESTING ONLY")
    print("   Run: nifra scan ./playground/vulnerable-rag-agent")
    print()

    chain = build_rag_chain()

    while True:
        query = input("Ask a question: ").strip()
        if not query:
            continue
        if query.lower() in ("exit", "quit"):
            break

        # VULNERABILITY: Raw LLM response returned without any output filtering
        # PII leakage possible if RAG retrieves customer records
        result = chain.invoke({"query": query})
        print(f"\nAnswer: {result['result']}\n")


if __name__ == "__main__":
    main()
