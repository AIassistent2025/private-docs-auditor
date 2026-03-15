"""Local RAG chain — Ollama LLM + ChromaDB retrieval. Zero cloud."""

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama

from src.config import DEFAULT_LLM_MODEL, OLLAMA_BASE_URL, RETRIEVER_K


SYSTEM_PROMPT = """You are a professional document auditor analyzing sensitive business documents.
Answer questions based ONLY on the provided context. If the context does not contain enough
information to answer, say so explicitly — never fabricate information.

Context:
{context}"""


class RAGChain:
    """Local RAG chain using Ollama LLM and ChromaDB retrieval."""

    def __init__(self, vectorstore, model: str = DEFAULT_LLM_MODEL, k: int = RETRIEVER_K):
        self.retriever = vectorstore.as_retriever(search_kwargs={"k": k})

        self.llm = ChatOllama(
            model=model,
            base_url=OLLAMA_BASE_URL,
            temperature=0.1,
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human", "{question}"),
        ])

        self.chain = self.prompt | self.llm | StrOutputParser()

    def query(self, question: str) -> dict:
        """Ask a question and get an answer with sources.

        Returns:
            {"answer": str, "sources": [{"source": str, "page": int}]}
        """
        docs = self.retriever.invoke(question)

        context = "\n\n".join(doc.page_content for doc in docs)

        answer = self.chain.invoke({
            "context": context,
            "question": question,
        })

        # Deduplicate sources
        seen = set()
        sources = []
        for doc in docs:
            source = doc.metadata.get("source", "unknown")
            page = doc.metadata.get("page", 0)
            key = (source, page)
            if key not in seen:
                seen.add(key)
                sources.append({"source": source, "page": page})

        return {"answer": answer, "sources": sources}
