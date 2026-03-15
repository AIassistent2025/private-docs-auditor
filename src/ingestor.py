"""Document ingestion — PDF/text → chunks → ChromaDB with local Ollama embeddings."""

import os
import shutil
from pathlib import Path

from langchain_chroma import Chroma
from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from src.config import CHROMA_DIR, CHUNK_SIZE, CHUNK_OVERLAP, DEFAULT_EMBED_MODEL, OLLAMA_BASE_URL


class DocumentIngestor:
    """Ingest documents into a local ChromaDB vector store using Ollama embeddings."""

    def __init__(
        self,
        embed_model: str = DEFAULT_EMBED_MODEL,
        chunk_size: int = CHUNK_SIZE,
        chunk_overlap: int = CHUNK_OVERLAP,
    ):
        self.chroma_dir = CHROMA_DIR
        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
        )
        self.embeddings = OllamaEmbeddings(
            model=embed_model,
            base_url=OLLAMA_BASE_URL,
        )

    def ingest(self, file_path: str) -> int:
        """Ingest a PDF or text file into the vector store.

        Returns the number of chunks indexed.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        ext = path.suffix.lower()
        if ext == ".pdf":
            loader = PyPDFLoader(str(path))
        elif ext in (".txt", ".md", ".log", ".csv"):
            loader = TextLoader(str(path), encoding="utf-8")
        else:
            raise ValueError(f"Unsupported file type: {ext}. Use .pdf, .txt, .md, .log, or .csv")

        documents = loader.load()
        chunks = self.splitter.split_documents(documents)

        if not chunks:
            return 0

        Chroma.from_documents(
            documents=chunks,
            embedding=self.embeddings,
            persist_directory=self.chroma_dir,
        )

        return len(chunks)

    def get_vectorstore(self) -> Chroma:
        """Return the ChromaDB vector store instance."""
        return Chroma(
            persist_directory=self.chroma_dir,
            embedding_function=self.embeddings,
        )

    def is_ready(self) -> bool:
        """Check if the vector store has been initialized with data."""
        path = Path(self.chroma_dir)
        return path.exists() and any(path.iterdir())

    def clear(self) -> None:
        """Delete the vector store from disk."""
        if os.path.exists(self.chroma_dir):
            shutil.rmtree(self.chroma_dir)
