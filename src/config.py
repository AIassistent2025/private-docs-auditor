"""Configuration for Private Docs Auditor — all local, zero cloud."""

OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_LLM_MODEL = "llama3.2"
DEFAULT_EMBED_MODEL = "nomic-embed-text"

CHROMA_DIR = "chroma_db"
CHUNK_SIZE = 1000
CHUNK_OVERLAP = 150
RETRIEVER_K = 5
