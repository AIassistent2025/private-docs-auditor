"""Private Docs Auditor — CLI entry point."""

import argparse
import json
import sys

from src.auditor import DocumentAuditor


def cmd_ingest(args):
    """Ingest a document into the local vector store."""
    from src.ingestor import DocumentIngestor

    ingestor = DocumentIngestor(embed_model=args.embed_model)
    n = ingestor.ingest(args.file)
    print(f"Indexed {n} chunks from {args.file}")


def cmd_query(args):
    """Ask a question about ingested documents."""
    from src.ingestor import DocumentIngestor
    from src.qa_chain import RAGChain

    ingestor = DocumentIngestor(embed_model=args.embed_model)
    if not ingestor.is_ready():
        print("Error: No documents indexed yet. Run 'ingest' first.")
        sys.exit(1)

    chain = RAGChain(ingestor.get_vectorstore(), model=args.model, k=args.k)
    result = chain.query(args.question)

    print("\nAnswer:")
    print(result["answer"])
    print("\nSources:")
    for src in result["sources"]:
        print(f"  - {src['source']} (page {src['page']})")


def cmd_audit(args):
    """Run a full document audit (PII, compliance, risks)."""
    auditor = DocumentAuditor()
    result = auditor.full_audit(args.file, framework=args.framework)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(auditor.format_report(result))


def cmd_clear(args):
    """Clear the local vector store."""
    from src.ingestor import DocumentIngestor

    ingestor = DocumentIngestor()
    ingestor.clear()
    print("Vector store cleared.")


def main():
    parser = argparse.ArgumentParser(
        description="Private Docs Auditor — on-premise document intelligence"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ingest
    p_ingest = sub.add_parser("ingest", help="Ingest a document into the local vector store")
    p_ingest.add_argument("file", help="Path to PDF or text file")
    p_ingest.add_argument("--embed-model", default="nomic-embed-text", help="Ollama embedding model")
    p_ingest.set_defaults(func=cmd_ingest)

    # query
    p_query = sub.add_parser("query", help="Ask a question about ingested documents")
    p_query.add_argument("question", help="Your question")
    p_query.add_argument("--model", default="llama3.2", help="Ollama LLM model")
    p_query.add_argument("--embed-model", default="nomic-embed-text", help="Ollama embedding model")
    p_query.add_argument("--k", type=int, default=5, help="Number of chunks to retrieve")
    p_query.set_defaults(func=cmd_query)

    # audit
    p_audit = sub.add_parser("audit", help="Run PII, compliance, and risk audit on a document")
    p_audit.add_argument("file", help="Path to PDF or text file")
    p_audit.add_argument("--framework", choices=["GDPR", "HIPAA", "SOX", "PCI-DSS"], help="Specific compliance framework")
    p_audit.add_argument("--json", action="store_true", help="Output as JSON")
    p_audit.set_defaults(func=cmd_audit)

    # clear
    p_clear = sub.add_parser("clear", help="Clear the local vector store")
    p_clear.set_defaults(func=cmd_clear)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
