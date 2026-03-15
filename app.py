"""Private Docs Auditor — Streamlit dashboard. Fully local, zero cloud."""

import os
import tempfile

import streamlit as st

from src.auditor import DocumentAuditor
from src.config import DEFAULT_LLM_MODEL, DEFAULT_EMBED_MODEL

st.set_page_config(page_title="Private Docs Auditor", page_icon="🔒", layout="wide")
st.title("🔒 Private Docs Auditor")
st.caption("On-premise document intelligence — your data never leaves this machine")

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Configuration")

    llm_model = st.text_input("LLM Model (Ollama)", value=DEFAULT_LLM_MODEL)
    embed_model = st.text_input("Embedding Model (Ollama)", value=DEFAULT_EMBED_MODEL)

    st.divider()
    st.header("Upload Document")
    uploaded = st.file_uploader(
        "PDF or Text file",
        type=["pdf", "txt", "md", "log"],
        help="Your file stays local — never uploaded to any cloud service",
    )

    st.divider()
    st.markdown(
        "**Privacy guarantee:** All processing happens locally via Ollama. "
        "No API keys. No cloud calls. No data exfiltration."
    )

# ── Main Content ──────────────────────────────────────────────────────────────

if uploaded:
    # Save uploaded file to temp
    suffix = os.path.splitext(uploaded.name)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    tab1, tab2, tab3 = st.tabs(["Document Audit", "Q&A (RAG)", "Raw Text"])

    # ── Tab 1: Audit ──────────────────────────────────────────────────────

    with tab1:
        st.subheader("Automated Compliance & Risk Audit")

        col1, col2 = st.columns(2)
        with col1:
            framework = st.selectbox(
                "Compliance Framework",
                ["All Frameworks", "GDPR", "HIPAA", "SOX", "PCI-DSS"],
            )
        with col2:
            run_audit = st.button("Run Audit", type="primary")

        if run_audit:
            fw = None if framework == "All Frameworks" else framework
            auditor = DocumentAuditor()

            with st.spinner("Scanning document..."):
                result = auditor.full_audit(tmp_path, framework=fw)

            # PII Results
            st.markdown("### PII Scan")
            pii = result["pii_scan"]
            if pii["total_findings"] == 0:
                st.success("No PII detected in this document.")
            else:
                st.error(f"{pii['total_findings']} PII items found!")
                for finding in pii["findings"]:
                    st.markdown(
                        f"- **{finding['type']}** ({finding['severity']}): "
                        f"{finding['count']} found — samples: `{', '.join(finding['samples'])}`"
                    )

            # Compliance Results
            st.markdown("### Compliance Check")
            for name, data in result["compliance"].items():
                with st.expander(f"{name} — Relevance: {data['relevance']}"):
                    st.markdown(f"*{data['description']}*")
                    st.markdown(f"Keywords matched: **{data['matched_keywords']}/{data['total_keywords']}**")
                    if data["details"]:
                        for d in data["details"][:10]:
                            st.markdown(f"- {d['keyword']} ({d['occurrences']})")

            # Risk Results
            st.markdown("### Risk Flags")
            risks = result["risk_flags"]
            if risks["total_flags"] == 0:
                st.success("No risk indicators detected.")
            else:
                st.warning(f"{risks['total_flags']} risk indicators found")
                for category, data in risks["categories"].items():
                    with st.expander(f"{category.title()} Risk ({data['severity']})"):
                        for flag in data["flags"]:
                            st.markdown(f"- **{flag['term']}** — {flag['occurrences']} occurrence(s)")

            # Full report download
            report_md = auditor.format_report(result)
            st.download_button(
                "Download Full Report (Markdown)",
                data=report_md,
                file_name=f"audit_{uploaded.name}.md",
                mime="text/markdown",
            )

    # ── Tab 2: Q&A ────────────────────────────────────────────────────────

    with tab2:
        st.subheader("Ask Questions About Your Document")
        st.info("This requires Ollama running locally with the configured models.")

        if st.button("Index Document"):
            with st.spinner(f"Indexing with {embed_model}..."):
                try:
                    from src.ingestor import DocumentIngestor

                    ingestor = DocumentIngestor(embed_model=embed_model)
                    n = ingestor.ingest(tmp_path)
                    st.success(f"Indexed {n} chunks into local ChromaDB")
                    st.session_state["indexed"] = True
                except Exception as e:
                    st.error(f"Indexing failed: {e}")
                    st.info("Make sure Ollama is running: `ollama serve`")

        if st.session_state.get("indexed"):
            question = st.text_input("Your question:")
            if question:
                with st.spinner("Thinking..."):
                    try:
                        from src.ingestor import DocumentIngestor
                        from src.qa_chain import RAGChain

                        ingestor = DocumentIngestor(embed_model=embed_model)
                        chain = RAGChain(ingestor.get_vectorstore(), model=llm_model)
                        result = chain.query(question)

                        st.markdown("### Answer")
                        st.markdown(result["answer"])

                        st.markdown("### Sources")
                        for src in result["sources"]:
                            st.markdown(f"- {src['source']} (page {src['page']})")

                    except Exception as e:
                        st.error(f"Query failed: {e}")
                        st.info("Make sure Ollama is running: `ollama serve`")

    # ── Tab 3: Raw Text ───────────────────────────────────────────────────

    with tab3:
        st.subheader("Extracted Text")
        auditor = DocumentAuditor()
        text = auditor.extract_text(tmp_path)
        st.text_area("Document content", value=text, height=500, disabled=True)
        st.caption(f"Word count: {len(text.split()):,}")

else:
    st.info("Upload a document in the sidebar to begin.")

    st.markdown("""
    ### What this tool does

    1. **PII Detection** — Scans for SSNs, credit cards, emails, phone numbers, IBANs
    2. **Compliance Check** — Tests against GDPR, HIPAA, SOX, PCI-DSS frameworks
    3. **Risk Flagging** — Identifies financial, legal, and operational risk indicators
    4. **Local Q&A** — Ask questions about your documents using a local LLM (Ollama)

    ### Privacy Architecture

    - LLM runs locally via **Ollama** (Llama 3.2, Mistral, etc.)
    - Embeddings generated locally via **nomic-embed-text**
    - Vector store on disk via **ChromaDB**
    - **Zero API keys required** — no OpenAI, no cloud services
    """)
