from __future__ import annotations

import streamlit as st
from analyzer import (
    LocalModelAnalyzer,
    ProofSecError,
)
from report import generate_markdown_report
from schemas import (
    FindingInput,
    TriageAssessment,
)

# Page configuration
st.set_page_config(
    page_title="ProofSec AI - Vulnerability Triage Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom minimal styling
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1a1e24;
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
    }
    .disclaimer-box {
        background-color: #262111;
        border-left: 4px solid #f6ad55;
        padding: 10px 14px;
        border-radius: 4px;
        margin-bottom: 12px;
        font-size: 0.9rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ ProofSec AI")
st.caption("Evidence-First Vulnerability Triage Assistant (Local Inference)")

# Session state initialization
if "f_title" not in st.session_state:
    st.session_state.f_title = ""
if "f_target" not in st.session_state:
    st.session_state.f_target = ""
if "f_desc" not in st.session_state:
    st.session_state.f_desc = ""
if "f_evidence" not in st.session_state:
    st.session_state.f_evidence = ""
if "f_model" not in st.session_state:
    st.session_state.f_model = ""
if "installed_models" not in st.session_state:
    st.session_state.installed_models = []
if "last_assessment" not in st.session_state:
    st.session_state.last_assessment = None
if "last_finding" not in st.session_state:
    st.session_state.last_finding = None

# Sidebar: Local Model & Endpoint Configuration
st.sidebar.header("⚙️ Local Inference Engine")
base_url_input = st.sidebar.text_input(
    "Ollama Base URL",
    value="http://localhost:11434",
    key="base_url",
    help="Address of your locally running Ollama instance.",
)

analyzer = LocalModelAnalyzer(base_url=base_url_input)

col_check, _ = st.sidebar.columns([1, 1])
if col_check.button("Verify Connection"):
    is_ok, msg = analyzer.verify_endpoint()
    if is_ok:
        st.sidebar.success(msg)
        try:
            st.session_state.installed_models = analyzer.list_installed_models()
        except Exception as e:
            st.sidebar.warning(f"Connected, but error querying models: {e}")
    else:
        st.sidebar.error(msg)

selected_model = ""
if st.session_state.installed_models:
    selected_model = st.sidebar.selectbox(
        "Select Local Model",
        options=st.session_state.installed_models,
        index=0,
    )
else:
    selected_model = st.sidebar.text_input(
        "Local Model Name",
        key="f_model",
        placeholder="e.g., mistral, llama3, qwen2.5-coder",
        help="Specify the name of a model installed on your local server.",
    )

st.sidebar.divider()
st.sidebar.markdown(
    """
    **Triage Status Definitions:**
    - `SUPPORTED`: Submitted evidence supports the claim (does not imply confirmed exploitability).
    - `INCONCLUSIVE`: Ambiguous proof or conflicting indicators.
    - `INSUFFICIENT_EVIDENCE`: Missing requisite technical proof.
    - `CONTRADICTED`: Evidence disproves the vulnerability claim.
    """
)

# Preset for quick evaluation
SAMPLE_FINDING = {
    "title": "Unauthenticated Path Traversal via /download Parameter",
    "target": "https://api.internal/download?file=",
    "description": "Report alleges that directory traversal allows unauthorized access to server files.",
    "evidence": (
        "HTTP Request:\n"
        "GET /download?file=../../../../etc/passwd HTTP/1.1\n"
        "Host: api.internal\n\n"
        "HTTP Response:\n"
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/plain\n\n"
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    ),
}

def load_sample_preset():
    st.session_state.f_title = SAMPLE_FINDING["title"]
    st.session_state.f_target = SAMPLE_FINDING["target"]
    st.session_state.f_desc = SAMPLE_FINDING["description"]
    st.session_state.f_evidence = SAMPLE_FINDING["evidence"]

col_input, col_output = st.columns([1, 1], gap="medium")

with col_input:
    st.subheader("1. Finding & Evidence Input")

    st.button("Load Sample Finding Preset", on_click=load_sample_preset)

    title = st.text_input(
        "Finding Title *",
        key="f_title",
        placeholder="e.g., Remote Code Execution in Image Processor",
    )

    target = st.text_input(
        "Target Component / URL (Optional)",
        key="f_target",
        placeholder="e.g., /api/v1/render",
    )

    description = st.text_area(
        "Finding Description / Context (Optional)",
        key="f_desc",
        height=90,
        placeholder="Reported narrative, attack scenario, or scanner context...",
    )

    evidence = st.text_area(
        "Supplied Technical Evidence * (Max 64KB)",
        key="f_evidence",
        height=200,
        placeholder=(
            "Paste verifiable technical proof here:\n"
            "- Raw HTTP Request / Response traces\n"
            "- Relevant application / system execution logs\n"
            "- Source code snippet demonstrating the flaw\n"
            "- Console or script execution output"
        ),
    )

    analyze_clicked = st.button("🚀 Analyze Evidence", type="primary", use_container_width=True)

    if analyze_clicked:
        if not selected_model:
            st.error("Please specify or select a local model in the sidebar.")
        else:
            try:
                # Validates input via Pydantic model (rejects empty strings or oversized evidence)
                finding_obj = FindingInput(
                    title=title,
                    evidence=evidence,
                    description=description,
                    target=target,
                )
                with st.spinner(f"Evaluating evidence against local model '{selected_model}'..."):
                    analyzer.model_name = selected_model
                    assessment = analyzer.analyze(finding_obj)
                    st.session_state.last_assessment = assessment
                    st.session_state.last_finding = finding_obj
                    st.success("Triage analysis complete.")
            except ProofSecError as err:
                st.error(f"Inference Engine Notice: {err}")
            except Exception as err:
                st.error(f"Input Validation Error: {err}")

with col_output:
    st.subheader("2. Triage Assessment")

    if st.session_state.last_assessment:
        assessment: TriageAssessment = st.session_state.last_assessment
        finding: FindingInput = st.session_state.last_finding

        # Explicit AI Disclaimer Banner
        st.warning(
            "⚠️ **Disclaimer:** AI triage provides assistive evidence analysis. It does **not** "
            "constitute independent vulnerability verification or confirmed exploitability."
        )

        # High-level assessment metrics
        m1, m2, m3 = st.columns(3)
        m1.metric("Status", assessment.status.value.upper())
        m2.metric("Estimated Severity", assessment.severity.value.upper())
        m3.metric("Confidence Score", f"{assessment.confidence.score}/100")

        st.info(f"**Confidence Rationale:** {assessment.confidence.rationale}")

        # Expander for submitted evidence inspection
        with st.expander("🔍 View Submitted Technical Evidence (Untrusted Input)", expanded=False):
            st.code(finding.evidence, language="text")

        tab_eval, tab_remed, tab_report, tab_json = st.tabs(
            ["🔬 Observations & Interpretations", "🛠️ Validation & Remediation", "📄 Markdown Report", "🔍 Schema JSON"]
        )

        with tab_eval:
            st.markdown("### Factual Technical Observations")
            st.caption("Verifiable technical facts extracted directly from the supplied evidence:")
            for o in assessment.observations:
                st.markdown(f"- {o}")

            st.divider()
            st.markdown("### Analytical Interpretations")
            st.caption("Security deductions and analytical conclusions:")
            for i in assessment.interpretations:
                st.markdown(f"- {i}")

            st.divider()
            st.markdown("### Missing Evidence Gaps")
            if assessment.missing_evidence:
                for m in assessment.missing_evidence:
                    st.markdown(f"- ⚠️ {m}")
            else:
                st.write("None identified. Submitted evidence was sufficient for this assessment level.")

        with tab_remed:
            st.markdown("### Safe Analyst Validation Steps")
            st.caption("Recommended non-destructive verification procedures for human analysts:")
            for v in assessment.validation_recommendations:
                st.markdown(f"- 🧪 {v}")

            st.divider()
            st.markdown("### Recommended Remediation Actions")
            for r in assessment.remediation:
                st.markdown(f"- 🔒 {r}")

            st.divider()
            st.markdown("### Assessment Limitations")
            for l in assessment.limitations:
                st.markdown(f"- ℹ️ {l}")

        with tab_report:
            report_md = generate_markdown_report(assessment, finding)
            safe_filename = f"triage_report_{assessment.finding_title.lower().replace(' ', '_')[:30]}.md"
            st.download_button(
                label="📥 Download Markdown Report (.md)",
                data=report_md,
                file_name=safe_filename,
                mime="text/markdown",
                use_container_width=True,
            )
            st.markdown(report_md)

        with tab_json:
            st.json(assessment.model_dump(mode="json"))

    else:
        st.info(
            "👈 Provide finding details and technical proof on the left, then click 'Analyze Evidence' to generate an assessment."
        )
