from __future__ import annotations

import streamlit as st
from analyzer import (
    LocalModelAnalyzer,
    ProofSecError,
)
from report import generate_markdown_report
from schemas import (
    FindingInput,
    SeverityEstimate,
    TriageAssessment,
    TriageStatus,
)

# Page configuration
st.set_page_config(
    page_title="ProofSec AI - Vulnerability Triage Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1a1e24;
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 14px;
        text-align: center;
    }
    .status-badge {
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 4px;
        display: inline-block;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ ProofSec AI")
st.caption("Evidence-First Vulnerability Triage Assistant (Local Inference)")

# Sidebar: Local Model & Endpoint Configuration
st.sidebar.header("⚙️ Local Inference Engine")
base_url_input = st.sidebar.text_input(
    "Ollama Base URL",
    value="http://localhost:11434",
    help="Address of your locally running Ollama instance (default: http://localhost:11434).",
)

if "installed_models" not in st.session_state:
    st.session_state.installed_models = []
if "last_assessment" not in st.session_state:
    st.session_state.last_assessment = None
if "last_finding" not in st.session_state:
    st.session_state.last_finding = None

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
        value="",
        placeholder="e.g., mistral, llama3, qwen2.5-coder",
        help="Specify the name of a model already pulled on your local Ollama server.",
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

col_input, col_output = st.columns([1, 1], gap="medium")

with col_input:
    st.subheader("1. Finding & Evidence Input")

    if st.button("Load Sample Finding Preset"):
        st.session_state.f_title = SAMPLE_FINDING["title"]
        st.session_state.f_target = SAMPLE_FINDING["target"]
        st.session_state.f_desc = SAMPLE_FINDING["description"]
        st.session_state.f_evidence = SAMPLE_FINDING["evidence"]

    title = st.text_input(
        "Finding Title *",
        value=st.session_state.get("f_title", ""),
        placeholder="e.g., Remote Code Execution in Image Processor",
    )

    target = st.text_input(
        "Target Component / URL (Optional)",
        value=st.session_state.get("f_target", ""),
        placeholder="e.g., /api/v1/render",
    )

    description = st.text_area(
        "Finding Description / Context (Optional)",
        value=st.session_state.get("f_desc", ""),
        height=90,
        placeholder="Reported narrative, attack scenario, or scanner context...",
    )

    evidence = st.text_area(
        "Supplied Technical Evidence * (Max 64KB)",
        value=st.session_state.get("f_evidence", ""),
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
                st.error(f"Triage Engine Notice: {err}")
            except Exception as err:
                st.error(f"Input Validation Error: {err}")

with col_output:
    st.subheader("2. Triage Assessment")

    if st.session_state.last_assessment:
        assessment: TriageAssessment = st.session_state.last_assessment
        finding: FindingInput = st.session_state.last_finding

        m1, m2, m3 = st.columns(3)
        m1.metric("Status", assessment.status.value.upper())
        m2.metric("Severity", assessment.severity.value.upper())
        m3.metric("Confidence", f"{assessment.confidence.score}/100")

        st.info(f"**Confidence Rationale:** {assessment.confidence.rationale}")

        tab_eval, tab_remed, tab_report, tab_json = st.tabs(
            ["🔬 Observations & Interpretations", "🛠️ Validation & Remediation", "📄 Markdown Report", "🔍 Schema JSON"]
        )

        with tab_eval:
            st.markdown("### Factual Technical Observations")
            for o in assessment.observations:
                st.markdown(f"- {o}")

            st.markdown("### Analytical Interpretations")
            for i in assessment.interpretations:
                st.markdown(f"- {i}")

            st.markdown("### Missing Evidence")
            if assessment.missing_evidence:
                for m in assessment.missing_evidence:
                    st.markdown(f"- ⚠️ {m}")
            else:
                st.write("None identified.")

        with tab_remed:
            st.markdown("### Safe Analyst Validation Steps")
            for v in assessment.validation_recommendations:
                st.markdown(f"- 🧪 {v}")

            st.markdown("### Remediation Actions")
            for r in assessment.remediation:
                st.markdown(f"- 🔒 {r}")

            st.markdown("### Assessment Limitations")
            for l in assessment.limitations:
                st.markdown(f"- ℹ️ {l}")

        with tab_report:
            report_md = generate_markdown_report(assessment, finding)
            st.download_button(
                label="📥 Download Markdown Report (.md)",
                data=report_md,
                file_name=f"triage_report_{assessment.finding_title.lower().replace(' ', '_')[:30]}.md",
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
