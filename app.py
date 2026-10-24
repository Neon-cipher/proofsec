from __future__ import annotations

import streamlit as st
from analyzer import OllamaClientError, VulnerabilityAnalyzer
from report import generate_markdown_report
from schemas import (
    FindingInput,
    OllamaEndpointConfig,
    SeverityLevel,
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
        padding: 14px;
        text-align: center;
    }
    .stCodeBlock {
        border-radius: 6px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# App Header
st.title("🛡️ ProofSec AI")
st.caption("Evidence-First Vulnerability Triage Assistant (Local Inference)")

# Sidebar: Local Model & Endpoint Configuration
st.sidebar.header("⚙️ Local Inference Engine")
base_url_input = st.sidebar.text_input(
    "Ollama Base URL",
    value="http://localhost:11434",
    help="Address of your locally running Ollama or compatible inference API.",
)

# State initialization
if "installed_models" not in st.session_state:
    st.session_state.installed_models = []
if "connection_verified" not in st.session_state:
    st.session_state.connection_verified = False
if "last_assessment" not in st.session_state:
    st.session_state.last_assessment = None
if "last_finding" not in st.session_state:
    st.session_state.last_finding = None

config = OllamaEndpointConfig(base_url=base_url_input)
analyzer = VulnerabilityAnalyzer(config)

col_check, col_refresh = st.sidebar.columns([1, 1])
if col_check.button("Test Connection"):
    is_ok, msg = analyzer.check_connection()
    st.session_state.connection_verified = is_ok
    if is_ok:
        st.sidebar.success(msg)
        try:
            models = analyzer.list_installed_models()
            st.session_state.installed_models = models
        except OllamaClientError as err:
            st.sidebar.warning(f"Connected, but error querying tags: {err}")
    else:
        st.sidebar.error(msg)

# Model selection
selected_model = ""
if st.session_state.installed_models:
    selected_model = st.sidebar.selectbox(
        "Installed Models (Verified)",
        options=st.session_state.installed_models,
        index=0,
        help="Models detected on your local Ollama instance.",
    )
else:
    st.sidebar.info(
        "No models detected or connection not checked. ProofSec AI does not download weights automatically."
    )
    selected_model = st.sidebar.text_input(
        "Or specify model name manually:",
        value="",
        placeholder="e.g., mistral, llama3, qwen2.5-coder",
    )

st.sidebar.divider()
st.sidebar.markdown(
    """
    **Guiding Principles:**
    - Evidence-first verification
    - 100% local inference privacy
    - Zero assumption of model availability
    - Strict Pydantic schema validation
    """
)

# Sample finding presets for testing
SAMPLE_FINDING = {
    "title": "Unauthenticated Path Traversal in File Viewer",
    "vulnerability_type": "Path Traversal (Arbitrary File Read)",
    "cwe_id": "CWE-22",
    "reported_severity": SeverityLevel.HIGH,
    "target_component": "/download?file=",
    "description": (
        "The file download endpoint does not sanitize directory traversal sequences, "
        "allowing unauthenticated users to read arbitrary files from the filesystem."
    ),
    "evidence_text": (
        "HTTP Request:\n"
        "GET /download?file=../../../../etc/passwd HTTP/1.1\n"
        "Host: target.internal\n\n"
        "HTTP Response:\n"
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/plain\n\n"
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    ),
}

# Main Application Layout
col_input, col_output = st.columns([1, 1], gap="medium")

with col_input:
    st.subheader("1. Security Finding & Evidence")

    if st.button("Load Sample Finding for Testing"):
        st.session_state.f_title = SAMPLE_FINDING["title"]
        st.session_state.f_type = SAMPLE_FINDING["vulnerability_type"]
        st.session_state.f_cwe = SAMPLE_FINDING["cwe_id"]
        st.session_state.f_severity = SAMPLE_FINDING["reported_severity"].value
        st.session_state.f_target = SAMPLE_FINDING["target_component"]
        st.session_state.f_desc = SAMPLE_FINDING["description"]
        st.session_state.f_evidence = SAMPLE_FINDING["evidence_text"]

    title = st.text_input(
        "Finding Title *",
        value=st.session_state.get("f_title", ""),
        placeholder="e.g., SQL Injection in Authentication Gateway",
    )

    row1_c1, row1_c2 = st.columns([1, 1])
    with row1_c1:
        vuln_type = st.text_input(
            "Vulnerability Type *",
            value=st.session_state.get("f_type", ""),
            placeholder="e.g., SQL Injection, IDOR, SSRF",
        )
    with row1_c2:
        cwe_id = st.text_input(
            "CWE ID (Optional)",
            value=st.session_state.get("f_cwe", ""),
            placeholder="e.g., CWE-89",
        )

    row2_c1, row2_c2 = st.columns([1, 1])
    with row2_c1:
        severity_options = [s.value for s in SeverityLevel if s != SeverityLevel.UNKNOWN]
        reported_severity_str = st.selectbox(
            "Reported Severity",
            options=severity_options,
            index=severity_options.index(st.session_state.get("f_severity", "MEDIUM"))
            if st.session_state.get("f_severity", "MEDIUM") in severity_options
            else 2,
        )
    with row2_c2:
        target_comp = st.text_input(
            "Target Endpoint / Component",
            value=st.session_state.get("f_target", ""),
            placeholder="e.g., /api/v1/auth/login",
        )

    description = st.text_area(
        "Vulnerability Description *",
        value=st.session_state.get("f_desc", ""),
        height=100,
        placeholder="Detailed explanation of the reported issue, attack vector, and potential impact...",
    )

    evidence_text = st.text_area(
        "Supplied Technical Evidence *",
        value=st.session_state.get("f_evidence", ""),
        height=180,
        placeholder=(
            "Paste raw proof here:\n"
            "- HTTP Request & Response\n"
            "- Execution logs\n"
            "- Source code snippet\n"
            "- Reproducible PoC script or command output"
        ),
    )

    analyze_clicked = st.button("🚀 Run Triage Analysis", type="primary", use_container_width=True)

    if analyze_clicked:
        if not selected_model:
            st.error("Please configure and select a verified local model in the sidebar.")
        else:
            try:
                finding_obj = FindingInput(
                    title=title,
                    vulnerability_type=vuln_type,
                    cwe_id=cwe_id if cwe_id else None,
                    reported_severity=SeverityLevel(reported_severity_str),
                    target_component=target_comp if target_comp else None,
                    description=description,
                    evidence_text=evidence_text,
                )
                with st.spinner(f"Analyzing evidence with local model '{selected_model}'..."):
                    assessment = analyzer.analyze(finding_obj, model_override=selected_model)
                    st.session_state.last_assessment = assessment
                    st.session_state.last_finding = finding_obj
                    st.success("Triage analysis complete!")
            except OllamaClientError as err:
                st.error(f"Inference Engine Error: {err}")
            except Exception as err:
                st.error(f"Validation or Input Error: {err}")

with col_output:
    st.subheader("2. Triage Results & Assessment")

    if st.session_state.last_assessment and st.session_state.last_finding:
        assessment: TriageAssessment = st.session_state.last_assessment
        finding: FindingInput = st.session_state.last_finding

        # Key metrics row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Verdict", assessment.verdict.value)
        m2.metric("Adjusted Severity", assessment.adjusted_severity.value)
        m3.metric("Confidence", f"{assessment.confidence_score * 100:.0f}%")
        m4.metric("Evidence Quality", assessment.evidence_quality.value)

        tab_summary, tab_report, tab_json = st.tabs(
            ["📋 Executive Summary", "📄 Markdown Report", "🔍 Raw JSON"]
        )

        with tab_summary:
            st.markdown(f"**Executive Summary:**\n{assessment.summary}")
            st.divider()
            st.markdown(f"**Evidence Breakdown:**\n{assessment.evidence_analysis}")

            st.write("**Validated Findings:**")
            if assessment.key_findings:
                for k in assessment.key_findings:
                    st.markdown(f"- {k}")
            else:
                st.write("None noted.")

            st.write("**Evidence Gaps / Missing Items:**")
            if assessment.missing_evidence:
                for m in assessment.missing_evidence:
                    st.markdown(f"- ⚠️ {m}")
            else:
                st.write("No missing evidence identified.")

            st.write("**Remediation Guidance:**")
            if assessment.remediation_recommendations:
                for r in assessment.remediation_recommendations:
                    st.markdown(f"- 🛠️ {r}")

        with tab_report:
            report_md = generate_markdown_report(finding, assessment)
            st.download_button(
                label="📥 Download Markdown Report (.md)",
                data=report_md,
                file_name=f"triage_report_{finding.title.lower().replace(' ', '_')[:30]}.md",
                mime="text/markdown",
                use_container_width=True,
            )
            st.markdown(report_md)

        with tab_json:
            st.json(assessment.model_dump(mode="json"))

    else:
        st.info(
            "👈 Provide finding details and supporting technical evidence on the left, then click 'Run Triage Analysis' to generate a verdict."
        )
