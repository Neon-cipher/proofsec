# ProofSec AI 🛡️
> **Evidence-First Vulnerability Triage Assistant**  
> *Category Submission: Best Open-Source AI Project — Hacktoberfest Hack Day Ahmedabad*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 24 Passed](https://img.shields.io/badge/tests-24%20passed-brightgreen.svg)](tests/)

---

## 1. The Problem ProofSec AI Solves

Security operations centers (SOCs), Application Security (AppSec) teams, and bug bounty triage queues are inundated with vulnerability alerts from automated DAST, SAST, and external report submissions. 

Two critical bottlenecks plague current workflows:
1. **Unsubstantiated Claims & Hallucinations**: Automated scanners often flag issues based on heuristic pattern matching or timing noise without tangible proof of exploitability.
2. **Confidentiality Risks**: Sending sensitive proprietary source code, internal hostnames, and zero-day execution logs to external commercial cloud AI APIs creates unacceptable privacy and compliance exposures.

**ProofSec AI** resolves this by providing a lightweight, **evidence-first triage assistant** that evaluates reported security claims exclusively against supplied technical proof (HTTP traffic, server execution logs, code snippets) using **locally running open-weight language models**. It strictly separates verifiable technical observations from subjective interpretations, rejects fabricated evidence, and enforces Pydantic v2 schemas on all outputs.

---

## 2. Intended Users & Use Cases

- **Application Security (AppSec) Engineers**: Pre-screening bug bounty submissions to filter out false positives before developer escalation.
- **Security Operations (SOC) Analysts**: Quickly triaging web application firewall (WAF) or intrusion detection alerts against raw HTTP request/response traces.
- **Independent Security Auditors**: Generating structured Markdown triage reports with remediation guidance for client deliverables.
- **Development Teams**: Reviewing scanner reports during CI/CD triage to verify whether reported vulnerabilities have actionable proof.

---

## 3. Why Open-Source AI is Central to ProofSec AI

Security triage involves the most sensitive data an organization possesses: live attack payloads, internal architectural endpoints, and exploit sequences. 

Using open-source, open-weight AI models is a fundamental design requirement, not an afterthought:
- **Zero Data Leakage (Local Privacy)**: Inference executes entirely on the local host (via an Ollama-compatible HTTP daemon on `localhost`). No telemetry, prompts, or vulnerability details leave your environment.
- **Air-Gappable Deployment**: Can operate in strictly isolated, air-gapped development and high-security defense networks without Internet access.
- **Deterministic & Auditable**: Open-weight models can be inspected, pinned, and audited. With zero temperature (`temperature=0.0`) and JSON schema-constrained decoding, output structures are repeatable and verifiable.
- **No Vendor Lock-In**: Supports any open-weight architecture served by Ollama (e.g., Llama 3, Mistral, Qwen 2.5 Coder) without subscription fees or API rate limits.

---

## 4. Tested Runtime & Model Compatibility

- **Inference Server**: [Ollama](https://ollama.com/) (local HTTP daemon serving `POST /api/chat` with structured JSON schema output).
- **Default Base URL**: `http://localhost:11434` (configurable via `PROOFSEC_OLLAMA_URL`).
- **Verified Local Open-Weight Models**:
  - `llama3:8b` (Meta open-weight model)
  - `mistral:7b` (Mistral AI open-weight model)
  - `qwen2.5-coder:7b` (Alibaba Cloud open-weight model)

> [!NOTE]
> ProofSec AI **never automatically downloads model weights** and does not hardcode assumptions about installed models. It verifies whether an endpoint is live and queries installed models via `/api/tags`.
> 
> *Model Note:* We do not claim support for Gemma 4 or any model that has not been explicitly tested on this environment.

---

## 5. Architecture & Project Structure

```text
proofsec/
├── app.py                         # Streamlit interactive UI (input, evaluation tabs, markdown download)
├── analyzer.py                    # Local Ollama client, prompt defense boundaries & schema validation
├── schemas.py                     # Strict Pydantic v2 data models, enumerations & bounds
├── report.py                      # Clean Markdown report generator with AI disclaimers
├── examples.py                    # 5 realistic, manually reviewable triage scenarios
├── requirements.txt               # Pinned dependencies (Pydantic v2, Streamlit, Requests, Pytest)
├── pytest.ini                     # Pytest configuration (pythonpath = .)
├── .gitignore                     # Ignores virtualenvs, caches, secrets, and IDE files
├── LICENSE                        # MIT License with third-party & model disclaimers
├── README.md                      # Comprehensive project documentation
└── tests/
    ├── test_schemas.py            # Unit tests for schemas, boundary limits, and report generation
    ├── test_app.py                # End-to-end headless Streamlit tests using AppTest
    └── test_regression_quality.py # Deterministic regression suite for Test Cases A through G
```

---

## 6. Installation & Configuration

### Prerequisites
- Python 3.11 or higher
- [Ollama](https://ollama.com/) installed and running locally

### Environment Variables (Optional)
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PROOFSEC_OLLAMA_URL` | `http://localhost:11434` | Base URL of local Ollama instance |
| `PROOFSEC_MODEL` | `""` (Empty) | Pre-selected default model name |

---

## 7. Startup Commands

### A. Windows (PowerShell)

```powershell
# 1. Clone and enter the repository
git clone https://github.com/Neon-cipher/proofsec.git
cd proofsec

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run automated test suite (offline)
pytest -v

# 5. Launch the Streamlit application
streamlit run app.py
```

### B. Linux / macOS (Bash)

```bash
# 1. Clone and enter the repository
git clone https://github.com/Neon-cipher/proofsec.git
cd proofsec

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run automated test suite (offline)
pytest -v

# 5. Launch the Streamlit application
streamlit run app.py
```

The app will start at **`http://localhost:8501`**.

---

## 8. Working Example & Expected Analysis

ProofSec AI includes 5 pre-configured scenarios selectable directly in the UI via the **"Select Example Scenario"** dropdown:

### Example: Insufficient XSS Evidence (Escaped HTML)
- **Title**: `Reflected Cross-Site Scripting (XSS) in Search Query`
- **Supplied Evidence**:
  ```text
  GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
  Host: example.com

  HTTP Response Body:
  <p>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</p>
  ```
- **Expected Analysis Behavior**:
  - **Status**: `INSUFFICIENT_EVIDENCE` (Crucial: The model **must not** claim JavaScript execution has been established).
  - **Factual Observations**: Direct fact that `<p>` tag reflects HTML entity-encoded `&lt;script&gt;`.
  - **Analytical Interpretation**: Browser treats entity-encoded characters as text, neutralizing execution context.
  - **Missing Evidence**: Proof of execution in an unencoded attribute or JavaScript execution block.
  - **Confidence**: High confidence that current evidence is insufficient to verify exploitability.

---

## 9. Automated Testing & Verification

The project includes an **offline unit and end-to-end regression test suite** that runs in under 3 seconds without requiring an active model or Internet access:

```powershell
pytest -v
```

### Actual Test Results (24 Passed / 0 Failed):
```text
tests/test_app.py::test_app_startup PASSED                               [  4%]
tests/test_app.py::test_app_invalid_empty_input_rejected PASSED          [  8%]
tests/test_app.py::test_app_successful_triage_flow PASSED                [ 12%]
tests/test_app.py::test_app_model_failure_graceful_handling PASSED       [ 16%]
tests/test_regression_quality.py::test_case_a_insufficient_xss_evidence PASSED [ 20%]
tests/test_regression_quality.py::test_case_b_ambiguous_sql_injection PASSED [ 25%]
tests/test_regression_quality.py::test_case_c_evidence_contradicts_claim PASSED [ 29%]
tests/test_regression_quality.py::test_case_d_prompt_injection_inside_evidence PASSED [ 33%]
tests/test_regression_quality.py::test_case_e_local_model_unavailable PASSED [ 37%]
tests/test_regression_quality.py::test_case_f_invalid_model_output PASSED [ 41%]
tests/test_regression_quality.py::test_case_g_oversized_input_rejected_before_network PASSED [ 45%]
tests/test_schemas.py::test_valid_schema PASSED                          [ 50%]
tests/test_schemas.py::test_invalid_confidence_out_of_bounds PASSED      [ 54%]
tests/test_schemas.py::test_invalid_status_rejected PASSED               [ 58%]
tests/test_schemas.py::test_invalid_severity_rejected PASSED             [ 62%]
tests/test_schemas.py::test_empty_required_inputs PASSED                 [ 66%]
tests/test_schemas.py::test_oversized_evidence_rejected PASSED           [ 70%]
tests/test_schemas.py::test_analyzer_successful_inference PASSED         [ 75%]
tests/test_schemas.py::test_analyzer_malformed_model_output PASSED       [ 79%]
tests/test_schemas.py::test_analyzer_schema_violation_from_model PASSED  [ 83%]
tests/test_schemas.py::test_analyzer_model_connection_failure PASSED     [ 87%]
tests/test_schemas.py::test_analyzer_read_timeout_failure PASSED         [ 91%]
tests/test_schemas.py::test_analyzer_model_404_not_found PASSED          [ 95%]
tests/test_schemas.py::test_markdown_report_generation PASSED            [100%]

============================= 24 passed in 2.80s ==============================
```

---

## 10. Responsible-Use Boundaries & Limitations

1. **Assistive, Not Autonomous**: ProofSec AI is an assistive triage tool. It **never automatically marks vulnerabilities as confirmed** without verifiable technical proof. A triage status of `SUPPORTED` denotes only that submitted logs or traces match the claim; it does **not** establish independent reproduction or confirmed exploitability.
2. **Passive Text Analysis**: ProofSec AI never executes supplied scripts or commands and never sends HTTP traffic to target hosts mentioned in evidence.
3. **Model Confidence Disclaimer**: The confidence score (0–100) measures internal consistency with the supplied text, **not** a calibrated mathematical probability of real-world exploitation.
4. **Not a Statistical Benchmark**: The included 24-test suite verifies schema rules, input boundaries, and defensive prompt isolation. It is an engineering regression suite, not a formal statistical false-positive benchmark.

---

## 11. Third-Party Dependencies & Attribution

- **[Streamlit](https://streamlit.io/)** (Apache 2.0): Web application framework.
- **[Pydantic v2](https://docs.pydantic.dev/)** (MIT License): Data validation and schema enforcement.
- **[Requests](https://requests.readthedocs.io/)** (Apache 2.0): HTTP client for Ollama communication.
- **[Pytest](https://pytest.org/)** (MIT License): Automated testing framework.
- **[Ollama](https://ollama.com/)** (MIT License): Local open-weight inference runtime.

*Open-weight models accessed via Ollama (e.g. Llama 3, Mistral, Qwen) are distributed independently under their respective licenses. ProofSec AI neither bundles nor assumes ownership of third-party model weights.*

---

## 12. Quick Demo Walkthrough (90 Seconds)

1. Open `http://localhost:8501`.
2. In the sidebar, click **Verify Connection** to detect available models on your local Ollama server.
3. Under **Select Example Scenario**, pick:
   `Insufficient XSS Evidence (Escaped HTML)`
4. Click **Load Preset** to populate the finding description and HTTP response snippet.
5. Click **🚀 Analyze Evidence**.
6. Observe the structured assessment:
   - Status badge evaluates to `INSUFFICIENT_EVIDENCE`.
   - The **Observations** tab explicitly notes that the input was HTML entity-escaped.
   - The **Interpretations** tab confirms that script execution was not established.
7. Click the **📄 Markdown Report** tab and click **📥 Download Markdown Report (.md)** to export the verified assessment.
