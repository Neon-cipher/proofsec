# ProofSec AI 🛡️

ProofSec AI is a minimal, evidence-first vulnerability triage assistant built for application security teams and security researchers.

It evaluates reported security vulnerabilities against supplied proof (HTTP traffic, execution logs, code snippets, or PoC output) using an Ollama-compatible local open-weight language model, strictly validates the assessment output with Pydantic v2 schemas, and produces clean Markdown triage reports.

---

## Architecture & Guiding Constraints

- **Evidence-First**: Triage decisions require verifiable technical proof; unsubstantiated assertions are flagged as `INSUFFICIENT_EVIDENCE` or `LIKELY_FALSE_POSITIVE`.
- **Local & Private**: All inference runs against local endpoints (e.g. Ollama). No external cloud APIs, telemetry, or remote prompts.
- **Zero Weight Presumption**: ProofSec AI never assumes a specific model is installed and **never downloads weights automatically**. It dynamically queries available models from your local endpoint.
- **Strict Schema Enforcement**: LLM output is constrained to structured JSON and validated against Pydantic v2 data models.
- **Lightweight & Hackathon-Sized**: Built without bloated multi-agent dependencies, databases, or autonomous exploitation tools.

---

## Project Structure

```text
proofsec/
├── app.py                 # Streamlit interactive UI
├── analyzer.py            # Local Ollama inference orchestrator & prompt logic
├── schemas.py             # Pydantic v2 schemas for findings and triage results
├── report.py              # Structured Markdown report generator
├── requirements.txt       # Minimal, pinned dependencies
├── tests/
│   └── test_schemas.py    # Unit tests for schemas, parser, and reporting
├── .gitignore             # Standard Python / Streamlit gitignore
├── LICENSE                # MIT License + third-party & model disclaimers
└── README.md              # Documentation & setup guide
```

---

## Prerequisites

- **Python**: 3.11 or higher
- **Local Inference Server**: [Ollama](https://ollama.com/) (or any compatible OpenAI/Ollama API server)
- **Local Model**: Pull your preferred local open-weight model before running, e.g.:
  ```bash
  ollama pull mistral
  # or
  ollama pull llama3
  # or
  ollama pull qwen2.5-coder:7b
  ```

---

## Configuration

ProofSec AI can be configured via environment variables or directly inside the Streamlit user interface sidebar:

| Setting | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **Ollama Base URL** | `PROOFSEC_OLLAMA_URL` | `http://localhost:11434` | Base address of the local inference service |
| **Default Model** | `PROOFSEC_MODEL` | `""` (Empty) | Target model identifier installed on the host |

---

## Quickstart Setup & Launch

### 1. Windows PowerShell

```powershell
# Navigate into repository
cd d:\proofsec

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run unit tests
pytest

# Launch Streamlit application
streamlit run app.py
```

### 2. Linux / macOS Bash

```bash
# Navigate into repository
cd /path/to/proofsec

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run unit tests
pytest

# Launch Streamlit application
streamlit run app.py
```

---

## Usage Workflow

1. Start your local Ollama daemon: `ollama serve` (if not already running).
2. Open the Streamlit web dashboard in your browser (typically `http://localhost:8501`).
3. In the sidebar, click **Test Connection** to detect available installed models from your local Ollama server.
4. Select an installed model from the dropdown.
5. In the main panel, enter finding information or click **Load Sample Finding for Testing**.
6. Paste the technical proof (HTTP request/response, logs, code, or PoC execution).
7. Click **Run Triage Analysis**.
8. Review the verdict (`CONFIRMED`, `LIKELY_FALSE_POSITIVE`, `INSUFFICIENT_EVIDENCE`), confidence score, evidence quality, and remediation steps.
9. Export or download the generated Markdown triage report for issue tracking.

---

## Running Tests

Run the test suite using `pytest`:

```bash
pytest -v
```

---

## License & Attribution

This project is open-source under the [MIT License](LICENSE). Please review the license for third-party software and independent model weight distribution caveats.
