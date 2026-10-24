import json
import os
import sys
from unittest.mock import MagicMock, patch

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from streamlit.testing.v1 import AppTest

from schemas import FindingInput, SeverityEstimate, TriageAssessment, TriageStatus, ConfidenceAssessment
from report import generate_markdown_report

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))


def test_app_startup():
    """Verify the Streamlit app loads and initializes without exceptions."""
    at = AppTest.from_file(APP_PATH).run()
    assert not at.exception
    assert at.title[0].value == "🛡️ ProofSec AI"


def test_app_invalid_empty_input_rejected():
    """Verify that clicking analyze without a model or with empty inputs displays an error."""
    at = AppTest.from_file(APP_PATH).run()
    # Click analyze button (first button is preset, second button is analyze)
    # Let's find button with label "🚀 Analyze Evidence"
    analyze_btn = next((b for b in at.button if "Analyze Evidence" in b.label), None)
    assert analyze_btn is not None
    analyze_btn.click().run()

    # Model not selected should display an error
    assert len(at.error) > 0
    assert any("Please specify or select a local model" in err.value for err in at.error)


def test_app_successful_triage_flow():
    """Verify full end-to-end UI workflow: preset load, mock model response, display, and report."""
    at = AppTest.from_file(APP_PATH).run()

    # Set model name in sidebar text input
    model_input = at.sidebar.text_input[1]  # second text input in sidebar
    model_input.input("mock-llama3").run()

    # Load preset
    load_preset_btn = next((b for b in at.button if "Load Preset" in b.label), None)
    assert load_preset_btn is not None
    load_preset_btn.click().run()

    # Mock analyzer response
    mock_assessment_payload = {
        "finding_title": "Unauthenticated Path Traversal via /download Parameter",
        "status": "supported",
        "severity": "high",
        "confidence": {
            "score": 90,
            "rationale": "Direct file read sequence demonstrated in HTTP traffic.",
        },
        "observations": ["GET /download?file=../../../../etc/passwd returned 200 with root entry"],
        "interpretations": ["Path traversal allows reading arbitrary server files"],
        "missing_evidence": ["Source code of download handler"],
        "validation_recommendations": ["Test in staging sandbox with dummy target files"],
        "remediation": ["Apply strict path basename whitelisting"],
        "limitations": ["Live filesystem permissions not inspected"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": "mock-llama3",
        "message": {
            "role": "assistant",
            "content": f"```json\n{json.dumps(mock_assessment_payload)}\n```",
        },
    }

    with patch("requests.post", return_value=mock_resp):
        analyze_btn = next((b for b in at.button if "Analyze Evidence" in b.label), None)
        analyze_btn.click().run()

    assert not at.exception
    # Check that metrics and disclaimer appear
    assert any("SUPPORTED" in m.value for m in at.metric)
    assert any("HIGH" in m.value for m in at.metric)
    assert any("90/100" in m.value for m in at.metric)
    assert any("Disclaimer:" in w.value for w in at.warning)

    # Check download button exists
    assert len(at.download_button) > 0


def test_app_model_failure_graceful_handling():
    """Verify that network or inference failure does not crash the UI and displays a clear message."""
    at = AppTest.from_file(APP_PATH).run()

    # Set model name
    model_input = at.sidebar.text_input[1]
    model_input.input("mock-model").run()

    # Load preset
    load_preset_btn = next((b for b in at.button if "Load Preset" in b.label), None)
    load_preset_btn.click().run()

    # Simulate connection error
    import requests
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        analyze_btn = next((b for b in at.button if "Analyze Evidence" in b.label), None)
        analyze_btn.click().run()

    # App should not crash with an unhandled exception
    assert not at.exception
    # User-friendly error should be shown
    assert any("Failed to connect to local Ollama server" in err.value for err in at.error)
