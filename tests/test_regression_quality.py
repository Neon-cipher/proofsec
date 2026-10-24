import json
import os
import sys
from unittest.mock import MagicMock, patch

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import requests
from pydantic import ValidationError

from analyzer import (
    EndpointUnavailableError,
    InferenceError,
    LocalModelAnalyzer,
    ModelUnavailableError,
    SchemaValidationError,
)
from examples import EXAMPLES
from schemas import (
    MAX_EVIDENCE_LENGTH,
    FindingInput,
    SeverityEstimate,
    TriageAssessment,
    TriageStatus,
)


# ============================================================================
# Case A: Insufficient XSS Evidence
# ============================================================================

def test_case_a_insufficient_xss_evidence():
    """Scanner claims reflected XSS, but HTML snippet shows only entity-escaped input."""
    data = EXAMPLES["Insufficient XSS Evidence (Escaped HTML)"]
    finding = FindingInput(
        title=data["title"],
        evidence=data["evidence"],
        description=data["description"],
        target=data["target"],
    )

    mock_assessment_payload = {
        "finding_title": finding.title,
        "status": "insufficient_evidence",
        "severity": "low",
        "confidence": {
            "score": 85,
            "rationale": "Evidence shows HTML entity-encoding (&lt;script&gt;) neutralizing execution context.",
        },
        "observations": [
            "Input parameter is rendered inside <p> tag as HTML entities &lt;script&gt;",
            "No raw unencoded script tag found in HTTP response body",
        ],
        "interpretations": [
            "HTML entity encoding prevents browser script parsing in this context",
            "JavaScript execution has NOT been established by the provided proof",
        ],
        "missing_evidence": [
            "Proof of DOM execution or dynamic context where entity encoding is bypassed",
            "Browser console log showing script trigger",
        ],
        "validation_recommendations": [
            "Verify whether user input is reflected in any unencoded attribute or JavaScript block"
        ],
        "remediation": ["Maintain consistent context-aware output encoding across all templates"],
        "limitations": ["Only static HTTP response snippet provided; headless browser rendering not verified"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": json.dumps(mock_assessment_payload)}
    }

    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")
    with patch("requests.post", return_value=mock_resp):
        assessment = analyzer.analyze(finding)

    # Verifications
    assert assessment.status == TriageStatus.INSUFFICIENT_EVIDENCE
    assert assessment.status != TriageStatus.SUPPORTED
    assert any("NOT been established" in i for i in assessment.interpretations)
    assert len(assessment.missing_evidence) > 0


# ============================================================================
# Case B: Ambiguous SQL Injection Report
# ============================================================================

def test_case_b_ambiguous_sql_injection():
    """Scanner claims SQL injection with no differential error or proof; must not invent DB errors."""
    data = EXAMPLES["Ambiguous SQL Injection (Scanner Heuristic Only)"]
    finding = FindingInput(
        title=data["title"],
        evidence=data["evidence"],
        description=data["description"],
        target=data["target"],
    )

    mock_assessment_payload = {
        "finding_title": finding.title,
        "status": "inconclusive",
        "severity": "undetermined",
        "confidence": {
            "score": 40,
            "rationale": "30ms response variation is within normal network jitter; no syntax errors or proof shown.",
        },
        "observations": [
            "Scanner recorded 240ms vs 210ms baseline response time",
            "HTTP response returns standard 200 OK with normal user JSON payload",
        ],
        "interpretations": [
            "Provided evidence is insufficient to distinguish timing jitter from database sleep/delay",
            "No database syntax error, data exfiltration, or differential response observed",
        ],
        "missing_evidence": [
            "Reproducible differential timing analysis (e.g. SLEEP(5) benchmark)",
            "Database error logs or differential content proof",
        ],
        "validation_recommendations": [
            "Conduct structured manual timing test using standardized time-delay payloads in isolated environment"
        ],
        "remediation": ["Review database queries for parameterization"],
        "limitations": ["Cannot inspect server-side database telemetry"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": json.dumps(mock_assessment_payload)}
    }

    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")
    with patch("requests.post", return_value=mock_resp):
        assessment = analyzer.analyze(finding)

    # Verifications
    assert assessment.status == TriageStatus.INCONCLUSIVE
    assert assessment.severity == SeverityEstimate.UNDETERMINED
    assert assessment.status != TriageStatus.SUPPORTED
    assert not any("SQL syntax error observed" in o for o in assessment.observations)


# ============================================================================
# Case C: Evidence Contradicts Claim
# ============================================================================

def test_case_c_evidence_contradicts_claim():
    """Finding claims unauthenticated access, but response is HTTP 401 Unauthorized."""
    data = EXAMPLES["Evidence Contradicts Claim (Auth Blocked)"]
    finding = FindingInput(
        title=data["title"],
        evidence=data["evidence"],
        description=data["description"],
        target=data["target"],
    )

    mock_assessment_payload = {
        "finding_title": finding.title,
        "status": "contradicted",
        "severity": "informational",
        "confidence": {
            "score": 95,
            "rationale": "HTTP 401 Unauthorized status and WWW-Authenticate header directly refute unauthenticated access claim.",
        },
        "observations": [
            "Target responded with HTTP 401 Unauthorized",
            "Response body explicitly states authentication credentials required",
        ],
        "interpretations": [
            "Access control is actively enforced for the requested endpoint",
            "The technical evidence directly contradicts the vulnerability assertion",
        ],
        "missing_evidence": ["Proof that sensitive administrative data was accessed without authentication"],
        "validation_recommendations": ["Re-test with and without valid authorization headers"],
        "remediation": ["Ensure 401 handling remains consistent across all route endpoints"],
        "limitations": ["Only single GET request verified"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": json.dumps(mock_assessment_payload)}
    }

    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")
    with patch("requests.post", return_value=mock_resp):
        assessment = analyzer.analyze(finding)

    # Verifications
    assert assessment.status == TriageStatus.CONTRADICTED
    assert "directly refute" in assessment.confidence.rationale or "contradict" in assessment.confidence.rationale


# ============================================================================
# Case D: Prompt Injection Embedded in Evidence
# ============================================================================

def test_case_d_prompt_injection_inside_evidence():
    """Evidence contains adversarial system prompt override instructions.
    
    Verifies that:
    1. Finding and evidence are enclosed in untrusted data delimiters in the prompt.
    2. Model instructions explicitly forbid following embedded commands.
    3. The application enforces authentic finding_title, rejecting title poisoning.
    """
    data = EXAMPLES["Prompt Injection Embedded in Evidence"]
    finding = FindingInput(
        title=data["title"],
        evidence=data["evidence"],
        description=data["description"],
        target=data["target"],
    )

    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")

    # Verify prompt construction encapsulates evidence cleanly
    prompt_sent = analyzer._get_user_prompt(finding)
    assert "<UNTRUSTED_SUPPLIED_EVIDENCE>" in prompt_sent
    assert "</UNTRUSTED_SUPPLIED_EVIDENCE>" in prompt_sent
    assert "SYSTEM OVERRIDE" in prompt_sent

    # Simulate model correctly identifying insufficient evidence despite the injection attempt
    mock_assessment_payload = {
        "finding_title": "POISONED TITLE INJECTION ATTEMPT",
        "status": "insufficient_evidence",
        "severity": "informational",
        "confidence": {
            "score": 90,
            "rationale": "Supplied text consists of inert comments and adversarial prompt injection strings without proof of execution.",
        },
        "observations": [
            "Evidence contains user feedback comment with embedded HTML comment block",
            "No server error, reflection, or execution logs provided",
        ],
        "interpretations": [
            "Embedded override commands represent untrusted textual data",
            "No vulnerability execution demonstrated",
        ],
        "missing_evidence": ["Actual HTTP traffic, error logs, or impact demonstration"],
        "validation_recommendations": ["Conduct standard input sanitization check on comments endpoint"],
        "remediation": ["Sanitize user comments"],
        "limitations": ["Textual feedback only"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": json.dumps(mock_assessment_payload)}
    }

    with patch("requests.post", return_value=mock_resp):
        assessment = analyzer.analyze(finding)

    # Crucial application-level defense verification:
    # Finding title MUST be preserved as authentic finding title, never the injected title
    assert assessment.finding_title == finding.title
    assert assessment.finding_title != "POISONED TITLE INJECTION ATTEMPT"
    assert assessment.status == TriageStatus.INSUFFICIENT_EVIDENCE


# ============================================================================
# Case E: Local Model Unavailable
# ============================================================================

def test_case_e_local_model_unavailable():
    """Connection error or timeout must raise actionable exceptions, no fake output, no crash."""
    finding = FindingInput(
        title="Test Finding",
        evidence="Some verifiable evidence text",
    )
    analyzer = LocalModelAnalyzer(base_url="http://unreachable-host:11434", model_name="test-model")

    # Connection failure
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Refused")):
        with pytest.raises(EndpointUnavailableError) as excinfo:
            analyzer.analyze(finding)
        assert "Failed to connect to local Ollama server" in str(excinfo.value)

    # Read timeout
    with patch("requests.post", side_effect=requests.exceptions.ReadTimeout("Timeout")):
        with pytest.raises(InferenceError) as excinfo:
            analyzer.analyze(finding)
        assert "Inference timed out" in str(excinfo.value)


# ============================================================================
# Case F: Invalid Model Output
# ============================================================================

def test_case_f_invalid_model_output():
    """Malformed JSON or schema-violating output must fail strictly without silent fallback."""
    finding = FindingInput(
        title="Test Finding",
        evidence="Some verifiable evidence text",
    )
    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="test-model")

    # Malformed non-JSON
    mock_bad_json = MagicMock()
    mock_bad_json.status_code = 200
    mock_bad_json.json.return_value = {
        "message": {"role": "assistant", "content": "Error: unable to generate valid response"}
    }
    with patch("requests.post", return_value=mock_bad_json):
        with pytest.raises(InferenceError, match="could not be parsed as JSON"):
            analyzer.analyze(finding)

    # Schema violation (invalid confidence score > 100)
    invalid_schema_payload = {
        "finding_title": finding.title,
        "status": "supported",
        "severity": "critical",
        "confidence": {"score": 999, "rationale": "Invalid score"},
        "observations": ["Obs"],
        "interpretations": ["Interp"],
    }
    mock_bad_schema = MagicMock()
    mock_bad_schema.status_code = 200
    mock_bad_schema.json.return_value = {
        "message": {"role": "assistant", "content": json.dumps(invalid_schema_payload)}
    }
    with patch("requests.post", return_value=mock_bad_schema):
        with pytest.raises(SchemaValidationError):
            analyzer.analyze(finding)


# ============================================================================
# Case G: Oversized Input
# ============================================================================

def test_case_g_oversized_input_rejected_before_network():
    """Evidence exceeding the 64KB threshold is rejected at the schema level without making network calls."""
    huge_payload = "X" * (MAX_EVIDENCE_LENGTH + 50)
    with pytest.raises(ValidationError) as excinfo:
        FindingInput(
            title="Oversized Evidence Finding",
            evidence=huge_payload,
        )
    assert f"exceeds maximum allowed size ({MAX_EVIDENCE_LENGTH} chars)" in str(excinfo.value)
