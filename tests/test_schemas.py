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
from report import generate_markdown_report
from schemas import (
    MAX_EVIDENCE_LENGTH,
    ConfidenceAssessment,
    FindingInput,
    SeverityEstimate,
    TriageAssessment,
    TriageStatus,
)


# ============================================================================
# 1. Schema Validation Tests
# ============================================================================

def test_valid_schema():
    """Verify that correctly formatted inputs parse and validate cleanly."""
    finding = FindingInput(
        title="Path Traversal in /view Endpoint",
        evidence="GET /view?path=../../etc/passwd returns root user entry",
        description="Arbitrary file read issue reported by researcher",
        target="https://target.local/view",
    )
    assert finding.title == "Path Traversal in /view Endpoint"
    assert "passwd" in finding.evidence

    confidence = ConfidenceAssessment(
        score=85,
        rationale="Evidence directly shows file disclosure with matching path parameters.",
    )
    assert confidence.score == 85

    assessment = TriageAssessment(
        finding_title=finding.title,
        status=TriageStatus.SUPPORTED,
        severity=SeverityEstimate.HIGH,
        confidence=confidence,
        observations=["HTTP GET request includes directory traversal sequence", "HTTP response returned root:x:0:0"],
        interpretations=["The endpoint does not adequately normalize file paths before opening."],
        missing_evidence=["Application source code", "Configuration of path sanitization middleware"],
        validation_recommendations=["Attempt read outside web root in a staging sandbox"],
        remediation=["Validate and whitelist file names against a base directory"],
        limitations=["Only static request/response trace provided; runtime access not verified"],
    )
    assert assessment.status == TriageStatus.SUPPORTED
    assert assessment.severity == SeverityEstimate.HIGH
    assert assessment.confidence.score == 85


def test_invalid_confidence_out_of_bounds():
    """Confidence score must be strictly bounded between 0 and 100."""
    with pytest.raises(ValidationError):
        ConfidenceAssessment(score=101, rationale="Too confident")

    with pytest.raises(ValidationError):
        ConfidenceAssessment(score=-1, rationale="Negative confidence")


def test_invalid_status_rejected():
    """Triage status must only be one of the four allowed enum values."""
    confidence = ConfidenceAssessment(score=50, rationale="Some rationale")
    with pytest.raises(ValidationError):
        TriageAssessment(
            finding_title="Test",
            status="confirmed_vulnerability",  # Invalid status string
            severity=SeverityEstimate.MEDIUM,
            confidence=confidence,
            observations=["Obs"],
            interpretations=["Interp"],
        )


def test_invalid_severity_rejected():
    """Severity estimate must only be one of the allowed enum values."""
    confidence = ConfidenceAssessment(score=50, rationale="Some rationale")
    with pytest.raises(ValidationError):
        TriageAssessment(
            finding_title="Test",
            status=TriageStatus.INCONCLUSIVE,
            severity="catastrophic",  # Invalid severity string
            confidence=confidence,
            observations=["Obs"],
            interpretations=["Interp"],
        )


def test_empty_required_inputs():
    """Empty or whitespace-only title or evidence must be rejected."""
    with pytest.raises(ValidationError):
        FindingInput(title="   ", evidence="Some valid evidence")

    with pytest.raises(ValidationError):
        FindingInput(title="Valid Title", evidence="   ")


def test_oversized_evidence_rejected():
    """Evidence exceeding the maximum allowed size limit must be rejected."""
    huge_evidence = "A" * (MAX_EVIDENCE_LENGTH + 1)
    with pytest.raises(ValidationError) as excinfo:
        FindingInput(title="Valid Title", evidence=huge_evidence)
    assert "exceeds maximum allowed size" in str(excinfo.value)


# ============================================================================
# 2. Mocked Offline Analyzer Tests (No Network / No Model Required)
# ============================================================================

@pytest.fixture
def sample_finding() -> FindingInput:
    return FindingInput(
        title="SQL Injection in Login Parameter",
        evidence="POST /login username=admin' OR 1=1-- returns 200 OK with session token",
        description="Authentication bypass flaw",
        target="/login",
    )


def test_analyzer_successful_inference(sample_finding):
    """Test successful chat inference and validation against mocked response."""
    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")

    mock_model_payload = {
        "finding_title": sample_finding.title,
        "status": "supported",
        "severity": "critical",
        "confidence": {
            "score": 90,
            "rationale": "Evidence indicates auth bypass via standard SQL injection vector.",
        },
        "observations": ["Payload admin' OR 1=1-- yields HTTP 200 with session cookie"],
        "interpretations": ["Direct string concatenation in query allows auth bypass"],
        "missing_evidence": ["Database query logs"],
        "validation_recommendations": ["Test with parameterized queries enabled in local environment"],
        "remediation": ["Employ prepared statements exclusively"],
        "limitations": ["Live database schema not inspected"],
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "model": "mock-model",
        "message": {
            "role": "assistant",
            "content": f"```json\n{json.dumps(mock_model_payload)}\n```",
        },
    }

    with patch("requests.post", return_value=mock_response) as mock_post:
        assessment = analyzer.analyze(sample_finding)
        assert mock_post.called
        assert assessment.status == TriageStatus.SUPPORTED
        assert assessment.severity == SeverityEstimate.CRITICAL
        assert assessment.confidence.score == 90
        assert "auth bypass" in assessment.confidence.rationale


def test_analyzer_malformed_model_output(sample_finding):
    """Test that malformed/non-JSON model output triggers an actionable InferenceError."""
    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"role": "assistant", "content": "I am not returning valid JSON."}
    }

    with patch("requests.post", return_value=mock_response):
        with pytest.raises(InferenceError, match="could not be parsed as JSON"):
            analyzer.analyze(sample_finding)


def test_analyzer_schema_violation_from_model(sample_finding):
    """Model returning JSON that violates Pydantic schema rules raises SchemaValidationError."""
    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")

    invalid_json_payload = {
        "finding_title": sample_finding.title,
        "status": "unsupported_status_string",  # Invalid enum
        "severity": "critical",
        "confidence": {"score": 150, "rationale": "Impossible score"},  # Invalid > 100
        "observations": ["Obs"],
        "interpretations": ["Interp"],
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"role": "assistant", "content": json.dumps(invalid_json_payload)}
    }

    with patch("requests.post", return_value=mock_response):
        with pytest.raises(SchemaValidationError):
            analyzer.analyze(sample_finding)


def test_analyzer_model_connection_failure(sample_finding):
    """Network connection failure raises a clean EndpointUnavailableError."""
    analyzer = LocalModelAnalyzer(base_url="http://unreachable-host:11434", model_name="mock-model")

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        with pytest.raises(EndpointUnavailableError, match="Failed to connect to local Ollama server"):
            analyzer.analyze(sample_finding)


def test_analyzer_read_timeout_failure(sample_finding):
    """Model execution timeout raises an actionable InferenceError."""
    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="mock-model")

    with patch("requests.post", side_effect=requests.exceptions.ReadTimeout("Inference timed out")):
        with pytest.raises(InferenceError, match="Inference timed out"):
            analyzer.analyze(sample_finding)


def test_analyzer_model_404_not_found(sample_finding):
    """HTTP 404 from Ollama raises ModelUnavailableError with actionable pull command."""
    analyzer = LocalModelAnalyzer(base_url="http://mock-ollama:11434", model_name="missing-model")

    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "model 'missing-model' not found"

    with patch("requests.post", return_value=mock_response):
        with pytest.raises(ModelUnavailableError, match="ollama pull missing-model"):
            analyzer.analyze(sample_finding)


# ============================================================================
# 3. Report Generation Tests
# ============================================================================

def test_markdown_report_generation(sample_finding):
    """Verify that all required sections, metrics, and disclaimers are in the Markdown report."""
    assessment = TriageAssessment(
        finding_title=sample_finding.title,
        status=TriageStatus.SUPPORTED,
        severity=SeverityEstimate.CRITICAL,
        confidence=ConfidenceAssessment(
            score=95,
            rationale="Log clearly captures unauthenticated admin session token issuance.",
        ),
        observations=["HTTP POST /login returned 200 OK with admin session token"],
        interpretations=["SQL syntax injection succeeded and bypassed credentials check"],
        missing_evidence=["Database query profile trace"],
        validation_recommendations=["Verify if backend uses PreparedStatement"],
        remediation=["Replace raw string concatenation with parameterized SQL queries"],
        limitations=["Only client-side request/response evaluated; DB state unconfirmed"],
    )

    report_md = generate_markdown_report(assessment, sample_finding)

    # Required elements
    assert sample_finding.title in report_md
    assert "SUPPORTED" in report_md
    assert "CRITICAL" in report_md
    assert "95/100" in report_md
    assert "Factual Technical Observations" in report_md
    assert "Analytical Interpretations" in report_md
    assert "Missing Evidence" in report_md
    assert "Safe Validation Steps" in report_md
    assert "Recommended Remediation Actions" in report_md
    assert "Assessment Limitations" in report_md
    assert "AI Assessment Disclaimer" in report_md
    assert "does not establish independent reproduction" in report_md
    assert "calibrated mathematical probability of exploitation" in report_md
