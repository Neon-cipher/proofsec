import os
import sys

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from pydantic import ValidationError

from analyzer import VulnerabilityAnalyzer, OllamaClientError
from report import generate_markdown_report
from schemas import (
    EvidenceQuality,
    FindingInput,
    OllamaEndpointConfig,
    SeverityLevel,
    TriageAssessment,
    TriageVerdict,
)


def test_finding_input_valid():
    finding = FindingInput(
        title="Reflected XSS in search query",
        vulnerability_type="Cross-Site Scripting",
        cwe_id="CWE-79",
        reported_severity=SeverityLevel.HIGH,
        target_component="/api/v1/search",
        description="The q parameter reflects raw user payload without HTML entity encoding.",
        evidence_text="GET /api/v1/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\nResponse reflects script tag in DOM."
    )
    assert finding.title == "Reflected XSS in search query"
    assert finding.reported_severity == SeverityLevel.HIGH
    assert finding.cwe_id == "CWE-79"


def test_finding_input_empty_whitespace_rejected():
    with pytest.raises(ValidationError):
        FindingInput(
            title="   ",
            vulnerability_type="SQLi",
            description="Valid description here",
            evidence_text="SELECT * FROM users"
        )


def test_finding_input_short_description_rejected():
    with pytest.raises(ValidationError):
        FindingInput(
            title="Valid Title",
            vulnerability_type="SQLi",
            description="too short",
            evidence_text="SELECT * FROM users"
        )


def test_triage_assessment_valid():
    assessment = TriageAssessment(
        verdict=TriageVerdict.CONFIRMED,
        adjusted_severity=SeverityLevel.HIGH,
        confidence_score=0.95,
        evidence_quality=EvidenceQuality.STRONG,
        summary="High-confidence confirmation of reflected XSS flaw.",
        evidence_analysis="HTTP response logs demonstrate unencoded payload reflection in browser context.",
        key_findings=["Direct reflection verified in response body", "No sanitization filter active"],
        missing_evidence=[],
        remediation_recommendations=["Implement contextual output encoding", "Apply strict Content-Security-Policy"],
        model_name="test-model"
    )
    assert assessment.verdict == TriageVerdict.CONFIRMED
    assert assessment.confidence_score == 0.95


def test_triage_assessment_confidence_bounds():
    with pytest.raises(ValidationError):
        TriageAssessment(
            verdict=TriageVerdict.CONFIRMED,
            adjusted_severity=SeverityLevel.HIGH,
            confidence_score=1.5,  # Out of range > 1.0
            evidence_quality=EvidenceQuality.STRONG,
            summary="Invalid confidence",
            evidence_analysis="Some valid analysis string here.",
        )


def test_ollama_config_url_normalization():
    cfg = OllamaEndpointConfig(base_url="http://localhost:11434/")
    assert cfg.base_url == "http://localhost:11434"

    with pytest.raises(ValidationError):
        OllamaEndpointConfig(base_url="ftp://localhost:11434")


def test_analyzer_json_extraction():
    raw_plain = '{"key": "value"}'
    assert VulnerabilityAnalyzer._extract_json_payload(raw_plain) == {"key": "value"}

    raw_fenced = 'Here is the report:\n```json\n{"verdict": "CONFIRMED"}\n```\nHope this helps.'
    assert VulnerabilityAnalyzer._extract_json_payload(raw_fenced) == {"verdict": "CONFIRMED"}

    raw_embedded = 'Leading text {"status": "ok", "count": 2} trailing text'
    assert VulnerabilityAnalyzer._extract_json_payload(raw_embedded) == {"status": "ok", "count": 2}


def test_analyzer_fails_without_model():
    analyzer = VulnerabilityAnalyzer(OllamaEndpointConfig(base_url="http://localhost:11434", model_name=""))
    finding = FindingInput(
        title="Test finding",
        vulnerability_type="IDOR",
        description="Detailed description for testing IDOR finding",
        evidence_text="GET /user/42 returns user 42 profile"
    )
    with pytest.raises(OllamaClientError, match="No local model specified"):
        analyzer.analyze(finding)


def test_generate_markdown_report():
    finding = FindingInput(
        title="SQL Injection in Login Endpoint",
        vulnerability_type="SQL Injection",
        cwe_id="CWE-89",
        reported_severity=SeverityLevel.CRITICAL,
        target_component="/login",
        description="SQL injection allows authentication bypass via crafted username input.",
        evidence_text="' OR '1'='1' -- results in HTTP 200 and admin session cookie"
    )
    assessment = TriageAssessment(
        verdict=TriageVerdict.CONFIRMED,
        adjusted_severity=SeverityLevel.CRITICAL,
        confidence_score=0.98,
        evidence_quality=EvidenceQuality.STRONG,
        summary="Authentication bypass via SQL injection confirmed by session token issuance.",
        evidence_analysis="Evidence confirms arbitrary authentication bypass due to string concatenation in SQL statement.",
        key_findings=["Session cookie returned without valid credentials"],
        missing_evidence=[],
        remediation_recommendations=["Use parameterized queries / prepared statements"],
        model_name="test-llama"
    )
    report_md = generate_markdown_report(finding, assessment)
    assert "# ProofSec AI Triage Report: SQL Injection in Login Endpoint" in report_md
    assert "CONFIRMED" in report_md
    assert "test-llama" in report_md
    assert "CWE-89" in report_md
    assert "parameterized queries" in report_md
