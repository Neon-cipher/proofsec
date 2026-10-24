from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class TriageVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NEEDS_FURTHER_INVESTIGATION = "NEEDS_FURTHER_INVESTIGATION"


class EvidenceQuality(str, Enum):
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    NONE = "NONE"


class FindingInput(BaseModel):
    title: str = Field(..., min_length=3, max_length=200, description="Short title of the vulnerability finding")
    vulnerability_type: str = Field(..., min_length=2, max_length=100, description="Type or classification (e.g., SQL Injection, SSRF)")
    cwe_id: Optional[str] = Field(None, max_length=30, description="Optional CWE identifier (e.g., CWE-89)")
    reported_severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM, description="Initial reporter-assigned severity")
    target_component: Optional[str] = Field(None, max_length=255, description="Affected URL, endpoint, microservice, or source file")
    description: str = Field(..., min_length=10, description="Narrative summary of the vulnerability report")
    evidence_text: str = Field(..., min_length=5, description="Raw supporting evidence: HTTP requests/responses, logs, code snippets, or PoC output")

    @field_validator("title", "vulnerability_type", "description", "evidence_text")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        v_stripped = v.strip()
        if not v_stripped:
            raise ValueError("Field cannot be empty or only whitespace")
        return v_stripped


class TriageAssessment(BaseModel):
    verdict: TriageVerdict = Field(..., description="Evidence-backed triage conclusion")
    adjusted_severity: SeverityLevel = Field(..., description="Evaluated severity based on verified evidence")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Assessment confidence score between 0.0 and 1.0")
    evidence_quality: EvidenceQuality = Field(..., description="Quality of the provided proof/evidence")
    summary: str = Field(..., min_length=10, description="Concise executive summary of the triage analysis")
    evidence_analysis: str = Field(..., min_length=10, description="Detailed analysis of provided evidence validity and impact")
    key_findings: List[str] = Field(default_factory=list, description="List of validated observations from the report")
    missing_evidence: List[str] = Field(default_factory=list, description="Evidence gaps required to reach full verification")
    remediation_recommendations: List[str] = Field(default_factory=list, description="Actionable fix or mitigation guidance")
    model_name: str = Field(default="unknown-model", description="Identifier of the model that executed the triage")
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="UTC timestamp of the triage run")


class OllamaEndpointConfig(BaseModel):
    base_url: str = Field(default="http://localhost:11434", description="Base URL of Ollama inference service")
    model_name: str = Field(default="", description="Target model name deployed on Ollama")
    timeout_seconds: int = Field(default=60, ge=5, le=300, description="HTTP request timeout in seconds")

    @field_validator("base_url")
    @classmethod
    def normalize_base_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("base_url must start with http:// or https://")
        return v
