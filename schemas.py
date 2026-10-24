from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict

MAX_EVIDENCE_LENGTH = 65_536  # 64 KB limit to prevent prompt flooding / resource exhaustion


class TriageStatus(str, Enum):
    SUPPORTED = "supported"
    INCONCLUSIVE = "inconclusive"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTRADICTED = "contradicted"


class SeverityEstimate(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNDETERMINED = "undetermined"


class FindingInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(..., min_length=1, max_length=255, description="Title of the vulnerability finding")
    evidence: str = Field(..., min_length=1, description="Raw technical proof (logs, HTTP request/response, snippet)")
    description: Optional[str] = Field(default="", max_length=10000, description="Optional finding background/context")
    target: Optional[str] = Field(default="", max_length=500, description="Optional component, URL, or affected asset")

    @field_validator("title")
    @classmethod
    def validate_title_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Finding title cannot be empty or whitespace only.")
        return v.strip()

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Evidence cannot be empty or whitespace only.")
        if len(stripped) > MAX_EVIDENCE_LENGTH:
            raise ValueError(
                f"Evidence length ({len(stripped)} chars) exceeds maximum allowed size ({MAX_EVIDENCE_LENGTH} chars)."
            )
        return stripped


class ConfidenceAssessment(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Confidence score bounded between 0 and 100")
    rationale: str = Field(..., min_length=1, description="Reasoning behind the confidence score")

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Confidence rationale cannot be empty.")
        return v.strip()


class TriageAssessment(BaseModel):
    finding_title: str = Field(..., min_length=1, description="Title of the finding analyzed")
    status: TriageStatus = Field(
        ...,
        description=(
            "Triage conclusion: 'supported' indicates submitted evidence supports the claim "
            "(does not imply independent reproduction or confirmed exploitability); "
            "'inconclusive', 'insufficient_evidence', or 'contradicted'."
        ),
    )
    severity: SeverityEstimate = Field(..., description="Estimated severity based on evidence")
    confidence: ConfidenceAssessment = Field(..., description="Bounded confidence score (0-100) and rationale")
    observations: List[str] = Field(
        ...,
        min_length=1,
        description="Factual, verifiable technical observations derived directly from the supplied evidence",
    )
    interpretations: List[str] = Field(
        ...,
        min_length=1,
        description="Security deductions and analytical conclusions (separated from factual observations)",
    )
    missing_evidence: List[str] = Field(
        default_factory=list,
        description="Specific technical proof or context missing that would be needed for conclusive validation",
    )
    validation_recommendations: List[str] = Field(
        default_factory=list,
        description="Concrete, safe verification steps an analyst should perform manually to reproduce or verify",
    )
    remediation: List[str] = Field(
        default_factory=list,
        description="Actionable mitigation or remediation guidance",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Known limitations of this automated assessment",
    )
