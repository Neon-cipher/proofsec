from __future__ import annotations

from schemas import FindingInput, TriageAssessment


def generate_markdown_report(finding: FindingInput, assessment: TriageAssessment) -> str:
    """Generate a clean, structured Markdown security triage report."""
    key_findings_md = (
        "\n".join([f"- {f}" for f in assessment.key_findings])
        if assessment.key_findings
        else "- None noted."
    )

    missing_evidence_md = (
        "\n".join([f"- {m}" for m in assessment.missing_evidence])
        if assessment.missing_evidence
        else "- No outstanding evidence gaps identified."
    )

    remediation_md = (
        "\n".join([f"- {r}" for r in assessment.remediation_recommendations])
        if assessment.remediation_recommendations
        else "- Refer to standard organizational mitigation guidelines."
    )

    analyzed_timestamp = assessment.analyzed_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    report = f"""# ProofSec AI Triage Report: {finding.title}

**Report Generated:** {analyzed_timestamp}  
**Triage Engine:** {assessment.model_name}  

---

## 1. Executive Summary

| Attribute | Assessment |
| :--- | :--- |
| **Verdict** | **{assessment.verdict.value}** |
| **Adjusted Severity** | `{assessment.adjusted_severity.value}` (Reported: `{finding.reported_severity.value}`) |
| **Evidence Quality** | `{assessment.evidence_quality.value}` |
| **Confidence Score** | `{assessment.confidence_score * 100:.1f}%` |
| **Vulnerability Type** | {finding.vulnerability_type} |
| **CWE ID** | {finding.cwe_id or "N/A"} |
| **Target Component** | `{finding.target_component or "N/A"}` |

### Summary
{assessment.summary}

---

## 2. Technical Evidence Analysis

### Evidence-First Evaluation
{assessment.evidence_analysis}

### Validated Technical Observations
{key_findings_md}

### Evidence Gaps / Missing Proof
{missing_evidence_md}

---

## 3. Supplied Finding Context

### Description
{finding.description}

### Raw Supplied Evidence
```text
{finding.evidence_text}
```

---

## 4. Remediation & Actionable Guidance

{remediation_md}

---

*Disclaimer: This report was automatically produced by ProofSec AI using local AI inference as assistive triage. Determinations should be validated by application security analysts prior to production deployment or service modifications.*
"""
    return report.strip()
