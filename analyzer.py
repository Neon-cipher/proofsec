from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import requests

from schemas import (
    EvidenceQuality,
    FindingInput,
    OllamaEndpointConfig,
    SeverityLevel,
    TriageAssessment,
    TriageVerdict,
)

DEFAULT_OLLAMA_URL = os.getenv("PROOFSEC_OLLAMA_URL", "http://localhost:11434")
DEFAULT_OLLAMA_MODEL = os.getenv("PROOFSEC_MODEL", "")


class OllamaClientError(Exception):
    """Custom exception raised for Ollama connection or analysis failures."""
    pass


class VulnerabilityAnalyzer:
    """Orchestrates communication with an Ollama-compatible endpoint for triage analysis."""

    def __init__(self, config: Optional[OllamaEndpointConfig] = None) -> None:
        self.config = config or OllamaEndpointConfig(
            base_url=DEFAULT_OLLAMA_URL,
            model_name=DEFAULT_OLLAMA_MODEL,
        )

    def check_connection(self) -> Tuple[bool, str]:
        """Verify if the configured Ollama base URL is reachable."""
        try:
            url = f"{self.config.base_url}/api/tags"
            resp = requests.get(url, timeout=self.config.timeout_seconds)
            if resp.status_code == 200:
                return True, f"Connected successfully to {self.config.base_url}"
            return False, f"Endpoint responded with HTTP {resp.status_code}: {resp.text[:100]}"
        except requests.exceptions.RequestException as err:
            return False, f"Unable to reach {self.config.base_url}: {err}"

    def list_installed_models(self) -> List[str]:
        """Fetch all models currently installed locally in the Ollama instance.
        
        Does not assume or invent models. Returns empty list if none are downloaded.
        """
        url = f"{self.config.base_url}/api/tags"
        try:
            resp = requests.get(url, timeout=self.config.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            models_data = data.get("models", [])
            return [m.get("name", "") for m in models_data if m.get("name")]
        except requests.exceptions.RequestException as err:
            raise OllamaClientError(f"Failed to fetch model list from {url}: {err}") from err

    def _build_prompt(self, finding: FindingInput) -> str:
        """Construct an evidence-first security triage evaluation prompt."""
        return (
            "You are a rigorous, evidence-first application security triage engineer.\n"
            "Analyze the vulnerability finding and supplied technical evidence below.\n"
            "You must determine whether the evidence definitively proves an exploitable flaw,\n"
            "is a false positive, or is insufficient to make a determination.\n\n"
            f"FINDING TITLE: {finding.title}\n"
            f"VULNERABILITY TYPE: {finding.vulnerability_type}\n"
            f"CWE: {finding.cwe_id or 'Not specified'}\n"
            f"REPORTED SEVERITY: {finding.reported_severity.value}\n"
            f"TARGET COMPONENT: {finding.target_component or 'Not specified'}\n\n"
            f"DESCRIPTION:\n{finding.description}\n\n"
            f"SUPPLIED EVIDENCE (Logs / HTTP Requests / Responses / Code / PoC):\n"
            f"{finding.evidence_text}\n\n"
            "INSTRUCTIONS:\n"
            "1. Base your verdict strictly on what the supplied evidence proves.\n"
            "2. If evidence does not demonstrate actual impact or valid reproduction, mark verdict as INSUFFICIENT_EVIDENCE or LIKELY_FALSE_POSITIVE.\n"
            "3. If evidence is conclusive, assign CONFIRMED and adjust severity accordingly.\n"
            "4. Respond ONLY with valid JSON conforming to the following keys:\n"
            "{\n"
            '  "verdict": "CONFIRMED" | "LIKELY_FALSE_POSITIVE" | "INSUFFICIENT_EVIDENCE" | "NEEDS_FURTHER_INVESTIGATION",\n'
            '  "adjusted_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN",\n'
            '  "confidence_score": <float between 0.0 and 1.0>,\n'
            '  "evidence_quality": "STRONG" | "MODERATE" | "WEAK" | "NONE",\n'
            '  "summary": "<executive summary of triage>",\n'
            '  "evidence_analysis": "<detailed rationale of what evidence confirms or lacks>",\n'
            '  "key_findings": ["<bullet 1>", "<bullet 2>"],\n'
            '  "missing_evidence": ["<missing proof item 1>", "..."],\n'
            '  "remediation_recommendations": ["<remediation action 1>", "..."]\n'
            "}"
        )

    @staticmethod
    def _extract_json_payload(raw_text: str) -> Dict[str, Any]:
        """Strip formatting or markdown fences and parse the JSON response."""
        cleaned = raw_text.strip()
        # Attempt direct JSON parse
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # Check for ```json ... ``` code fence
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if match:
            candidate = match.group(1).strip()
            return json.loads(candidate)

        # Look for innermost/outermost brackets { ... }
        match_brace = re.search(r"\{[\s\S]*\}", cleaned)
        if match_brace:
            return json.loads(match_brace.group(0))

        raise ValueError(f"Could not extract valid JSON from model response: {raw_text[:200]}")

    def analyze(self, finding: FindingInput, model_override: Optional[str] = None) -> TriageAssessment:
        """Submit the finding and evidence to the local model, parsing into TriageAssessment."""
        target_model = model_override or self.config.model_name
        if not target_model:
            raise OllamaClientError(
                "No local model specified. Please select or configure a verified model installed in your local Ollama instance."
            )

        prompt = self._build_prompt(finding)
        url = f"{self.config.base_url}/api/generate"
        payload = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,  # Low temperature for deterministic security evaluation
            },
        }

        try:
            resp = requests.post(url, json=payload, timeout=self.config.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            raw_response_text = data.get("response", "")
            if not raw_response_text:
                raise OllamaClientError("Model returned an empty response.")

            parsed_dict = self._extract_json_payload(raw_response_text)
            parsed_dict["model_name"] = target_model

            # Validate against Pydantic schema
            assessment = TriageAssessment.model_validate(parsed_dict)
            return assessment

        except requests.exceptions.RequestException as err:
            raise OllamaClientError(f"HTTP error communicating with Ollama at {url}: {err}") from err
        except (json.JSONDecodeError, ValueError) as err:
            raise OllamaClientError(f"Failed to parse model response into expected JSON format: {err}") from err
        except Exception as err:
            raise OllamaClientError(f"Validation error creating TriageAssessment: {err}") from err
