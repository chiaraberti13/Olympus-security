"""Modello ML per il rilevamento dei falsi positivi."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Dict, List


@dataclass(frozen=True)
class ModelWeights:
    intercept: float
    weights: Dict[str, float]


DEFAULT_WEIGHTS = ModelWeights(
    intercept=-0.35,
    weights={
        "severity_score": -1.8,
        "has_cve": -1.2,
        "has_evidence": -0.9,
        "has_repro": -0.6,
        "tool_reliability": -0.8,
        "description_length": -0.4,
        "mentions_placeholder": 1.4,
        "mentions_simulation": 1.1,
        "mentions_generic": 0.7,
        "missing_host": 0.6,
    },
)


class FalsePositiveModel:
    """Semplice modello logistico per stimare la probabilità di falso positivo."""

    version = "1.0.0"

    def __init__(self, weights: ModelWeights | None = None) -> None:
        self._weights = weights or DEFAULT_WEIGHTS

    def predict_proba(self, features: Dict[str, float]) -> float:
        linear = self._weights.intercept
        for name, weight in self._weights.weights.items():
            linear += weight * features.get(name, 0.0)
        return 1 / (1 + math.exp(-linear))

    def top_factors(self, features: Dict[str, float], limit: int = 4) -> List[Dict[str, float]]:
        contributions = []
        for name, weight in self._weights.weights.items():
            value = features.get(name, 0.0)
            contributions.append(
                {
                    "feature": name,
                    "weight": weight,
                    "value": value,
                    "contribution": weight * value,
                }
            )
        contributions.sort(key=lambda item: abs(item["contribution"]), reverse=True)
        return contributions[:limit]


def build_features(finding: Dict[str, object]) -> Dict[str, float]:
    severity = str(finding.get("severity", "")).lower()
    severity_score = {
        "info": 0.9,
        "low": 0.75,
        "medium": 0.5,
        "high": 0.2,
        "critical": 0.1,
    }.get(severity, 0.6)

    description = str(finding.get("description", ""))
    description_lower = description.lower()

    tool = str(finding.get("tool", "")).lower()
    tool_reliability = {
        "nuclei": 0.7,
        "nmap": 0.8,
        "nikto": 0.65,
        "sqlmap": 0.9,
        "xsstrike": 0.6,
        "zap": 0.85,
        "burp": 0.9,
        "wapiti": 0.7,
        "commix": 0.75,
        "acunetix": 0.9,
        "nessus": 0.95,
    }.get(tool, 0.5)

    has_cve = 1.0 if finding.get("cve") else 0.0
    has_evidence = 1.0 if finding.get("evidence") else 0.0
    has_repro = 1.0 if finding.get("reproduction") else 0.0
    description_length = min(len(description) / 400, 1.0)

    mentions_placeholder = 1.0 if "placeholder" in description_lower else 0.0
    mentions_simulation = 1.0 if "simulazione" in description_lower else 0.0
    mentions_generic = 1.0 if "potenziale" in description_lower else 0.0
    missing_host = 1.0 if not finding.get("host") else 0.0

    return {
        "severity_score": severity_score,
        "has_cve": has_cve,
        "has_evidence": has_evidence,
        "has_repro": has_repro,
        "tool_reliability": tool_reliability,
        "description_length": description_length,
        "mentions_placeholder": mentions_placeholder,
        "mentions_simulation": mentions_simulation,
        "mentions_generic": mentions_generic,
        "missing_host": missing_host,
    }
