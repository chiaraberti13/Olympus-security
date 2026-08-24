#!/usr/bin/env python3
"""Utility per valutare SLA/performance budget di scansioni e report."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class BudgetBreach:
    """Rappresenta una violazione di budget prestazionale."""

    dimension: str
    observed_seconds: float
    budget_seconds: float

    def to_dict(self) -> Dict[str, float | str]:
        return {
            "dimension": self.dimension,
            "observed_seconds": round(self.observed_seconds, 3),
            "budget_seconds": round(self.budget_seconds, 3),
        }


def evaluate_performance_budget(
    *,
    scan_runtime_seconds: float,
    report_render_seconds: Optional[float],
    scan_runtime_budget_seconds: int,
    report_render_budget_seconds: int,
) -> Dict[str, object]:
    """Valuta se runtime scansione e rendering report rispettano i rispettivi SLA."""
    breaches: List[BudgetBreach] = []

    normalized_scan_runtime = max(float(scan_runtime_seconds), 0.0)
    normalized_scan_budget = max(int(scan_runtime_budget_seconds), 1)
    if normalized_scan_runtime > normalized_scan_budget:
        breaches.append(
            BudgetBreach(
                dimension="scan_runtime",
                observed_seconds=normalized_scan_runtime,
                budget_seconds=float(normalized_scan_budget),
            )
        )

    normalized_report_budget = max(int(report_render_budget_seconds), 1)
    if report_render_seconds is not None:
        normalized_report_runtime = max(float(report_render_seconds), 0.0)
        if normalized_report_runtime > normalized_report_budget:
            breaches.append(
                BudgetBreach(
                    dimension="report_render",
                    observed_seconds=normalized_report_runtime,
                    budget_seconds=float(normalized_report_budget),
                )
            )

    return {
        "within_budget": not breaches,
        "scan_runtime_seconds": round(normalized_scan_runtime, 3),
        "report_render_seconds": None if report_render_seconds is None else round(max(float(report_render_seconds), 0.0), 3),
        "breaches": [breach.to_dict() for breach in breaches],
    }
