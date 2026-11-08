"""Threat correlation across reports. Owner: P3.

Link reports that share registrable domains, IPs, payment IDs (UPI), phone numbers,
cert fingerprints or near-identical message text. Matching must be deterministic;
AI may only summarise the relationship.
"""
from app.schemas import AnalysisReport, CorrelationResult


def find_related(report: AnalysisReport) -> list[str]:
    """Called by the pipeline when a report is created. Return ids of related past reports."""
    # TODO(P3): compare report indicators with stored reports (app.db.list_reports / a new index table)
    return []


def related_details(report: AnalysisReport) -> CorrelationResult:
    """Used by GET /api/correlations/{id}: which reports are related and through which indicators."""
    # TODO(P3)
    return CorrelationResult(related=[])
