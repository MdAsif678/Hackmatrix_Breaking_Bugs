"""Threat correlation across reports. Owner: P1. Guide: docs/tasks/P1-lead.md

Link reports that share registrable domains, IPs, payment IDs (UPI), phone numbers,
cert fingerprints or near-identical message text. Matching must be deterministic;
AI may only summarise the relationship.
"""
from app.schemas import AnalysisReport, CorrelationResult


def find_related(report: AnalysisReport) -> list[str]:
    """Called by the pipeline when a report is created. Return ids of related past reports."""
    # TODO(P1): compare report indicators with stored reports (app.db.list_reports / a new index table)
    return []


def related_details(report: AnalysisReport) -> CorrelationResult:
    """Used by GET /api/correlations/{id}: which reports are related and through which indicators."""
    # TODO(P1)
    return CorrelationResult(related=[])
