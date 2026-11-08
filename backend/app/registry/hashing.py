"""Canonical report hashing — AGENTS.md §7. Owner: P4.

The hash covers the whole report EXCEPT the `chain` field (which is filled after
registration). Anyone can recompute it from the stored report and compare it with
the on-chain value. Do not change the canonicalisation after reports are registered.
"""
import hashlib
import json

from app.schemas import AnalysisReport


def canonical_json(report: AnalysisReport) -> str:
    data = report.model_dump(mode="json", exclude={"chain"})
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def report_hash(report: AnalysisReport) -> str:
    """0x-prefixed SHA-256 hex digest (fits a Solidity bytes32)."""
    return "0x" + hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
