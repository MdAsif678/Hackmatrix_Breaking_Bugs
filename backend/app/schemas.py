"""SHARED DATA CONTRACT — see AGENTS.md §4.

Every analyzer returns a CheckResult; the pipeline combines them into an AnalysisReport.
frontend/src/types.ts mirrors these models exactly.

Change this file ONLY with agreement from the whole team.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RiskLevel(str, Enum):
    low_risk = "low_risk"
    suspicious = "suspicious"
    high_risk = "high_risk"
    confirmed_malicious = "confirmed_malicious"
    inconclusive = "inconclusive"


CheckName = Literal["url", "dns", "threat_intel", "tls", "headers", "message"]


class Finding(BaseModel):
    id: str  # unique within a check, e.g. "tls.expired", "url.homoglyph"
    check: CheckName
    title: str  # short human title: "Certificate expired"
    severity: Severity
    evidence: str  # concrete technical evidence: "notAfter=2024-01-03T00:00:00Z"
    source: str  # where it came from: "TLS handshake", "URLhaus", "crt.sh", "regex"
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    authoritative: bool = False  # True ONLY for a match in a trusted threat-intel feed


class CheckResult(BaseModel):
    check: CheckName
    status: Literal["ok", "error", "skipped"]
    target: Optional[str] = None  # what was checked (filled in by the pipeline)
    findings: list[Finding] = []
    data: dict[str, Any] = {}  # raw facts for display (cert subject, issuer, IPs, redirect chain...)
    limitations: list[str] = []  # what could not be checked and why
    duration_ms: int = 0


class Explanation(BaseModel):
    summary: str
    key_points: list[str]  # each should reference finding ids, e.g. "[tls.expired] ..."
    recommendations: list[str]


class ChainRecord(BaseModel):
    report_hash: str  # 0x-prefixed SHA-256 hex (AGENTS.md §7)
    chain_report_id: int
    tx_hash: str
    network: str = "sepolia"
    contract_address: str


class AnalysisReport(BaseModel):
    id: str  # uuid4
    input_type: Literal["url", "domain", "message"]
    input: str  # stored in OUR db only — never on-chain
    normalized_target: Optional[str] = None
    created_at: datetime
    risk_level: RiskLevel
    risk_reasons: list[str]  # why the engine picked this level
    coverage: float = Field(ge=0, le=1)  # fraction of checks that ran successfully
    checks: list[CheckResult]
    extracted_indicators: dict[str, list[str]] = {}  # urls, domains, emails, phones, upi_ids
    explanation: Optional[Explanation] = None
    recommendations: list[str] = []
    limitations: list[str] = []
    related_report_ids: list[str] = []  # from correlation engine
    chain: Optional[ChainRecord] = None  # filled after on-chain registration


# ---------- API request / response bodies ----------


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class MessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)


class VerifyResult(BaseModel):
    recomputed_hash: str
    onchain_hash: Optional[str] = None
    match: bool
    tx_hash: Optional[str] = None
    block_timestamp: Optional[int] = None
    status: str  # "verified", "mismatch" or "not_registered"
    chain_status: Optional[str] = None  # on-chain record status: active / disputed / revised
    submitter: Optional[str] = None  # wallet address that registered the report
    explorer_url: Optional[str] = None  # block-explorer link for the registration transaction


class RelatedReport(BaseModel):
    report_id: str
    shared_indicators: list[str]  # e.g. "same domain: paypa1.com", "same UPI payment ID: x@ybl"
    label: Optional[str] = None  # target URL or "Pasted message"
    risk_level: Optional[RiskLevel] = None
    created_at: Optional[datetime] = None


class CorrelationResult(BaseModel):
    related: list[RelatedReport] = []
