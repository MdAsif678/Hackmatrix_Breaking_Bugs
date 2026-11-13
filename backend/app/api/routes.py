"""HTTP API — AGENTS.md §5. Owner: P1."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from app import db, pipeline
from app.core.rate_limit import CHECK_RULES, SEAL_RULES, enforce
from app.correlation.engine import related_details
from app.registry import chain
from app.registry.hashing import canonical_json, report_hash
from app.schemas import (
    AnalysisReport,
    ChainRecord,
    CorrelationResult,
    MessageRequest,
    UrlRequest,
    VerifyResult,
)

router = APIRouter(prefix="/api")


def _get_or_404(report_id: str) -> AnalysisReport:
    report = db.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/analyze/url", response_model=AnalysisReport)
async def analyze_url(body: UrlRequest, request: Request) -> AnalysisReport:
    enforce(request, CHECK_RULES)
    try:
        return await pipeline.analyze_url(body.url)
    except pipeline.InvalidTarget as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/analyze/message", response_model=AnalysisReport)
async def analyze_message(body: MessageRequest, request: Request) -> AnalysisReport:
    enforce(request, CHECK_RULES)
    return await pipeline.analyze_message(body.text)


@router.get("/reports", response_model=list[AnalysisReport])
async def list_reports(limit: int = 50) -> list[AnalysisReport]:
    return db.list_reports(limit=min(max(limit, 1), 200))


@router.get("/reports/{report_id}", response_model=AnalysisReport)
async def get_report(report_id: str) -> AnalysisReport:
    return _get_or_404(report_id)


@router.get("/reports/{report_id}/canonical")
async def canonical(report_id: str) -> dict:
    """The exact text that is fingerprinted (AGENTS.md §7) and its SHA-256, so a browser can recompute the hash
    itself and compare it with the value it reads from the blockchain, without trusting this server's verdict."""
    report = _get_or_404(report_id)
    return {"canonical": canonical_json(report), "sha256": report_hash(report), "chain": report.chain}


@router.post("/registry/submit/{report_id}", response_model=ChainRecord)
async def registry_submit(report_id: str, request: Request) -> ChainRecord:
    report = _get_or_404(report_id)
    if report.chain is not None:
        return report.chain  # already sealed: costs nothing, so it is not counted against the limits
    enforce(request, SEAL_RULES)
    try:
        record = await run_in_threadpool(chain.submit, report)
    except chain.RegistrationRejected as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except chain.RegistryError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    report.chain = record
    db.save_report(report)
    return record


@router.get("/registry/verify/{report_id}", response_model=VerifyResult)
async def registry_verify(report_id: str) -> VerifyResult:
    report = _get_or_404(report_id)
    try:
        return await run_in_threadpool(chain.verify, report)
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except chain.RegistryError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get("/correlations/{report_id}", response_model=CorrelationResult)
async def correlations(report_id: str) -> CorrelationResult:
    return related_details(_get_or_404(report_id))
