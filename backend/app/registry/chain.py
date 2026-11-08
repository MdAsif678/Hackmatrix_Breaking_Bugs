"""On-chain threat-report registry via web3.py. Owner: P4.

Only the report hash + risk level go on-chain — never URLs, messages or personal data.
Uses SEPOLIA_RPC_URL, REGISTRY_PRIVATE_KEY (throwaway testnet wallet) and
REGISTRY_CONTRACT_ADDRESS from .env. Contract ABI: contracts/ build output.
"""
from app.registry.hashing import report_hash
from app.schemas import AnalysisReport, ChainRecord, VerifyResult


class RegistryNotConfigured(NotImplementedError):
    pass


def submit(report: AnalysisReport) -> ChainRecord:
    """Call ThreatRegistry.submitReport(hash, riskLevel); wait for receipt; return the record."""
    # TODO(P4)
    raise RegistryNotConfigured("On-chain registry not implemented yet")


def verify(report: AnalysisReport) -> VerifyResult:
    """Recompute the hash and compare with ThreatRegistry.getReport(report.chain.chain_report_id)."""
    recomputed = report_hash(report)
    if report.chain is None:
        return VerifyResult(recomputed_hash=recomputed, match=False, status="not_registered")
    # TODO(P4): read on-chain hash + timestamp, compare
    raise RegistryNotConfigured("On-chain verification not implemented yet")
