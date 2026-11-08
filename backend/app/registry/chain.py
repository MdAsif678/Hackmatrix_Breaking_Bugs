"""On-chain threat-report registry via web3.py. Owner: P1. Guide: docs/tasks/P1-lead.md

Only the report hash + risk level go on-chain — never URLs, messages or personal data.

Needs (from P4's deployment):
- contracts/ThreatRegistry.abi.json  (ABI array from Remix, or a Hardhat artifact with an "abi" key)
- .env: SEPOLIA_RPC_URL, REGISTRY_PRIVATE_KEY (throwaway testnet wallet), REGISTRY_CONTRACT_ADDRESS

Contract interface: AGENTS.md §7.
"""
import json
from dataclasses import dataclass
from typing import Any, Optional

from app.config import REPO_ROOT, settings
from app.registry.hashing import report_hash
from app.schemas import AnalysisReport, ChainRecord, VerifyResult

ABI_PATH = REPO_ROOT / "contracts" / "ThreatRegistry.abi.json"
RECEIPT_TIMEOUT_SECONDS = 180
NETWORK_NAMES = {11155111: "sepolia", 31337: "localhost", 1337: "localhost", 80002: "polygon-amoy", 84532: "base-sepolia"}
EXPLORERS = {"sepolia": "https://sepolia.etherscan.io", "polygon-amoy": "https://amoy.polygonscan.com",
             "base-sepolia": "https://sepolia.basescan.org"}
CHAIN_STATUS = {0: "active", 1: "disputed", 2: "revised"}


class RegistryNotConfigured(NotImplementedError):
    """Raised when the contract/RPC/wallet isn't set up yet -> API answers 501 with this message."""


class RegistryError(RuntimeError):
    """Raised when the blockchain call itself fails (RPC down, out of test ETH, tx reverted...)."""


@dataclass
class _Conn:
    w3: Any
    contract: Any
    account: Any
    network: str


def load_abi(path=ABI_PATH) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["abi"] if isinstance(data, dict) else data


def to_bytes32(hex_hash: str) -> bytes:
    raw = bytes.fromhex(hex_hash.removeprefix("0x"))
    if len(raw) != 32:
        raise ValueError("report hash must be 32 bytes")
    return raw


def _connection() -> _Conn:
    missing = [name for name, value in (
        ("SEPOLIA_RPC_URL", settings.sepolia_rpc_url),
        ("REGISTRY_PRIVATE_KEY", settings.registry_private_key),
        ("REGISTRY_CONTRACT_ADDRESS", settings.registry_contract_address),
    ) if not value.strip()]
    if not ABI_PATH.exists():
        missing.append("contracts/ThreatRegistry.abi.json")
    if missing:
        raise RegistryNotConfigured("On-chain registry not configured yet (missing: " + ", ".join(missing) + ")")

    from web3 import Web3  # heavy import, only when needed

    w3 = Web3(Web3.HTTPProvider(settings.sepolia_rpc_url.strip(), request_kwargs={"timeout": 20}))
    try:
        chain_id = w3.eth.chain_id
    except Exception as exc:
        raise RegistryError(f"Blockchain RPC unreachable: {type(exc).__name__}") from exc
    contract = w3.eth.contract(address=Web3.to_checksum_address(settings.registry_contract_address.strip()),
                               abi=load_abi())
    account = w3.eth.account.from_key(settings.registry_private_key.strip())
    return _Conn(w3=w3, contract=contract, account=account, network=NETWORK_NAMES.get(chain_id, f"chain-{chain_id}"))


def _send(conn: _Conn, call) -> tuple[str, Any]:
    """Sign and send a contract call with the registry wallet; wait for the receipt."""
    from web3 import Web3

    try:
        tx = call.build_transaction({
            "from": conn.account.address,
            "nonce": conn.w3.eth.get_transaction_count(conn.account.address, "pending"),
            "chainId": conn.w3.eth.chain_id,
        })
        signed = conn.account.sign_transaction(tx)
        tx_hash = conn.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = conn.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT_SECONDS)
    except Exception as exc:
        text = str(exc).lower()
        hint = " (registry wallet needs Sepolia test ETH)" if "insufficient funds" in text else ""
        raise RegistryError(f"Blockchain transaction failed: {type(exc).__name__}{hint}") from exc
    if receipt["status"] != 1:
        raise RegistryError(f"Transaction reverted: {Web3.to_hex(tx_hash)}")
    return Web3.to_hex(tx_hash), receipt


def submit(report: AnalysisReport) -> ChainRecord:
    """Call ThreatRegistry.submitReport(hash, riskLevel); wait for the receipt; return the record."""
    conn = _connection()
    h = report_hash(report)
    tx_hash, receipt = _send(conn, conn.contract.functions.submitReport(to_bytes32(h), report.risk_level.value))
    events = conn.contract.events.ReportSubmitted().process_receipt(receipt)
    if not events:
        raise RegistryError("Transaction succeeded but no ReportSubmitted event was found (ABI mismatch?)")
    return ChainRecord(
        report_hash=h,
        chain_report_id=int(events[0]["args"]["id"]),
        tx_hash=tx_hash,
        network=conn.network,
        contract_address=conn.contract.address,
    )


def read_onchain(conn: _Conn, chain_report_id: int) -> dict:
    from web3 import Web3

    h, submitter, timestamp, risk_level, status, revisions = conn.contract.functions.getReport(chain_report_id).call()
    return {
        "hash": Web3.to_hex(h),
        "submitter": submitter,
        "timestamp": int(timestamp),
        "risk_level": risk_level,
        "status": CHAIN_STATUS.get(int(status), str(status)),
        "revisions": int(revisions),
    }


def verify(report: AnalysisReport) -> VerifyResult:
    """Recompute the hash from OUR stored copy and compare it with the hash recorded on-chain."""
    recomputed = report_hash(report)
    if report.chain is None:
        return VerifyResult(recomputed_hash=recomputed, match=False, status="not_registered")
    conn = _connection()
    try:
        onchain = read_onchain(conn, report.chain.chain_report_id)
    except Exception as exc:
        raise RegistryError(f"Could not read report {report.chain.chain_report_id} from the contract: {type(exc).__name__}") from exc
    match = onchain["hash"].lower() == recomputed.lower()
    return VerifyResult(
        recomputed_hash=recomputed,
        onchain_hash=onchain["hash"],
        match=match,
        tx_hash=report.chain.tx_hash,
        block_timestamp=onchain["timestamp"],
        status="verified" if match else "mismatch",
        chain_status=onchain["status"],
        submitter=onchain["submitter"],
        explorer_url=explorer_tx_url(report.chain.network, report.chain.tx_hash),
    )


def explorer_tx_url(network: str, tx_hash: str) -> Optional[str]:
    base = EXPLORERS.get(network)
    return f"{base}/tx/{tx_hash}" if base else None
