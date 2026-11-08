"""DEMO ONLY (local Hardhat chain): play a hacker who edits a report AND makes his own blockchain seal for it.

Usage (from backend/, with `npm run chain` running in contracts/):
    python scripts/fake_seal_attack.py <report_id>

What it does:
  1. changes the stored report's verdict to "low_risk" (hiding a dangerous site)
  2. seals the edited report on the blockchain using a DIFFERENT wallet (Hardhat test account #1)
  3. points the report at that fake seal
Then click Verify in the app: it must say the seal was not added by TrustLens's wallet.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web3 import Web3  # noqa: E402

from app import db  # noqa: E402
from app.config import settings  # noqa: E402
from app.registry.chain import load_abi  # noqa: E402
from app.registry.hashing import report_hash  # noqa: E402
from app.schemas import ChainRecord, RiskLevel  # noqa: E402

# Hardhat local test account #1 — publicly documented, only works on the local chain
HACKER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(1)
    w3 = Web3(Web3.HTTPProvider(settings.sepolia_rpc_url))
    if w3.eth.chain_id != 31337:
        raise SystemExit("Refusing: this demo only runs against the local Hardhat chain (chain id 31337).")
    report = db.get_report(sys.argv[1])
    if report is None:
        raise SystemExit(f"No report with id {sys.argv[1]}")
    if report.chain is None:
        raise SystemExit("Register this report on-chain in the app first, then run the attack.")

    before = report.risk_level.value
    report.risk_level = RiskLevel.low_risk
    fake_hash = report_hash(report)

    hacker = w3.eth.account.from_key(HACKER_KEY)
    registry = w3.eth.contract(address=Web3.to_checksum_address(settings.registry_contract_address), abi=load_abi())
    tx = registry.functions.submitReport(bytes.fromhex(fake_hash[2:]), "low_risk").build_transaction(
        {"from": hacker.address, "nonce": w3.eth.get_transaction_count(hacker.address), "chainId": 31337}
    )
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(hacker.sign_transaction(tx).raw_transaction))
    slot = registry.events.ReportSubmitted().process_receipt(receipt)[0]["args"]["id"]

    report.chain = ChainRecord(report_hash=fake_hash, chain_report_id=slot, tx_hash=Web3.to_hex(receipt["transactionHash"]),
                               network="localhost", contract_address=registry.address)
    db.save_report(report)
    print(f"Hacker changed the verdict {before} -> low_risk and sealed the fake version in slot {slot} "
          f"from wallet {hacker.address}. Now click Verify in the app.")


if __name__ == "__main__":
    main()
