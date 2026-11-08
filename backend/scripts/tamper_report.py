"""DEMO ONLY: secretly edit a stored report to show that on-chain verification catches it.

Usage (from backend/):  python scripts/tamper_report.py <report_id>

It changes the stored verdict to "low_risk" (as an attacker hiding a phishing report would).
Then open the Verify page: the recomputed hash no longer matches the blockchain -> ✗ mismatch.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db  # noqa: E402
from app.schemas import RiskLevel  # noqa: E402


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(1)
    report = db.get_report(sys.argv[1])
    if report is None:
        raise SystemExit(f"No report with id {sys.argv[1]}")
    before = report.risk_level.value
    report.risk_level = RiskLevel.low_risk
    report.risk_reasons = ["No significant malicious indicators within the available checks"]
    db.save_report(report)  # NOTE: bypasses the pipeline on purpose
    print(f"Tampered report {report.id}: risk_level {before} -> low_risk. Now verify it in the app.")


if __name__ == "__main__":
    main()
