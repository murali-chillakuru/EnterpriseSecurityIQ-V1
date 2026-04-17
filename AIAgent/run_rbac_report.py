"""
EnterpriseSecurityIQ — RBAC Report Runner (CLI)

Generates an interactive HTML report showing the full Azure RBAC hierarchy:
Management Groups → Subscriptions → Resource Groups → Resources
with role assignments, PIM eligibility, principal names, and group expansion.

Usage:
    python run_rbac_report.py --tenant <tenant-id>
    python run_rbac_report.py --tenant <tenant-id> --output-dir ./my-output
    python run_rbac_report.py --tenant <tenant-id> --subscriptions sub1-id sub2-id
"""

import argparse
import asyncio
import json
import pathlib
import sys
from datetime import datetime, timezone

from app.auth import ComplianceCredentials
from app.collectors.azure.rbac_collector import collect_rbac_data
from app.reports.rbac_report import generate_rbac_report
from app.reports.pdf_export import convert_all_html_to_pdf
from app.logger import log


async def _main(args: argparse.Namespace) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%I%M%S_%p")
    # Default output to the project-level output/ directory (one level up from AIAgent/)
    default_output = pathlib.Path(__file__).resolve().parent.parent / "output" / ts
    base_dir = pathlib.Path(args.output_dir or str(default_output))
    output_dir = base_dir / "RBAC-Report"
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info("=== EnterpriseSecurityIQ RBAC Tree Report ===")
    log.info("Tenant: %s", args.tenant or "(auto-detect)")

    # Authenticate
    creds = ComplianceCredentials(tenant_id=args.tenant or "")
    subscriptions = await creds.list_subscriptions(
        subscription_filter=args.subscriptions if args.subscriptions else None,
    )
    if not subscriptions:
        log.error("No subscriptions found. Check your Azure login and permissions.")
        sys.exit(1)
    log.info("Subscriptions: %d", len(subscriptions))
    for s in subscriptions:
        log.info("  • %s (%s)", s["display_name"], s["subscription_id"])

    # Collect
    log.info("Collecting RBAC hierarchy data …")
    data = await collect_rbac_data(creds, subscriptions)

    # Save raw data
    raw_path = output_dir / "rbac-data.json"
    raw_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log.info("Raw data saved to %s", raw_path)

    # Generate report
    log.info("Generating HTML report …")
    report_path = generate_rbac_report(data, output_dir)

    # Summary
    stats = data.get("stats", {})
    risks = data.get("risks", [])
    log.info("─" * 60)
    log.info("RBAC Report complete")
    log.info("  Score       : %d/100", stats.get("rbac_score", 0))
    log.info("  Assignments : %d total (%d active, %d PIM eligible)",
             stats.get("total_assignments", 0),
             stats.get("active_assignments", 0),
             stats.get("eligible_assignments", 0))
    log.info("  Privileged  : %d active, %d eligible",
             stats.get("privileged_active", 0),
             stats.get("privileged_eligible", 0))
    log.info("  Principals  : %d unique (%d groups)",
             stats.get("unique_principals", 0),
             stats.get("groups_with_roles", 0))
    log.info("  Risks       : %d findings", len(risks))
    log.info("  Report      : %s", report_path)
    xlsx_path = output_dir / "rbac-report.xlsx"
    if xlsx_path.exists():
        log.info("  Excel       : %s", xlsx_path)
    log.info("  Raw JSON    : %s", raw_path)
    # Generate PDFs from all HTML reports
    pdf_paths = await convert_all_html_to_pdf(output_dir)
    for pp in pdf_paths:
        log.info("  PDF         : %s", pp)
    log.info("─" * 60)

    # Close credential
    try:
        await creds.credential.close()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="EnterpriseSecurityIQ — RBAC Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--tenant", "-t", default="",
        help="Azure AD tenant ID (auto-detected if omitted)",
    )
    parser.add_argument(
        "--output-dir", "-o", default="",
        help="Output directory (default: output/<timestamp>)",
    )
    parser.add_argument(
        "--subscriptions", "-s", nargs="*", default=None,
        help="Limit to specific subscription IDs or names",
    )
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    main()
