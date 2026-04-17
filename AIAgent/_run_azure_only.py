"""One-shot Azure-only assessment across 5 frameworks."""
import asyncio
import pathlib
from datetime import datetime
from app.auth import ComplianceCredentials
from app.config import AssessmentConfig
from app.orchestrator import run_full_assessment

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

TENANT = "4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67"
FRAMEWORKS = ["FedRAMP", "PCI-DSS", "NIST-800-53", "MCSB", "CIS"]


async def main():
    ts = datetime.now().strftime("%Y%m%d_%I%M%S_%p")
    out = str(_REPO_ROOT / "output" / ts)

    config = AssessmentConfig.from_env()
    config.frameworks = FRAMEWORKS
    config.output_formats = ["json", "html", "md"]
    config.collectors.entra_enabled = False  # Azure resources ONLY
    config.collectors.collector_timeout = 600

    creds = ComplianceCredentials(tenant_id=TENANT)
    pf = await creds.preflight_check()

    print(f"User: {pf['user']}")
    print(f"Tenant: {pf['tenant']}")
    print(f"ARM subs: {pf['arm_subs']}")
    print(f"Frameworks: {FRAMEWORKS}")
    print("Scope: Azure Resources ONLY (Entra disabled)")
    print(f"Output: {out}")
    print()

    result = await run_full_assessment(creds, config=config, output_dir=out)
    s = result.get("summary", {})

    print()
    print("=" * 60)
    print("ASSESSMENT RESULTS")
    print("=" * 60)
    for fw, d in s.get("FrameworkResults", {}).items():
        sc = d.get("Score", 0)
        c = d.get("Compliant", 0)
        tot = d.get("TotalControls", 0)
        print(f"  {fw}: {sc}% ({c}/{tot} compliant)")
    rp = result.get("report_paths", {})
    for k, v in rp.items():
        print(f"  {k}: {v}")
    elapsed = s.get("ElapsedSeconds", 0)
    print(f"Elapsed: {elapsed:.0f}s")
    await creds.close()


asyncio.run(main())
