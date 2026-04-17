"""
OSCAL Evidence Export
Exports assessment results in NIST OSCAL Assessment Results format (JSON).
See: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/
"""

from __future__ import annotations
import json, pathlib, uuid
from datetime import datetime, timezone
from typing import Any
from app.logger import log
from app.models import ENTERPRISESECURITYIQ_NS


def export_oscal(
    results: dict[str, Any],
    tenant_info: dict | None = None,
    output_dir: str = "output",
) -> str:
    """Generate an OSCAL Assessment Results JSON file and return the path."""
    ts = datetime.now(timezone.utc)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "oscal-assessment-results.json"

    tenant = tenant_info or {}
    summary = results.get("summary", {})
    controls = results.get("control_results", [])
    findings = results.get("findings", [])

    # Map EnterpriseSecurityIQ statuses to OSCAL result states (lowercase to match Status enum)
    status_map = {
        "compliant": "satisfied",
        "non_compliant": "not-satisfied",
        "not_assessed": "not-applicable",
        "missing_evidence": "not-applicable",
        "partial": "other",
    }

    oscal_findings: list[dict] = []
    for ctrl in controls:
        oscal_findings.append({
            "uuid": str(uuid.uuid5(ENTERPRISESECURITYIQ_NS, f"oscal-finding|{ctrl.get('control_id', '')}")),
            "title": ctrl.get("title", ""),
            "description": ctrl.get("rationale", ""),
            "target": {
                "type": "objective-id",
                "target-id": ctrl.get("control_id", ""),
                "status": {
                    "state": status_map.get(ctrl.get("status", ""), "not-applicable"),
                },
            },
            "related-observations": [],
        })

    # Build observations from raw findings
    observations: list[dict] = []
    for idx, f in enumerate(findings):
        observations.append({
            "uuid": str(uuid.uuid5(ENTERPRISESECURITYIQ_NS, f"oscal-obs|{f.get('control_id', '')}|{f.get('check', '')}|{idx}")),
            "title": f.get("check", f.get("control_id", "")),
            "description": f.get("detail", ""),
            "methods": ["EXAMINE", "TEST"],
            "collected": ts.isoformat(),
            "relevant-evidence": [
                {
                    "description": f.get("detail", ""),
                    "props": [
                        {"name": "severity", "value": f.get("severity", "medium")},
                        {"name": "resource", "value": f.get("resource", "N/A")},
                    ],
                }
            ],
        })

    # Deterministic document & result UUIDs seeded on tenant + score
    _tenant_id = tenant.get("tenant_id", "unknown")
    _doc_seed = f"oscal-doc|{_tenant_id}|{summary.get('TotalControls', 0)}"
    _res_seed = f"oscal-result|{_tenant_id}|{summary.get('ComplianceScore', 0)}"

    doc: dict[str, Any] = {
        "assessment-results": {
            "uuid": str(uuid.uuid5(ENTERPRISESECURITYIQ_NS, _doc_seed)),
            "metadata": {
                "title": "EnterpriseSecurityIQ Assessment Results",
                "last-modified": ts.isoformat(),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "tenant-id", "value": tenant.get("tenant_id", "unknown")},
                    {"name": "tenant-name", "value": tenant.get("display_name", "unknown")},
                ],
            },
            "results": [
                {
                    "uuid": str(uuid.uuid5(ENTERPRISESECURITYIQ_NS, _res_seed)),
                    "title": "EnterpriseSecurityIQ Assessment Results",
                    "description": (
                        f"Compliance score: {summary.get('ComplianceScore', 0):.1f}% "
                        f"({summary.get('Compliant', 0)}/{summary.get('TotalControls', 0)})"
                    ),
                    "start": ts.isoformat(),
                    "findings": oscal_findings,
                    "observations": observations,
                },
            ],
        }
    }

    path.write_text(json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")
    log.info("OSCAL report written to %s", path)
    return str(path)
