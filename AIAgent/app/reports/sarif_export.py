"""
SARIF Export — Static Analysis Results Interchange Format v2.1.0

Generates ``compliance-results.sarif`` for GitHub Advanced Security integration.
Each non-compliant or partial finding becomes a SARIF ``result`` with severity
mapped to SARIF's ``level`` (error / warning / note / none).
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from app.logger import log

_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_VERSION = "2.1.0"

_SEV_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "none",
}


def export_sarif(
    results: dict[str, Any],
    tenant_info: dict[str, Any],
    output_dir: str,
) -> str:
    """Generate ``compliance-results.sarif`` and return its path."""
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "compliance-results.sarif"

    findings = results.get("findings", [])
    control_results = results.get("control_results", [])

    # Build rules from control_results (deduplicated by ControlId)
    rules_map: dict[str, dict] = {}
    for cr in control_results:
        cid = cr.get("ControlId", "")
        if cid and cid not in rules_map:
            rules_map[cid] = {
                "id": cid,
                "name": cid.replace(".", "_"),
                "shortDescription": {"text": cr.get("Title", cid)},
                "fullDescription": {"text": cr.get("Description", cr.get("Title", cid))},
                "defaultConfiguration": {
                    "level": _SEV_TO_LEVEL.get(cr.get("Severity", "medium"), "warning"),
                },
                "properties": {
                    "domain": cr.get("Domain", ""),
                    "framework": cr.get("Framework", ""),
                },
            }

    rules = list(rules_map.values())
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    # Build results from findings
    sarif_results = []
    for f in findings:
        cid = f.get("ControlId", "")
        sev = f.get("Severity", "medium")
        level = _SEV_TO_LEVEL.get(sev, "warning")
        status = f.get("Status", "non_compliant")
        desc = f.get("Description", "")
        remediation = f.get("Remediation", "")

        result_obj: dict[str, Any] = {
            "ruleId": cid,
            "level": level,
            "message": {"text": desc or f"Control {cid} is {status}"},
            "properties": {
                "severity": sev,
                "complianceStatus": status,
                "domain": f.get("Domain", ""),
                "framework": f.get("Framework", ""),
            },
        }

        if cid in rule_index:
            result_obj["ruleIndex"] = rule_index[cid]

        # Add location from SupportingEvidence if available
        se = f.get("SupportingEvidence", [])
        if se and isinstance(se, list):
            for ev in se[:1]:
                resource_id = ev.get("ResourceId", ev.get("resource_id", ""))
                if resource_id:
                    result_obj["locations"] = [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": resource_id,
                                "uriBaseId": "AZURE",
                            },
                        },
                    }]

        if remediation:
            result_obj["fixes"] = [{
                "description": {"text": remediation},
            }]

        sarif_results.append(result_obj)

    tenant_name = tenant_info.get("display_name", tenant_info.get("tenant_id", "unknown"))

    sarif_doc = {
        "$schema": _SCHEMA,
        "version": _VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "EnterpriseSecurityIQ",
                    "informationUri": "https://github.com/enterprisesecurityiq",
                    "version": "1.0.0",
                    "rules": rules,
                },
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "tenant": tenant_name,
                    "totalControls": results.get("summary", {}).get("TotalControls", 0),
                    "complianceScore": results.get("summary", {}).get("ComplianceScore", 0),
                },
            }],
        }],
    }

    path.write_text(json.dumps(sarif_doc, indent=2, sort_keys=True), encoding="utf-8")
    log.info("SARIF export → %s (%d results, %d rules)", path, len(sarif_results), len(rules))
    return str(path)
