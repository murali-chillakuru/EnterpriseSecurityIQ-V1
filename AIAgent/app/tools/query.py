"""
Query Tool — Queries assessment results.
"""

from __future__ import annotations
from typing import Any


def query_results(results: dict[str, Any], question: str) -> str:
    """Query assessment results for specific controls, domains, or findings."""
    if not results:
        return "No assessment results available. Please run an assessment first."

    q = question.lower()
    findings = results.get("findings", [])
    controls = results.get("control_results", [])
    summary = results.get("summary", {})

    # Search by control ID
    for ctrl in controls:
        cid = ctrl.get("ControlId", "")
        if cid.lower() in q or cid.lower().replace("fedramp-", "") in q:
            related = [f for f in findings if f.get("ControlId") == cid]
            result = f"## {cid}: {ctrl.get('ControlTitle', '')}\n"
            result += f"- Status: {ctrl['Status']}\n- Severity: {ctrl['Severity']}\n"
            result += f"- Findings: {len(related)}\n\n"
            for rf in related:
                result += f"- [{rf['Status'].upper()}] {rf['Description']}\n"
            return result

    # Search by domain
    for domain in ("access", "identity", "data_protection", "logging", "network", "governance"):
        if domain in q:
            domain_ctrls = [c for c in controls if c.get("Domain") == domain]
            domain_findings = [f for f in findings if f.get("Domain") == domain]
            result = f"## {domain.title()} Domain\n"
            ds = summary.get("DomainScores", {}).get(domain, {})
            result += f"- Score: {ds.get('Score', 0):.1f}%\n"
            result += f"- Controls: {len(domain_ctrls)}, Findings: {len(domain_findings)}\n\n"
            nc = [c for c in domain_ctrls if c["Status"] == "non_compliant"]
            if nc:
                result += "### Non-Compliant Controls:\n"
                for c in nc:
                    result += f"- {c['ControlId']}: {c.get('ControlTitle', '')} ({c['Severity']})\n"
            return result

    # Search by severity
    for sev in ("critical", "high", "medium", "low"):
        if sev in q:
            sev_findings = [f for f in findings if f.get("Severity") == sev]
            return (
                f"## {sev.upper()} Findings ({len(sev_findings)})\n\n"
                + "\n".join(
                    f"- [{f.get('ControlId', '')}] {f.get('Description', '')}"
                    for f in sev_findings[:20]
                )
            )

    # General summary
    return (
        f"## Summary\n"
        f"- Score: {summary.get('ComplianceScore', 0):.1f}%\n"
        f"- Controls: {summary.get('TotalControls', 0)}\n"
        f"- Compliant: {summary.get('Compliant', 0)}\n"
        f"- Non-Compliant: {summary.get('NonCompliant', 0)}\n"
        f"- Findings: {summary.get('TotalFindings', 0)}\n"
    )
