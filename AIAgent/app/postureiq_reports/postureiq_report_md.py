"""
Compliance Report — Full Markdown
Detailed compliance report with resource inventories, RBAC analysis,
Entra details, findings, and remediation roadmap.
Matches the structure of the PowerShell-generated compliance-report.md.
"""

from __future__ import annotations
import pathlib
from datetime import datetime, timezone
from typing import Any
from app.logger import log
from app.postureiq_reports.inventory import extract_inventory, get_environment_summary


def generate_postureiq_report_md(
    results: dict[str, Any],
    evidence: list[dict],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    """Generate the full PostureIQ report markdown and return the file path."""
    ts = datetime.now(timezone.utc)
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "compliance-report.md"

    inv = extract_inventory(evidence)
    env_summary = get_environment_summary(inv)

    summary = results.get("summary", {})
    controls = results.get("control_results", [])
    findings = results.get("findings", [])
    missing = results.get("missing_evidence", [])
    domain_scores = summary.get("DomainScores", {})
    tenant = tenant_info or {}

    score = summary.get("ComplianceScore", 0)
    frameworks = summary.get("Frameworks", ["FedRAMP"])
    fw_label = ", ".join(frameworks)
    report_id = f"CIQ-{ts.strftime('%Y%m%d-%H%M%S')}"

    lines: list[str] = []
    W = lines.append

    # ── Title & Document Control ─────────────────────────────────────
    W(f"# PostureIQ — Compliance Assessment Report\n")
    W(f"## Document Control\n")
    W(f"| Property | Value |")
    W(f"|---|---|")
    W(f"| Report Identifier | {report_id} |")
    W(f"| Assessment Name | PostureIQ {fw_label} Assessment |")
    W(f"| Date Generated | {ts.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
    W(f"| Tenant ID | `{tenant.get('TenantId', tenant.get('tenant_id', 'N/A'))}` |")
    W(f"| Tenant Name | {tenant.get('DisplayName', tenant.get('display_name', 'Unknown'))} |")
    W(f"| Frameworks | {fw_label} |")
    W(f"| Classification | CONFIDENTIAL |")
    W(f"| Tool | PostureIQ AI Agent v1.0 |")
    W("")

    # ── 1. Executive Summary ─────────────────────────────────────────
    W("## 1. Executive Summary\n")
    W(f"Overall Compliance Score: **{score:.1f}%**\n")
    W("### Compliance Metrics\n")
    W("| Metric | Value |")
    W("|---|---|")
    W(f"| Total Controls | {summary.get('TotalControls', 0)} |")
    W(f"| Compliant | {summary.get('Compliant', 0)} |")
    W(f"| Non-Compliant | {summary.get('NonCompliant', 0)} |")
    W(f"| Partial | {summary.get('Partial', 0)} |")
    W(f"| Missing Evidence | {summary.get('MissingEvidence', 0)} |")
    W(f"| Total Evidence Records | {summary.get('TotalEvidence', 0):,} |")
    W(f"| Critical Findings | {summary.get('CriticalFindings', 0)} |")
    W(f"| High Findings | {summary.get('HighFindings', 0)} |")
    W(f"| Medium Findings | {summary.get('MediumFindings', 0)} |")
    W("")

    W("### Assessed Environment Summary\n")
    W("| Category | Count |")
    W("|---|---|")
    for k, v in env_summary.items():
        W(f"| {k} | {v:,} |")
    W("")

    # ── 2. Scope & Methodology ───────────────────────────────────────
    W("## 2. Assessment Scope & Methodology\n")
    W("### 2.1 Scope\n")
    W("This assessment covers control-plane configurations of:\n")
    W(f"- **Azure Resources:** All accessible subscriptions ({len(inv['subscriptions'])}), "
      f"resource groups ({len(inv['resource_groups'])}), resources ({len(inv['resources'])}), "
      f"RBAC assignments ({len(inv['rbac_assignments'])}), and policy assignments ({len(inv['policy_assignments'])}).")
    W(f"- **Microsoft Entra ID:** Tenant configuration, directory roles ({len(inv['entra_roles'])}), "
      f"conditional access policies ({len(inv['entra_ca_policies'])}), application registrations ({len(inv['entra_applications'])}), "
      f"and service principals ({len(inv['entra_service_principals'])}).\n")
    W("### 2.2 Methodology\n")
    W("1. **Evidence Collection** — Read-only calls to Azure Resource Manager and Microsoft Graph APIs.")
    W("2. **Normalization** — Collected data transformed into standardized evidence records.")
    W("3. **Evaluation** — Evidence mapped to compliance framework controls and evaluated.")
    W("4. **Reporting** — Findings generated with severity ratings and remediation guidance.\n")
    W("> **Important:** This assessment evaluates control-plane configurations only. "
      "Data-plane analysis is outside scope.\n")

    # ── 3. Azure Resource Inventory ──────────────────────────────────
    W("## 3. Azure Resource Inventory\n")

    W(f"### 3.1 Subscriptions ({len(inv['subscriptions'])})\n")
    if inv['subscriptions']:
        W("| Subscription ID | Name | State |")
        W("|---|---|---|")
        for s in inv['subscriptions']:
            W(f"| `{s.get('SubscriptionId', '')}` | {s.get('SubscriptionName', '')} | {s.get('State', 'Enabled')} |")
        W("")

    W(f"### 3.2 Resource Groups ({len(inv['resource_groups'])})\n")
    if inv['resource_groups']:
        W("| Resource Group | Subscription | Location |")
        W("|---|---|---|")
        for r in sorted(inv['resource_groups'], key=lambda x: x.get("ResourceGroup", ""))[:100]:
            W(f"| {r.get('ResourceGroup', '')} | {r.get('SubscriptionName', '')} | {r.get('Location', '')} |")
        if len(inv['resource_groups']) > 100:
            W(f"\n*Showing 100 of {len(inv['resource_groups'])} resource groups.*\n")
        W("")

    W(f"### 3.3 Resources ({len(inv['resources'])})\n")
    W("#### Resource Type Distribution\n")
    if inv['resource_type_counts']:
        W("| Resource Type | Count |")
        W("|---|---|")
        for rt, c in sorted(inv['resource_type_counts'].items(), key=lambda x: -x[1]):
            W(f"| `{rt}` | {c} |")
        W("")

    W(f"### 3.4 RBAC Assignments ({len(inv['rbac_assignments'])} total, "
      f"{len(inv['privileged_assignments'])} privileged, {len(inv['owner_assignments'])} owners)\n")
    W("#### Privileged Role Assignments\n")
    if inv['privileged_assignments']:
        W("| Role | Principal | Type | Scope | Subscription |")
        W("|---|---|---|---|---|")
        for ra in inv['privileged_assignments'][:200]:
            role = ra.get("RoleName") or ra.get("RoleDefinitionName", "")
            principal = ra.get("PrincipalName") or ra.get("PrincipalDisplayName", "")
            ptype = ra.get("PrincipalType", "")
            scope = ra.get("ScopeLevel", _scope_level(ra.get("Scope", "")))
            sub = ra.get("SubscriptionName", "")
            W(f"| {role} | {principal} | {ptype} | {scope} | {sub} |")
        if len(inv['privileged_assignments']) > 200:
            W(f"\n*Showing 200 of {len(inv['privileged_assignments'])} privileged assignments.*\n")
        W("")

    W(f"### 3.5 Policy Assignments ({len(inv['policy_assignments'])})\n")
    if inv['policy_assignments']:
        W("| Policy | Scope | Enforcement |")
        W("|---|---|---|")
        for p in inv['policy_assignments'][:50]:
            name = p.get("DisplayName") or p.get("Name", "")
            scope = p.get("Scope", "")[-80:]
            enforcement = p.get("EnforcementMode", "Default")
            W(f"| {name} | `{scope}` | {enforcement} |")
        if len(inv['policy_assignments']) > 50:
            W(f"\n*Showing 50 of {len(inv['policy_assignments'])} policies.*\n")
        W("")

    # ── 4. Entra ID Inventory ────────────────────────────────────────
    W("## 4. Microsoft Entra ID Inventory\n")

    W("### 4.1 Tenant Information\n")
    if inv.get("entra_tenant"):
        W("| Property | Value |")
        W("|---|---|")
        for k, v in inv["entra_tenant"].items():
            if v:
                W(f"| {k} | {v} |")
        W("")

    W(f"### 4.2 Directory Roles ({len(inv['entra_roles'])})\n")
    if inv['entra_roles']:
        W("| Role | Built-In | Description |")
        W("|---|---|---|")
        for r in inv['entra_roles'][:50]:
            name = r.get("DisplayName") or r.get("displayName", "")
            builtin = r.get("IsBuiltIn", r.get("isBuiltIn", True))
            desc = (r.get("Description") or r.get("description", ""))[:100]
            W(f"| {name} | {builtin} | {desc} |")
        W("")

    W(f"### 4.3 Conditional Access Policies ({len(inv['entra_ca_policies'])})\n")
    if inv['entra_ca_policies']:
        W("| Policy | State | Requires MFA |")
        W("|---|---|---|")
        for p in inv['entra_ca_policies']:
            name = p.get("DisplayName") or p.get("displayName", "")
            state = p.get("State") or p.get("state", "")
            gc = p.get("GrantControls") or p.get("grantControls") or {}
            if isinstance(gc, list):
                builtins = gc
            elif isinstance(gc, dict):
                builtins = gc.get("BuiltInControls") or gc.get("builtInControls") or []
            else:
                builtins = []
            mfa = "Yes" if "mfa" in [str(b).lower() for b in builtins] else "No"
            W(f"| {name} | {state} | {mfa} |")
        W("")

    W(f"### 4.4 Applications ({len(inv['entra_applications'])} registrations, "
      f"{len(inv['entra_service_principals'])} service principals)\n")

    if inv['entra_users_summary']:
        u = inv['entra_users_summary']
        total = u.get("TotalUsers") or u.get("totalUsers", 0)
        guests = u.get("GuestUsers") or u.get("guestUsers", 0)
        members = u.get("MemberUsers") or u.get("memberUsers", 0)
        enabled = u.get("EnabledUsers") or u.get("enabledUsers", 0)
        disabled = u.get("DisabledUsers") or u.get("disabledUsers", 0)
        W("### 4.5 User Demographics\n")
        W("| Metric | Count |")
        W("|---|---|")
        W(f"| Total Users | {total:,} |")
        W(f"| Member Users | {members:,} |")
        W(f"| Guest Users | {guests:,} |")
        W(f"| Enabled | {enabled:,} |")
        W(f"| Disabled | {disabled:,} |")
        W("")
    if inv['entra_mfa_summary']:
        m = inv['entra_mfa_summary']
        reg = m.get("MfaRegistered") or m.get("mfaRegistered", 0)
        tot = m.get("TotalUsers") or m.get("totalUsers", 0)
        pct = (reg / tot * 100) if tot > 0 else 0
        W(f"MFA Registered: **{reg:,}** of {tot:,} ({pct:.1f}%)\n")

    # ── 5. Framework Summary ─────────────────────────────────────────
    W("## 5. Compliance Evaluation — Framework Summary\n")
    W(f"**Overall Compliance Score: {score:.1f}%**\n")
    fw_summaries = summary.get("FrameworkSummaries", {})
    if fw_summaries:
        W("| Framework | Score | Compliant | Non-Compliant | Missing |")
        W("|---|---|---|---|---|")
        for fk, fv in fw_summaries.items():
            W(f"| {fv.get('FrameworkName', fk)} | {fv.get('ComplianceScore', 0):.1f}% "
              f"| {fv.get('Compliant', 0)} | {fv.get('NonCompliant', 0)} | {fv.get('MissingEvidence', 0)} |")
        W("")

    # ── 6. Domain Analysis ───────────────────────────────────────────
    W("## 6. Domain Analysis\n")
    W("| Domain | Score | Compliant | Total |")
    W("|---|---|---|---|")
    for domain, data in domain_scores.items():
        W(f"| {domain.replace('_', ' ').title()} | {data.get('Score', 0):.0f}% | {data.get('Compliant', 0)} | {data.get('Total', 0)} |")
    W("")

    # ── 7. Control Results ───────────────────────────────────────────
    W(f"## 7. Control Results ({len(controls)})\n")
    W("| Control | Title | Framework | Severity | Status | Findings |")
    W("|---|---|---|---|---|---|")
    for c in sorted(controls, key=lambda x: (_sev_order(x.get("Severity", "medium")), x.get("ControlId", ""))):
        cid = c.get("ControlId", "")
        title = c.get("ControlTitle", "")
        fw = c.get("Framework", "")
        sev = c.get("Severity", "medium").upper()
        status = c.get("Status", "not_assessed").replace("_", " ").title()
        fc = c.get("FindingCount", 0)
        W(f"| `{cid}` | {title} | {fw} | **{sev}** | {status} | {fc} |")
    W("")

    # ── 8. Detailed Findings ─────────────────────────────────────────
    W(f"## 8. Detailed Findings ({len(findings)})\n")
    for f in sorted(findings, key=lambda x: _sev_order(x.get("Severity", "medium"))):
        cid = f.get("ControlId", "")
        title = f.get("ControlTitle", "")
        sev = f.get("Severity", "medium").upper()
        status = f.get("Status", "").replace("_", " ").title()
        desc = f.get("Description", "")
        rec = f.get("Recommendation", "")
        fw = f.get("Framework", "")
        domain = f.get("Domain", "")
        W(f"### `{cid}` — {title}\n")
        W(f"- **Severity:** {sev}")
        W(f"- **Status:** {status}")
        W(f"- **Framework:** {fw}")
        W(f"- **Domain:** {domain}")
        W(f"- **Description:** {desc}")
        if rec and f.get("Status") == "non_compliant":
            W(f"\n> **Recommendation:** {rec}\n")
        W("")

    # ── 9. Remediation Roadmap ───────────────────────────────────────
    nc = [f for f in findings if f.get("Status") == "non_compliant"]
    W(f"## 9. Remediation Roadmap ({len(nc)} items)\n")
    if nc:
        nc.sort(key=lambda x: _sev_order(x.get("Severity", "medium")))
        groups: dict[str, list] = {}
        for f in nc:
            groups.setdefault(f.get("Severity", "medium"), []).append(f)
        priority = 1
        for sev in ["critical", "high", "medium", "low"]:
            items = groups.get(sev, [])
            if not items:
                continue
            timeline = "0-14 days" if sev == "critical" else "0-30 days" if sev == "high" else "30-90 days" if sev == "medium" else "90-180 days"
            W(f"### Priority {priority}: {sev.upper()} ({len(items)} items) — {timeline}\n")
            seen: set[str] = set()
            for f in items:
                key = f.get("ControlId", "") + (f.get("Recommendation", "") or f.get("Description", ""))
                if key in seen:
                    continue
                seen.add(key)
                W(f"- **`{f.get('ControlId', '')}`**: {f.get('Description', '')}")
                if f.get('Recommendation'):
                    W(f"  - *Action:* {f.get('Recommendation')}")
            W("")
            priority += 1
    else:
        W("No non-compliant findings requiring remediation.\n")

    # ── 10. Missing Evidence ─────────────────────────────────────────
    W(f"## 10. Missing Evidence ({len(missing)})\n")
    if missing:
        # Summary by category
        cat_counts: dict[str, int] = {}
        for m in missing:
            cat = m.get("PrimaryCategory", "Unknown")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        W("**Summary by Category:**\n")
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            W(f"- **{cat}**: {count} control(s)")
        W("")

        # Detailed breakdown per control
        for m in missing:
            cid = m.get("ControlId", "")
            sev = m.get("Severity", "medium").upper()
            fw = m.get("Framework", "")
            cat = m.get("PrimaryCategory", "Unknown")
            W(f"### `{cid}` ({fw}) — {sev}\n")
            W(f"**Category:** {cat}\n")

            types_detail = m.get("TypesDetail", [])
            if types_detail:
                for td in types_detail:
                    dname = td.get("DisplayName", td.get("EvidenceType", ""))
                    etype = td.get("EvidenceType", "")
                    source = td.get("Source", "")
                    tcat = td.get("Category", "")
                    explanation = td.get("Explanation", "")
                    resolution = td.get("Resolution", "")
                    W(f"#### {dname}")
                    W(f"- **Evidence Type:** `{etype}` ({source})")
                    W(f"- **Classification:** {tcat}")
                    W(f"- **Why Missing:** {explanation}")
                    W(f"- **Resolution:**")
                    for line in resolution.split("\n"):
                        line = line.strip()
                        if line:
                            W(f"  {line}")
                    W("")
            else:
                types = ", ".join(m.get("MissingTypes", []))
                W(f"- **Missing Types:** {types}\n")
    else:
        W("All evidence types collected successfully.\n")

    # ── 11. Access Denied ────────────────────────────────────────────
    ad = access_denied or []
    W(f"## 11. Access Denied ({len(ad)})\n")
    if ad:
        W("| Collector | Source | API | Status |")
        W("|---|---|---|---|")
        for a in ad:
            W(f"| {a.get('collector', '')} | {a.get('source', '')} | {a.get('api', '')} | {a.get('status_code', 403)} |")
        W("")
        W("> **Note:** Ensure your account has the required role assignments for the above APIs.\n")

    W(f"\n---\n*Generated by PostureIQ AI Agent v1.0 — {ts.strftime('%Y-%m-%d')} — CONFIDENTIAL*\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log.info("Compliance report MD: %s", path)
    return str(path)


def _scope_level(scope: str) -> str:
    if "/managementGroups/" in scope:
        return "ManagementGroup"
    if "/resourceGroups/" in scope and "/providers/" in scope:
        return "Resource"
    if "/resourceGroups/" in scope:
        return "ResourceGroup"
    if "/subscriptions/" in scope:
        return "Subscription"
    return "Unknown"


def _sev_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev.lower(), 4)
