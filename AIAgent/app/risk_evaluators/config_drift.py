"""
Risk evaluator — Configuration drift analysis.

Checks: missing diagnostics, Azure Policy violations, tag governance.
"""
from __future__ import annotations

from app.risk_evaluators.finding import risk_finding as _risk_finding


def analyze_config_drift(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_diagnostic_coverage(evidence_index))
    findings.extend(_check_policy_noncompliance(evidence_index))
    findings.extend(_check_tag_governance(evidence_index))
    return findings


def _check_diagnostic_coverage(evidence_index: dict) -> list[dict]:
    diags = evidence_index.get("azure-diagnostic-setting", [])
    resources = evidence_index.get("azure-resource", [])

    diaggable_types = {
        "microsoft.compute/virtualmachines",
        "microsoft.network/networksecuritygroups",
        "microsoft.keyvault/vaults",
        "microsoft.sql/servers",
        "microsoft.web/sites",
        "microsoft.storage/storageaccounts",
        "microsoft.containerservice/managedclusters",
    }

    resources_with_diags: set[str] = set()
    for ev in diags:
        rid = ev.get("ResourceId", ev.get("resource_id", ""))
        if rid:
            parts = rid.split("/providers/microsoft.insights/diagnosticSettings/")
            if parts:
                resources_with_diags.add(parts[0].lower())

    missing: list[dict] = []
    for ev in resources:
        data = ev.get("Data", ev.get("data", {}))
        rtype = data.get("ResourceType", data.get("type", "")).lower()
        rid = ev.get("ResourceId", ev.get("resource_id", "")).lower()
        if rtype in diaggable_types and rid not in resources_with_diags:
            missing.append({
                "Type": rtype,
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })

    if missing:
        return [_risk_finding(
            category="config",
            subcategory="missing_diagnostics",
            title=f"{len(missing)} resources without diagnostic settings",
            description="Resources without diagnostics lack audit trails, making incident investigation difficult.",
            severity="medium",
            affected_resources=missing[:50],
            remediation={
                "Description": "Enable diagnostic settings for all critical resources.",
                "AzureCLI": (
                    "az monitor diagnostic-settings create -n 'diag-audit' "
                    "--resource <resource-id> --workspace <la-workspace-id> "
                    "--logs '[{\"category\":\"AuditEvent\",\"enabled\":true}]'"
                ),
            },
        )]
    return []


def _check_policy_noncompliance(evidence_index: dict) -> list[dict]:
    policy_states = evidence_index.get("azure-policy-compliance", [])
    noncompliant: list[dict] = []

    for ev in policy_states:
        data = ev.get("Data", ev.get("data", {}))
        state = data.get("ComplianceState", data.get("compliance_state", ""))
        if state.lower() == "noncompliant":
            noncompliant.append({
                "Type": "PolicyViolation",
                "PolicyName": data.get("PolicyDefinitionName", data.get("policy_name", "Unknown")),
                "ResourceId": data.get("ResourceId", ev.get("ResourceId", "")),
                "ResourceType": data.get("ResourceType", data.get("resource_type", "")),
            })

    if noncompliant:
        return [_risk_finding(
            category="config",
            subcategory="policy_noncompliance",
            title=f"{len(noncompliant)} Azure Policy violations detected",
            description="Non-compliant resources indicate configuration drift from organizational standards.",
            severity="medium" if len(noncompliant) < 20 else "high",
            affected_resources=noncompliant[:50],
            remediation={
                "Description": "Review non-compliant resources and remediate or create exemptions.",
                "AzureCLI": "az policy state trigger-scan --resource-group <rg>",
                "PortalSteps": [
                    "Navigate to Azure Policy > Compliance",
                    "Filter by non-compliant, review and remediate each violation",
                ],
            },
        )]
    return []


def _check_tag_governance(evidence_index: dict) -> list[dict]:
    resources = evidence_index.get("azure-resource", [])
    skip_types = {"microsoft.resources/resourcegroups",
                  "microsoft.managedidentity/userassignedidentities"}
    untagged: list[dict] = []

    for ev in resources:
        data = ev.get("Data", ev.get("data", {}))
        tags = data.get("Tags", data.get("tags")) or {}
        rtype = data.get("ResourceType", data.get("type", "")).lower()
        if rtype in skip_types:
            continue
        if not tags:
            untagged.append({
                "Type": rtype,
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })

    if len(untagged) > 10:
        return [_risk_finding(
            category="config",
            subcategory="missing_tags",
            title=f"{len(untagged)} resources without tags",
            description="Untagged resources impede cost attribution, ownership tracking, and governance.",
            severity="low",
            affected_resources=untagged[:50],
            remediation={
                "Description": "Apply required tags (Environment, Owner, CostCenter) to all resources.",
                "AzureCLI": "az tag create --resource-id <id> --tags Environment=Production Owner=team@co.com",
                "PowerShell": "Update-AzTag -ResourceId <id> -Tag @{Environment='Production'} -Operation Merge",
            },
        )]
    return []
