"""DLP readiness evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


def analyze_dlp_readiness(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess DLP policy readiness for M365 Copilot interactions."""
    findings: list[dict] = []
    findings.extend(_check_dlp_policy_existence(evidence_index))
    findings.extend(_check_dlp_label_integration(evidence_index))
    findings.extend(_check_dlp_workload_coverage(evidence_index))
    findings.extend(_check_endpoint_dlp(evidence_index))
    return findings


def _check_dlp_policy_existence(idx: dict) -> list[dict]:
    """Check if any DLP policies exist."""
    dlp = idx.get("m365-dlp-policies", [])
    if not dlp:
        # Check alternative evidence types
        dlp_alt = idx.get("m365-dlp-label-integration", [])
        labels = idx.get("m365-label-summary", [])
        if not dlp_alt and not labels:
            return [_cr_finding(
                "dlp_readiness", "no_dlp_policies",
                "No DLP policies detected — Copilot interactions are unprotected",
                "Data Loss Prevention policies are critical to prevent Copilot from "
                "surfacing or generating content that violates data handling rules.",
                "high",
                [{"Type": "DLPConfig", "Name": "DLP Policies",
                  "ResourceId": "m365-dlp", "PolicyCount": 0}],
                {"Description": "Create DLP policies covering Teams, Exchange, and SharePoint.",
                 "PortalSteps": ["Go to Microsoft Purview compliance portal > Data loss prevention > Policies", "Click '+ Create policy'", "Select a template or create custom policy", "Set locations: Exchange, SharePoint, OneDrive, Teams", "Add conditions for sensitive information types", "Set actions: Block, notify, audit", "Test policy in simulation mode first"]},
                compliance_status="gap",
            )]
    return []


def _check_dlp_label_integration(idx: dict) -> list[dict]:
    """Check if DLP policies reference sensitivity labels."""
    integration = idx.get("m365-dlp-label-integration", [])
    for ev in integration:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasLabelBasedDLP"):
            return [_cr_finding(
                "dlp_readiness", "no_label_based_dlp",
                "No DLP policies reference sensitivity labels — label-aware protection missing",
                "DLP policies that reference sensitivity labels provide the strongest "
                "protection for Copilot interactions by ensuring labeled content is "
                "handled according to its classification.",
                "medium",
                [{"Type": "DLPConfig", "Name": "Label-based DLP",
                  "ResourceId": "m365-dlp-label-integration",
                  "HasLabelBasedDLP": False}],
                {"Description": "Add sensitivity label conditions to DLP policies.",
                 "PortalSteps": ["Go to Microsoft Purview compliance portal > Data loss prevention > Policies", "Edit existing DLP policy > Conditions", "Add condition: 'Content contains sensitivity label'", "Select labels that should trigger DLP actions", "Save and publish changes"]},
                compliance_status="gap",
            )]
    return []


def _check_dlp_workload_coverage(idx: dict) -> list[dict]:
    """Check DLP coverage across M365 workloads relevant to Copilot."""
    dlp = idx.get("m365-dlp-policies", [])
    if not dlp:
        return []

    covered_workloads: set[str] = set()
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        workloads = data.get("Workloads", [])
        if isinstance(workloads, list):
            covered_workloads.update(w.lower() for w in workloads)
        elif isinstance(workloads, str):
            covered_workloads.add(workloads.lower())

    required = {"exchange", "sharepoint", "onedriveforbusiness", "teams"}
    missing = required - covered_workloads
    if missing:
        return [_cr_finding(
            "dlp_readiness", "incomplete_workload_coverage",
            f"DLP policies missing coverage for: {', '.join(sorted(missing))}",
            "Copilot operates across Teams, Exchange, SharePoint, and OneDrive. "
            "DLP policies must cover all workloads to prevent data leakage.",
            "medium",
            [{"Type": "DLPCoverage", "Name": f"Missing: {w}", "ResourceId": "m365-dlp"}
             for w in sorted(missing)],
            {"Description": f"Extend DLP policies to cover: {', '.join(sorted(missing))}"},
            compliance_status="partial",
        )]
    return []


def _check_endpoint_dlp(idx: dict) -> list[dict]:
    """Check if Endpoint DLP is enabled for Copilot content protection."""
    dlp = idx.get("m365-dlp-policies", [])
    if not dlp:
        return []  # _check_dlp_policy_existence already flags missing DLP

    # Check if any DLP policy covers endpoint/device locations
    has_endpoint = False
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        workloads = data.get("Workloads", [])
        if isinstance(workloads, str):
            workloads = [workloads]
        for w in workloads:
            if "endpoint" in str(w).lower() or "device" in str(w).lower():
                has_endpoint = True
                break
        if has_endpoint:
            break

    if not has_endpoint:
        return [_cr_finding(
            "dlp_readiness", "no_endpoint_dlp",
            "No DLP policy covers endpoint/device locations — Copilot content can be copied unmonitored",
            "Endpoint DLP monitors and restricts sensitive content when copied to local "
            "devices. Without it, Copilot-generated summaries containing sensitive data "
            "can be saved locally without DLP enforcement.",
            "medium",
            [{"Type": "DLPCoverage", "Name": "Endpoint DLP",
              "ResourceId": "m365-dlp-endpoint",
              "HasEndpointDLP": False}],
            {"Description": "Enable Endpoint DLP for devices accessing Copilot.",
             "PortalSteps": [
                 "Go to Microsoft Purview compliance portal > Data loss prevention > Policies",
                 "Create or edit a DLP policy",
                 "Under 'Locations', enable 'Devices'",
                 "Ensure Windows/macOS devices are onboarded to Microsoft Purview",
                 "Configure policy rules for sensitive content types",
             ]},
            compliance_status="gap",
        )]
    return []

