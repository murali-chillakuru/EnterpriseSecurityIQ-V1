"""
Data Security — M365 Data Lifecycle evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_m365_data_lifecycle(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess M365 data lifecycle management: retention policies, eDiscovery, holds."""
    findings: list[dict] = []
    findings.extend(_check_retention_labels_exist(evidence_index))
    findings.extend(_check_ediscovery_readiness(evidence_index))
    findings.extend(_check_data_minimization(evidence_index))
    return findings


def _check_data_minimization(idx: dict) -> list[dict]:
    """Flag if no retention policies enforce deletion (data minimization)."""
    labels = idx.get("m365-retention-label", [])
    if not labels:
        return []
    has_delete = False
    for ev in labels:
        data = ev.get("Data", ev.get("data", {}))
        action = data.get("ActionAfterRetentionPeriod",
                 data.get("retentionAction", "")).lower()
        if action in ("delete", "deleteandlabel"):
            has_delete = True
            break
    if not has_delete:
        return [_ds_finding(
            "data_lifecycle", "no_data_minimization",
            "No retention labels enforce automatic deletion (data minimization)",
            "Data minimization is a core principle of GDPR and Zero Trust. Without "
            "retention labels that automatically delete data after the retention "
            "period, stale data accumulates and increases the blast radius of breaches.",
            "low", [],
            {"Description": "Create retention labels with deletion action.",
             "PortalSteps": [
                 "compliance.microsoft.com > Data lifecycle management > Labels",
                 "Create labels with 'Delete items automatically' after retention",
                 "Publish to Exchange, SharePoint, OneDrive locations",
             ]},
        )]
    return []


def _check_retention_labels_exist(idx: dict) -> list[dict]:
    """Flag if no retention labels are configured."""
    retention_labels = idx.get("m365-retention-label", [])
    retention_summary = idx.get("m365-retention-summary", [])

    has_labels = bool(retention_labels)
    if not has_labels:
        for ev in retention_summary:
            data = ev.get("Data", ev.get("data", {}))
            if data.get("HasRetentionLabels"):
                has_labels = True
                break

    # Only flag if we have M365 evidence (collector ran) but no retention
    has_m365 = any(k.startswith("m365-") for k in idx)
    if has_m365 and not has_labels:
        return [_ds_finding(
            "data_lifecycle", "no_retention_labels",
            "No M365 retention labels configured",
            "Without retention labels, organizational data may be deleted prematurely "
            "or retained indefinitely, violating regulatory requirements. Retention "
            "policies are essential for GDPR, HIPAA, and SOX compliance.",
            "medium", [],
            {"Description": "Configure retention labels in Microsoft Purview.",
             "PortalSteps": [
                 "Go to compliance.microsoft.com > Data lifecycle management",
                 "Create retention labels with appropriate retention periods",
                 "Publish labels via label policies to Exchange, SharePoint, OneDrive",
                 "Consider auto-apply labels for known content types",
             ]},
        )]

    # Check for in-use labels
    in_use = [
        ev for ev in retention_labels
        if ev.get("Data", {}).get("IsInUse", False)
    ]
    if retention_labels and not in_use:
        return [_ds_finding(
            "data_lifecycle", "retention_labels_unused",
            f"{len(retention_labels)} retention labels defined but none are in use",
            "Retention labels exist but are not applied to any content, providing "
            "no actual data lifecycle protection.",
            "low",
            [{"Type": "RetentionLabel", "Name": ev.get("Data", {}).get("DisplayName", "")}
             for ev in retention_labels],
            {"Description": "Apply retention labels to content or publish via policies.",
             "PortalSteps": [
                 "compliance.microsoft.com > Data lifecycle management > Label policies",
                 "Create a label policy and publish labels to locations",
             ]},
        )]
    return []


def _check_ediscovery_readiness(idx: dict) -> list[dict]:
    """Assess eDiscovery readiness — check for active cases and coverage."""
    ediscovery_cases = idx.get("m365-ediscovery-case", [])
    ediscovery_summary = idx.get("m365-ediscovery-summary", [])

    has_cases = bool(ediscovery_cases)
    if not has_cases:
        for ev in ediscovery_summary:
            data = ev.get("Data", ev.get("data", {}))
            if data.get("HasCases"):
                has_cases = True
                break

    has_m365 = any(k.startswith("m365-") for k in idx)
    if has_m365 and not has_cases:
        return [_ds_finding(
            "data_lifecycle", "no_ediscovery_cases",
            "No eDiscovery cases configured",
            "Without eDiscovery cases, the organization cannot place legal holds "
            "on relevant data during litigation or investigations. This creates "
            "risk of evidence spoliation.",
            "low", [],
            {"Description": "Create eDiscovery cases as needed for legal hold and investigation.",
             "PortalSteps": [
                 "Go to compliance.microsoft.com > eDiscovery > Standard or Premium",
                 "Create a case when litigation or investigation requires data preservation",
                 "Add custodians and place holds on relevant mailboxes and sites",
             ]},
        )]
    return []


