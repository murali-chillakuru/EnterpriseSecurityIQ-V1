"""
Data Security — M365 DLP Policies evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_m365_dlp(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Microsoft 365 DLP policy coverage for data loss prevention.
    Requires Microsoft Graph evidence (collected via enrichment when Graph
    credentials are available).
    """
    findings: list[dict] = []
    findings.extend(_check_dlp_policy_exists(evidence_index))
    findings.extend(_check_dlp_policy_disabled(evidence_index))
    findings.extend(_check_dlp_coverage_gaps(evidence_index))
    findings.extend(_check_dlp_notify_only_actions(evidence_index))
    findings.extend(_check_dlp_sensitive_info_types(evidence_index))
    findings.extend(_check_dlp_rule_effectiveness(evidence_index))
    return findings


def _check_dlp_policy_exists(idx: dict) -> list[dict]:
    """Flag if no DLP policies are defined."""
    dlp = idx.get("m365-dlp-policies", [])
    # Only flag if we have data services (implicit need for DLP) but no policies
    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
    )
    if data_services and not dlp:
        return [_ds_finding(
            "m365_dlp", "no_dlp_policies",
            "No Microsoft 365 DLP policies found",
            "Without Data Loss Prevention policies, sensitive data (PII, PCI, PHI) "
            "can be shared externally without detection or blocking.",
            "medium", [],
            {"Description": "Create DLP policies in Microsoft Purview compliance portal.",
             "PortalSteps": [
                 "Go to compliance.microsoft.com > Data loss prevention > Policies",
                 "Create a policy targeting sensitive information types (SSN, credit card, etc.)",
                 "Apply to Exchange, SharePoint, OneDrive, and Teams",
                 "Set to 'Test with notifications' first, then enforce",
             ]},
        )]
    return []


def _check_dlp_policy_disabled(idx: dict) -> list[dict]:
    """Flag DLP policies that are defined but not enabled."""
    dlp = idx.get("m365-dlp-policies", [])
    disabled: list[dict] = []
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        state = data.get("state", data.get("State", "")).lower()
        if state in ("disabled", "testwithounotifications"):
            disabled.append({
                "Type": "DLPPolicy",
                "Name": data.get("name", data.get("Name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "State": state,
            })
    if disabled:
        return [_ds_finding(
            "m365_dlp", "dlp_policy_disabled",
            f"{len(disabled)} DLP policies are disabled or in test-only mode",
            "Disabled DLP policies provide no protection against sensitive data leakage.",
            "high", disabled,
            {"Description": "Enable DLP policies to actively detect and block sensitive data sharing.",
             "PortalSteps": [
                 "compliance.microsoft.com > Data loss prevention > Policies",
                 "Edit the policy > Turn on the policy",
             ]},
        )]
    return []


def _check_dlp_coverage_gaps(idx: dict) -> list[dict]:
    """Flag gaps in DLP workload coverage (Exchange, SPO, OneDrive, Teams)."""
    dlp = idx.get("m365-dlp-policies", [])
    if not dlp:
        return []
    all_workloads = {"exchange", "sharepoint", "onedrive", "teams", "devices"}
    covered = set()
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        locations = data.get("locations", data.get("Locations", []))
        if isinstance(locations, list):
            for loc in locations:
                loc_name = (loc.get("workload", loc.get("Workload", ""))
                            if isinstance(loc, dict) else str(loc)).lower()
                covered.add(loc_name)
    gaps = all_workloads - covered
    if gaps:
        gap_list = [{"Type": "DLPWorkloadGap", "Name": w.title(), "ResourceId": "N/A"} for w in sorted(gaps)]
        return [_ds_finding(
            "m365_dlp", "dlp_coverage_gap",
            f"DLP policies do not cover {len(gaps)} workload(s): {', '.join(sorted(gaps))}",
            "Gaps in DLP workload coverage allow sensitive data to leak through unmonitored channels.",
            "medium", gap_list,
            {"Description": f"Extend DLP policies to cover: {', '.join(sorted(gaps))}.",
             "PortalSteps": [
                 "compliance.microsoft.com > Data loss prevention > Policies",
                 "Edit existing policies to include missing workloads",
             ]},
        )]
    return []


def _check_dlp_notify_only_actions(idx: dict) -> list[dict]:
    """Flag DLP policies with notify-only actions (not blocking)."""
    dlp = idx.get("m365-dlp-policies", [])
    notify_only: list[dict] = []
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        state = data.get("state", data.get("State", "")).lower()
        if state == "disabled":
            continue
        mode = data.get("mode", data.get("Mode", "")).lower()
        actions = data.get("actions", data.get("Actions", []))
        has_block = False
        if isinstance(actions, list):
            for action in actions:
                act_type = action.get("type", "").lower() if isinstance(action, dict) else str(action).lower()
                if "block" in act_type or "restrict" in act_type:
                    has_block = True
                    break
        if mode in ("testwithnotifications", "auditonly") or (not has_block and state == "enabled"):
            notify_only.append({
                "Type": "DLPPolicy",
                "Name": data.get("name", data.get("Name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Mode": mode or state,
            })
    if notify_only:
        return [_ds_finding(
            "m365_dlp", "dlp_notify_only",
            f"{len(notify_only)} DLP policies with notify-only actions (no blocking)",
            "DLP policies that only notify without blocking allow sensitive data to be "
            "shared externally despite detection. Escalate to block actions for high-risk rules.",
            "medium", notify_only,
            {"Description": "Add blocking actions to DLP policies for sensitive data.",
             "PortalSteps": [
                 "compliance.microsoft.com > Data loss prevention > Policies",
                 "Edit policy > Customize advanced DLP rules > Add 'Block' action",
             ]},
        )]
    return []


def _check_dlp_sensitive_info_types(idx: dict) -> list[dict]:
    """Flag DLP policies that lack coverage for common sensitive information types."""
    dlp = idx.get("m365-dlp-policies", [])
    if not dlp:
        return []
    # Essential SIT categories
    essential_sits = {"credit card", "ssn", "social security", "passport", "bank account",
                      "iban", "driver's license", "health", "medical", "pii"}
    policies_missing_sits: list[dict] = []
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        state = data.get("state", data.get("State", "")).lower()
        if state == "disabled":
            continue
        sit_names = data.get("sensitiveInfoTypes", data.get("SensitiveInfoTypes", []))
        covered_lower = set()
        if isinstance(sit_names, list):
            for sit in sit_names:
                sit_name = sit.get("name", sit) if isinstance(sit, dict) else str(sit)
                covered_lower.add(sit_name.lower())
        if not covered_lower:
            policies_missing_sits.append({
                "Type": "DLPPolicy",
                "Name": data.get("name", data.get("Name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Issue": "No sensitive information types configured",
            })
    if policies_missing_sits:
        return [_ds_finding(
            "m365_dlp", "dlp_no_sensitive_info_types",
            f"{len(policies_missing_sits)} DLP policies without sensitive information types",
            "DLP policies without configured sensitive information types (PII, PCI, PHI) "
            "cannot detect or protect specific categories of sensitive data.",
            "high", policies_missing_sits,
            {"Description": "Add sensitive information types (credit card, SSN, etc.) to DLP policies.",
             "PortalSteps": [
                 "compliance.microsoft.com > Data loss prevention > Policies",
                 "Edit policy > Choose information to protect > Add sensitive info types",
                 "Include at minimum: Credit Card, SSN, Passport, Health/Medical records",
             ]},
        )]
    return []


def _check_dlp_rule_effectiveness(idx: dict) -> list[dict]:
    """Flag DLP policies without rule conditions or with overly broad rules."""
    dlp = idx.get("m365-dlp-policies", [])
    if not dlp:
        return []
    weak_rules: list[dict] = []
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        state = data.get("state", data.get("State", "")).lower()
        if state == "disabled":
            continue
        rules = data.get("rules", data.get("Rules", []))
        if not rules or not isinstance(rules, list):
            weak_rules.append({
                "Type": "DLPPolicy",
                "Name": data.get("name", data.get("Name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Issue": "No rules defined",
            })
            continue
        for rule in rules:
            conditions = rule.get("conditions", rule.get("Conditions", []))
            if not conditions:
                weak_rules.append({
                    "Type": "DLPPolicyRule",
                    "Name": f"{data.get('name', 'Unknown')} / {rule.get('name', 'Unnamed rule')}",
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "Issue": "Rule has no conditions — matches all content",
                })
    if weak_rules:
        return [_ds_finding(
            "m365_dlp", "dlp_weak_rules",
            f"{len(weak_rules)} DLP policy rules with missing or empty conditions",
            "DLP rules without conditions match all content indiscriminately, "
            "causing excessive false positives or providing no meaningful protection.",
            "medium", weak_rules,
            {"Description": "Define specific conditions (SIT types, document properties) for each DLP rule.",
             "PortalSteps": [
                 "compliance.microsoft.com > Data loss prevention > Policies",
                 "Edit policy > Customize advanced DLP rules",
                 "Add conditions targeting specific sensitive information types",
             ]},
        )]
    return []


