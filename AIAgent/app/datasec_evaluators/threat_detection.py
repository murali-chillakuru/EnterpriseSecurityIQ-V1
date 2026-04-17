"""
Data Security — Threat Detection & Incident Response evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_threat_detection(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess threat detection and incident response posture for data services."""
    findings: list[dict] = []
    findings.extend(_check_defender_coverage_gaps(evidence_index))
    findings.extend(_check_security_alert_action_groups(evidence_index))
    findings.extend(_check_audit_log_retention(evidence_index))
    findings.extend(_check_immutable_audit_logs(evidence_index))
    return findings


def _check_immutable_audit_logs(idx: dict) -> list[dict]:
    """Flag Log Analytics workspaces without immutability configured."""
    workspaces = idx.get("azure-log-analytics", [])
    no_immut: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        features = props.get("features", {})
        immutable = False
        if isinstance(features, dict):
            immutable = features.get("immutableAuditLog", False) or \
                        features.get("immutableIngestion", False) or \
                        features.get("enableLogAccessUsingOnlyResourcePermissions", False)
        if not immutable:
            no_immut.append({
                "Type": "LogAnalyticsWorkspace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_immut:
        return [_ds_finding(
            "threat_detection", "no_immutable_audit_logs",
            f"{len(no_immut)} Log Analytics workspaces without immutable audit logs",
            "Without immutable ingestion, an attacker with workspace access could "
            "tamper with or delete security logs to cover their tracks. Immutable "
            "logs ensure audit trail integrity for forensic investigations.",
            "medium", no_immut,
            {"Description": "Enable immutable log ingestion on Log Analytics workspaces.",
             "PortalSteps": [
                 "Azure Portal > Log Analytics workspace > Properties",
                 "Enable 'Immutable Audit' under workspace features",
             ]},
        )]
    return []


def _check_defender_coverage_gaps(idx: dict) -> list[dict]:
    """Flag data-relevant Defender plans that are not enabled."""
    plans = idx.get("azure-defender-plans", [])
    # Build a map of which plans are enabled per subscription
    plan_map: dict[str, dict[str, str]] = {}  # sub_id -> {plan_name: tier}
    for ev in plans:
        data = ev.get("Data", ev.get("data", {}))
        sub_id = data.get("subscriptionId", "")
        name = data.get("name", "").lower()
        tier = data.get("pricingTier", "Free")
        if sub_id:
            plan_map.setdefault(sub_id, {})[name] = tier
    required_plans = {"storageaccounts", "sqlservers", "keyvaults",
                      "opensourcerelationaldatabases", "cosmosdb"}
    gaps: list[dict] = []
    for sub_id, sub_plans in plan_map.items():
        for plan_name in required_plans:
            tier = sub_plans.get(plan_name, "NotConfigured")
            if tier.lower() in ("free", "notconfigured"):
                gaps.append({
                    "Type": "DefenderPlan",
                    "Name": f"{plan_name} ({sub_id[:8]}…)",
                    "ResourceId": f"/subscriptions/{sub_id}",
                    "PricingTier": tier,
                })
    if gaps:
        return [_ds_finding(
            "threat_detection", "defender_coverage_gaps",
            f"{len(gaps)} Defender for Cloud plans not enabled for data services",
            "Microsoft Defender plans for Storage, SQL, Key Vault, Cosmos DB, and OSS databases "
            "provide threat detection, anomaly alerting, and vulnerability assessments. "
            "Gaps in coverage leave data services unmonitored.",
            "high", gaps,
            {"Description": "Enable all data-relevant Defender plans.",
             "AzureCLI": "az security pricing create -n <PlanName> --tier Standard"},
        )]
    return []


def _check_security_alert_action_groups(idx: dict) -> list[dict]:
    """Flag if no action groups are configured for security alert routing."""
    action_groups = idx.get("azure-action-groups", [])
    defender_plans = idx.get("azure-defender-plans", [])
    if not defender_plans:
        return []
    if not action_groups:
        return [_ds_finding(
            "threat_detection", "no_security_action_groups",
            "No Azure Monitor action groups configured for security alerts",
            "Without action groups, security alerts from Defender for Cloud are only visible "
            "in the portal. Configure email, SMS, webhook, or Logic App notifications "
            "for timely incident response.",
            "medium", [],
            {"Description": "Create action groups for security alert routing.",
             "AzureCLI": (
                 "az monitor action-group create -g <rg> -n SecurityAlerts "
                 "--action email SecurityTeam security@company.com"
             )},
        )]
    return []


def _check_audit_log_retention(idx: dict) -> list[dict]:
    """Flag diagnostic settings with retention shorter than 90 days."""
    diag_settings = idx.get("azure-diagnostic-settings", [])
    short_retention: list[dict] = []
    for ev in diag_settings:
        data = ev.get("Data", ev.get("data", {}))
        resource_id = data.get("resourceId", ev.get("ResourceId", ""))
        logs = data.get("logs", data.get("Logs", []))
        for log_cfg in logs:
            retention = log_cfg.get("retentionPolicy", log_cfg.get("RetentionPolicy", {}))
            if not retention:
                continue
            enabled = retention.get("enabled", retention.get("Enabled", False))
            days = retention.get("days", retention.get("Days", 0))
            if enabled and isinstance(days, (int, float)) and days < 90:
                short_retention.append({
                    "Type": "DiagnosticSetting",
                    "ResourceId": resource_id,
                    "Category": log_cfg.get("category", log_cfg.get("Category", "Unknown")),
                    "RetentionDays": days,
                })
    if short_retention:
        return [_ds_finding(
            "threat_detection", "audit_log_short_retention",
            f"{len(short_retention)} diagnostic log categories with retention < 90 days",
            "Regulatory frameworks (PCI DSS, HIPAA, SOC 2) typically require at least "
            "90 days of audit log retention. Short retention windows may result in "
            "evidence gaps during investigations.",
            "medium", short_retention,
            {"Description": "Increase log retention to at least 90 days.",
             "AzureCLI": (
                 "az monitor diagnostic-settings update -n <setting-name> "
                 "--resource <resource-id> "
                 "--logs '[{\"category\":\"<category>\",\"enabled\":true,"
                 "\"retentionPolicy\":{\"enabled\":true,\"days\":90}}]'"
             )},
        )]
    return []


