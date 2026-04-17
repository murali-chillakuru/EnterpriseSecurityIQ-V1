"""Audit and monitoring evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .copilot_security import _check_defender_copilot_incidents
from .finding import _cr_finding


def analyze_audit_monitoring(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess audit and monitoring readiness for M365 Copilot."""
    findings: list[dict] = []
    findings.extend(_check_audit_logging(evidence_index))
    findings.extend(_check_copilot_interaction_logging(evidence_index))
    findings.extend(_check_alert_policies(evidence_index))
    findings.extend(_check_defender_cloud_apps(evidence_index))
    # Phase 3/4 enhancements
    findings.extend(_check_copilot_usage_analytics(evidence_index))
    findings.extend(_check_copilot_audit_log_analysis(evidence_index))
    findings.extend(_check_prompt_patterns(evidence_index))
    # Phase 6: Checklist gap closure
    findings.extend(_check_defender_copilot_incidents(evidence_index))
    return findings


def _check_audit_logging(idx: dict) -> list[dict]:
    """Check if unified audit logging is enabled."""
    audit = idx.get("m365-audit-config", [])
    if not audit:
        return [_cr_finding(
            "audit_monitoring", "audit_logging_unknown",
            "Unified audit logging status could not be verified",
            "Unified audit logging must be enabled to track M365 Copilot interactions, "
            "including what content Copilot accessed and generated.",
            "high",
            [{"Type": "AuditConfig", "Name": "Unified Audit Log",
              "ResourceId": "m365-audit-config"}],
            {"Description": "Enable unified audit logging in Microsoft Purview.",
             "PowerShell": "Set-OrganizationConfig -AuditDisabled $false",
             "PortalSteps": ["Go to Microsoft Purview compliance portal > Audit", "If prompted, click 'Start recording user and admin activity'", "Verify status shows 'On'", "Configure audit log retention policies"],
             "Notes": "The legacy Set-AdminAuditLogConfig cmdlet is deprecated. Use Set-OrganizationConfig -AuditDisabled $false (Exchange Online PowerShell) instead."},
            compliance_status="gap",
        )]
    return []


def _check_copilot_interaction_logging(idx: dict) -> list[dict]:
    """Check readiness for Copilot interaction auditing."""
    # Only emit this finding if unified audit logging IS available
    # (i.e. we have audit config evidence) so the recommendation is actionable.
    audit = idx.get("m365-audit-config", [])
    if not audit:
        return []  # _check_audit_logging already flags the missing audit config
    return [_cr_finding(
        "audit_monitoring", "copilot_interaction_audit",
        "Verify Copilot interaction events are captured in audit log",
        "M365 Copilot generates audit events for interactions (CopilotInteraction). "
        "Verify these events are being captured and that alert policies exist for "
        "sensitive content access via Copilot.",
        "informational",
        [{"Type": "AuditConfig", "Name": "Copilot Audit Events",
          "ResourceId": "m365-copilot-audit"}],
        {"Description": "Search audit log for 'CopilotInteraction' events. "
         "Create alert policies for sensitive content access.",
         "PortalSteps": ["Go to Microsoft Purview compliance portal > Audit > Search", "Search for activity type 'CopilotInteraction'", "Go to Alert policies > Create alert policy", "Set condition: Activity is 'CopilotInteraction' with sensitive labels"]},
        compliance_status="partial",
    )]


def _check_alert_policies(idx: dict) -> list[dict]:
    """Check if alert policies are configured for Copilot activity monitoring."""
    alerts = idx.get("m365-alert-policies", [])
    if not alerts:
        return [_cr_finding(
            "audit_monitoring", "no_alert_policies",
            "No alert policies detected for sensitive content and Copilot activity",
            "Alert policies proactively notify administrators when sensitive content "
            "is accessed or when anomalous activity occurs. Without alert policies, "
            "Copilot-related security events may go unnoticed.",
            "medium",
            [{"Type": "AlertPolicy", "Name": "Alert Policies",
              "ResourceId": "m365-alert-policies"}],
            {"Description": "Create alert policies for Copilot and sensitive content activity.",
             "PortalSteps": [
                 "Go to Microsoft Purview compliance portal > Alert policies",
                 "Click '+ New alert policy'",
                 "Set conditions for: sensitive label access, DLP policy matches, Copilot interactions",
                 "Configure notification recipients (security team)",
                 "Set severity and throttling thresholds",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_defender_cloud_apps(idx: dict) -> list[dict]:
    """Check if Microsoft Defender for Cloud Apps is available for session monitoring."""
    skus = idx.get("m365-subscribed-skus", [])
    if not skus:
        return []  # SKU evidence not collected — skip

    mcas_keywords = ("cloud_app_security", "defender_cloud_apps", "mcas",
                     "ems_e5", "emspremium")
    e5_keywords = ("m365_e5", "microsoft_365_e5", "spe_e5", "enterprisepremium")

    has_mcas = False
    for ev in skus:
        sku_name = (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
        if any(kw in sku_name for kw in mcas_keywords + e5_keywords):
            has_mcas = True
            break

    if not has_mcas:
        return [_cr_finding(
            "audit_monitoring", "no_defender_cloud_apps",
            "Microsoft Defender for Cloud Apps not detected — no real-time session monitoring for Copilot",
            "Defender for Cloud Apps (formerly MCAS) provides session-level monitoring and control "
            "that can detect risky data transfers, enforce DLP in real-time, and block anomalous "
            "Copilot interactions. Without it, session-level threats go unmonitored.",
            "medium",
            [{"Type": "License", "Name": "Defender for Cloud Apps",
              "ResourceId": "m365-mcas-license"}],
            {"Description": "Enable Defender for Cloud Apps for session monitoring.",
             "PortalSteps": [
                 "Verify your license includes Defender for Cloud Apps (M365 E5 or add-on)",
                 "Go to security.microsoft.com > Cloud Apps > Settings",
                 "Enable the Defender for Cloud Apps connector",
                 "Configure session policies for M365 Copilot app",
                 "Create anomaly detection policies for bulk data access",
             ]},
            compliance_status="gap",
        )]
    return []


# ── Phase 3/4: Audit & Monitoring Enhancements ─────────────────────

def _check_copilot_usage_analytics(idx: dict) -> list[dict]:
    """Check if Copilot usage analytics/reports are being consumed."""
    usage = idx.get("m365-copilot-usage-reports", [])
    skus = idx.get("m365-subscribed-skus", [])
    # Only flag if Copilot is licensed
    copilot_keywords = ("copilot", "microsoft_365_copilot", "microsoft365_copilot")
    has_copilot = any(
        any(kw in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
            for kw in copilot_keywords)
        for ev in skus
    )
    if not has_copilot:
        return []
    if not usage:
        return [_cr_finding(
            "audit_monitoring", "no_copilot_usage_analytics",
            "Copilot usage analytics not configured — adoption and risk patterns unknown",
            "M365 Copilot usage reports in the admin center provide visibility into "
            "adoption rates, active users, and interaction patterns. Without these "
            "reports, you cannot identify abnormal usage that may indicate data risk.",
            "low",
            [{"Type": "UsageReport", "Name": "Copilot Usage Analytics",
              "ResourceId": "m365-copilot-usage-reports"}],
            {"Description": "Enable and review Copilot usage reports.",
             "PortalSteps": [
                 "Go to Microsoft 365 admin center > Reports > Usage",
                 "Select 'Microsoft 365 Copilot' report",
                 "Review adoption metrics and active user counts",
                 "Monitor for unusual usage patterns (bulk queries, off-hours activity)",
                 "Export data for security team analysis",
             ]},
            compliance_status="partial",
        )]
    return []


def _check_copilot_audit_log_analysis(idx: dict) -> list[dict]:
    """Check if Copilot-specific audit events are being captured and analyzed."""
    audit = idx.get("m365-audit-config", [])
    copilot_audit = idx.get("m365-copilot-audit-events", [])
    if not audit:
        return []  # _check_audit_logging already flags missing audit config
    if not copilot_audit:
        return [_cr_finding(
            "audit_monitoring", "copilot_audit_events_not_analyzed",
            "Copilot audit events (CopilotInteraction) not actively monitored",
            "While the unified audit log may capture CopilotInteraction events, no active "
            "analysis or alerting was detected. Without proactive analysis, sensitive data "
            "access via Copilot goes undetected until a security incident occurs.",
            "medium",
            [{"Type": "AuditAnalysis", "Name": "Copilot Audit Analysis",
              "ResourceId": "m365-copilot-audit-analysis"}],
            {"Description": "Set up automated analysis for Copilot audit events.",
             "PortalSteps": [
                 "Go to Microsoft Purview > Audit > Search",
                 "Create a saved search for 'CopilotInteraction' activities",
                 "Set up automated exports via Power Automate or SIEM integration",
                 "Create alert rules for sensitive content access patterns",
                 "Review weekly summaries of Copilot interaction patterns",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_prompt_patterns(idx: dict) -> list[dict]:
    """Check for detection of high-risk prompt patterns in Copilot interactions."""
    prompt_monitoring = idx.get("m365-copilot-prompt-monitoring", [])
    # Only relevant if there are Copilot audit events
    copilot_audit = idx.get("m365-copilot-audit-events", [])
    audit = idx.get("m365-audit-config", [])
    if not audit:
        return []
    if not prompt_monitoring:
        return [_cr_finding(
            "audit_monitoring", "no_prompt_pattern_monitoring",
            "No prompt pattern monitoring configured for Copilot interactions",
            "High-risk prompt patterns (e.g., 'show me all passwords', "
            "'list confidential documents', 'export all customer data') should trigger "
            "alerts. Without prompt pattern monitoring, intentional data exfiltration "
            "via Copilot prompts goes undetected.",
            "low",
            [{"Type": "PromptMonitoring", "Name": "Prompt Pattern Analysis",
              "ResourceId": "m365-copilot-prompt-monitoring"}],
            {"Description": "Implement prompt pattern detection for Copilot usage.",
             "PortalSteps": [
                 "Integrate Copilot audit events with your SIEM (Sentinel, Splunk, etc.)",
                 "Create detection rules for high-risk keywords in Copilot prompts",
                 "Monitor for: 'confidential', 'secret', 'password', 'export all', 'bulk download'",
                 "Set up Communication Compliance policies for prompt content review",
                 "Configure insider risk indicators for Copilot prompt patterns",
             ]},
            compliance_status="partial",
        )]
    return []

