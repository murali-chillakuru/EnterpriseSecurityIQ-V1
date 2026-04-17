"""
Incident Response Domain Evaluator
Controls: IR-4, IR-5, IR-6, IR-8 (NIST), PCI 12.10, HIPAA 164.308(a)(6).
Evaluates security contact config, incident detection capability,
alerting infrastructure, and investigation readiness.
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_incident_response(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_security_contact_config": _check_security_contact_config,
        "check_incident_detection": _check_incident_detection,
        "check_incident_alerting": _check_incident_alerting,
        "check_incident_investigation_readiness": _check_investigation_readiness,
        "check_sentinel_monitoring": _check_sentinel_monitoring,
        "check_alert_response_coverage": _check_alert_response_coverage,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", ""),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="incident_response", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[{"ResourceId": resource_id, "ResourceName": resource_name,
                              "ResourceType": resource_type}] if resource_name else (evidence_items or []),
    ).to_dict()


def _check_security_contact_config(cid, ctrl, evidence, idx, thresholds=None):
    """Verify security contacts are configured with email and alert notifications."""
    findings = []
    contacts = idx.get("azure-security-contact", [])

    if not contacts:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No security contacts configured for incident notification.",
                   recommendation="Configure security contacts in Microsoft Defender for Cloud with email and phone.")]

    alert_contacts = [c for c in contacts
                      if c.get("Data", {}).get("AlertNotifications") == "On"]
    email_contacts = [c for c in contacts
                      if c.get("Data", {}).get("Email")]

    if not alert_contacts:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "Security contacts exist but alert notifications are not enabled.",
                          recommendation="Enable alert notifications on security contacts for timely incident response."))
    if not email_contacts:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "Security contacts have no email addresses configured.",
                          recommendation="Add email addresses to security contacts for breach notification."))

    admin_notify = [c for c in contacts
                    if c.get("Data", {}).get("NotifyAdmins") == "On"
                    or c.get("Data", {}).get("AlertsToAdmins") == "On"]

    if alert_contacts and email_contacts:
        msg = f"{len(contacts)} security contact(s) configured with alerts enabled."
        if admin_notify:
            msg += f" Admin notification enabled on {len(admin_notify)}."
        findings.append(_f(cid, ctrl, Status.COMPLIANT, msg))

    return findings


def _check_incident_detection(cid, ctrl, evidence, idx, thresholds=None):
    """Verify Defender plans and alert rules provide incident detection capability."""
    findings = []
    defender = idx.get("azure-defender-pricing", [])
    alert_rules = idx.get("azure-alert-rule", [])
    risk_summary = idx.get("entra-risk-summary", [])

    enabled_plans = [d for d in defender
                     if d.get("Data", {}).get("PricingTier") == "Standard"]
    critical_plans = {"VirtualMachines", "SqlServers", "AppServices",
                      "StorageAccounts", "KeyVaults", "Arm", "Containers"}
    enabled_names = {d.get("Data", {}).get("PlanName") for d in enabled_plans}
    missing_critical = critical_plans - enabled_names

    if not enabled_plans:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Defender for Cloud plans enabled — no automated threat detection.",
                          recommendation="Enable Microsoft Defender for Cloud on all critical resource types."))
    elif missing_critical:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Missing Defender plans for incident detection: {', '.join(sorted(missing_critical))}.",
                          recommendation="Enable Defender for all critical resource types to ensure comprehensive threat detection."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(critical_plans)} critical Defender plans enabled for threat detection."))

    if not alert_rules:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Azure Monitor alert rules configured for incident detection.",
                          recommendation="Configure alert rules for critical security events and resource health."))
    else:
        enabled_alerts = [r for r in alert_rules
                          if r.get("Data", {}).get("Enabled") is not False]
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(enabled_alerts)} alert rules configured for incident detection."))

    # Identity risk signals
    if risk_summary:
        for rs in risk_summary:
            d = rs.get("Data", {})
            high = d.get("HighRiskUsers", 0) + d.get("HighRiskDetections", 0)
            if high > 0:
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"Active high-risk identity signals detected ({high} high-risk items).",
                                  recommendation="Investigate and remediate high-risk identity detections immediately."))

    return findings


def _check_incident_alerting(cid, ctrl, evidence, idx, thresholds=None):
    """Verify action groups and alert routing for incident notification."""
    findings = []
    action_groups = idx.get("azure-action-group", [])
    alert_rules = idx.get("azure-alert-rule", [])
    contacts = idx.get("azure-security-contact", [])

    if not action_groups:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No action groups configured for incident alerting.",
                          recommendation="Create action groups with email/SMS/webhook receivers for incident notification."))
    else:
        # Check action groups have receivers
        groups_with_receivers = 0
        for ag in action_groups:
            d = ag.get("Data", {})
            has_email = d.get("EmailReceivers") or d.get("HasEmailReceivers")
            has_sms = d.get("SmsReceivers") or d.get("HasSmsReceivers")
            has_webhook = d.get("WebhookReceivers") or d.get("HasWebhookReceivers")
            if has_email or has_sms or has_webhook:
                groups_with_receivers += 1

        if groups_with_receivers == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(action_groups)} action group(s) exist but none have configured receivers.",
                              recommendation="Add email, SMS, or webhook receivers to action groups."))
        else:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"{groups_with_receivers}/{len(action_groups)} action groups have notification receivers."))

    # Verify alert rules are linked to action groups
    if alert_rules and action_groups:
        rules_with_actions = [r for r in alert_rules
                              if r.get("Data", {}).get("ActionGroups")
                              or r.get("Data", {}).get("Actions")]
        if not rules_with_actions:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              "Alert rules exist but none are linked to action groups.",
                              recommendation="Link alert rules to action groups for automated incident notification."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "Incident alerting infrastructure configured with action groups and rules."))
    return findings


def _check_investigation_readiness(cid, ctrl, evidence, idx, thresholds=None):
    """Verify logging and analytics infrastructure supports incident investigation."""
    findings = []
    diag = idx.get("azure-diagnostic-setting", [])
    log_analytics = idx.get("azure-log-analytics", [])
    activity_logs = idx.get("azure-activity-log", [])

    # Log Analytics workspace for centralized investigation
    if not log_analytics:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Log Analytics workspaces for centralized incident investigation.",
                          recommendation="Deploy a Log Analytics workspace and route all diagnostic/activity logs to it."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(log_analytics)} Log Analytics workspace(s) available for investigation."))

    # Diagnostic settings coverage
    if not diag:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No diagnostic settings — incident investigation will lack resource-level logs.",
                          recommendation="Enable diagnostic settings on all resources to support forensic investigation."))
    else:
        has_diag = sum(1 for d in diag if d.get("Data", {}).get("HasDiagnostics"))
        total = len(diag)
        pct = (has_diag / total) * 100 if total else 0
        if pct < 80:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Diagnostic coverage {pct:.0f}% — insufficient for comprehensive incident investigation.",
                              recommendation="Increase diagnostic settings coverage to ≥80% for forensic readiness."))
        else:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"Diagnostic coverage {pct:.0f}% supports incident investigation."))

    # Activity log availability
    if activity_logs:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Activity logs available ({len(activity_logs)} entries) for change forensics."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "Insufficient logging infrastructure for incident investigation."))
    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for incident response control ({len(evidence)} items).")]


# ---------------------------------------------------------------------------
# Sentinel monitoring
# ---------------------------------------------------------------------------
def _check_sentinel_monitoring(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    workspaces = idx.get("azure-sentinel-workspace", [])
    connectors = idx.get("azure-sentinel-connector", [])
    rules = idx.get("azure-sentinel-rule", [])
    automation = idx.get("azure-sentinel-automation", [])

    if not workspaces:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No Sentinel-enabled workspaces found.",
                   recommendation="Enable Microsoft Sentinel on a Log Analytics workspace.")]

    for item in workspaces:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        conn_count = d.get("ConnectorCount", 0)
        rule_count = d.get("RuleCount", 0)
        if conn_count == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Sentinel workspace '{name}' has no data connectors.",
                              recommendation="Configure data connectors to ingest security data.",
                              resource_id=d.get("WorkspaceId", ""), resource_name=name,
                              resource_type="Microsoft.OperationalInsights/workspaces"))
        if rule_count == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Sentinel workspace '{name}' has no analytics rules.",
                              recommendation="Create analytics rules for threat detection.",
                              resource_id=d.get("WorkspaceId", ""), resource_name=name,
                              resource_type="Microsoft.OperationalInsights/workspaces"))

    if not automation:
        findings.append(_f(cid, ctrl, Status.INFO,
                          "No Sentinel automation rules configured for automated response.",
                          recommendation="Configure automation rules for incident response playbooks."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Sentinel monitoring configured: {len(workspaces)} workspace(s), "
                          f"{len(connectors)} connector(s), {len(rules)} rule(s)."))
    return findings


# ---------------------------------------------------------------------------
# Alert response coverage (Defender alerts + Sentinel incidents)
# ---------------------------------------------------------------------------
def _check_alert_response_coverage(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    alerts = idx.get("azure-security-alert", [])
    incidents = idx.get("azure-sentinel-incident", [])
    action_groups = idx.get("azure-action-group", [])

    high_sev_alerts = [a for a in alerts if a.get("Data", {}).get("Severity", "").lower() in ("high", "critical")]
    if high_sev_alerts and not action_groups:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(high_sev_alerts)} high/critical security alerts but no action groups for notification.",
                          recommendation="Configure action groups for high-severity alert notifications."))

    open_incidents = [i for i in incidents if i.get("Data", {}).get("Status", "").lower() in ("new", "active")]
    if len(open_incidents) > 50:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(open_incidents)} open Sentinel incidents may indicate alert fatigue.",
                          recommendation="Review and triage open incidents. Consider tuning analytics rules."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Alert response coverage adequate: {len(alerts)} alerts, {len(incidents)} incidents."))
    return findings
