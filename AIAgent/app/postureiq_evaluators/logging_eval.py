"""
Logging Domain Evaluator
Controls: AU-2, AU-3, AU-6, AU-12, AU-6(1), AU-12(1).
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_logging(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_logging_enabled": _check_logging_enabled,
        "check_threat_detection": _check_threat_detection,
        "check_audit_review": _check_audit_review,
        "check_nsg_flow_logs": _check_nsg_flow_logs,
        "check_activity_log_audit_trail": _check_activity_log_trail,
        "check_activity_logs": _check_activity_log_trail,
        "check_diagnostic_settings": _check_logging_enabled,
        "check_monitoring_alerts": _check_monitoring_coverage,
        "check_activity_event_analysis": _check_activity_event_analysis,
        "check_signin_log_monitoring": _check_signin_monitoring,
        "check_directory_audit_logging": _check_directory_audit,
        "check_monitoring_coverage": _check_monitoring_coverage,
        "check_log_retention_analysis": _check_log_retention_analysis,
        "check_alert_response_coverage": _check_alert_response_coverage,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", "FedRAMP"),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="logging", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[{"ResourceId": resource_id, "ResourceName": resource_name,
                              "ResourceType": resource_type}] if resource_name else (evidence_items or []),
    ).to_dict()


def _res(item, rtype=""):
    """Extract resource context from an evidence item."""
    d = item.get("Data", {})
    ctx = item.get("Context", {})
    return dict(
        resource_id=d.get("ResourceId") or ctx.get("ResourceId") or item.get("ResourceId", ""),
        resource_name=d.get("Name") or d.get("DisplayName") or ctx.get("ResourceName", ""),
        resource_type=rtype or d.get("ResourceType") or ctx.get("ResourceType", ""),
    )


def _check_logging_enabled(cid, ctrl, evidence, idx, thresholds=None):
    diag = idx.get("azure-diagnostic-setting", [])
    if not diag:
        return [_f(cid, ctrl, Status.NON_COMPLIANT, "No diagnostic settings found.")]

    total = len(diag)
    has_diag = sum(1 for d in diag if d.get("Data", {}).get("HasDiagnostics"))
    pct = (has_diag / total) * 100 if total > 0 else 0

    if pct >= 80:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"Diagnostic coverage {pct:.0f}% (≥80% threshold).")]
    elif pct >= 50:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   f"Diagnostic coverage {pct:.0f}% (50-79%, below 80% target).")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT,
               f"Diagnostic coverage {pct:.0f}% (<50%, critical gap).")]


def _check_threat_detection(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    defender = idx.get("azure-defender-pricing", [])
    alerts = idx.get("azure-alert-rule", [])

    enabled_plans = [d for d in defender if d.get("Data", {}).get("PricingTier") == "Standard"]
    if not enabled_plans:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "No Defender plans enabled."))
    if not alerts:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "No alert rules configured."))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(enabled_plans)} Defender plans, {len(alerts)} alert rules."))
    return findings


def _check_audit_review(cid, ctrl, evidence, idx, thresholds=None):
    diag = idx.get("azure-diagnostic-setting", [])
    has_la = [d for d in diag if d.get("Data", {}).get("HasLogAnalytics")]
    if has_la:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"{len(has_la)} resources export to Log Analytics.")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT,
               "No resources configured to export to Log Analytics.")]


def _check_nsg_flow_logs(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    flow_logs = idx.get("azure-nsg-flow-log", [])

    if not flow_logs:
        return [_f(cid, ctrl, Status.NON_COMPLIANT, "No NSG flow logs configured.")]

    for fl in flow_logs:
        d = fl.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(fl, "Microsoft.Network/networkWatchers/flowLogs")
        if not d.get("Enabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Flow log '{name}' disabled.",
                              recommendation="Enable the NSG flow log for network traffic monitoring.", **r))
        retention = d.get("RetentionDays", 0)
        if retention < 90:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Flow log '{name}' retention ({retention}d) < 90 days.",
                              recommendation="Increase NSG flow log retention to at least 90 days.", **r))
        if not d.get("TrafficAnalyticsEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Flow log '{name}' traffic analytics disabled.",
                              recommendation="Enable Traffic Analytics on the NSG flow log for visibility.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "NSG flow logs properly configured."))
    return findings


def _check_activity_log_trail(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    activity = idx.get("azure-activity-log", [])

    for a in activity:
        d = a.get("Data", {})
        failed_ops = d.get("FailedOps", 0)
        if failed_ops > 50:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"High activity log failure rate ({failed_ops} failed ops)."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Activity log audit trail adequate."))
    return findings


def _check_signin_monitoring(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    signins = idx.get("entra-signin-summary", [])
    risks = idx.get("entra-risk-summary", [])

    for s in signins:
        d = s.get("Data", {})
        risk_count = d.get("RiskSignIns", 0)
        if risk_count > 10:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"High-risk sign-ins ({risk_count}) exceed threshold of 10."))

    for r in risks:
        d = r.get("Data", {})
        high = d.get("HighRiskDetections", 0)
        if high > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{high} high-risk detections found."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Sign-in monitoring adequate."))
    return findings


def _check_directory_audit(cid, ctrl, evidence, idx, thresholds=None):
    audit = idx.get("entra-directory-audit-summary", [])
    for a in audit:
        cats = a.get("Data", {}).get("CategoriesBreakdown", {})
        total = a.get("Data", {}).get("TotalSampled", 0)
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"Directory audit logging active ({total} events, {len(cats)} categories).")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT, "No directory audit data collected.")]


def _check_monitoring_coverage(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    la = idx.get("azure-log-analytics", [])
    alerts = idx.get("azure-alert-rule", [])
    ag = idx.get("azure-action-group", [])

    for workspace in la:
        d = workspace.get("Data", {})
        r = _res(workspace, "Microsoft.OperationalInsights/workspaces")
        ret = d.get("RetentionInDays", 0)
        if ret < 90:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Log Analytics retention ({ret}d) < 90 days.",
                              recommendation="Increase Log Analytics workspace retention to at least 90 days.", **r))

    disabled_alerts = [a for a in alerts if not a.get("Data", {}).get("Enabled")]
    if disabled_alerts:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(disabled_alerts)} alert rules disabled."))

    if not ag:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "No action groups configured."))
    else:
        no_receivers = [g for g in ag
                        if g.get("Data", {}).get("TotalReceivers", 0) == 0]
        if no_receivers:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(no_receivers)} action groups with no receivers."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Monitoring coverage adequate."))
    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for logging control ({len(evidence)} items).")]


def _check_activity_event_analysis(cid, ctrl, evidence, idx, thresholds=None):
    """Analyze individual activity log events for suspicious patterns."""
    findings = []
    events = idx.get("azure-activity-event", [])

    if not events:
        return [_f(cid, ctrl, Status.COMPLIANT, "No significant activity events to analyze.")]

    failed = [e for e in events if e.get("Data", {}).get("Status") == "Failed"]
    deletes = [e for e in events if "/delete" in (e.get("Data", {}).get("OperationName", "")).lower()]

    # Check for suspicious failure patterns
    callers: dict[str, int] = {}
    for e in failed:
        caller = e.get("Data", {}).get("Caller", "unknown")
        callers[caller] = callers.get(caller, 0) + 1

    for caller, count in callers.items():
        if count > 10:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Caller '{caller}' generated {count} failed operations."))

    # Check for bulk deletions
    if len(deletes) > 20:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Bulk deletions detected ({len(deletes)} delete events in 90 days)."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Activity event analysis: {len(events)} events reviewed, no anomalies."))
    return findings


def _check_log_retention_analysis(cid, ctrl, evidence, idx, thresholds=None):
    """Evaluate log retention periods across Log Analytics and NSG flow logs."""
    findings = []
    la = idx.get("azure-log-analytics", [])
    flow_logs = idx.get("azure-nsg-flow-log", [])

    if not la and not flow_logs:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No Log Analytics workspaces or flow logs to evaluate for retention.",
                   recommendation="Deploy Log Analytics workspaces with \u226590 day retention.")]

    for workspace in la:
        d = workspace.get("Data", {})
        name = d.get("Name", "unknown")
        ret = d.get("RetentionInDays", 0)
        r = _res(workspace, "Microsoft.OperationalInsights/workspaces")
        if ret < 90:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Log Analytics '{name}' retention {ret}d < 90 days.",
                              recommendation="Increase retention to \u226590 days for compliance.", **r))
        elif ret < 365:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"Log Analytics '{name}' retention {ret}d meets 90-day minimum.", **r))
        else:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"Log Analytics '{name}' retention {ret}d meets 1-year recommendation.", **r))

    for fl in flow_logs:
        d = fl.get("Data", {})
        name = d.get("Name", "unknown")
        ret = d.get("RetentionDays", 0)
        r = _res(fl, "Microsoft.Network/networkWatchers/flowLogs")
        if ret < 90:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"NSG flow log '{name}' retention {ret}d < 90 days.",
                              recommendation="Increase NSG flow log retention to \u226590 days.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "All log retention periods meet compliance requirements."))
    return findings


def _check_alert_response_coverage(cid, ctrl, evidence, idx, thresholds=None):
    """Evaluate whether alert rules cover key resource types and have active action groups."""
    findings = []
    alerts = idx.get("azure-alert-rule", [])
    action_groups = idx.get("azure-action-group", [])
    defender = idx.get("azure-defender-pricing", [])

    if not alerts:
        if defender:
            return [_f(cid, ctrl, Status.NON_COMPLIANT,
                       "No custom alert rules configured (Defender alerts only).",
                       recommendation="Configure Azure Monitor alert rules for operational and security events.")]
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No alert rules or Defender plans — no alert response capability.",
                   recommendation="Configure alert rules and enable Defender for Cloud.")]

    enabled_alerts = [a for a in alerts if a.get("Data", {}).get("Enabled") is not False]
    disabled_alerts = len(alerts) - len(enabled_alerts)

    if disabled_alerts > 0:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{disabled_alerts} alert rules are disabled.",
                          recommendation="Review and re-enable disabled alert rules or remove obsolete ones."))

    # Alerts without action groups = alerts nobody sees
    alerts_no_actions = [a for a in enabled_alerts
                         if not a.get("Data", {}).get("ActionGroups")
                         and not a.get("Data", {}).get("Actions")]
    if alerts_no_actions:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(alerts_no_actions)} enabled alerts have no action groups attached.",
                          recommendation="Link action groups to all alert rules so incidents trigger notifications."))

    if not action_groups:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No action groups — alert notifications cannot be delivered.",
                          recommendation="Create action groups with email/SMS/webhook receivers."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Alert response coverage: {len(enabled_alerts)} active alerts, {len(action_groups)} action groups."))
    return findings
