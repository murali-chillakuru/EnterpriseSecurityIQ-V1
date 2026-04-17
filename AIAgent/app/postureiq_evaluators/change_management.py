"""
Change Management Domain Evaluator
Controls: CM-3, CM-4, CM-5 (NIST), PCI 6.4, ISO A.8.32.
Evaluates change control policies, resource locks, configuration tracking,
and policy enforcement for change governance.
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_change_management(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_change_control_policies": _check_change_control_policies,
        "check_resource_lock_governance": _check_resource_lock_governance,
        "check_configuration_change_tracking": _check_change_tracking,
        "check_policy_enforcement": _check_policy_enforcement,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", ""),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="change_management", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[{"ResourceId": resource_id, "ResourceName": resource_name,
                              "ResourceType": resource_type}] if resource_name else (evidence_items or []),
    ).to_dict()


def _check_change_control_policies(cid, ctrl, evidence, idx, thresholds=None):
    """Verify Azure policies enforce change governance (deny/audit effects)."""
    findings = []
    policies = idx.get("azure-policy-assignment", [])
    policy_defs = idx.get("azure-policy-definition", [])

    if not policies:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No Azure policies assigned — no change control enforcement.",
                   recommendation="Assign Azure policies with deny/audit effects for change governance.")]

    # Policies with deny or audit effects that control changes
    deny_policies = [p for p in policies
                     if any(k in str(p.get("Data", {}).get("DisplayName", "")).lower()
                            for k in ("deny", "restrict", "not allowed", "prohibited", "require"))]
    audit_policies = [p for p in policies
                      if any(k in str(p.get("Data", {}).get("DisplayName", "")).lower()
                             for k in ("audit", "monitor", "assess"))]

    if not deny_policies:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No deny/restrict policies found for change control.",
                          recommendation="Implement deny policies for unauthorized resource types, locations, or SKUs."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(deny_policies)} change control policies with restrictive effects."))

    if audit_policies:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(audit_policies)} audit policies monitoring configuration changes."))

    # Custom policy definitions indicate governance maturity
    if policy_defs:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(policy_defs)} custom policy definitions supporting change governance."))

    return findings


def _check_resource_lock_governance(cid, ctrl, evidence, idx, thresholds=None):
    """Verify resource locks protect critical resources from unauthorized changes."""
    findings = []
    locks = idx.get("azure-resource-lock", [])
    resource_groups = idx.get("azure-resource-group", [])

    if not locks:
        if resource_groups:
            return [_f(cid, ctrl, Status.NON_COMPLIANT,
                       f"{len(resource_groups)} resource groups exist but no resource locks are configured.",
                       recommendation="Apply CanNotDelete or ReadOnly locks on production resource groups and critical resources.")]
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No resource locks configured.",
                   recommendation="Apply resource locks to prevent accidental deletion of critical resources.")]

    cant_delete = sum(1 for lk in locks if lk.get("Data", {}).get("Level") == "CanNotDelete")
    read_only = sum(1 for lk in locks if lk.get("Data", {}).get("Level") == "ReadOnly")

    total_locks = len(locks)
    if resource_groups and total_locks < len(resource_groups):
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Only {total_locks} locks for {len(resource_groups)} resource groups — incomplete coverage.",
                          recommendation="Ensure all production resource groups have at least a CanNotDelete lock."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Resource locks configured: {cant_delete} CanNotDelete, {read_only} ReadOnly."))

    return findings


def _check_change_tracking(cid, ctrl, evidence, idx, thresholds=None):
    """Verify activity event logging tracks configuration changes."""
    findings = []
    activity_logs = idx.get("azure-activity-log", [])
    activity_events = idx.get("azure-activity-event", [])
    diag = idx.get("azure-diagnostic-setting", [])

    if not activity_logs and not activity_events:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No activity logs available for change tracking.",
                   recommendation="Ensure Azure Activity Log is routed to Log Analytics for change audit trail.")]

    # Check for write/delete operations (change events)
    write_events = [e for e in activity_events
                    if e.get("Data", {}).get("OperationType") in ("Write", "Delete", "Action")]
    if activity_events:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(activity_events)} activity events tracked ({len(write_events)} change operations)."))
    elif activity_logs:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Activity log configured with {len(activity_logs)} log entries for change tracking."))

    # Diagnostic settings ensure logs are retained
    if diag:
        log_analytics_targets = [d for d in diag
                                 if d.get("Data", {}).get("WorkspaceId")
                                 or d.get("Data", {}).get("HasLogAnalytics")]
        if log_analytics_targets:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"{len(log_analytics_targets)} diagnostic settings route to Log Analytics for change retention."))

    return findings


def _check_policy_enforcement(cid, ctrl, evidence, idx, thresholds=None):
    """Verify policy compliance rate indicates enforced configuration management."""
    findings = []
    compliance = idx.get("azure-policy-compliance", [])
    policies = idx.get("azure-policy-assignment", [])

    if not compliance and not policies:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No policy assignments or compliance data for configuration enforcement.",
                   recommendation="Assign Azure policies and monitor compliance for change management.")]

    if compliance:
        total = len(compliance)
        compliant = sum(1 for c in compliance
                        if c.get("Data", {}).get("ComplianceState") == "Compliant")
        rate = (compliant / total) * 100 if total else 0

        if rate >= 80:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"Policy compliance rate {rate:.0f}% (≥80%) — effective change enforcement."))
        elif rate >= 50:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Policy compliance rate {rate:.0f}% (50-79%) — change enforcement needs improvement.",
                              recommendation="Remediate non-compliant resources or strengthen policy effects to deny."))
        else:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Policy compliance rate {rate:.0f}% (<50%) — change enforcement is weak.",
                              recommendation="Review and remediate policy violations. Consider using deny effects for critical policies."))
    elif policies:
        # Has policies but no compliance data
        initiatives = [p for p in policies if p.get("Data", {}).get("IsPolicySet")]
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(policies)} policies assigned ({len(initiatives)} initiatives) for configuration enforcement."))

    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for change management control ({len(evidence)} items).")]
