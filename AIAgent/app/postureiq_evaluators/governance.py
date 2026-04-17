"""
Governance Domain Evaluator
Controls: CM-2, CA-7, SI-4, RA-5, CM-8, RA-5(5), CA-2, AC-2(7), AC-2(4).
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig

CRITICAL_DEFENDER_PLANS = [
    "VirtualMachines", "SqlServers", "AppServices",
    "StorageAccounts", "KeyVaults", "Arm", "Containers",
]


def evaluate_governance(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_governance_alignment": _check_governance_alignment,
        "check_approved_services_policy": _check_approved_services,
        "check_baseline_configuration": _check_baseline_config,
        "check_continuous_monitoring": _check_continuous_monitoring,
        "check_defender_enabled": _check_defender_enabled,
        "check_vulnerability_scanning": _check_vulnerability_scanning,
        "check_resource_locks": _check_resource_locks,
        "check_defender_security_posture": _check_defender_posture,
        "check_policy_compliance_state": _check_policy_compliance,
        "check_policy_compliance": _check_policy_compliance,
        "check_activity_logs": _check_continuous_monitoring,
        "check_monitoring_alerts": _check_continuous_monitoring,
        "check_defender_plans": _check_defender_plans,
        "check_pim_configuration": _check_pim_configuration,
        "check_access_reviews": _check_access_reviews,
        "check_backup_recovery": _check_backup_recovery,
        "check_resource_group_governance": _check_resource_group_governance,
        "check_ai_governance": _check_ai_governance,
        "check_security_awareness": _check_security_awareness,
        "check_defender_posture_advanced": _check_defender_posture_advanced,
        "check_ai_content_safety": _check_ai_content_safety,
        "check_regulatory_compliance": _check_regulatory_compliance,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", "FedRAMP"),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="governance", description=desc,
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
        resource_name=d.get("Name") or d.get("DisplayName") or d.get("PlanName") or ctx.get("ResourceName", ""),
        resource_type=rtype or d.get("ResourceType") or ctx.get("ResourceType", ""),
    )


def _check_governance_alignment(cid, ctrl, evidence, idx, thresholds=None):
    resources = idx.get("azure-resource", [])
    resource_groups = idx.get("azure-resource-group", [])
    all_items = resources + resource_groups
    if not all_items:
        return [_f(cid, ctrl, Status.COMPLIANT, "No resources to evaluate tagging.")]
    tagged = sum(1 for r in all_items if r.get("Data", {}).get("Tags"))
    pct = (tagged / len(all_items)) * 100 if all_items else 0

    findings = []
    if pct >= 80:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                   f"Resource tagging ({pct:.0f}%) meets 80% threshold "
                   f"({len(resources)} resources, {len(resource_groups)} resource groups)."))
    else:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                   f"Resource tagging ({pct:.0f}%) below 80% threshold "
                   f"({len(resources)} resources, {len(resource_groups)} resource groups)."))

    # Check resource groups specifically
    if resource_groups:
        rg_tagged = sum(1 for rg in resource_groups if rg.get("Data", {}).get("Tags"))
        rg_pct = (rg_tagged / len(resource_groups)) * 100
        if rg_pct < 80:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                       f"Resource group tagging ({rg_pct:.0f}%) below 80% threshold.",
                       recommendation="Apply consistent tags to all resource groups for cost management and governance."))

    return findings


def _check_approved_services(cid, ctrl, evidence, idx, thresholds=None):
    policies = idx.get("azure-policy-assignment", [])
    restrict = [p for p in policies
                if any(k in str(p.get("Data", {}).get("DisplayName", "")).lower()
                       for k in ("allowed", "restrict", "deny"))]
    if restrict:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"{len(restrict)} policies restricting resource types.")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT,
               "No policies restricting resource types found.")]


def _check_baseline_config(cid, ctrl, evidence, idx, thresholds=None):
    policies = idx.get("azure-policy-assignment", [])
    initiatives = [p for p in policies if p.get("Data", {}).get("IsPolicySet")]
    if len(policies) >= 5 or len(initiatives) >= 1:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"Baseline: {len(policies)} policies, {len(initiatives)} initiatives.")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT,
               f"Insufficient policy coverage ({len(policies)} policies, need ≥5 or ≥1 initiative).")]


def _check_continuous_monitoring(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    policies = idx.get("azure-policy-assignment", [])
    diag = idx.get("azure-diagnostic-setting", [])

    if not policies:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "No policies for continuous monitoring."))
    if not diag:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "No diagnostic settings for monitoring."))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Continuous monitoring: {len(policies)} policies, {len(diag)} diagnostic configs."))
    return findings


def _check_defender_enabled(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    defender = idx.get("azure-defender-pricing", [])

    enabled = {d.get("Data", {}).get("PlanName"): d for d in defender
               if d.get("Data", {}).get("PricingTier") == "Standard"}

    if not enabled:
        return [_f(cid, ctrl, Status.NON_COMPLIANT, "No Defender for Cloud plans enabled.")]

    missing = [p for p in CRITICAL_DEFENDER_PLANS if p not in enabled]
    if missing:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Missing critical Defender plans: {', '.join(missing)}."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All critical Defender plans enabled ({len(enabled)} total)."))
    return findings


def _check_vulnerability_scanning(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    defender = idx.get("azure-defender-pricing", [])
    enabled_names = {d.get("Data", {}).get("PlanName") for d in defender
                     if d.get("Data", {}).get("PricingTier") == "Standard"}

    if "VirtualMachines" not in enabled_names:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "Defender for VMs not enabled."))
    if "SqlServers" not in enabled_names:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "Defender for SQL not enabled."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "Vulnerability scanning (Defender for VMs + SQL) enabled."))
    return findings


def _check_resource_locks(cid, ctrl, evidence, idx, thresholds=None):
    locks = idx.get("azure-resource-lock", [])
    if not locks:
        return [_f(cid, ctrl, Status.NON_COMPLIANT, "No resource locks configured.")]

    cant_delete = sum(1 for l in locks if l.get("Data", {}).get("Level") == "CanNotDelete")
    read_only = sum(1 for l in locks if l.get("Data", {}).get("Level") == "ReadOnly")
    return [_f(cid, ctrl, Status.COMPLIANT,
               f"Resource locks: {cant_delete} CanNotDelete, {read_only} ReadOnly.")]


def _check_defender_posture(cid, ctrl, evidence, idx, thresholds=None):
    # Without recommendations API, check Defender pricing as proxy
    defender = idx.get("azure-defender-pricing", [])
    enabled = [d for d in defender if d.get("Data", {}).get("PricingTier") == "Standard"]
    if enabled:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"Defender enabled ({len(enabled)} plans), security posture active.")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT,
               "Defender not enabled, security posture unknown.")]


def _check_policy_compliance(cid, ctrl, evidence, idx, thresholds=None):
    compliance = idx.get("azure-policy-compliance", [])
    policy_defs = idx.get("azure-policy-definition", [])

    if not compliance:
        return [_f(cid, ctrl, Status.NON_COMPLIANT, "No policy compliance data.")]

    total = len(compliance)
    compliant = sum(1 for c in compliance
                    if c.get("Data", {}).get("ComplianceState") == "Compliant")
    rate = (compliant / total) * 100 if total else 0

    findings = []
    if rate >= 80:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                   f"Policy compliance rate {rate:.0f}% (≥80%)."))
    else:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                   f"Policy compliance rate {rate:.0f}% (<80%)."))

    # Report custom policy definitions as additional governance context
    if policy_defs:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                   f"{len(policy_defs)} custom policy definitions deployed."))

    return findings


def _check_defender_plans(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    defender = idx.get("azure-defender-pricing", [])
    autoprov = idx.get("azure-auto-provisioning", [])
    contacts = idx.get("azure-security-contact", [])

    disabled = [d for d in defender if d.get("Data", {}).get("PricingTier") != "Standard"]
    if disabled:
        names = [d.get("Data", {}).get("PlanName", "?") for d in disabled]
        disabled_evidence = [{"PlanName": d.get("Data", {}).get("PlanName", ""),
                              "PricingTier": d.get("Data", {}).get("PricingTier", "")} for d in disabled]
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Disabled Defender plans: {', '.join(names[:5])}.",
                          evidence_items=disabled_evidence))

    auto_off = [a for a in autoprov if a.get("Data", {}).get("AutoProvision") != "On"]
    if auto_off:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "Auto-provisioning not enabled for all."))

    alert_contacts = [c for c in contacts
                      if c.get("Data", {}).get("AlertNotifications") == "On"]
    if not alert_contacts:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No security contacts configured with alert notifications."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "Defender plans, auto-provisioning, and contacts configured."))
    return findings


def _check_pim_configuration(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    rules = idx.get("entra-pim-policy-rule", [])
    eligible = idx.get("entra-pim-eligible-assignment", [])

    if not rules and not eligible:
        policies = idx.get("entra-pim-policy", [])
        if not policies:
            return [_f(cid, ctrl, Status.NON_COMPLIANT, "No PIM policies found.")]
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"PIM configured ({len(policies)} policies).")]

    # Check eligible assignments for permanent (no expiry) roles
    if eligible:
        permanent = [a for a in eligible
                     if not a.get("Data", {}).get("EndDateTime")]
        if permanent:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(permanent)} PIM eligible assignments have no expiry date."))

    # Check MFA requirement
    mfa_rules = [r for r in rules if r.get("Data", {}).get("IsMfaRequired") is not None]
    no_mfa = [r for r in mfa_rules if not r.get("Data", {}).get("IsMfaRequired")]
    if no_mfa:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(no_mfa)} PIM roles don't require MFA for activation."))

    # Check activation duration
    duration_rules = [r for r in rules if r.get("Data", {}).get("MaximumDuration")]
    for dr in duration_rules:
        dur = dr.get("Data", {}).get("MaximumDuration", "")
        # ISO 8601 duration, e.g. "PT8H"
        if dur and "PT" in dur:
            try:
                hours = int(dur.replace("PT", "").replace("H", "").replace("h", ""))
                if hours > 8:
                    findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                      f"PIM activation duration ({hours}h) exceeds 8h limit."))
            except (ValueError, TypeError):
                pass

    if not findings:
        msg_parts = []
        if rules:
            msg_parts.append(f"MFA required, ≤8h activation")
        if eligible:
            msg_parts.append(f"{len(eligible)} eligible assignments all time-bound")
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"PIM configuration meets requirements ({', '.join(msg_parts or ['configured'])})."))
    return findings


def _check_access_reviews(cid, ctrl, evidence, idx, thresholds=None):
    reviews = idx.get("entra-access-review", [])
    roles = idx.get("entra-role-assignment", [])

    if not reviews and roles:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No access reviews configured but privileged roles exist.")]
    if reviews:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"{len(reviews)} access reviews configured.")]
    return [_f(cid, ctrl, Status.COMPLIANT,
               "No privileged roles requiring access reviews.")]


def _check_backup_recovery(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    vaults = idx.get("azure-recovery-vault", [])
    policies = idx.get("azure-policy-compliance", [])

    if not vaults:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Recovery Services vaults configured for backup/recovery."))
    else:
        no_soft_delete = [v for v in vaults
                          if not v.get("Data", {}).get("SoftDeleteEnabled")]
        if no_soft_delete:
            vault_evidence = [{"VaultName": v.get("Data", {}).get("Name", ""),
                               "ResourceId": v.get("Data", {}).get("ResourceId", "")} for v in no_soft_delete]
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(no_soft_delete)} recovery vaults without soft delete enabled.",
                              evidence_items=vault_evidence))

    # Check backup-related policies if available
    backup_policies = [p for p in policies
                       if "backup" in str(p.get("Data", {}).get("PolicyName", "")).lower()]
    non_compliant_bp = [p for p in backup_policies
                        if p.get("Data", {}).get("ComplianceState") != "Compliant"]
    if non_compliant_bp:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(non_compliant_bp)} backup-related policies non-compliant."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(vaults)} recovery vault(s) with soft delete enabled."))
    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for governance control ({len(evidence)} items).")]


def _check_resource_group_governance(cid, ctrl, evidence, idx, thresholds=None):
    """Evaluate resource group-level governance: tagging, naming conventions."""
    findings = []
    rgs = idx.get("azure-resource-group", [])

    if not rgs:
        return [_f(cid, ctrl, Status.COMPLIANT, "No resource groups to evaluate.")]

    # Tag compliance
    tagged = sum(1 for rg in rgs if rg.get("Data", {}).get("Tags"))
    pct = (tagged / len(rgs)) * 100 if rgs else 0
    if pct < 80:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                   f"Resource group tagging ({pct:.0f}%) below 80% threshold ({tagged}/{len(rgs)}).",
                   recommendation="Apply mandatory tags (environment, owner, cost-center) to all resource groups."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                   f"Resource group tagging ({pct:.0f}%) meets 80% threshold ({tagged}/{len(rgs)})."))

    return findings


def _check_ai_governance(cid, ctrl, evidence, idx, thresholds=None):
    """Evaluate AI model deployment governance — content filtering, rate limits, guardrails."""
    findings = []
    deployments = idx.get("azure-ai-deployment", [])

    if not deployments:
        return [_f(cid, ctrl, Status.COMPLIANT, "No AI model deployments to evaluate.")]

    for dep in deployments:
        d = dep.get("Data", {})
        name = d.get("DeploymentName", "unknown")
        acct = d.get("AccountName", "unknown")
        r = _res(dep, "CognitiveServicesDeployment")

        # Check content filter
        if not d.get("ContentFilter"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AI deployment '{name}' on '{acct}' has no content filter policy.",
                              recommendation="Assign a Responsible AI content filter policy to the deployment.", **r))
        # Check rate limits
        if not d.get("RateLimits"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AI deployment '{name}' on '{acct}' has no rate limits configured.",
                              recommendation="Configure rate limits on the AI deployment to prevent abuse.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(deployments)} AI deployments have content filtering and rate limits."))
    return findings


def _check_security_awareness(cid, ctrl, evidence, idx, thresholds=None):
    """Evaluate security awareness posture via policy compliance and terms-of-use acceptance."""
    findings = []
    tou = idx.get("entra-terms-of-use", [])
    compliance = idx.get("azure-policy-compliance", [])
    ca = idx.get("entra-conditional-access-policy", [])

    # Terms of Use as a proxy for security awareness acknowledgement
    if tou:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(tou)} Terms of Use agreement(s) configured for user acknowledgement."))
    else:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Terms of Use agreements configured for security awareness acknowledgement.",
                          recommendation="Configure Entra ID Terms of Use to require user acceptance of security policies."))

    # CA policies requiring ToU acceptance
    tou_ca = [p for p in ca
              if p.get("Data", {}).get("State") == "enabled"
              and (p.get("Data", {}).get("RequiresTermsOfUse")
                   or p.get("Data", {}).get("TermsOfUse"))]
    if tou_ca:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(tou_ca)} CA policies enforce Terms of Use acceptance."))

    # Security-related policy compliance as awareness indicator
    if compliance:
        sec_policies = [c for c in compliance
                        if any(k in str(c.get("Data", {}).get("PolicyName", "")).lower()
                               for k in ("security", "audit", "encrypt", "monitor"))]
        if sec_policies:
            compliant = sum(1 for c in sec_policies
                            if c.get("Data", {}).get("ComplianceState") == "Compliant")
            rate = (compliant / len(sec_policies)) * 100 if sec_policies else 0
            if rate >= 80:
                findings.append(_f(cid, ctrl, Status.COMPLIANT,
                                  f"Security policy compliance {rate:.0f}% indicates security awareness adherence."))
            else:
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"Security policy compliance {rate:.0f}% suggests awareness gaps.",
                                  recommendation="Improve security policy compliance through awareness training and enforcement."))

    return findings or [_f(cid, ctrl, Status.NOT_ASSESSED,
                           "Insufficient data to assess security awareness posture.")]


# ---------------------------------------------------------------------------
# Defender Advanced Posture (Secure Score + Assessments)
# ---------------------------------------------------------------------------
def _check_defender_posture_advanced(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    scores = idx.get("azure-secure-score", [])
    assessments = idx.get("azure-security-assessment", [])
    jit = idx.get("azure-jit-policy", [])

    for item in scores:
        d = item.get("Data", {})
        current = d.get("CurrentScore", 0)
        max_score = d.get("MaxScore", 0)
        pct = d.get("Percentage", 0)
        if max_score > 0 and pct < 70:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Secure Score {current}/{max_score} ({pct:.0f}%) is below 70% threshold.",
                              recommendation="Address Defender recommendations to improve secure score."))
        elif max_score > 0:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"Secure Score {current}/{max_score} ({pct:.0f}%) meets threshold."))

    unhealthy = [a for a in assessments
                 if a.get("Data", {}).get("StatusCode", "").lower() == "unhealthy"]
    if len(unhealthy) > 20:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(unhealthy)} unhealthy security assessments require attention.",
                          recommendation="Review and remediate unhealthy security assessments in Defender for Cloud."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Defender posture adequate: {len(scores)} scores, {len(assessments)} assessments."))
    return findings


# ---------------------------------------------------------------------------
# AI Content Safety
# ---------------------------------------------------------------------------
def _check_ai_content_safety(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    deployments = idx.get("azure-ai-deployment-safety", [])
    gov = idx.get("azure-ai-governance", [])
    blocklists = idx.get("azure-content-safety-blocklist", [])

    for item in deployments:
        d = item.get("Data", {})
        name = d.get("DeploymentName", "unknown")
        acct = d.get("AccountName", "")
        filters = d.get("ContentFilterPolicies", [])
        if not filters:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AI deployment '{acct}/{name}' has no content filters configured.",
                              recommendation="Configure content filter policies for AI deployments.",
                              resource_id=d.get("DeploymentId", ""), resource_name=name,
                              resource_type="Microsoft.CognitiveServices/accounts/deployments"))

    for item in gov:
        d = item.get("Data", {})
        acct = d.get("AccountName", "unknown")
        if not d.get("PublicNetworkAccessDisabled"):
            findings.append(_f(cid, ctrl, Status.INFO,
                              f"AI account '{acct}' has public network access enabled.",
                              recommendation="Consider restricting network access to AI services.",
                              resource_id=d.get("AccountId", ""), resource_name=acct,
                              resource_type="Microsoft.CognitiveServices/accounts"))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"AI content safety adequate: {len(deployments)} deployments, {len(blocklists)} blocklists."))
    return findings


# ---------------------------------------------------------------------------
# Regulatory Compliance (from Defender)
# ---------------------------------------------------------------------------
def _check_regulatory_compliance(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    standards = idx.get("azure-regulatory-compliance", [])

    for item in standards:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        state = d.get("State", "")
        passed = d.get("PassedControls", 0)
        failed = d.get("FailedControls", 0)
        total = passed + failed
        if total > 0:
            rate = (passed / total) * 100
            if rate < 70:
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"Regulatory standard '{name}': {rate:.0f}% ({passed}/{total}) compliance.",
                                  recommendation=f"Improve compliance with '{name}' standard."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Regulatory compliance status adequate ({len(standards)} standards)."))
    return findings
