"""
Identity Domain Evaluator
Controls: IA-2, IA-5, AC-20, AC-2(3), AC-6(10), IA-2(1), SI-4(5), cross-tenant.
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_identity(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_centralized_identity": _check_centralized_identity,
        "check_identity_protection": _check_identity_protection,
        "check_user_authentication": _check_user_authentication,
        "check_mfa_all_users": _check_user_authentication,
        "check_mfa_admins": _check_identity_protection,
        "check_mfa_enforcement": _check_user_authentication,
        "check_conditional_access": _check_security_defaults_vs_ca,
        "check_app_identity_security": _check_app_identity_security,
        "check_authenticator_management": _check_authenticator_management,
        "check_security_defaults_vs_ca": _check_security_defaults_vs_ca,
        "check_guest_user_review": _check_guest_user_review,
        "check_device_compliance": _check_device_compliance,
        "check_user_lifecycle": _check_user_lifecycle,
        "check_oauth2_consent_governance": _check_oauth2_consent_governance,
        "check_mfa_registration_coverage": _check_mfa_registration_coverage,
        "check_risky_users": _check_risky_users,
        "check_cross_tenant_access": _check_cross_tenant_access,
        "check_named_locations": _check_named_locations,
        "check_legacy_auth_blocking": _check_legacy_auth_blocking,
        "check_service_principal_hygiene": _check_service_principal_hygiene,
        "check_workload_identity_security": _check_workload_identity_security,
        "check_auth_methods_security": _check_auth_methods_security,
        "check_managed_identity_hygiene": _check_managed_identity_hygiene,
    }
    handler = dispatch.get(func, _default)
    return handler(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", "FedRAMP"),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="identity", description=desc,
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
        resource_id=d.get("ResourceId") or d.get("AppId") or ctx.get("ResourceId") or item.get("ResourceId", ""),
        resource_name=d.get("Name") or d.get("DisplayName") or d.get("AppDisplayName") or ctx.get("ResourceName", ""),
        resource_type=rtype or d.get("ResourceType") or ctx.get("ResourceType", ""),
    )


def _check_centralized_identity(cid, ctrl, evidence, idx, thresholds=None):
    tenant = idx.get("entra-tenant-info", [])
    ca = [p for p in idx.get("entra-conditional-access-policy", [])
          if p.get("Data", {}).get("State") == "enabled"]
    if tenant:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"Centralized identity via Entra ID with {len(ca)} active CA policies.")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT, "No tenant info collected.")]


def _check_identity_protection(cid, ctrl, evidence, idx, thresholds=None):
    ca = idx.get("entra-conditional-access-policy", [])
    findings = []
    mfa_admin_policies = [
        p for p in ca
        if p.get("Data", {}).get("State") == "enabled"
        and p.get("Data", {}).get("RequiresMFA")
        and p.get("Data", {}).get("TargetsAdmins")
    ]
    for p in mfa_admin_policies:
        d = p.get("Data", {})
        name = d.get("DisplayName", "unknown")
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"CA policy '{name}' enforces MFA for admins.",
                          resource_id=d.get("Id", ""), resource_name=name,
                          resource_type="Entra/ConditionalAccessPolicy"))
    if not mfa_admin_policies:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Conditional Access policies enforce MFA for administrators.",
                          recommendation="Create a Conditional Access policy requiring MFA for all admin roles."))
    return findings


def _check_user_authentication(cid, ctrl, evidence, idx, thresholds=None):
    ca = idx.get("entra-conditional-access-policy", [])
    findings = []
    mfa_all = [
        p for p in ca
        if p.get("Data", {}).get("State") == "enabled"
        and p.get("Data", {}).get("RequiresMFA")
        and p.get("Data", {}).get("TargetsAllUsers")
    ]
    for p in mfa_all:
        d = p.get("Data", {})
        name = d.get("DisplayName", "unknown")
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"CA policy '{name}' enforces MFA for all users.",
                          resource_id=d.get("Id", ""), resource_name=name,
                          resource_type="Entra/ConditionalAccessPolicy"))
    if mfa_all:
        return findings
    mfa_any = [p for p in ca
               if p.get("Data", {}).get("State") == "enabled"
               and p.get("Data", {}).get("RequiresMFA")]
    if mfa_any:
        for p in mfa_any:
            d = p.get("Data", {})
            name = d.get("DisplayName", "unknown")
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"CA policy '{name}' requires MFA but does not target all users.",
                              recommendation="Expand the CA policy to target all users or create an all-users MFA policy.",
                              resource_id=d.get("Id", ""), resource_name=name,
                              resource_type="Entra/ConditionalAccessPolicy"))
        return findings
    return [_f(cid, ctrl, Status.NON_COMPLIANT, "No enabled MFA policies found.",
               recommendation="Create a Conditional Access policy requiring MFA for all users.")]


def _check_app_identity_security(cid, ctrl, evidence, idx, thresholds=None):
    apps = idx.get("entra-application", [])
    findings = []
    expired = [a for a in apps if a.get("Data", {}).get("HasExpiredCredentials")]
    for a in expired:
        d = a.get("Data", {})
        name = d.get("DisplayName", "unknown")
        app_id = d.get("AppId", "")
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"App registration '{name}' has expired credentials.",
                          recommendation="Rotate or remove expired credentials on the app registration.",
                          resource_id=app_id, resource_name=name,
                          resource_type="Entra/Application"))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "No apps with expired credentials."))
    return findings


def _check_authenticator_management(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    mfa = idx.get("entra-mfa-registration", [])
    mfa_summary = idx.get("entra-mfa-summary", [])
    apps = idx.get("entra-application", [])

    # Use summary for aggregate counts (collector only emits sampled per-user records)
    admins_no_mfa_count = 0
    no_default_pct = 0
    mfa_total = 0
    for s in mfa_summary:
        d = s.get("Data", {})
        admins_no_mfa_count = d.get("AdminsWithoutMfa", 0)
        no_default_pct = d.get("NoDefaultMfaMethodPercent", 0)
        mfa_total = d.get("TotalUsers", 0)

    # Fallback to per-user records if no summary available
    if not mfa_summary and mfa:
        admins_no_mfa_count = sum(1 for m in mfa
                                  if m.get("Data", {}).get("IsAdmin")
                                  and not m.get("Data", {}).get("IsMfaRegistered"))
        no_default = [m for m in mfa if m.get("Data", {}).get("DefaultMfaMethod") == "none"]
        mfa_total = len(mfa)
        no_default_pct = (len(no_default) / mfa_total * 100) if mfa_total > 0 else 0

    if admins_no_mfa_count > 0:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{admins_no_mfa_count} admins without MFA registration."))

    if mfa_total > 0 and no_default_pct > 30:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{no_default_pct:.0f}% of users have no default MFA method."))

    expired = [a for a in apps if a.get("Data", {}).get("HasExpiredCredentials")]
    if expired:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(expired)} apps with expired credentials."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "Authenticator management checks passed."))
    return findings


def _check_security_defaults_vs_ca(cid, ctrl, evidence, idx, thresholds=None):
    sd = idx.get("entra-security-defaults", [])
    ca = [p for p in idx.get("entra-conditional-access-policy", [])
          if p.get("Data", {}).get("State") == "enabled"]
    sd_enabled = any(s.get("Data", {}).get("IsEnabled") for s in sd)
    has_ca = len(ca) > 0

    if has_ca and not sd_enabled:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   "CA policies active with Security Defaults disabled.")]
    if sd_enabled and not has_ca:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   "Security Defaults enabled (no CA policies).")]
    if sd_enabled and has_ca:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "Both Security Defaults and CA policies enabled simultaneously.")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT,
               "Neither Security Defaults nor CA policies enabled.")]


def _check_guest_user_review(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    users = idx.get("entra-user-detail", [])
    reviews = idx.get("entra-access-review", [])
    lifecycle = idx.get("entra-user-lifecycle-summary", [])

    # Prefer lifecycle summary for accurate counts (collector samples per-user records)
    stale_guest_count = 0
    guest_never_signed_count = 0
    if lifecycle:
        d = lifecycle[0].get("Data", {})
        stale_guest_count = d.get("StaleGuests", 0)
        guest_never_signed_count = d.get("GuestNeverSignedIn", 0)
    else:
        # Fallback to per-user records
        guests = [u for u in users if u.get("Data", {}).get("UserType") == "Guest"]
        stale_guest_count = sum(1 for g in guests if g.get("Data", {}).get("IsStale"))
        guest_never_signed_count = sum(1 for g in guests if g.get("Data", {}).get("HasNeverSignedIn"))

    if stale_guest_count > 0:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{stale_guest_count} stale guest accounts (90+ days inactive)."))
    if guest_never_signed_count > 0:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{guest_never_signed_count} guest accounts that never signed in."))
    if not reviews:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No access reviews configured for guest users."))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Guest user review checks passed."))
    return findings


def _check_device_compliance(cid, ctrl, evidence, idx, thresholds=None):
    ca = idx.get("entra-conditional-access-policy", [])
    compliant_device = [
        p for p in ca
        if p.get("Data", {}).get("State") == "enabled"
        and p.get("Data", {}).get("RequiresCompliantDevice")
    ]
    if compliant_device:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   f"{len(compliant_device)} CA policies require compliant devices.")]
    return [_f(cid, ctrl, Status.NON_COMPLIANT,
               "No CA policies requiring compliant devices.")]


def _check_user_lifecycle(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    summary = idx.get("entra-user-lifecycle-summary", [])

    for s in summary:
        d = s.get("Data", {})
        stale_pct = d.get("StalePercentage", 0)
        if stale_pct > 20:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Stale accounts ({stale_pct}%) exceed 20% threshold."))

        stale_guests = d.get("StaleGuests", 0)
        if stale_guests > 10:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Stale guest accounts ({stale_guests}) exceed limit of 10."))

        stale_enabled = d.get("StaleEnabledUsers", 0)
        if stale_enabled > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{stale_enabled} stale accounts still enabled."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "User lifecycle checks passed."))
    return findings


def _check_oauth2_consent_governance(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    grants = idx.get("entra-oauth2-grant", [])

    HIGH_PRIV_SCOPES = {"Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All",
                        "User.ReadWrite.All", "Application.ReadWrite.All"}
    high_priv = [
        g for g in grants
        if any(s in (g.get("Data", {}).get("Scope", "") or "")
               for s in HIGH_PRIV_SCOPES)
    ]
    if len(high_priv) > 5:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"High-privilege OAuth scopes ({len(high_priv)}) exceed limit of 5."))

    admin_grants = [g for g in grants
                    if g.get("Data", {}).get("ConsentType") == "AllPrincipals"]
    if len(admin_grants) > 20:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Admin-consented grants ({len(admin_grants)}) exceed limit of 20."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "OAuth consent governance passed."))
    return findings


def _check_mfa_registration_coverage(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    summary = idx.get("entra-mfa-summary", [])
    mfa = idx.get("entra-mfa-registration", [])

    for s in summary:
        d = s.get("Data", {})
        pct = d.get("MfaRegistrationPercent", 0)
        if pct < 90:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"MFA registration ({pct}%) below 90% target."))

        admins_no = d.get("AdminsWithoutMfa", 0)
        if admins_no > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{admins_no} admins not MFA-registered."))

        not_registered = d.get("NotRegistered", 0)
        if not_registered > 10:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{not_registered} users not MFA-registered (>10)."))

    # Fallback if no summary — use per-user records
    if not summary and mfa:
        not_reg = [m for m in mfa if not m.get("Data", {}).get("IsMfaRegistered")]
        if len(not_reg) > 10:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(not_reg)} users not MFA-registered (>10)."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "MFA registration coverage adequate."))
    return findings


def _check_risky_users(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    risky = idx.get("entra-risky-user", [])
    detections = idx.get("entra-risk-detection", [])

    compromised = [u for u in risky if "confirmedcompromised" in str(
        u.get("Data", {}).get("RiskState", "")).lower()]
    seen_upns = set()
    for u in compromised:
        d = u.get("Data", {})
        upn = d.get("UserPrincipalName", "unknown")
        seen_upns.add(upn)
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"User '{upn}' confirmed compromised.",
                          recommendation="Reset the user's password, revoke sessions, and investigate compromise.",
                          resource_id=d.get("Id", ""), resource_name=upn,
                          resource_type="Entra/User"))

    high_risk = [u for u in risky if u.get("Data", {}).get("IsHighRisk")]
    for u in high_risk:
        d = u.get("Data", {})
        upn = d.get("UserPrincipalName", "unknown")
        if upn not in seen_upns:
            seen_upns.add(upn)
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"User '{upn}' is high-risk (level: {d.get('RiskLevel', 'high')}).",
                              recommendation="Require MFA re-registration and password reset for the user.",
                              resource_id=d.get("Id", ""), resource_name=upn,
                              resource_type="Entra/User"))

    at_risk = [u for u in risky if "atrisk" in str(
        u.get("Data", {}).get("RiskState", "")).lower()]
    if len(at_risk) > 5:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(at_risk)} users still in 'atRisk' state (>5).",
                          recommendation="Investigate and remediate at-risk users. Enable risk-based CA policies."))

    # Check risk detections for high-severity events
    high_detections = [d for d in detections
                       if str(d.get("Data", {}).get("RiskLevel", "")).lower() == "high"]
    if high_detections:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(high_detections)} high-severity risk detections found."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "No significant risky users."))
    return findings


def _check_cross_tenant_access(cid, ctrl, evidence, idx, thresholds=None):
    cta = idx.get("entra-cross-tenant-policy", [])
    partners = idx.get("entra-cross-tenant-partner", [])
    if not cta:
        return [_f(cid, ctrl, Status.NON_COMPLIANT, "No cross-tenant access policy found.")]
    if not partners:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   "Cross-tenant access policy configured with no external partners.")]
    return [_f(cid, ctrl, Status.COMPLIANT,
               f"Cross-tenant accessible with {len(partners)} partner configurations.")]


def _check_named_locations(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    locations = idx.get("entra-named-location", [])
    ca = idx.get("entra-conditional-access-policy", [])

    if not locations:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No named locations configured for location-based access control.")]

    trusted = [l for l in locations if l.get("Data", {}).get("IsTrusted")]
    if not trusted:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(locations)} named locations exist but none marked as trusted."))

    # Check if any CA policy references location conditions
    location_ca = [p for p in ca
                   if p.get("Data", {}).get("State") == "enabled"
                   and p.get("Data", {}).get("HasLocationCondition")]
    if not location_ca:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Conditional Access policies use location-based conditions."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(trusted)} trusted locations, {len(location_ca)} CA policies with location conditions."))
    return findings


def _check_legacy_auth_blocking(cid, ctrl, evidence, idx, thresholds=None):
    ca = idx.get("entra-conditional-access-policy", [])
    findings = []
    blockers = [
        p for p in ca
        if p.get("Data", {}).get("State") == "enabled"
        and p.get("Data", {}).get("BlocksLegacyAuth")
    ]
    for p in blockers:
        d = p.get("Data", {})
        name = d.get("DisplayName", "unknown")
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"CA policy '{name}' blocks legacy authentication.",
                          resource_id=d.get("Id", ""), resource_name=name,
                          resource_type="Entra/ConditionalAccessPolicy"))
    if not blockers:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No Conditional Access policies blocking legacy authentication protocols.",
                          recommendation="Create a CA policy to block legacy authentication protocols."))
    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for identity control ({len(evidence)} evidence items).")]


def _check_service_principal_hygiene(cid, ctrl, evidence, idx, thresholds=None):
    """Evaluate service principal risk, credential rotation, and ownership."""
    findings = []
    sps = idx.get("entra-service-principal", [])
    risky_sps = idx.get("entra-risky-service-principal", [])
    apps = idx.get("entra-application", [])

    # Risky service principals
    if risky_sps:
        high_risk = [sp for sp in risky_sps
                     if sp.get("Data", {}).get("RiskLevel") in ("high", "critical")]
        if high_risk:
            names = sorted(sp.get("Data", {}).get("DisplayName", "unknown") for sp in high_risk[:5])
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(high_risk)} high/critical-risk service principals: {', '.join(names)}.",
                              recommendation="Investigate and remediate high-risk service principals immediately."))
        medium_risk = [sp for sp in risky_sps
                       if sp.get("Data", {}).get("RiskLevel") == "medium"]
        if medium_risk:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{len(medium_risk)} medium-risk service principals detected.",
                              recommendation="Review and address medium-risk service principal detections."))

    # Expired credentials on service principals
    expired_apps = [a for a in apps if a.get("Data", {}).get("HasExpiredCredentials")]
    if expired_apps:
        names = sorted(a.get("Data", {}).get("DisplayName", "unknown") for a in expired_apps[:5])
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(expired_apps)} app registrations with expired credentials: {', '.join(names)}.",
                          recommendation="Rotate or remove expired credentials. Prefer managed identities where possible."))

    # Service principals without owners
    if sps:
        no_owner = sum(1 for sp in sps
                       if not sp.get("Data", {}).get("Owners")
                       and not sp.get("Data", {}).get("OwnerCount"))
        if no_owner > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{no_owner} service principals without assigned owners.",
                              recommendation="Assign owners to all service principals for lifecycle management."))

    if not findings:
        total = len(sps) + len(apps)
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Service principal hygiene checks passed ({total} principals/apps reviewed)."))
    return findings


# ---------------------------------------------------------------------------
# Workload identity security (federated credentials)
# ---------------------------------------------------------------------------
def _check_workload_identity_security(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    fed_creds = idx.get("entra-federated-credential", [])
    managed_sps = idx.get("entra-managed-identity-sp", [])
    reviews = idx.get("entra-workload-credential-review", [])

    # Check federated credentials for broad audiences
    for item in fed_creds:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        app_name = d.get("ApplicationDisplayName", "")
        audiences = d.get("Audiences", [])
        issuer = d.get("Issuer", "")
        if not issuer:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Federated credential '{app_name}/{name}' has no issuer configured.",
                              recommendation="Verify and configure the issuer URL for federated credentials."))

    # Check workload credential review results
    for item in reviews:
        d = item.get("Data", {})
        pwd_count = d.get("PasswordCredentialCount", 0)
        key_count = d.get("KeyCredentialCount", 0)
        has_secrets = d.get("HasSecretCredentials", False)
        if has_secrets and pwd_count > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"App '{d.get('DisplayName', '')}' uses {pwd_count} password credentials instead of federated.",
                              recommendation="Migrate from password credentials to workload identity federation."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Workload identity checks passed ({len(fed_creds)} federated creds, "
                          f"{len(managed_sps)} managed identity SPs)."))
    return findings


# ---------------------------------------------------------------------------
# Authentication methods policy security
# ---------------------------------------------------------------------------
def _check_auth_methods_security(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    policies = idx.get("entra-auth-methods-policy", [])
    strengths = idx.get("entra-auth-strength-policy", [])

    for item in policies:
        d = item.get("Data", {})
        methods = d.get("Methods", [])
        for m in methods:
            method_type = m.get("Type", "").lower()
            state = m.get("State", "").lower()
            if state == "enabled" and any(w in method_type for w in ("sms", "voice", "email")):
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"Weak auth method '{m.get('Type', '')}' is enabled.",
                                  recommendation="Disable SMS/Voice/Email OTP methods in favor of phishing-resistant methods."))

    if not strengths:
        findings.append(_f(cid, ctrl, Status.INFO,
                          "No custom authentication strength policies found.",
                          recommendation="Consider creating auth strength policies requiring phishing-resistant methods."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Authentication methods policy checks passed ({len(policies)} policies, {len(strengths)} strength policies)."))
    return findings


# ---------------------------------------------------------------------------
# Managed identity hygiene
# ---------------------------------------------------------------------------
def _check_managed_identity_hygiene(cid, ctrl, evidence, idx, thresholds=None):
    findings = []
    managed_sps = idx.get("entra-managed-identity-sp", [])
    managed_ids = idx.get("azure-managed-identity", [])

    orphaned = [sp for sp in managed_sps
                if sp.get("Data", {}).get("AccountEnabled") is False]
    if orphaned:
        names = sorted(sp.get("Data", {}).get("DisplayName", "unknown") for sp in orphaned[:10])
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"{len(orphaned)} disabled managed identity service principals detected: {', '.join(names)}.",
                          recommendation="Review and clean up orphaned managed identity service principals."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Managed identity hygiene checks passed ({len(managed_sps)} SPs, {len(managed_ids)} identities)."))
    return findings
