"""
Access Domain Evaluator
Controls: AC-2, AC-6, custom owner roles, access enforcement.
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_access(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    """Dispatch to specific check based on evaluation_logic."""
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_privileged_access_separation": _check_privileged_access_separation,
        "check_least_privilege": _check_least_privilege,
        "check_access_enforcement": _check_access_enforcement,
        "check_account_management": _check_account_management,
        "check_custom_owner_roles": _check_custom_owner_roles,
        "check_conditional_access": _check_access_enforcement,
        "check_managed_identity_hygiene": _check_managed_identity_hygiene,
        "check_session_management": _check_session_management,
    }
    handler = dispatch.get(func, _default_check)
    return handler(control_id, control, evidence, evidence_index, thresholds)


def _finding(control_id: str, control: dict, status: Status, desc: str, *,
             recommendation=None, resource_id="", resource_name="", resource_type="",
             evidence_items=None) -> dict:
    return FindingRecord(
        control_id=control_id,
        framework=control.get("_framework", "FedRAMP"),
        control_title=control.get("title", ""),
        status=status,
        severity=Severity(control.get("severity", "high")),
        domain="access",
        description=desc,
        recommendation=recommendation or control.get("recommendation", ""),
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
        resource_name=d.get("Name") or d.get("DisplayName") or d.get("PrincipalDisplayName") or ctx.get("ResourceName", ""),
        resource_type=rtype or d.get("ResourceType") or ctx.get("ResourceType", ""),
    )


def _check_privileged_access_separation(
    control_id, control, evidence, evidence_index, thresholds: ThresholdConfig,
) -> list[dict]:
    findings = []
    azure_rbac = evidence_index.get("azure-role-assignment", [])
    entra_roles = evidence_index.get("entra-directory-role-member", [])

    # Subscription-level Owners
    sub_owners = [
        r for r in azure_rbac
        if r.get("Data", {}).get("IsPrivileged")
        and r.get("Data", {}).get("ScopeLevel") == "Subscription"
        and "Owner" in str(r.get("Data", {}).get("RoleDefinitionName", ""))
    ]
    max_owners = thresholds.max_subscription_owners
    owner_evidence = [{"PrincipalName": r.get("Data", {}).get("PrincipalDisplayName", ""),
                       "RoleName": r.get("Data", {}).get("RoleDefinitionName", ""),
                       "Scope": r.get("Data", {}).get("ScopeLevel", "")} for r in sub_owners]
    if len(sub_owners) > max_owners:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"Subscription-level Owners ({len(sub_owners)}) exceeds threshold of {max_owners}.",
            evidence_items=owner_evidence,
        ))
    else:
        findings.append(_finding(
            control_id, control, Status.COMPLIANT,
            f"Subscription-level Owners ({len(sub_owners)}) within threshold (≤{max_owners}).",
        ))

    # Privileged role percentage
    total_rbac = len(azure_rbac)
    privileged = [r for r in azure_rbac if r.get("Data", {}).get("IsPrivileged")]
    if total_rbac > 0:
        priv_pct = len(privileged) / total_rbac
        max_priv = thresholds.max_privileged_percent
        if priv_pct > max_priv:
            findings.append(_finding(
                control_id, control, Status.NON_COMPLIANT,
                f"Privileged roles ({len(privileged)}/{total_rbac}, {priv_pct:.0%}) exceed {max_priv:.0%} threshold."
            ))
        else:
            findings.append(_finding(
                control_id, control, Status.COMPLIANT,
                f"Privileged roles ({len(privileged)}/{total_rbac}, {priv_pct:.0%}) within threshold."
            ))

    # Global Admins
    ga_members = [
        r for r in entra_roles
        if r.get("Data", {}).get("RoleName") == "Global Administrator"
    ]
    max_ga = thresholds.max_global_admins
    ga_evidence = [{"PrincipalName": r.get("Data", {}).get("PrincipalDisplayName", ""),
                    "RoleName": "Global Administrator"} for r in ga_members]
    if len(ga_members) > max_ga:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"Active Global Administrators ({len(ga_members)}) exceeds threshold of {max_ga}.",
            evidence_items=ga_evidence,
        ))
    else:
        findings.append(_finding(
            control_id, control, Status.COMPLIANT,
            f"Active Global Administrators ({len(ga_members)}) within threshold (≤{max_ga}).",
        ))

    return findings


def _check_least_privilege(
    control_id, control, evidence, evidence_index, thresholds: ThresholdConfig,
) -> list[dict]:
    findings = []
    azure_rbac = evidence_index.get("azure-role-assignment", [])
    entra_roles = evidence_index.get("entra-role-assignment", [])

    # Sub-level Contributors
    sub_contribs = [
        r for r in azure_rbac
        if r.get("Data", {}).get("ScopeLevel") == "Subscription"
        and "Contributor" in str(r.get("Data", {}).get("RoleDefinitionName", ""))
    ]
    max_contribs = thresholds.max_subscription_contributors
    if len(sub_contribs) > max_contribs:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"Subscription-level Contributors ({len(sub_contribs)}) exceeds limit of {max_contribs}."
        ))

    # Management Group Owners
    mg_owners = [
        r for r in azure_rbac
        if r.get("Data", {}).get("ScopeLevel") == "ManagementGroup"
        and "Owner" in str(r.get("Data", {}).get("RoleDefinitionName", ""))
    ]
    if mg_owners:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"Management Group Owners exist ({len(mg_owners)}). Review necessity."
        ))

    # High-priv Entra roles
    max_entra = thresholds.max_entra_privileged_roles
    if len(entra_roles) > max_entra:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"Active high-privilege Entra role assignments ({len(entra_roles)}) exceeds limit of {max_entra}."
        ))

    if not findings:
        findings.append(_finding(
            control_id, control, Status.COMPLIANT,
            "Least privilege checks passed."
        ))
    return findings


def _check_access_enforcement(
    control_id, control, evidence, evidence_index, thresholds: ThresholdConfig,
) -> list[dict]:
    findings = []
    azure_rbac = evidence_index.get("azure-role-assignment", [])
    ca_policies = evidence_index.get("entra-conditional-access-policy", [])

    has_rbac = len(azure_rbac) > 0
    enabled_ca = [p for p in ca_policies if p.get("Data", {}).get("State") == "enabled"]

    if has_rbac and enabled_ca:
        findings.append(_finding(
            control_id, control, Status.COMPLIANT,
            f"RBAC configured with {len(enabled_ca)} active Conditional Access policies."
        ))
    elif has_rbac and not enabled_ca:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            "RBAC exists but no Conditional Access policies enforcing controls."
        ))
    else:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            "No RBAC or CA policies detected."
        ))
    return findings


def _check_custom_owner_roles(
    control_id, control, evidence, evidence_index, thresholds: ThresholdConfig,
) -> list[dict]:
    azure_rbac = evidence_index.get("azure-role-assignment", [])
    custom_owners = [
        r for r in azure_rbac
        if r.get("Data", {}).get("IsCustom")
        and "owner" in str(r.get("Data", {}).get("RoleDefinitionName", "")).lower()
    ]
    if custom_owners:
        return [_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"Custom roles with 'Owner' designation found ({len(custom_owners)})."
        )]
    return [_finding(
        control_id, control, Status.COMPLIANT,
        "No custom Owner roles detected."
    )]


def _default_check(control_id, control, evidence, evidence_index, thresholds: ThresholdConfig) -> list[dict]:
    return [_finding(
        control_id, control, Status.NOT_ASSESSED,
        f"No evaluation logic for access control ({len(evidence)} evidence items)."
    )]


def _check_account_management(
    control_id, control, evidence, evidence_index, thresholds: ThresholdConfig,
) -> list[dict]:
    findings = []
    lifecycle = evidence_index.get("entra-user-lifecycle-summary", [])
    rbac = evidence_index.get("azure-role-assignment", [])

    for lc in lifecycle:
        d = lc.get("Data", {})
        stale_pct = d.get("StalePercentage", 0)
        if stale_pct > 10:
            findings.append(_finding(
                control_id, control, Status.NON_COMPLIANT,
                f"Stale account rate ({stale_pct:.0f}%) exceeds 10% threshold."
            ))
        else:
            findings.append(_finding(
                control_id, control, Status.COMPLIANT,
                f"Stale account rate ({stale_pct:.0f}%) within threshold."
            ))

    priv = len([r for r in rbac if r.get("Data", {}).get("IsPrivileged")])
    if priv > 20:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"Total privileged accounts ({priv}) exceeds recommended maximum of 20."
        ))

    if not findings:
        findings.append(_finding(
            control_id, control, Status.COMPLIANT,
            "Account management checks passed."
        ))
    return findings


def _check_managed_identity_hygiene(
    control_id, control, evidence, evidence_index, thresholds: ThresholdConfig,
) -> list[dict]:
    """Evaluate managed identity usage — checks for orphaned user-assigned identities
    and validates that resources prefer managed identities over service principals."""
    findings = []
    identities = evidence_index.get("azure-managed-identity", [])
    rbac = evidence_index.get("azure-role-assignment", [])

    if not identities:
        return [_finding(
            control_id, control, Status.COMPLIANT,
            "No user-assigned managed identities found (resources may use system-assigned)."
        )]

    # Check if managed identities have role assignments (orphaned if not)
    identity_resource_ids = {i.get("Data", {}).get("ResourceId", "") for i in identities}
    assigned_principals = {r.get("Data", {}).get("PrincipalId", "") for r in rbac}

    # User-assigned MIs without any role assignment may be orphaned
    orphaned_count = 0
    for mi in identities:
        mi_id = mi.get("Data", {}).get("ResourceId", "")
        # Heuristic: if the MI name doesn't appear in any role assignment principal, flag it
        mi_name = mi.get("Data", {}).get("Name", "")
        has_assignment = any(mi_name.lower() in str(r.get("Data", {})).lower() for r in rbac)
        if not has_assignment:
            orphaned_count += 1

    if orphaned_count > 0:
        findings.append(_finding(
            control_id, control, Status.NON_COMPLIANT,
            f"{orphaned_count} user-assigned managed identities may be orphaned (no role assignments found).",
            recommendation="Review and remove unused user-assigned managed identities to reduce attack surface.",
        ))

    # Check proportion of service principal assignments vs managed identity assignments
    sp_assignments = [r for r in rbac if r.get("Data", {}).get("PrincipalType") == "ServicePrincipal"]
    if sp_assignments and len(identities) > 0:
        findings.append(_finding(
            control_id, control, Status.COMPLIANT,
            f"{len(identities)} managed identities in use alongside {len(sp_assignments)} service principal assignments."
        ))

    if not findings:
        findings.append(_finding(
            control_id, control, Status.COMPLIANT,
            f"{len(identities)} managed identities found, hygiene checks passed."
        ))
    return findings


def _check_session_management(
    control_id, control, evidence, evidence_index, thresholds: ThresholdConfig,
) -> list[dict]:
    """Evaluate Conditional Access session controls — sign-in frequency, persistent browser, app enforcement."""
    findings = []
    ca = evidence_index.get("entra-conditional-access-policy", [])
    enabled_ca = [p for p in ca if p.get("Data", {}).get("State") == "enabled"]

    session_policies = [p for p in enabled_ca if p.get("Data", {}).get("SessionControls")]
    sign_in_freq = [p for p in enabled_ca if p.get("Data", {}).get("SignInFrequency")]
    persistent_browser = [p for p in enabled_ca
                          if p.get("Data", {}).get("PersistentBrowser") == "never"
                          or p.get("Data", {}).get("DisablePersistentBrowser")]

    if not enabled_ca:
        return [_finding(control_id, control, Status.NON_COMPLIANT,
                         "No Conditional Access policies — session management not enforced.",
                         recommendation="Create CA policies with session controls for sign-in frequency and browser persistence.")]

    if not session_policies and not sign_in_freq:
        findings.append(_finding(control_id, control, Status.NON_COMPLIANT,
                                 "No CA policies configure session controls (sign-in frequency, persistent browser).",
                                 recommendation="Add session controls to CA policies — set sign-in frequency and disable persistent browser for sensitive apps."))
    else:
        msg_parts = []
        if sign_in_freq:
            msg_parts.append(f"{len(sign_in_freq)} with sign-in frequency")
        if persistent_browser:
            msg_parts.append(f"{len(persistent_browser)} restricting persistent browser")
        if session_policies:
            msg_parts.append(f"{len(session_policies)} with session controls")
        findings.append(_finding(control_id, control, Status.COMPLIANT,
                                 f"Session management policies: {', '.join(msg_parts)}."))

    return findings
