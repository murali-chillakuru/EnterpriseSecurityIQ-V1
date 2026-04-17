"""Data access governance evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding
from .copilot_security import (
    _check_hybrid_identity_accounts,
    _check_copilot_license_segmentation,
)


def analyze_access_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data access governance controls for Copilot."""
    findings: list[dict] = []
    findings.extend(_check_copilot_conditional_access(evidence_index))
    findings.extend(_check_copilot_license_scoping(evidence_index))
    findings.extend(_check_copilot_licensing(evidence_index))
    findings.extend(_check_access_reviews(evidence_index))
    findings.extend(_check_information_barriers(evidence_index))
    findings.extend(_check_mfa_enforcement(evidence_index))
    findings.extend(_check_pim_active(evidence_index))
    findings.extend(_check_named_locations(evidence_index))
    findings.extend(_check_signin_risk_policy(evidence_index))
    findings.extend(_check_device_compliance(evidence_index))
    # Phase 1 enhancements
    findings.extend(_check_stale_accounts(evidence_index))
    findings.extend(_check_excessive_global_admins(evidence_index))
    findings.extend(_check_shared_accounts(evidence_index))
    findings.extend(_check_group_based_licensing(evidence_index))
    findings.extend(_check_session_controls(evidence_index))
    # Phase 2 enhancements
    findings.extend(_check_mailbox_delegation(evidence_index))
    findings.extend(_check_shared_mailbox_permissions(evidence_index))
    findings.extend(_check_ib_enforcement_detail(evidence_index))
    findings.extend(_check_license_offboarding(evidence_index))
    # Phase 5: App protection
    findings.extend(_check_app_protection_policies(evidence_index))
    # Phase 6: Checklist gap closure
    findings.extend(_check_hybrid_identity_accounts(evidence_index))
    findings.extend(_check_copilot_license_segmentation(evidence_index))
    return findings


def _check_copilot_conditional_access(idx: dict) -> list[dict]:
    """Check if Conditional Access policies cover M365 Copilot."""
    ca_policies = idx.get("entra-conditional-access-policy", [])

    # Guard: if no CA policies were collected at all, the collector likely
    # received a 403 (user lacks Security Reader).  Emit "unable to assess".
    if not ca_policies:
        return [_cr_finding(
            "access_governance", "ca_unable_to_assess",
            "Conditional Access policies could not be assessed — no policy data collected",
            "The Copilot readiness assessment could not retrieve Conditional Access policies. "
            "This typically means your user account lacks the Security Reader Entra role, "
            "or when running via az login the Azure CLI app may not have consent for the required Graph scopes. "
            "Without CA visibility, Copilot access governance cannot be evaluated.",
            "high",
            [{"Type": "ConditionalAccess", "Name": "CA Policies",
              "ResourceId": "entra-conditional-access"}],
            {"Description": "Assign the Security Reader Entra role to your user account.",
             "PortalSteps": [
                 "Go to Entra admin center > Roles & administrators",
                 "Search for 'Security Reader'",
                 "Add your user account (or use appregistration auth mode with consented permissions)",
                 "Re-run the Copilot Readiness assessment",
             ]},
            compliance_status="gap",
        )]

    copilot_covered = False
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        apps = data.get("IncludedApplications", [])
        if isinstance(apps, list):
            for app in apps:
                if "copilot" in str(app).lower() or app == "All":
                    copilot_covered = True
                    break
        if copilot_covered:
            break

    if not copilot_covered and ca_policies:
        return [_cr_finding(
            "access_governance", "no_copilot_ca_policy",
            "No Conditional Access policy explicitly covers M365 Copilot",
            "Create Conditional Access policies that target M365 Copilot to enforce "
            "device compliance, location restrictions, and session controls.",
            "medium",
            [{"Type": "ConditionalAccess", "Name": "Copilot CA Policy",
              "ResourceId": "entra-ca-copilot"}],
            {"Description": "Add M365 Copilot to Conditional Access policy target apps.",
             "PortalSteps": ["Go to Entra admin center > Protection > Conditional Access", "Create or edit a policy targeting cloud apps", "Under 'Target resources', add 'Microsoft 365 Copilot'", "Configure grant controls (require compliant device, MFA)", "Enable the policy"]},
            compliance_status="gap",
        )]
    return []


def _check_copilot_license_scoping(idx: dict) -> list[dict]:
    """Check if Copilot is being rolled out in a scoped manner."""
    settings = idx.get("m365-copilot-settings", [])
    if settings:
        return []  # Evidence collected successfully — no finding needed

    # Check whether the collector emitted a 403 warning with scope info
    warnings = idx.get("m365-copilot-settings-warning", [])
    if warnings:
        w_data = warnings[0].get("Data", warnings[0].get("data", {}))
        return [_cr_finding(
            "access_governance", "copilot_deployment_scope_denied",
            "M365 Copilot deployment settings inaccessible — OrgSettings.Read.All scope missing",
            "The Graph API endpoint admin/microsoft365Apps/installationOptions returned 403 Forbidden. "
            "This endpoint requires the OrgSettings.Read.All delegated permission, which is not included "
            "in the Azure CLI first-party app's pre-consented scope set. Your Entra roles (including "
            "Global Administrator) cannot override this — it is a Graph API OAuth scope limitation.",
            "informational",
            [{"Type": "CopilotConfig", "Name": "Deployment Settings",
              "ResourceId": "m365-copilot-settings",
              "RequiredScope": w_data.get("RequiredScope", "OrgSettings.Read.All"),
              "Error": w_data.get("Error", "403 Forbidden")}],
            {"Description": w_data.get("Workaround",
                "Use a custom app registration with OrgSettings.Read.All granted, "
                "or verify deployment configuration manually."),
             "PortalSteps": [
                 "Go to Entra admin center > App registrations > New registration",
                 "Add Microsoft Graph > Delegated > OrgSettings.Read.All permission",
                 "Grant admin consent, then authenticate via that app",
                 "Alternatively, verify deployment in M365 admin center > Settings > Org settings > Microsoft 365 on the web",
             ]},
            compliance_status="partial",
        )]

    # No settings and no warning — generic fallback
    return [_cr_finding(
        "access_governance", "copilot_deployment_unknown",
        "M365 Copilot deployment configuration could not be assessed",
        "Unable to retrieve M365 Copilot deployment settings. Ensure Copilot "
        "is deployed to a pilot group first before organization-wide rollout.",
        "informational",
        [{"Type": "CopilotConfig", "Name": "Deployment Settings",
          "ResourceId": "m365-copilot-settings"}],
        {"Description": "Deploy Copilot to a pilot group first. Use group-based licensing.",
         "PortalSteps": ["Go to Microsoft 365 admin center > Billing > Licenses", "Select 'Microsoft 365 Copilot' license", "Assign to a pilot security group first", "Monitor usage before expanding to all users"]},
        compliance_status="partial",
    )]


def _check_copilot_licensing(idx: dict) -> list[dict]:
    """Check if the tenant has M365 Copilot licenses via subscribedSkus."""
    skus = idx.get("m365-subscribed-skus", [])
    if not skus:
        return []  # Evidence not collected — don't emit false finding

    copilot_sku_keywords = ("copilot", "microsoft_365_copilot", "microsoft365_copilot")
    copilot_skus = []
    for ev in skus:
        data = ev.get("Data", ev.get("data", {}))
        sku_name = (data.get("SkuPartNumber", "") or "").lower()
        display = (data.get("DisplayName", "") or "").lower()
        if any(kw in sku_name or kw in display for kw in copilot_sku_keywords):
            copilot_skus.append(data)

    if not copilot_skus:
        return [_cr_finding(
            "access_governance", "no_copilot_license",
            "No M365 Copilot license found in the tenant",
            "The assessment did not detect a Microsoft 365 Copilot SKU among the "
            "tenant's subscribed licenses. Copilot readiness improvements are moot "
            "without an active Copilot license.",
            "informational",
            [{"Type": "License", "Name": "M365 Copilot SKU",
              "ResourceId": "m365-subscribed-skus"}],
            {"Description": "Purchase and assign Microsoft 365 Copilot licenses.",
             "PortalSteps": [
                 "Go to Microsoft 365 admin center > Billing > Purchase services",
                 "Search for 'Microsoft 365 Copilot'",
                 "Purchase and assign to a pilot group",
             ]},
            compliance_status="partial",
        )]

    # Check license utilization — consumed vs available
    findings: list[dict] = []
    total_enabled = 0
    total_consumed = 0
    for sku in copilot_skus:
        prepaid = sku.get("PrepaidUnits", {})
        enabled = prepaid.get("Enabled", 0) if isinstance(prepaid, dict) else 0
        consumed = sku.get("ConsumedUnits", 0)
        total_enabled += enabled
        total_consumed += consumed

    if total_enabled > 0 and total_consumed == 0:
        findings.append(_cr_finding(
            "access_governance", "copilot_licenses_unassigned",
            f"Copilot licenses purchased ({total_enabled}) but none assigned to users",
            f"The tenant has {total_enabled} Copilot license(s) available but "
            f"0 have been assigned. Copilot cannot be used until licenses are "
            f"assigned to users or groups.",
            "medium",
            [{"Type": "License", "Name": "M365 Copilot Assignment",
              "ResourceId": "m365-copilot-license-assignment",
              "EnabledUnits": total_enabled, "ConsumedUnits": 0}],
            {"Description": "Assign Copilot licenses to a pilot user group.",
             "PortalSteps": [
                 "Go to Microsoft 365 admin center > Billing > Licenses",
                 "Select 'Microsoft 365 Copilot'",
                 "Click 'Assign licenses' and select a pilot security group",
                 "Or use group-based licensing: Entra Admin Center > Groups > Licenses",
             ]},
            compliance_status="gap",
        ))
    elif total_enabled > 0:
        utilization = (total_consumed / total_enabled) * 100
        if utilization < 50:
            findings.append(_cr_finding(
                "access_governance", "low_copilot_license_utilization",
                f"Low Copilot license utilization — {total_consumed}/{total_enabled} assigned ({utilization:.0f}%)",
                f"Only {total_consumed} of {total_enabled} available Copilot licenses are assigned "
                f"({utilization:.0f}% utilization). Consider expanding rollout or reclaiming unused licenses.",
                "informational",
                [{"Type": "License", "Name": "M365 Copilot Utilization",
                  "ResourceId": "m365-copilot-license-utilization",
                  "EnabledUnits": total_enabled, "ConsumedUnits": total_consumed,
                  "Utilization": f"{utilization:.0f}%"}],
                {"Description": "Expand Copilot assignment or reclaim unused licenses.",
                 "PortalSteps": [
                     "Go to Microsoft 365 admin center > Billing > Licenses",
                     "Review Copilot license assignment",
                     "Assign to additional user groups if readiness prerequisites are met",
                     "Reclaim unneeded licenses via Billing > Purchase services",
                 ]},
                compliance_status="partial",
            ))

    return findings


def _check_access_reviews(idx: dict) -> list[dict]:
    """Check if Entra access reviews are configured for governance."""
    reviews = idx.get("entra-access-review-definitions", [])
    if not reviews:
        return [_cr_finding(
            "access_governance", "no_access_reviews",
            "No Entra access reviews configured — permission sprawl risk for Copilot",
            "Access reviews regularly validate that users still need the permissions "
            "they hold. Without them, stale permissions accumulate and Copilot can "
            "surface content users should no longer access.",
            "medium",
            [{"Type": "AccessReview", "Name": "Access Reviews",
              "ResourceId": "entra-access-reviews"}],
            {"Description": "Configure recurring access reviews for groups and applications.",
             "PortalSteps": [
                 "Go to Entra admin center > Identity Governance > Access reviews",
                 "Click '+ New access review'",
                 "Select scope: Groups and applications",
                 "Set recurring schedule (quarterly recommended)",
                 "Assign reviewers (group owners or managers)",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_information_barriers(idx: dict) -> list[dict]:
    """Check if information barrier policies are configured."""
    ib = idx.get("m365-information-barriers", [])
    if not ib:
        return [_cr_finding(
            "access_governance", "no_information_barriers",
            "No information barrier policies detected — Copilot can surface content across compliance boundaries",
            "Information barriers segment users and groups to prevent communication and content "
            "sharing across compliance boundaries. Without them, Copilot may surface content "
            "from restricted segments (e.g., investment banking to retail).",
            "medium",
            [{"Type": "InformationBarrier", "Name": "IB Policies",
              "ResourceId": "m365-information-barriers"}],
            {"Description": "Configure information barriers if your organization has compliance boundaries.",
             "PortalSteps": [
                 "Go to Microsoft Purview compliance portal > Information barriers",
                 "Define user segments based on directory attributes",
                 "Create barrier policies between segments",
                 "Apply policies and verify enforcement",
                 "Note: Requires Microsoft 365 E5 or Information Barriers add-on",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_mfa_enforcement(idx: dict) -> list[dict]:
    """Check if MFA is enforced for all users via Conditional Access."""
    ca_policies = idx.get("entra-conditional-access-policy", [])
    if not ca_policies:
        return []  # _check_copilot_conditional_access already flags missing CA data

    mfa_all_users = False
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        state = (data.get("State", "") or "").lower()
        if state not in ("enabled", "enabledforreportingbutnotenforced"):
            continue
        if data.get("RequiresMFA") and data.get("TargetsAllUsers"):
            mfa_all_users = True
            break

    if not mfa_all_users:
        return [_cr_finding(
            "access_governance", "no_mfa_enforcement",
            "No Conditional Access policy enforces MFA for all users — Copilot access may rely on single-factor credentials",
            "Multi-factor authentication is the single most effective control against credential-based "
            "attacks. Without MFA enforcement on all users, compromised credentials can give an attacker "
            "full Copilot access to the victim's data surface.",
            "high",
            [{"Type": "ConditionalAccess", "Name": "MFA Enforcement",
              "ResourceId": "entra-ca-mfa"}],
            {"Description": "Create a Conditional Access policy requiring MFA for all users.",
             "PortalSteps": [
                 "Go to Entra admin center > Protection > Conditional Access",
                 "Create a new policy targeting 'All users'",
                 "Under 'Target resources', select 'All cloud apps' or 'Microsoft 365 Copilot'",
                 "Under 'Grant', select 'Require multifactor authentication'",
                 "Enable the policy (start with 'Report-only' to verify impact)",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_pim_active(idx: dict) -> list[dict]:
    """Check if Privileged Identity Management (PIM) is configured for admin roles."""
    pim = idx.get("entra-pim-role-assignments", [])
    if not pim:
        return [_cr_finding(
            "access_governance", "no_pim_configured",
            "Privileged Identity Management not detected — admin roles have standing access to Copilot configuration",
            "PIM enables just-in-time role elevation so admin roles (Global Admin, SharePoint Admin, "
            "Compliance Admin) are not permanently active. Without PIM, compromised admin accounts "
            "have immediate, persistent access to change Copilot data exposure settings.",
            "medium",
            [{"Type": "PIM", "Name": "PIM Role Assignments",
              "ResourceId": "entra-pim"}],
            {"Description": "Enable PIM for privileged admin roles.",
             "PortalSteps": [
                 "Go to Entra admin center > Identity Governance > Privileged Identity Management",
                 "Click 'Azure AD roles' > 'Roles'",
                 "For each privileged role (Global Admin, SharePoint Admin, etc.)",
                 "Set 'Assignment type' to 'Eligible' instead of 'Active'",
                 "Configure activation maximum duration and approval requirements",
                 "Note: Requires Microsoft Entra ID P2 or Entra ID Governance license",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_named_locations(idx: dict) -> list[dict]:
    """Check if named (trusted) locations are defined for Conditional Access."""
    locs = idx.get("entra-named-locations", [])
    if not locs:
        return [_cr_finding(
            "access_governance", "no_named_locations",
            "No named locations defined — Conditional Access cannot restrict Copilot by network location",
            "Named locations define trusted corporate networks and countries. Without them, "
            "Conditional Access policies cannot enforce location-based restrictions for "
            "Copilot access, leaving it accessible from any network worldwide.",
            "medium",
            [{"Type": "NamedLocation", "Name": "Named Locations",
              "ResourceId": "entra-named-locations"}],
            {"Description": "Define trusted named locations for Conditional Access policies.",
             "PortalSteps": [
                 "Go to Entra admin center > Protection > Conditional Access > Named locations",
                 "Click '+ IP ranges location' to define corporate network ranges",
                 "Click '+ Countries location' to define trusted countries",
                 "Mark corporate networks as 'Mark as trusted location'",
                 "Reference these locations in Conditional Access policies",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_signin_risk_policy(idx: dict) -> list[dict]:
    """Check if sign-in risk-based Conditional Access policies are configured."""
    risk_policies = idx.get("entra-risk-based-ca-policies", [])
    if not risk_policies:
        return [_cr_finding(
            "access_governance", "no_signin_risk_policy",
            "No sign-in risk policy detected — Identity Protection cannot challenge risky Copilot authentications",
            "Sign-in risk policies (Identity Protection) evaluate real-time signals like "
            "impossible travel, anonymous IP, and leaked credentials to block or challenge "
            "risky sign-ins. Without them, compromised sessions can access Copilot data.",
            "medium",
            [{"Type": "IdentityProtection", "Name": "Sign-in Risk Policy",
              "ResourceId": "entra-identity-protection"}],
            {"Description": "Configure sign-in risk-based Conditional Access policies.",
             "PortalSteps": [
                 "Go to Entra admin center > Protection > Conditional Access",
                 "Create a new policy targeting 'All users'",
                 "Under 'Conditions' > 'Sign-in risk', select 'High' and 'Medium'",
                 "Under 'Grant', select 'Require multifactor authentication'",
                 "Enable the policy",
                 "Note: Requires Microsoft Entra ID P2 license",
             ]},
            compliance_status="gap",
        )]

    # Check if any are actually enabled
    enabled_risk = [
        ev for ev in risk_policies
        if (ev.get("Data", {}).get("State", "") or "").lower() == "enabled"
    ]
    if not enabled_risk:
        return [_cr_finding(
            "access_governance", "no_signin_risk_policy",
            "Sign-in risk policies exist but none are enabled — risky Copilot authentications are not blocked",
            "Risk-based Conditional Access policies were found but are in disabled or report-only state. "
            "Enable at least one sign-in risk policy to actively block suspicious authentication attempts.",
            "low",
            [{"Type": "IdentityProtection", "Name": "Sign-in Risk Policy",
              "ResourceId": "entra-identity-protection",
              "TotalPolicies": len(risk_policies), "EnabledPolicies": 0}],
            {"Description": "Enable existing sign-in risk policies.",
             "PortalSteps": [
                 "Go to Entra admin center > Protection > Conditional Access",
                 "Find existing risk-based policies",
                 "Change state from 'Report-only' or 'Off' to 'On'",
             ]},
            compliance_status="partial",
        )]
    return []


def _check_device_compliance(idx: dict) -> list[dict]:
    """Check if device compliance is required via Conditional Access."""
    ca_policies = idx.get("entra-conditional-access-policy", [])
    if not ca_policies:
        return []  # _check_copilot_conditional_access already flags missing CA data

    device_compliance_enforced = False
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        state = (data.get("State", "") or "").lower()
        if state not in ("enabled", "enabledforreportingbutnotenforced"):
            continue
        if data.get("RequiresCompliantDevice") and data.get("TargetsAllUsers"):
            device_compliance_enforced = True
            break

    if not device_compliance_enforced:
        return [_cr_finding(
            "access_governance", "no_device_compliance",
            "No CA policy requires device compliance for all users — Copilot accessible from unmanaged devices",
            "Device compliance policies ensure Copilot is accessed only from managed, encrypted, and "
            "patched devices. Without this, users can access Copilot data from personal or compromised "
            "devices where data may be leaked or intercepted.",
            "medium",
            [{"Type": "ConditionalAccess", "Name": "Device Compliance",
              "ResourceId": "entra-ca-device-compliance"}],
            {"Description": "Require compliant devices for Copilot access.",
             "PortalSteps": [
                 "Go to Entra admin center > Protection > Conditional Access",
                 "Create or edit a policy targeting 'All users'",
                 "Under 'Target resources', add 'Microsoft 365 Copilot' or 'All cloud apps'",
                 "Under 'Grant', select 'Require device to be marked as compliant'",
                 "Ensure Intune device compliance policies are configured first",
             ]},
            compliance_status="gap",
        )]
    return []


# ── Phase 1: Identity & Licensing Enhancements ──────────────────────

def _check_stale_accounts(idx: dict) -> list[dict]:
    """Flag user accounts with no sign-in in 90+ days that still have Copilot-accessible data."""
    users = idx.get("entra-user-details", [])
    if not users:
        return []
    stale: list[dict] = []
    for ev in users:
        data = ev.get("Data", ev.get("data", {}))
        last_sign_in = data.get("LastSignInDateTime", "")
        if not last_sign_in:
            continue
        try:
            last_dt = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - last_dt).days
            if age_days > 90 and data.get("AccountEnabled", True):
                stale.append({
                    "Type": "EntraUser",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("UserId", ""),
                    "DaysSinceSignIn": age_days,
                    "UPN": data.get("UserPrincipalName", ""),
                })
        except (ValueError, TypeError):
            continue
    if stale:
        return [_cr_finding(
            "access_governance", "stale_accounts_detected",
            f"{len(stale)} stale accounts (90+ days inactive) still enabled — Copilot data exposure risk",
            "Stale user accounts retain their SharePoint and OneDrive permissions. "
            "If compromised, an attacker can use the account's Copilot access to "
            "surface all content the stale user ever had access to.",
            "high" if len(stale) > 10 else "medium",
            stale[:50],
            {"Description": "Disable or delete stale accounts. Review permissions before re-enabling.",
             "PowerShell": "Get-MgUser -Filter \"signInActivity/lastSignInDateTime le "
                           "2024-01-01T00:00:00Z and accountEnabled eq true\" -Property signInActivity",
             "PortalSteps": [
                 "Go to Entra admin center > Users > All users",
                 "Filter by 'Last sign-in' > 90 days ago",
                 "Disable or delete accounts no longer needed",
                 "For accounts to keep: review and reduce permissions",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_excessive_global_admins(idx: dict) -> list[dict]:
    """Flag if the tenant has more than 5 Global Administrators."""
    roles = idx.get("entra-directory-role-members", [])
    if not roles:
        return []
    ga_members: list[dict] = []
    for ev in roles:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("RoleName", "").lower() == "global administrator":
            ga_members.append({
                "Type": "EntraUser",
                "Name": data.get("MemberDisplayName", "Unknown"),
                "ResourceId": data.get("MemberId", ""),
                "UPN": data.get("MemberUPN", ""),
            })
    if len(ga_members) > 5:
        return [_cr_finding(
            "access_governance", "excessive_global_admins",
            f"{len(ga_members)} Global Administrators detected (recommended ≤ 5) — "
            "excessive privileged access to Copilot configuration",
            "Microsoft recommends no more than 5 Global Administrators. Each GA has "
            "unrestricted access to change Copilot settings, data access policies, "
            "and sensitivity labels. Excessive GAs increase the blast radius of "
            "credential compromise.",
            "high",
            ga_members[:20],
            {"Description": "Reduce Global Admins to ≤ 5. Use least-privilege admin roles.",
             "PowerShell": "Get-MgDirectoryRoleMember -DirectoryRoleId "
                           "(Get-MgDirectoryRole -Filter \"displayName eq 'Global Administrator'\").Id",
             "PortalSteps": [
                 "Go to Entra admin center > Roles & administrators > Global Administrator",
                 "Review all assigned members",
                 "Convert non-essential GAs to scoped admin roles (SharePoint Admin, Compliance Admin, etc.)",
                 "Use PIM for just-in-time GA elevation",
                 "Microsoft recommends no more than 5 standing Global Admins",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_shared_accounts(idx: dict) -> list[dict]:
    """Detect shared/generic accounts that undermine individual accountability."""
    users = idx.get("entra-user-details", [])
    if not users:
        return []
    shared_keywords = ("shared", "generic", "service", "noreply", "no-reply",
                       "admin@", "info@", "support@", "test@", "demo@")
    shared: list[dict] = []
    for ev in users:
        data = ev.get("Data", ev.get("data", {}))
        upn = (data.get("UserPrincipalName", "") or "").lower()
        display = (data.get("DisplayName", "") or "").lower()
        mail_type = (data.get("MailboxType", "") or "").lower()
        if mail_type == "shared":
            shared.append({
                "Type": "SharedAccount",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("UserId", ""),
                "UPN": data.get("UserPrincipalName", ""),
                "Indicator": "SharedMailbox",
            })
        elif any(kw in upn or kw in display for kw in shared_keywords):
            shared.append({
                "Type": "SharedAccount",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("UserId", ""),
                "UPN": data.get("UserPrincipalName", ""),
                "Indicator": "NamingPattern",
            })
    if shared:
        return [_cr_finding(
            "access_governance", "shared_accounts_detected",
            f"{len(shared)} shared/generic accounts detected — accountability gap for Copilot actions",
            "Shared accounts make it impossible to attribute Copilot interactions to "
            "specific individuals. Audit logs show the shared account identity, not "
            "the actual person, undermining accountability and insider risk detection.",
            "medium",
            shared[:30],
            {"Description": "Convert shared accounts to shared mailboxes or eliminate them.",
             "PortalSteps": [
                 "Go to Entra admin center > Users > All users",
                 "Identify accounts with shared/generic naming patterns",
                 "Convert to shared mailboxes (no license needed)",
                 "Or: disable interactive sign-in and use delegated access",
                 "Ensure all Copilot users have individual, named accounts",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_group_based_licensing(idx: dict) -> list[dict]:
    """Check if Copilot licenses are assigned via group-based licensing for governance."""
    users = idx.get("entra-user-details", [])
    skus = idx.get("m365-subscribed-skus", [])
    if not users or not skus:
        return []
    # Check if any Copilot SKU is present
    copilot_keywords = ("copilot", "microsoft_365_copilot", "microsoft365_copilot")
    has_copilot = any(
        any(kw in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
            for kw in copilot_keywords)
        for ev in skus
    )
    if not has_copilot:
        return []

    # Check users with license assignment state info
    direct_assigned = 0
    group_assigned = 0
    for ev in users:
        data = ev.get("Data", ev.get("data", {}))
        assignment_type = (data.get("LicenseAssignmentType", "") or "").lower()
        copilot_licensed = data.get("HasCopilotLicense", False)
        if copilot_licensed:
            if assignment_type == "group":
                group_assigned += 1
            elif assignment_type == "direct":
                direct_assigned += 1

    if direct_assigned > 0 and group_assigned == 0:
        return [_cr_finding(
            "access_governance", "no_group_based_licensing",
            f"{direct_assigned} Copilot licenses directly assigned — group-based licensing not used",
            "Directly assigned licenses make it harder to manage Copilot rollout at scale "
            "and to ensure users meet readiness prerequisites. Group-based licensing enables "
            "governed rollout via security groups aligned to readiness criteria.",
            "low",
            [{"Type": "LicenseAssignment", "Name": "Copilot Direct Assignments",
              "ResourceId": "m365-copilot-licensing",
              "DirectAssigned": direct_assigned, "GroupAssigned": group_assigned}],
            {"Description": "Switch to group-based licensing for Copilot deployment.",
             "PortalSteps": [
                 "Go to Entra admin center > Groups > All groups",
                 "Create a 'Copilot-Ready Users' security group",
                 "Assign the M365 Copilot license to the group",
                 "Add users who meet readiness prerequisites to the group",
                 "Remove direct license assignments from individual users",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_session_controls(idx: dict) -> list[dict]:
    """Check if CA policies enforce sign-in frequency and persistent browser controls."""
    ca_policies = idx.get("entra-conditional-access-policy", [])
    if not ca_policies:
        return []

    has_signin_freq = False
    has_persistent_browser = False
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        state = (data.get("State", "") or "").lower()
        if state not in ("enabled", "enabledforreportingbutnotenforced"):
            continue
        session = data.get("SessionControls", {}) or {}
        if isinstance(session, dict):
            if session.get("SignInFrequency") or session.get("SignInFrequencyEnabled"):
                has_signin_freq = True
            if session.get("PersistentBrowser") or session.get("PersistentBrowserMode"):
                has_persistent_browser = True

    findings: list[dict] = []
    if not has_signin_freq:
        findings.append(_cr_finding(
            "access_governance", "no_session_signin_frequency",
            "No CA policy enforces sign-in frequency — Copilot sessions may persist indefinitely",
            "Sign-in frequency controls force users to re-authenticate periodically. "
            "Without this, a compromised session token grants indefinite Copilot access "
            "until the refresh token naturally expires.",
            "medium",
            [{"Type": "SessionControl", "Name": "Sign-in Frequency",
              "ResourceId": "entra-ca-session-controls"}],
            {"Description": "Configure sign-in frequency in a Conditional Access policy.",
             "PortalSteps": [
                 "Go to Entra admin center > Protection > Conditional Access",
                 "Edit an existing policy or create a new one",
                 "Under 'Session' > 'Sign-in frequency', set to 8 or 12 hours",
                 "Apply to Copilot users or all users",
             ]},
            compliance_status="gap",
        ))
    if not has_persistent_browser:
        findings.append(_cr_finding(
            "access_governance", "no_persistent_browser_control",
            "No CA policy controls persistent browser sessions for Copilot",
            "Persistent browser sessions keep users signed in even after closing the browser. "
            "On unmanaged devices, this leaves Copilot accessible to anyone who opens the browser.",
            "low",
            [{"Type": "SessionControl", "Name": "Persistent Browser",
              "ResourceId": "entra-ca-persistent-browser"}],
            {"Description": "Disable persistent browser sessions for unmanaged devices.",
             "PortalSteps": [
                 "Go to Entra admin center > Protection > Conditional Access",
                 "Edit an existing policy targeting unmanaged devices",
                 "Under 'Session' > 'Persistent browser session', set to 'Never persistent'",
             ]},
            compliance_status="gap",
        ))
    return findings


# ── Phase 2: Exchange & Governance Enhancements ────────────────────

def _check_mailbox_delegation(idx: dict) -> list[dict]:
    """Check for Exchange mailbox delegation that grants extra Copilot data surface."""
    delegations = idx.get("exchange-mailbox-delegations", [])
    if not delegations:
        return []
    risky: list[dict] = []
    for ev in delegations:
        data = ev.get("Data", ev.get("data", {}))
        access_rights = data.get("AccessRights", "")
        if "FullAccess" in str(access_rights):
            risky.append({
                "Type": "MailboxDelegation",
                "Name": data.get("MailboxDisplayName", "Unknown"),
                "ResourceId": data.get("MailboxId", ""),
                "Delegate": data.get("DelegateDisplayName", ""),
                "AccessRights": str(access_rights),
            })
    if risky:
        return [_cr_finding(
            "access_governance", "mailbox_delegation_fullaccess",
            f"{len(risky)} mailboxes have FullAccess delegation — expanded Copilot data surface for delegates",
            "FullAccess mailbox delegation means the delegate's Copilot can search and surface "
            "content from the delegated mailbox. This silently expands the data Copilot can access.",
            "medium",
            risky[:30],
            {"Description": "Review and minimize FullAccess mailbox delegations.",
             "PowerShell": 'Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | '
                           'Where-Object { $_.AccessRights -contains "FullAccess" -and '
                           '$_.IsInherited -eq $false }',
             "PortalSteps": [
                 "Connect to Exchange Online PowerShell",
                 "Run Get-MailboxPermission for each mailbox",
                 "Remove unneccesary FullAccess grants",
                 "Consider using Send-As or Send-On-Behalf instead",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_shared_mailbox_permissions(idx: dict) -> list[dict]:
    """Check shared mailbox permission sprawl."""
    shared_mboxes = idx.get("exchange-shared-mailboxes", [])
    if not shared_mboxes:
        return []
    over_delegated: list[dict] = []
    for ev in shared_mboxes:
        data = ev.get("Data", ev.get("data", {}))
        member_count = data.get("MemberCount", 0)
        if member_count > 25:
            over_delegated.append({
                "Type": "SharedMailbox",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("MailboxId", ""),
                "MemberCount": member_count,
            })
    if over_delegated:
        return [_cr_finding(
            "access_governance", "shared_mailbox_over_delegated",
            f"{len(over_delegated)} shared mailboxes have 25+ members — broad Copilot data exposure",
            "Shared mailboxes with excessive membership expose their entire email archive "
            "to all members via Copilot. Each member's Copilot can surface shared mailbox "
            "content, creating an unintended oversharing vector.",
            "medium",
            over_delegated[:20],
            {"Description": "Reduce shared mailbox membership. Use distribution groups for broadcast email.",
             "PowerShell": 'Get-Mailbox -RecipientTypeDetails SharedMailbox | '
                           'Get-MailboxPermission | Where-Object { $_.AccessRights -contains "FullAccess" }',
             "PortalSteps": [
                 "Go to Exchange admin center > Recipients > Shared mailboxes",
                 "Review membership for each shared mailbox",
                 "Remove users who don't need individual access",
                 "Consider converting to distribution groups for broadcast Email",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_ib_enforcement_detail(idx: dict) -> list[dict]:
    """Provide detail on information barrier segment assignments."""
    ib = idx.get("m365-information-barriers", [])
    if not ib:
        return []  # _check_information_barriers already flags missing IB
    ib_segments = idx.get("m365-ib-segments", [])
    if not ib_segments:
        return [_cr_finding(
            "access_governance", "ib_segments_not_assigned",
            "Information barrier policies exist but no segment assignments detected",
            "Information barriers are defined but user segments may not be assigned. "
            "Without segment assignments, IB policies have no effect and Copilot can "
            "surface content across compliance boundaries.",
            "medium",
            [{"Type": "InformationBarrier", "Name": "IB Segments",
              "ResourceId": "m365-ib-segments"}],
            {"Description": "Assign users to IB segments for enforcement to take effect.",
             "PortalSteps": [
                 "Go to Microsoft Purview > Information barriers > Segments",
                 "Verify segment membership rules are configured",
                 "Run Start-InformationBarrierPoliciesApplication to apply changes",
                 "Verify segment assignments: Get-InformationBarrierRecipientStatus",
             ]},
            compliance_status="partial",
        )]
    return []


def _check_license_offboarding(idx: dict) -> list[dict]:
    """Check for disabled users still holding Copilot licenses."""
    users = idx.get("entra-user-details", [])
    if not users:
        return []
    disabled_with_copilot: list[dict] = []
    for ev in users:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("AccountEnabled", True) and data.get("HasCopilotLicense", False):
            disabled_with_copilot.append({
                "Type": "EntraUser",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("UserId", ""),
                "UPN": data.get("UserPrincipalName", ""),
            })
    if disabled_with_copilot:
        return [_cr_finding(
            "access_governance", "disabled_users_with_copilot_license",
            f"{len(disabled_with_copilot)} disabled users still hold Copilot licenses — wasted cost & security risk",
            "Disabled accounts with active Copilot licenses waste license spend. If these "
            "accounts are re-enabled without review, they retain their full data access "
            "surface for Copilot.",
            "medium",
            disabled_with_copilot[:30],
            {"Description": "Remove Copilot licenses from disabled accounts.",
             "PowerShell": 'Get-MgUser -Filter "accountEnabled eq false" -Property assignedLicenses | '
                           'Where-Object { $_.AssignedLicenses.SkuId -contains "<CopilotSkuId>" }',
             "PortalSteps": [
                 "Go to Entra admin center > Users > All users",
                 "Filter by 'Account enabled = No'",
                 "Check for active Copilot license assignments",
                 "Remove Copilot licenses from disabled accounts",
                 "Add license removal to your offboarding workflow",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_app_protection_policies(idx: dict) -> list[dict]:
    """Check if Intune App Protection Policies (MAM) are configured.

    App Protection Policies control how corporate data flows between managed
    apps on mobile devices.  Without MAM policies, Copilot-generated content
    can be copy-pasted from managed apps into unmanaged personal apps,
    bypassing DLP and encryption controls.
    """
    policies = idx.get("intune-app-protection-policies", [])
    if not policies:
        return [_cr_finding(
            "access_governance", "no_app_protection_policies",
            "No Intune App Protection Policies (MAM) configured — Copilot data leakage risk on mobile",
            "App Protection Policies (MAM) prevent corporate data from leaving managed applications. "
            "Without these policies, users can copy Copilot-generated answers containing sensitive "
            "data from Outlook, Teams, or Office apps into unmanaged personal apps. MAM policies "
            "enforce encryption, block cut/copy/paste to unmanaged apps, and require PIN/biometric "
            "access to corporate data on both managed and BYOD devices.",
            "high",
            [{"Type": "IntuneConfig", "Name": "App Protection Policies",
              "ResourceId": "intune-mam-policies", "Status": "NotConfigured"}],
            {"Description": "Create App Protection Policies in Microsoft Intune for iOS, Android, "
             "and Windows to protect Copilot data on mobile and BYOD devices.",
             "PortalSteps": [
                 "Go to Microsoft Intune admin center > Apps > App protection policies",
                 "Create separate policies for iOS, Android, and Windows",
                 "Under 'Data protection': set 'Restrict cut, copy, and paste between other apps' to 'Policy managed apps'",
                 "Set 'Encrypt org data' to 'Require'",
                 "Under 'Access requirements': require PIN and biometric authentication",
                 "Assign policies to groups with Copilot licenses",
                 "Monitor policy compliance in Intune > Apps > Monitor > App protection status",
             ]},
            compliance_status="gap",
        )]

    # Check platform coverage
    platforms_covered: set[str] = set()
    active_policies: list[dict] = []
    for ev in policies:
        data = ev.get("Data", ev.get("data", {}))
        platform = data.get("Platform", "").lower()
        is_active = data.get("IsActive", True)
        if is_active and platform:
            platforms_covered.add(platform)
            active_policies.append(data)

    expected_platforms = {"ios", "android"}
    missing_platforms = expected_platforms - platforms_covered
    if missing_platforms:
        return [_cr_finding(
            "access_governance", "app_protection_platform_gaps",
            f"App Protection Policies missing for platform(s): {', '.join(sorted(missing_platforms))}",
            "App Protection Policies are not configured for all mobile platforms. "
            "Users on unprotected platforms can copy Copilot-generated sensitive content "
            "into personal unmanaged apps without restriction.",
            "medium",
            [{"Type": "IntuneConfig", "Name": "App Protection Policies",
              "ResourceId": "intune-mam-policies",
              "CoveredPlatforms": sorted(platforms_covered),
              "MissingPlatforms": sorted(missing_platforms)}],
            {"Description": f"Create App Protection Policies for: {', '.join(sorted(missing_platforms))}.",
             "PortalSteps": [
                 "Go to Microsoft Intune admin center > Apps > App protection policies",
                 f"Create policies for missing platforms: {', '.join(sorted(missing_platforms))}",
                 "Configure data protection settings to match existing platform policies",
                 "Assign to the same user groups as Copilot licenses",
             ]},
            compliance_status="gap",
        )]
    return []

