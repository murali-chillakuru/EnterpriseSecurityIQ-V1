"""
Risk evaluator — Identity attack surface analysis.

Checks: dormant accounts, over-permissioned SPs, credential hygiene,
MFA gaps, admin proliferation, guest risks, risky users.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from app.risk_evaluators.finding import risk_finding as _risk_finding


def analyze_identity_risk(
    evidence_index: dict[str, list[dict]],
    thresholds: Any | None = None,
) -> list[dict]:
    """Analyze identity-related security risks from collected evidence."""
    findings: list[dict] = []
    findings.extend(_check_dormant_accounts(evidence_index, thresholds))
    findings.extend(_check_overpermissioned_sps(evidence_index))
    findings.extend(_check_app_credential_hygiene(evidence_index))
    findings.extend(_check_mfa_gaps(evidence_index, thresholds))
    findings.extend(_check_admin_proliferation(evidence_index, thresholds))
    findings.extend(_check_guest_risks(evidence_index))
    findings.extend(_check_risky_users(evidence_index))
    return findings


def _check_dormant_accounts(evidence_index: dict, thresholds: Any) -> list[dict]:
    max_stale_pct = getattr(thresholds, "max_stale_percent", 20.0) if thresholds else 20.0
    user_summaries = evidence_index.get("entra-user-summary", [])
    total_users = stale_users = 0
    triggered = False

    for ev in user_summaries:
        data = ev.get("Data", ev.get("data", {}))
        total = data.get("TotalUsers", data.get("total_users", 0))
        stale = data.get("StaleUsers", data.get("stale_users", 0))
        stale_pct = data.get("StalePercent", data.get("stale_percent", 0))
        total_users += total
        stale_users += stale
        if stale_pct > max_stale_pct:
            triggered = True

    if triggered:
        severity = "high" if stale_users > 50 else "medium"
        return [_risk_finding(
            category="identity",
            subcategory="dormant_accounts",
            title=f"Dormant accounts detected ({stale_users} stale / {total_users} total)",
            description=(
                f"{stale_users} user accounts have not signed in for over 90 days. "
                "Dormant accounts increase attack surface and are common targets for compromise."
            ),
            severity=severity,
            affected_resources=[{"Type": "UserPopulation", "StaleUsers": stale_users, "TotalUsers": total_users}],
            remediation={
                "Description": "Review and disable dormant accounts, or remove if no longer needed.",
                "AzureCLI": "az ad user update --id <user-object-id> --account-enabled false",
                "PowerShell": "Update-MgUser -UserId <user-object-id> -AccountEnabled:$false",
                "PortalSteps": [
                    "Navigate to Entra ID > Users",
                    "Filter by 'Last sign-in' > 90 days ago",
                    "Review each account and disable or delete as appropriate",
                ],
            },
        )]
    return []


def _check_overpermissioned_sps(evidence_index: dict) -> list[dict]:
    role_assignments = evidence_index.get("azure-role-assignment", [])
    overpermissioned: list[dict] = []

    for ev in role_assignments:
        data = ev.get("Data", ev.get("data", {}))
        principal_type = data.get("PrincipalType", data.get("principal_type", ""))
        role_name = data.get("RoleName", data.get("role_name", ""))
        scope = data.get("Scope", data.get("scope", ""))

        if principal_type.lower() == "serviceprincipal" and role_name in ("Owner", "Contributor"):
            scope_parts = scope.strip("/").split("/")
            if len(scope_parts) <= 2:  # subscription-level or higher
                overpermissioned.append({
                    "Type": "ServicePrincipal",
                    "PrincipalId": data.get("PrincipalId", data.get("principal_id", "")),
                    "PrincipalName": data.get("PrincipalName", data.get("principal_name", "Unknown")),
                    "RoleName": role_name,
                    "Scope": scope,
                })

    if overpermissioned:
        return [_risk_finding(
            category="identity",
            subcategory="overpermissioned_service_principals",
            title=f"{len(overpermissioned)} service principals with excessive permissions",
            description=(
                f"{len(overpermissioned)} service principals have Owner or Contributor role "
                "at subscription scope or higher, violating least-privilege."
            ),
            severity="high",
            affected_resources=overpermissioned,
            remediation={
                "Description": "Replace broad roles with custom, resource-group-scoped roles.",
                "AzureCLI": (
                    "az role assignment delete --assignee <sp-id> --role Contributor "
                    "--scope /subscriptions/<sub-id>\n"
                    "az role assignment create --assignee <sp-id> --role Reader "
                    "--scope /subscriptions/<sub-id>/resourceGroups/<rg>"
                ),
                "PowerShell": (
                    "Remove-AzRoleAssignment -ObjectId <sp-id> -RoleDefinitionName 'Contributor' "
                    "-Scope '/subscriptions/<sub-id>'\n"
                    "New-AzRoleAssignment -ObjectId <sp-id> -RoleDefinitionName 'Reader' "
                    "-Scope '/subscriptions/<sub-id>/resourceGroups/<rg>'"
                ),
            },
        )]
    return []


def _check_app_credential_hygiene(evidence_index: dict) -> list[dict]:
    apps = evidence_index.get("entra-application", [])
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=30)
    expired: list[dict] = []
    expiring_soon: list[dict] = []

    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        app_name = data.get("DisplayName", data.get("display_name", "Unknown"))
        app_id = data.get("AppId", data.get("app_id", ""))

        for cred in data.get("PasswordCredentials", data.get("password_credentials", [])):
            end = cred.get("EndDateTime", cred.get("end_date_time"))
            if not end:
                continue
            try:
                end_dt = (
                    datetime.fromisoformat(end.replace("Z", "+00:00"))
                    if isinstance(end, str)
                    else end
                )
                if end_dt < now:
                    expired.append({"Type": "Application", "Name": app_name, "AppId": app_id,
                                    "CredentialExpiry": str(end_dt), "Status": "Expired"})
                elif end_dt < soon:
                    expiring_soon.append({"Type": "Application", "Name": app_name, "AppId": app_id,
                                          "CredentialExpiry": str(end_dt), "Status": "ExpiringSoon"})
            except (ValueError, TypeError):
                continue

    findings: list[dict] = []
    if expired:
        findings.append(_risk_finding(
            category="identity",
            subcategory="expired_credentials",
            title=f"{len(expired)} applications with expired credentials",
            description="Applications with expired credentials may fail silently or indicate abandoned registrations.",
            severity="high",
            affected_resources=expired,
            remediation={
                "Description": "Remove expired credentials and rotate, or delete abandoned registrations.",
                "AzureCLI": "az ad app credential reset --id <app-id>",
                "PowerShell": "Remove-MgApplicationPassword -ApplicationId <app-id> -KeyId <key-id>",
            },
        ))
    if expiring_soon:
        findings.append(_risk_finding(
            category="identity",
            subcategory="expiring_credentials",
            title=f"{len(expiring_soon)} applications with credentials expiring within 30 days",
            description="Proactively rotate credentials before they expire to prevent service disruption.",
            severity="medium",
            affected_resources=expiring_soon,
            remediation={
                "Description": "Rotate credentials before expiry. Consider managed identities instead.",
                "AzureCLI": "az ad app credential reset --id <app-id> --years 1",
                "PowerShell": "Add-MgApplicationPassword -ApplicationId <app-id> "
                              "-PasswordCredential @{EndDateTime=(Get-Date).AddYears(1)}",
            },
        ))
    return findings


def _check_mfa_gaps(evidence_index: dict, thresholds: Any) -> list[dict]:
    min_mfa = getattr(thresholds, "min_mfa_percent", 90.0) if thresholds else 90.0
    mfa_summaries = evidence_index.get("entra-mfa-summary", [])

    for ev in mfa_summaries:
        data = ev.get("Data", ev.get("data", {}))
        registered = data.get("RegisteredCount", data.get("registered_count", 0))
        total = data.get("TotalUsers", data.get("total_users", 0))
        if total == 0:
            continue
        pct = (registered / total) * 100
        if pct < min_mfa:
            gap = total - registered
            return [_risk_finding(
                category="identity",
                subcategory="mfa_gaps",
                title=f"MFA coverage at {pct:.0f}% — {gap} users without MFA",
                description=(
                    f"Only {registered}/{total} users ({pct:.1f}%) registered for MFA. "
                    "Accounts without MFA are vulnerable to credential-based attacks."
                ),
                severity="critical" if pct < 50 else "high",
                affected_resources=[{"Type": "MFACoverage", "Registered": registered,
                                     "Total": total, "Percent": round(pct, 1)}],
                remediation={
                    "Description": "Enable security defaults or create a Conditional Access policy requiring MFA.",
                    "PortalSteps": [
                        "Navigate to Entra ID > Security > Conditional Access",
                        "Create policy: 'Require MFA for all users'",
                        "Target: All users, Exclude: Break-glass accounts",
                        "Grant: Require multifactor authentication",
                    ],
                },
            )]
    return []


def _check_admin_proliferation(evidence_index: dict, thresholds: Any) -> list[dict]:
    max_ga = getattr(thresholds, "max_global_admins", 5) if thresholds else 5
    roles = evidence_index.get("entra-directory-role-member", [])
    global_admins: list[dict] = []

    for ev in roles:
        data = ev.get("Data", ev.get("data", {}))
        role_name = data.get("RoleName", data.get("role_name", ""))
        if "global administrator" in role_name.lower():
            global_admins.append({
                "Type": "GlobalAdmin",
                "UserId": data.get("MemberId", data.get("member_id", "")),
                "UserName": data.get("MemberName", data.get("member_name", "Unknown")),
            })

    if len(global_admins) > max_ga:
        return [_risk_finding(
            category="identity",
            subcategory="admin_proliferation",
            title=f"{len(global_admins)} Global Administrators (threshold: {max_ga})",
            description=(
                f"{len(global_admins)} Global Administrators exceed the recommended maximum of "
                f"{max_ga}. Excessive privileged accounts increase blast radius of compromise."
            ),
            severity="critical" if len(global_admins) > max_ga * 2 else "high",
            affected_resources=global_admins,
            remediation={
                "Description": "Reduce Global Admin count; use least-privilege roles and PIM just-in-time access.",
                "PowerShell": (
                    "Get-MgDirectoryRoleMember -DirectoryRoleId <ga-role-id> | Select DisplayName, Id\n"
                    "Remove-MgDirectoryRoleMember -DirectoryRoleId <ga-role-id> -DirectoryObjectId <user-id>"
                ),
                "PortalSteps": [
                    "Navigate to Entra ID > Roles and administrators > Global Administrator",
                    "Review each assignment; replace with least-privilege roles",
                    "Enable PIM for remaining Global Admin assignments",
                ],
            },
        )]
    return []


def _check_guest_risks(evidence_index: dict) -> list[dict]:
    user_summaries = evidence_index.get("entra-user-summary", [])
    access_reviews = evidence_index.get("entra-access-review", [])
    total_guests = total_users = 0

    for ev in user_summaries:
        data = ev.get("Data", ev.get("data", {}))
        total_guests += data.get("GuestUsers", data.get("guest_users", 0))
        total_users += data.get("TotalUsers", data.get("total_users", 0))

    findings: list[dict] = []
    if total_users > 0 and total_guests > 0:
        guest_pct = (total_guests / total_users) * 100
        if guest_pct > 20:
            findings.append(_risk_finding(
                category="identity",
                subcategory="guest_user_risk",
                title=f"High guest ratio: {total_guests} guests ({guest_pct:.0f}%)",
                description=(
                    f"{total_guests} guest users represent {guest_pct:.1f}% of the directory. "
                    "Unmanaged guest accounts may have stale access to sensitive resources."
                ),
                severity="medium",
                affected_resources=[{"Type": "GuestPopulation", "GuestCount": total_guests,
                                     "TotalUsers": total_users, "Percent": round(guest_pct, 1)}],
                remediation={
                    "Description": "Implement access reviews for guest users and restrict invitation settings.",
                    "PortalSteps": [
                        "Navigate to Entra ID > Identity Governance > Access Reviews",
                        "Create review for all guest users, set to quarterly auto-apply",
                    ],
                },
            ))

        has_guest_review = any(
            "guest" in (ev.get("Data", {}).get("DisplayName", "") or "").lower()
            for ev in access_reviews
        )
        if total_guests > 10 and not has_guest_review:
            findings.append(_risk_finding(
                category="identity",
                subcategory="missing_guest_review",
                title="No access reviews configured for guest users",
                description="Guest users should be reviewed periodically to ensure continued need for access.",
                severity="medium",
                affected_resources=[{"Type": "MissingAccessReview", "GuestCount": total_guests}],
                remediation={
                    "Description": "Create recurring access reviews for guest users.",
                    "PortalSteps": [
                        "Navigate to Entra ID > Identity Governance > Access Reviews",
                        "Create review targeting Guest users, quarterly, auto-apply, require justification",
                    ],
                },
            ))
    return findings


def _check_risky_users(evidence_index: dict) -> list[dict]:
    risky_users = evidence_index.get("entra-risky-user", [])
    high_risk: list[dict] = []
    medium_risk: list[dict] = []

    for ev in risky_users:
        data = ev.get("Data", ev.get("data", {}))
        risk_level = data.get("RiskLevel", data.get("risk_level", "")).lower()
        risk_state = data.get("RiskState", data.get("risk_state", "")).lower()
        if risk_state in ("dismissed", "remediated", "confirmedsafe"):
            continue
        entry = {
            "Type": "RiskyUser",
            "UserId": data.get("UserId", data.get("id", "")),
            "UserName": data.get("UserPrincipalName", data.get("user_principal_name", "Unknown")),
            "RiskLevel": risk_level,
            "RiskState": risk_state,
        }
        if risk_level == "high":
            high_risk.append(entry)
        elif risk_level == "medium":
            medium_risk.append(entry)

    findings: list[dict] = []
    if high_risk:
        findings.append(_risk_finding(
            category="identity",
            subcategory="high_risk_users",
            title=f"{len(high_risk)} users flagged as high risk",
            description="Identity Protection detected high-risk users requiring immediate investigation.",
            severity="critical",
            affected_resources=high_risk,
            remediation={
                "Description": "Force password reset and revoke sessions for high-risk users.",
                "PowerShell": "Revoke-MgUserSignInSession -UserId <user-id>",
                "PortalSteps": [
                    "Navigate to Entra ID > Security > Risky users",
                    "Investigate each high-risk user",
                    "Require password change or confirm compromise",
                ],
            },
        ))
    if medium_risk:
        findings.append(_risk_finding(
            category="identity",
            subcategory="medium_risk_users",
            title=f"{len(medium_risk)} users flagged as medium risk",
            description="Medium-risk detections should be reviewed and remediated.",
            severity="high",
            affected_resources=medium_risk,
            remediation={
                "Description": "Review medium-risk users; require MFA re-registration or password change.",
                "PortalSteps": [
                    "Navigate to Entra ID > Security > Risky users",
                    "Filter by risk level: Medium",
                    "Review and remediate each user",
                ],
            },
        ))
    return findings
