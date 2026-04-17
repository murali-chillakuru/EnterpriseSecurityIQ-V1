"""
Data Security — Identity & Access evaluator — stale perms, data exfiltration, CA/PIM.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_stale_permissions(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#9 Stale Permission Detection — RBAC roles on data resources with no recent sign-in."""
    findings: list[dict] = []
    assignments = evidence_index.get("azure-role-assignments", [])
    sign_ins = evidence_index.get("azure-sign-in-activity", [])
    if not assignments:
        return findings

    from datetime import timezone, timedelta
    now = datetime.now(timezone.utc)
    stale_threshold = now - timedelta(days=90)

    # Build sign-in lookup: principalId -> lastSignIn
    sign_in_map: dict[str, str] = {}
    for ev in sign_ins:
        data = ev.get("Data", {})
        pid = data.get("principalId", "")
        last = data.get("lastSignInDateTime", "")
        if pid:
            sign_in_map[pid] = last

    _DATA_ROLES = {"storage blob data", "sql", "cosmos", "key vault",
                   "data factory", "contributor", "owner", "reader"}

    stale: list[dict] = []
    for ev in assignments:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        role_name = str(data.get("roleDefinitionName", "")).lower()
        scope = data.get("scope", "")
        principal_id = data.get("principalId", "")
        principal_type = data.get("principalType", "")

        if not any(kw in role_name for kw in _DATA_ROLES):
            continue
        if principal_type.lower() in ("serviceprincipal", "managedidentity"):
            continue

        last_sign = sign_in_map.get(principal_id, "")
        is_stale = False
        if not last_sign:
            is_stale = True
        else:
            try:
                last_dt = datetime.fromisoformat(last_sign.replace("Z", "+00:00"))
                if last_dt < stale_threshold:
                    is_stale = True
            except (ValueError, TypeError):
                is_stale = True

        if is_stale:
            stale.append({
                "Type": "RoleAssignment",
                "Name": f"{role_name} on {scope.rsplit('/', 1)[-1] if '/' in scope else scope}",
                "ResourceId": rid,
                "PrincipalId": principal_id,
                "RoleName": role_name,
                "LastSignIn": last_sign or "Never",
            })

    if stale:
        severity = "critical" if len(stale) > 10 else "high"
        findings.append(_ds_finding("stale_permissions", "stale_data_role_assignment",
            f"{len(stale)} stale RBAC assignments on data resources (no sign-in > 90 days)",
            "Stale role assignments increase blast radius — compromised dormant accounts retain data access privileges.",
            severity, stale,
            {"Description": "Remove or disable stale role assignments.",
             "AzureCLI": "az role assignment delete --ids <assignment-id>"}))
    return findings


def analyze_data_exfiltration(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#12 Data Exfiltration Prevention — storage firewall bypass, cross-tenant, NSG outbound."""
    findings: list[dict] = []

    # Storage firewall bypass check
    storage = evidence_index.get("azure-storage-security", [])
    bypass_issues: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        rid = ev.get("ResourceId", "")
        name = data.get("StorageAccountName", data.get("name", "Unknown"))
        bypass = str(data.get("Bypass", data.get("bypass", ""))).lower()
        default_action = str(data.get("NetworkDefaultAction",
                       data.get("network_default_action", ""))).lower()

        if default_action == "allow":
            continue  # Already flagged by storage checks
        if "azureservices" in bypass and (
            "logging" in bypass or "metrics" in bypass
        ):
            continue  # Normal bypass
        if bypass and bypass != "none" and "azureservices" not in bypass:
            bypass_issues.append({
                "Type": "StorageAccount",
                "Name": name,
                "ResourceId": rid,
                "BypassConfig": bypass,
            })

    if bypass_issues:
        findings.append(_ds_finding("data_exfiltration", "storage_unusual_bypass",
            f"{len(bypass_issues)} storage accounts with unusual firewall bypass configuration",
            "Unusual bypass configurations may allow data exfiltration through trusted service abuse.",
            "medium", bypass_issues,
            {"Description": "Review and restrict storage firewall bypass settings.",
             "AzureCLI": "az storage account update -n <name> -g <rg> --bypass AzureServices"}))

    # Cross-tenant access — check for storage accounts accessible from other tenants
    pe_connections = evidence_index.get("azure-private-endpoint-connections", [])
    cross_tenant: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        rid = ev.get("ResourceId", "")
        name = data.get("StorageAccountName", data.get("name", "Unknown"))
        pec = data.get("privateEndpointConnections", [])
        if isinstance(pec, list):
            for pe in pec:
                props = pe.get("properties", pe) if isinstance(pe, dict) else {}
                status = str(props.get("privateLinkServiceConnectionState", {}).get("status", "")).lower()
                if status == "approved":
                    pe_id = props.get("privateEndpoint", {}).get("id", "")
                    if pe_id:
                        storage_sub = rid.split("/")[2] if len(rid.split("/")) > 2 else ""
                        pe_sub = pe_id.split("/")[2] if len(pe_id.split("/")) > 2 else ""
                        if storage_sub and pe_sub and storage_sub != pe_sub:
                            cross_tenant.append({
                                "Type": "StorageAccount",
                                "Name": name,
                                "ResourceId": rid,
                                "CrossSub": pe_sub,
                            })

    if cross_tenant:
        findings.append(_ds_finding("data_exfiltration", "cross_sub_private_endpoint",
            f"{len(cross_tenant)} storage accounts with cross-subscription private endpoints",
            "Cross-subscription private endpoints may enable data exfiltration to external subscriptions.",
            "high", cross_tenant,
            {"Description": "Review and restrict cross-subscription private endpoint approvals.",
             "AzureCLI": "az storage account private-endpoint-connection reject --account-name <name> -g <rg> --name <connection>"}))

    # NSG outbound — check for unrestricted outbound to Internet
    nsgs = evidence_index.get("azure-nsg", [])
    unrestricted_outbound: list[dict] = []
    for ev in nsgs:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", "Unknown")
        rules = data.get("securityRules", [])
        for rule in rules if isinstance(rules, list) else []:
            props = rule if isinstance(rule, dict) else {}
            direction = str(props.get("direction", props.get("properties", {}).get("direction", ""))).lower()
            access = str(props.get("access", props.get("properties", {}).get("access", ""))).lower()
            dest = str(props.get("destinationAddressPrefix", props.get("properties", {}).get("destinationAddressPrefix", "")))
            dest_port = str(props.get("destinationPortRange", props.get("properties", {}).get("destinationPortRange", "")))
            if direction == "outbound" and access == "allow" and dest in ("*", "Internet", "0.0.0.0/0") and dest_port in ("*", "443", "80"):
                unrestricted_outbound.append({"Type": "NSG", "Name": name, "ResourceId": rid})
                break

    if unrestricted_outbound:
        findings.append(_ds_finding("data_exfiltration", "nsg_unrestricted_outbound",
            f"{len(unrestricted_outbound)} NSGs allow unrestricted outbound Internet access",
            "Unrestricted outbound access enables data exfiltration via HTTPS to attacker-controlled endpoints.",
            "medium", unrestricted_outbound,
            {"Description": "Restrict outbound NSG rules to required destinations only.",
             "AzureCLI": "az network nsg rule update -g <rg> --nsg-name <nsg> -n <rule> --destination-address-prefix <service-tag>"}))
    return findings


def analyze_conditional_access_pim(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#13 Conditional Access + PIM — MFA on data admin roles, JIT activation."""
    findings: list[dict] = []
    ca_policies = evidence_index.get("azure-conditional-access", [])
    pim_roles = evidence_index.get("azure-pim-roles", [])

    # Check Conditional Access for data admin roles
    if not ca_policies:
        # If we have no CA policy data, flag the absence
        findings.append(_ds_finding("conditional_access", "no_ca_policy_data",
            "Unable to assess Conditional Access policies — data not available",
            "Without CA policy assessment, MFA enforcement on data admin roles cannot be validated.",
            "informational", [],
            {"Description": "Ensure your user account has the Security Reader Entra role, or use appregistration auth mode with Policy.Read.All consented.",
             "AzureCLI": "# Assign Security Reader role in Entra admin center > Roles & administrators"}))
    else:
        # Check if any CA policy targets data admin roles with MFA
        has_mfa_policy = False
        for ev in ca_policies:
            data = ev.get("Data", {})
            # Collector stores RequiresMFA bool and GrantControls list
            if data.get("RequiresMFA"):
                has_mfa_policy = True
                break
            # Fallback: check GrantControls list for "mfa"
            grant_list = data.get("GrantControls", [])
            if isinstance(grant_list, list) and "mfa" in [str(c).lower() for c in grant_list]:
                has_mfa_policy = True
                break
        if not has_mfa_policy:
            findings.append(_ds_finding("conditional_access", "no_mfa_ca_policy",
                "No Conditional Access policy enforcing MFA detected",
                "Without MFA enforcement, data admin roles can be accessed with compromised passwords alone.",
                "high", [],
                {"Description": "Create a Conditional Access policy requiring MFA for admin roles.",
                 "AzureCLI": "# Create via Azure Portal > Entra ID > Security > Conditional Access"}))

    # Check PIM for just-in-time activation
    if pim_roles:
        permanent: list[dict] = []
        for ev in pim_roles:
            data = ev.get("Data", {})
            rid = ev.get("ResourceId", "")
            role_name = data.get("roleName", "")
            assignment_type = str(data.get("assignmentType", "")).lower()
            if assignment_type == "permanent":
                permanent.append({
                    "Type": "PIMRoleAssignment",
                    "Name": role_name,
                    "ResourceId": rid,
                })
        if permanent:
            findings.append(_ds_finding("conditional_access", "pim_permanent_assignments",
                f"{len(permanent)} PIM roles with permanent active assignments",
                "Permanent privileged role assignments violate least-privilege; JIT activation limits exposure windows.",
                "high", permanent,
                {"Description": "Convert permanent assignments to eligible with time-bound activation.",
                 "AzureCLI": "# Configure via Azure Portal > Entra ID > PIM > Azure AD Roles"}))
    return findings


