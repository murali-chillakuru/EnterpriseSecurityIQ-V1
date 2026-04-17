"""
Attack Path Analysis  (v45 — Multi-Hop Deep Analysis)
Identifies privilege escalation chains, lateral movement paths, blast radius,
credential chains, network adjacency pivots, and Conditional Access bypass gaps
by correlating RBAC assignments, network topology, identity configurations,
Key Vault access policies, and Conditional Access rules.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from app.logger import log


# ── Privilege escalation patterns ────────────────────────────────────────
_ESCALATION_ROLES = {
    "Owner",
    "User Access Administrator",
    "Contributor",
    "Key Vault Administrator",
    "Storage Blob Data Owner",
    "Virtual Machine Contributor",
}

_IAM_WRITE_ROLES = {
    "Owner",
    "User Access Administrator",
}

# Roles granting secret/key/cert read on Key Vault
_KV_READ_ROLES = {
    "Key Vault Administrator",
    "Key Vault Secrets Officer",
    "Key Vault Secrets User",
    "Key Vault Crypto Officer",
    "Key Vault Certificates Officer",
    "Key Vault Reader",
    "Owner",
    "Contributor",
}

# High-value target resource types (blast radius amplifiers)
_HIGH_VALUE_TARGETS = {
    "Microsoft.KeyVault/vaults",
    "Microsoft.Sql/servers",
    "Microsoft.DocumentDB/databaseAccounts",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.ContainerRegistry/registries",
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Web/sites",
    "Microsoft.ManagedIdentity/userAssignedIdentities",
}

# Roles that grant broad data-plane access — used in credential chain analysis
_DATA_PLANE_ROLES = {
    "Storage Blob Data Owner",
    "Storage Blob Data Contributor",
    "Cosmos DB Account Reader Role",
    "SQL Server Contributor",
    "Key Vault Administrator",
}


def analyze_attack_paths(evidence_index: dict[str, list[dict]]) -> dict[str, Any]:
    """Analyze collected evidence for attack paths.

    Returns:
        {
            "paths": [...],           # Identified attack path chains
            "summary": {...},         # Aggregate metrics
            "privilege_escalation": [...],
            "lateral_movement": [...],
            "exposed_high_value": [...],
        }
    """
    paths: list[dict] = []
    priv_esc: list[dict] = []
    lateral: list[dict] = []
    exposed_hv: list[dict] = []

    # 1. RBAC-based privilege escalation chains
    rbac_items = evidence_index.get("azure-role-assignment", [])
    entra_roles = evidence_index.get("entra-role-assignment", [])
    sp_items = evidence_index.get("entra-service-principal", [])

    # Index: principal → roles
    principal_roles: dict[str, list[dict]] = {}
    for item in rbac_items:
        d = item.get("Data", {})
        principal = d.get("PrincipalId", "") or d.get("principalId", "")
        role = d.get("RoleDefinitionName", "") or d.get("roleDefinitionName", "")
        scope = d.get("Scope", "") or d.get("scope", "")
        ptype = d.get("PrincipalType", "") or d.get("principalType", "")
        if principal:
            principal_roles.setdefault(principal, []).append({
                "Role": role, "Scope": scope, "PrincipalType": ptype,
            })

    # Detect principals with IAM-write roles (can grant themselves anything)
    for pid, roles in principal_roles.items():
        iam_write = [r for r in roles if r["Role"] in _IAM_WRITE_ROLES]
        if iam_write:
            escalation_targets = [r for r in roles if r["Role"] in _ESCALATION_ROLES]
            if len(escalation_targets) > 1:
                path = {
                    "Type": "privilege_escalation",
                    "PrincipalId": pid,
                    "PrincipalType": iam_write[0].get("PrincipalType", "Unknown"),
                    "Chain": f"Has '{iam_write[0]['Role']}' at scope '{iam_write[0]['Scope']}' → "
                             f"can grant self any role. Currently holds {len(escalation_targets)} "
                             f"privileged roles.",
                    "Roles": [r["Role"] for r in escalation_targets],
                    "RiskScore": 95,
                    "Severity": "critical",
                }
                priv_esc.append(path)
                paths.append(path)

    # 2. Service principal → managed identity chains (lateral movement)
    mi_items = evidence_index.get("azure-managed-identity", [])
    for item in mi_items:
        d = item.get("Data", {})
        mi_name = d.get("Name", d.get("DisplayName", "unknown"))
        mi_id = d.get("PrincipalId", d.get("principalId", ""))
        mi_roles = principal_roles.get(mi_id, [])
        priv_roles = [r for r in mi_roles if r["Role"] in _ESCALATION_ROLES]

        if priv_roles:
            # Check if this MI is attached to a compute resource
            resources = d.get("AssociatedResources", [])
            for res in resources[:5]:  # limit to first 5
                path = {
                    "Type": "lateral_movement",
                    "Source": f"Managed Identity '{mi_name}'",
                    "Target": res.get("ResourceId", res) if isinstance(res, dict) else str(res),
                    "Chain": f"MI '{mi_name}' has '{priv_roles[0]['Role']}' → "
                             f"compromising host gives attacker privileged Azure access.",
                    "Roles": [r["Role"] for r in priv_roles],
                    "RiskScore": 85,
                    "Severity": "high",
                }
                lateral.append(path)
                paths.append(path)

    # 3. Publicly exposed resources with access to high-value targets
    nsgs = evidence_index.get("azure-nsg-rule", [])
    storage = evidence_index.get("azure-storage-account", [])
    kvs = evidence_index.get("azure-keyvault", [])
    sqls = evidence_index.get("azure-sql-server", [])

    # Check storage accounts with public access
    for item in storage:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        public_access = d.get("AllowBlobPublicAccess", d.get("PublicNetworkAccess", ""))
        if str(public_access).lower() in ("true", "enabled"):
            exposed_hv.append({
                "Type": "exposed_high_value",
                "ResourceType": "Storage Account",
                "ResourceName": name,
                "ResourceId": d.get("ResourceId", ""),
                "Exposure": "Public blob access enabled",
                "RiskScore": 80,
                "Severity": "high",
            })

    # Check SQL servers with public access
    for item in sqls:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        public = d.get("PublicNetworkAccess", "")
        if str(public).lower() in ("enabled", "true"):
            exposed_hv.append({
                "Type": "exposed_high_value",
                "ResourceType": "SQL Server",
                "ResourceName": name,
                "ResourceId": d.get("ResourceId", ""),
                "Exposure": "Public network access enabled",
                "RiskScore": 85,
                "Severity": "high",
            })

    # Check Key Vaults with public access
    for item in kvs:
        d = item.get("Data", {})
        name = d.get("VaultName", d.get("Name", "unknown"))
        network_rules = d.get("NetworkAcls", d.get("NetworkRuleSet", {}))
        default_action = ""
        if isinstance(network_rules, dict):
            default_action = network_rules.get("DefaultAction", network_rules.get("defaultAction", ""))
        if str(default_action).lower() == "allow":
            exposed_hv.append({
                "Type": "exposed_high_value",
                "ResourceType": "Key Vault",
                "ResourceName": name,
                "ResourceId": d.get("ResourceId", ""),
                "Exposure": "Network default action is Allow (unrestricted)",
                "RiskScore": 90,
                "Severity": "critical",
            })

    paths.extend(exposed_hv)

    # 4. Entra role escalation: users with Global Admin + no PIM
    for item in entra_roles:
        d = item.get("Data", {})
        role_name = d.get("RoleName", d.get("DisplayName", ""))
        principal_name = d.get("PrincipalDisplayName", d.get("MemberName", "unknown"))
        is_eligible = d.get("AssignmentType", "").lower() == "eligible"
        is_permanent = not is_eligible and not d.get("EndDateTime")

        if role_name == "Global Administrator" and is_permanent:
            path = {
                "Type": "privilege_escalation",
                "PrincipalId": d.get("PrincipalId", ""),
                "PrincipalName": principal_name,
                "Chain": f"'{principal_name}' has permanent Global Administrator "
                         f"assignment (not PIM-eligible). Compromise of this account "
                         f"gives full tenant control.",
                "RiskScore": 100,
                "Severity": "critical",
            }
            priv_esc.append(path)
            paths.append(path)

    # ── Multi-hop deep analysis (v45) ──────────────────────────────────

    kv_chain: list[dict] = []
    ca_bypass: list[dict] = []
    credential_chain: list[dict] = []
    network_pivot: list[dict] = []
    app_mi_chain: list[dict] = []

    # 5. Key Vault → Identity → Resource chain
    #    Who can read secrets in Key Vault → what other resources can they reach?
    kv_items = evidence_index.get("azure-keyvault", [])
    for kv in kv_items:
        d = kv.get("Data", {})
        vault_name = d.get("VaultName", d.get("Name", "unknown"))
        vault_id = d.get("ResourceId", "")
        # Find principals with KV read roles scoped to this vault (or broader)
        for pid, roles in principal_roles.items():
            kv_roles = [r for r in roles
                        if r["Role"] in _KV_READ_ROLES
                        and (vault_id in r.get("Scope", "") or r.get("Scope", "").count("/") <= 4)]
            other_priv = [r for r in roles if r["Role"] in _ESCALATION_ROLES and r["Role"] not in _KV_READ_ROLES]
            if kv_roles and other_priv:
                path = {
                    "Type": "credential_chain",
                    "Subtype": "keyvault_to_resource",
                    "PrincipalId": pid,
                    "PrincipalType": kv_roles[0].get("PrincipalType", "Unknown"),
                    "Source": f"Key Vault '{vault_name}'",
                    "Target": f"{other_priv[0]['Role']} at {other_priv[0]['Scope']}",
                    "Chain": (
                        f"Principal has '{kv_roles[0]['Role']}' on Key Vault '{vault_name}' → "
                        f"can read secrets/keys/certs → also holds '{other_priv[0]['Role']}' at "
                        f"'{other_priv[0]['Scope']}'. Compromising this identity exposes both "
                        f"vault secrets AND privileged resource access."
                    ),
                    "Roles": [r["Role"] for r in kv_roles + other_priv],
                    "RiskScore": 88,
                    "Severity": "high",
                }
                kv_chain.append(path)
                paths.append(path)

    # 6. App/Function → Managed Identity → Privileged Resource chain
    #    Web Apps or Functions with system MI that hold privileged roles
    webapps = evidence_index.get("azure-webapp-config", [])
    func_apps = evidence_index.get("azure-function-app", [])
    compute_apps = webapps + func_apps
    for app in compute_apps:
        d = app.get("Data", {})
        app_name = d.get("Name", d.get("SiteName", "unknown"))
        app_type = "Function App" if app.get("EvidenceType") == "azure-function-app" else "Web App"
        # Check if this app has a managed identity
        mi_principal = d.get("Identity", {}).get("PrincipalId", "") if isinstance(d.get("Identity"), dict) else ""
        mi_type = d.get("Identity", {}).get("Type", "") if isinstance(d.get("Identity"), dict) else ""
        if not mi_principal:
            mi_principal = d.get("ManagedIdentityPrincipalId", d.get("identityPrincipalId", ""))
        if mi_principal:
            mi_priv_roles = [r for r in principal_roles.get(mi_principal, [])
                             if r["Role"] in _ESCALATION_ROLES]
            if mi_priv_roles:
                path = {
                    "Type": "lateral_movement",
                    "Subtype": "app_mi_to_resource",
                    "Source": f"{app_type} '{app_name}'",
                    "Target": f"{mi_priv_roles[0]['Role']} at {mi_priv_roles[0]['Scope']}",
                    "Chain": (
                        f"{app_type} '{app_name}' has system-assigned MI → MI holds "
                        f"'{mi_priv_roles[0]['Role']}' at '{mi_priv_roles[0]['Scope']}'. "
                        f"Exploiting the app (e.g., SSRF, RCE) grants the attacker "
                        f"privileged Azure access via the MI's token endpoint."
                    ),
                    "Roles": [r["Role"] for r in mi_priv_roles],
                    "RiskScore": 87,
                    "Severity": "high",
                }
                app_mi_chain.append(path)
                paths.append(path)

    # 7. Conditional Access bypass — privileged roles without MFA enforcement
    ca_policies = evidence_index.get("entra-conditional-access-policy", [])
    enabled_ca = [p for p in ca_policies
                  if p.get("Data", {}).get("State") == "enabled"
                  and p.get("Data", {}).get("RequiresMFA")]
    # Collect all role IDs that are protected by at least one MFA policy
    mfa_protected_roles: set[str] = set()
    targets_all_users = False
    for pol in enabled_ca:
        pd = pol.get("Data", {})
        if pd.get("TargetsAllUsers"):
            targets_all_users = True
        for role_id in pd.get("IncludeRoles", []):
            mfa_protected_roles.add(role_id)

    if not targets_all_users:
        # Check Entra role assignments for roles NOT protected by CA MFA
        for item in entra_roles:
            d = item.get("Data", {})
            role_name = d.get("RoleName", d.get("DisplayName", ""))
            role_id = d.get("RoleDefinitionId", d.get("RoleId", ""))
            principal_name = d.get("PrincipalDisplayName", d.get("MemberName", "unknown"))
            # Only flag privileged Entra roles
            if role_name in ("Global Administrator", "Privileged Role Administrator",
                             "Exchange Administrator", "SharePoint Administrator",
                             "Security Administrator", "User Administrator",
                             "Application Administrator", "Cloud Application Administrator",
                             "Authentication Administrator", "Intune Administrator"):
                if role_id not in mfa_protected_roles and "All" not in mfa_protected_roles:
                    path = {
                        "Type": "ca_bypass",
                        "Subtype": "privileged_role_no_mfa",
                        "PrincipalName": principal_name,
                        "PrincipalId": d.get("PrincipalId", ""),
                        "RoleName": role_name,
                        "Chain": (
                            f"'{principal_name}' holds '{role_name}' but no Conditional Access "
                            f"policy enforces MFA for this role. An attacker with stolen "
                            f"credentials can sign in without a second factor."
                        ),
                        "RiskScore": 92,
                        "Severity": "critical",
                    }
                    ca_bypass.append(path)
                    paths.append(path)

    # 8. Service Principal with expiring/expired credentials + privileged role
    sp_items_all = evidence_index.get("entra-service-principal", [])
    app_items = evidence_index.get("entra-application", [])
    for item in app_items + sp_items_all:
        d = item.get("Data", {})
        display = d.get("DisplayName", "unknown")
        obj_id = d.get("ObjectId", "")
        has_expired = d.get("HasExpiredCredentials", False)
        has_expiring = d.get("HasExpiringCredentials", False)
        total_creds = d.get("TotalCredentials", 0)
        if (has_expired or has_expiring) and total_creds > 0:
            sp_roles = principal_roles.get(obj_id, [])
            priv = [r for r in sp_roles if r["Role"] in _ESCALATION_ROLES]
            if priv:
                status = "expired" if has_expired else "expiring within 30 days"
                path = {
                    "Type": "credential_chain",
                    "Subtype": "weak_credential_privileged_sp",
                    "PrincipalName": display,
                    "PrincipalId": obj_id,
                    "CredentialStatus": status,
                    "Chain": (
                        f"'{display}' has {status} credentials AND holds "
                        f"'{priv[0]['Role']}' at '{priv[0]['Scope']}'. Credential "
                        f"mismanagement on a privileged SP creates a window for "
                        f"unauthorized access or loss of automation continuity."
                    ),
                    "Roles": [r["Role"] for r in priv],
                    "RiskScore": 82 if has_expired else 75,
                    "Severity": "high" if has_expired else "medium",
                }
                credential_chain.append(path)
                paths.append(path)

    # 9. Network adjacency pivot — VNets with open NSG + VMs holding privileged roles
    vnets = evidence_index.get("azure-virtual-network", [])
    nsg_rules = evidence_index.get("azure-nsg-rule", [])
    vm_items = evidence_index.get("azure-vm-config", [])

    # Find NSGs that allow any inbound from Internet
    open_nsg_subs: set[str] = set()
    for rule in nsg_rules:
        rd = rule.get("Data", {})
        if rd.get("IsAllowAnyInbound"):
            port = rd.get("DestinationPortRange", "")
            sub_id = rd.get("SubscriptionId", "")
            if sub_id:
                open_nsg_subs.add(sub_id)

    # Find VMs with managed identities that hold privileged roles
    for vm in vm_items:
        vd = vm.get("Data", {})
        vm_name = vd.get("Name", vd.get("VMName", "unknown"))
        vm_sub = vd.get("SubscriptionId", "")
        vm_mi = vd.get("Identity", {})
        mi_principal = ""
        if isinstance(vm_mi, dict):
            mi_principal = vm_mi.get("PrincipalId", "")
        if not mi_principal:
            mi_principal = vd.get("ManagedIdentityPrincipalId", "")
        if mi_principal and vm_sub in open_nsg_subs:
            vm_priv = [r for r in principal_roles.get(mi_principal, [])
                       if r["Role"] in _ESCALATION_ROLES]
            if vm_priv:
                path = {
                    "Type": "network_pivot",
                    "Subtype": "internet_exposed_vm_privileged_mi",
                    "Source": f"Internet → VM '{vm_name}'",
                    "Target": f"{vm_priv[0]['Role']} at {vm_priv[0]['Scope']}",
                    "Chain": (
                        f"VM '{vm_name}' is in a subscription with Internet-exposed NSG "
                        f"rules AND its managed identity holds '{vm_priv[0]['Role']}' at "
                        f"'{vm_priv[0]['Scope']}'. An attacker exploiting this VM can "
                        f"request an MI token from IMDS (169.254.169.254) and pivot to "
                        f"privileged Azure resource access."
                    ),
                    "Roles": [r["Role"] for r in vm_priv],
                    "RiskScore": 93,
                    "Severity": "critical",
                }
                network_pivot.append(path)
                paths.append(path)

    # ── Sort all paths by risk score ─────────────────────────────────
    paths.sort(key=lambda p: p.get("RiskScore", 0), reverse=True)

    # De-duplicate paths with same principal + type + subtype
    seen: set[str] = set()
    deduped: list[dict] = []
    for p in paths:
        key = f"{p.get('Type')}|{p.get('Subtype', '')}|{p.get('PrincipalId', '')}|{p.get('Source', '')}"
        if key not in seen:
            seen.add(key)
            deduped.append(p)
    paths = deduped

    summary = {
        "TotalPaths": len(paths),
        "PrivilegeEscalation": len(priv_esc),
        "LateralMovement": len(lateral) + len(app_mi_chain),
        "ExposedHighValue": len(exposed_hv),
        "CredentialChain": len(kv_chain) + len(credential_chain),
        "CABypass": len(ca_bypass),
        "NetworkPivot": len(network_pivot),
        "AppMIChain": len(app_mi_chain),
        "CriticalPaths": sum(1 for p in paths if p.get("Severity") == "critical"),
        "HighPaths": sum(1 for p in paths if p.get("Severity") == "high"),
        "MediumPaths": sum(1 for p in paths if p.get("Severity") == "medium"),
        "TopPaths": paths[:10],
    }

    log.info(
        "Attack path analysis: %d paths (%d escalation, %d lateral, %d exposed HV, "
        "%d credential chain, %d CA bypass, %d network pivot, %d app→MI)",
        len(paths), len(priv_esc), len(lateral), len(exposed_hv),
        len(kv_chain) + len(credential_chain), len(ca_bypass),
        len(network_pivot), len(app_mi_chain),
    )

    return {
        "paths": paths,
        "summary": summary,
        "privilege_escalation": priv_esc,
        "lateral_movement": lateral + app_mi_chain,
        "exposed_high_value": exposed_hv,
        "credential_chain": kv_chain + credential_chain,
        "ca_bypass": ca_bypass,
        "network_pivot": network_pivot,
    }
