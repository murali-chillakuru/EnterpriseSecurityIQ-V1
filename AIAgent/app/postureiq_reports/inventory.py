"""
Evidence Inventory Extractor
Extracts structured inventory data from collected evidence for report generation.
"""

from __future__ import annotations
from typing import Any


def extract_inventory(evidence: list[dict]) -> dict[str, Any]:
    """
    Extract structured inventory from raw evidence records.
    Returns a dict with subscriptions, resource_groups, resources, rbac, entra sections.
    """
    inv: dict[str, Any] = {
        "subscriptions": [],
        "resource_groups": [],
        "resources": [],
        "resource_type_counts": {},
        "rbac_assignments": [],
        "privileged_assignments": [],
        "owner_assignments": [],
        "policy_assignments": [],
        "diagnostic_settings": [],
        "entra_users_summary": {},
        "entra_mfa_summary": {},
        "entra_roles": [],
        "entra_role_members": [],
        "entra_ca_policies": [],
        "entra_applications": [],
        "entra_service_principals": [],
        "entra_tenant": {},
        "defender_plans": [],
        "nsg_rules": [],
        "storage_accounts": [],
        "key_vaults": [],
        "virtual_networks": [],
    }

    for ev in evidence:
        etype = ev.get("EvidenceType", "")
        data = ev.get("Data", {})
        ctx = ev.get("Context", {})

        if etype == "azure-resource":
            _extract_resource(inv, data, ctx)
        elif etype == "azure-subscription":
            inv["subscriptions"].append(data)
        elif etype == "azure-resource-group":
            inv["resource_groups"].append(data)
        elif etype == "azure-role-assignment":
            _extract_rbac(inv, data, ctx)
        elif etype == "azure-policy-assignment":
            inv["policy_assignments"].append(data)
        elif etype == "azure-diagnostic-setting":
            inv["diagnostic_settings"].append(data)
        elif etype == "azure-defender-pricing":
            inv["defender_plans"].append(data)
        elif etype == "azure-nsg-rule":
            inv["nsg_rules"].append(data)
        elif etype == "azure-storage-security":
            inv["storage_accounts"].append(data)
        elif etype == "azure-keyvault":
            inv["key_vaults"].append(data)
        elif etype == "azure-virtual-network":
            inv["virtual_networks"].append(data)
        elif etype == "entra-user-summary":
            inv["entra_users_summary"] = data
        elif etype == "entra-mfa-summary":
            inv["entra_mfa_summary"] = data
        elif etype == "entra-role-definition" or etype == "entra-directory-role":
            inv["entra_roles"].append(data)
        elif etype == "entra-directory-role-member":
            inv["entra_role_members"].append(data)
        elif etype == "entra-conditional-access-policy":
            inv["entra_ca_policies"].append(data)
        elif etype == "entra-application":
            inv["entra_applications"].append(data)
        elif etype == "entra-service-principal":
            inv["entra_service_principals"].append(data)
        elif etype in ("entra-tenant-info", "entra-tenant"):
            inv["entra_tenant"] = data
        elif etype == "entra-role-assignment":
            inv["entra_role_members"].append(data)

    # Deduplicate subscriptions and resource groups from resources
    _derive_subscriptions_and_rgs(inv)

    # Count resource types
    for r in inv["resources"]:
        rt = r.get("ResourceType") or r.get("Type") or r.get("type", "Unknown")
        inv["resource_type_counts"][rt] = inv["resource_type_counts"].get(rt, 0) + 1

    # Identify privileged assignments
    privileged_roles = {"Owner", "Contributor", "User Access Administrator"}
    for ra in inv["rbac_assignments"]:
        role = ra.get("RoleName") or ra.get("RoleDefinitionName", "")
        if role in privileged_roles:
            inv["privileged_assignments"].append(ra)
        if role == "Owner":
            inv["owner_assignments"].append(ra)

    return inv


def _extract_resource(inv: dict, data: dict, ctx: dict) -> None:
    """Extract resource from evidence."""
    resource = {**data}
    if ctx:
        resource.setdefault("SubscriptionId", ctx.get("SubscriptionId", ""))
        resource.setdefault("SubscriptionName", ctx.get("SubscriptionName", ""))
        resource.setdefault("ResourceGroup", ctx.get("ResourceGroup", ""))
        resource.setdefault("Location", ctx.get("Location", ""))
        resource.setdefault("ResourceType", ctx.get("ResourceType", ""))
        resource.setdefault("ResourceName", ctx.get("ResourceName", ""))
    inv["resources"].append(resource)


def _extract_rbac(inv: dict, data: dict, ctx: dict) -> None:
    """Extract RBAC assignment."""
    assignment = {**data}
    if ctx:
        assignment.setdefault("SubscriptionName", ctx.get("SubscriptionName", ""))
    inv["rbac_assignments"].append(assignment)


def _derive_subscriptions_and_rgs(inv: dict) -> None:
    """Derive unique subscriptions and resource groups from resource inventory.
    Merges with any already-added from explicit evidence types."""
    sub_map: dict[str, dict] = {}
    rg_map: dict[str, dict] = {}

    # Seed from already-collected explicit evidence
    for s in inv["subscriptions"]:
        sid = s.get("SubscriptionId", "")
        if sid:
            sub_map[sid] = s
    for r in inv["resource_groups"]:
        rg = r.get("ResourceGroup", "")
        sid = r.get("SubscriptionId", "")
        key = f"{sid}/{rg}" if sid else rg
        if key:
            rg_map[key] = r

    # Derive from resource inventory
    for r in inv["resources"]:
        sub_id = r.get("SubscriptionId", "")
        sub_name = r.get("SubscriptionName", "")
        rg = r.get("ResourceGroup", "")

        if sub_id and sub_id not in sub_map:
            sub_map[sub_id] = {
                "SubscriptionId": sub_id,
                "SubscriptionName": sub_name,
                "State": "Enabled",
            }

        if rg and sub_id:
            rg_key = f"{sub_id}/{rg}"
            if rg_key not in rg_map:
                rg_map[rg_key] = {
                    "ResourceGroup": rg,
                    "SubscriptionId": sub_id,
                    "SubscriptionName": sub_name,
                    "Location": r.get("Location", ""),
                }

    inv["subscriptions"] = list(sub_map.values())
    inv["resource_groups"] = list(rg_map.values())


def get_environment_summary(inv: dict) -> dict[str, int]:
    """Get a summary of the assessed environment."""
    return {
        "Azure Subscriptions": len(inv["subscriptions"]),
        "Azure Resource Groups": len(inv["resource_groups"]),
        "Azure Resources": len(inv["resources"]),
        "Azure Role Assignments": len(inv["rbac_assignments"]),
        "Azure Policy Assignments": len(inv["policy_assignments"]),
        "Storage Accounts": len(inv.get("storage_accounts", [])),
        "Key Vaults": len(inv.get("key_vaults", [])),
        "Virtual Networks": len(inv.get("virtual_networks", [])),
        "NSG Rules": len(inv.get("nsg_rules", [])),
        "Defender Plans": len(inv.get("defender_plans", [])),
        "Entra Directory Roles": len(inv["entra_roles"]),
        "Entra Conditional Access Policies": len(inv["entra_ca_policies"]),
        "Entra Application Registrations": len(inv["entra_applications"]),
        "Entra Service Principals": len(inv["entra_service_principals"]),
    }
