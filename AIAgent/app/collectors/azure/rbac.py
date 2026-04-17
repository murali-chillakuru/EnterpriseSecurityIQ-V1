"""
Azure RBAC Collector
Collects role assignments across all subscriptions.
"""

from __future__ import annotations
from azure.mgmt.authorization.aio import AuthorizationManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

PRIVILEGED_ROLES = [
    # Original 5 roles
    "Owner", "Contributor", "User Access Administrator",
    "Security Admin", "Global Administrator",
    # Phase 1 expansion — Azure built-in high-privilege roles
    "Key Vault Administrator",
    "Key Vault Secrets Officer",
    "Storage Account Contributor",
    "Virtual Machine Contributor",
    "Network Contributor",
    "SQL Server Contributor",
    "SQL Security Manager",
    "Monitoring Contributor",
    "Log Analytics Contributor",
    "Automation Operator",
    "Managed Identity Operator",
    "Role Based Access Control Administrator",
    "Azure Kubernetes Service Cluster Admin Role",
    "Azure Kubernetes Service RBAC Admin",
]


@register_collector(name="rbac", plane="control", source="azure", priority=20)
async def collect_azure_rbac(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        role_def_cache: dict[str, tuple[str, str]] = {}  # role_definition_id → (name, type)
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = AuthorizationManagementClient(creds.credential, sub_id)
                assignments = await paginate_arm(client.role_assignments.list_for_subscription())
                for ra in assignments:
                    role_name = ""
                    if ra.role_definition_id:
                        parts = ra.role_definition_id.split("/")
                        role_name = parts[-1] if parts else ""
                    # Resolve role definition name (cached to avoid N+1 API calls)
                    if ra.role_definition_id in role_def_cache:
                        role_name, role_type = role_def_cache[ra.role_definition_id]
                    else:
                        try:
                            role_def = await client.role_definitions.get_by_id(ra.role_definition_id)
                            role_name = role_def.role_name or role_name
                            role_type = role_def.role_type or "BuiltInRole"
                            role_def_cache[ra.role_definition_id] = (role_name, role_type)
                        except Exception:
                            role_type = "Unknown"
                            role_def_cache[ra.role_definition_id] = (role_name, role_type)

                    scope = ra.scope or ""
                    scope_level = "Unknown"
                    if "/managementGroups/" in scope:
                        scope_level = "ManagementGroup"
                    elif scope.count("/") <= 2:
                        scope_level = "Subscription"
                    elif "/resourceGroups/" in scope and scope.count("/") <= 4:
                        scope_level = "ResourceGroup"
                    else:
                        scope_level = "Resource"

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureRBAC",
                        evidence_type="azure-role-assignment",
                        description=f"Role: {role_name} → {ra.principal_id}",
                        data={
                            "RoleAssignmentId": ra.id,
                            "RoleDefinitionName": role_name,
                            "RoleDefinitionId": ra.role_definition_id,
                            "PrincipalId": ra.principal_id,
                            "PrincipalType": _v(ra.principal_type, "Unknown"),
                            "Scope": scope,
                            "ScopeLevel": scope_level,
                            "RoleType": role_type,
                            "IsPrivileged": role_name in PRIVILEGED_ROLES,
                            "IsCustom": role_type == "CustomRole",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ra.id or "", resource_type="RoleAssignment",
                    ))
                await client.close()
                log.info("  [AzureRBAC] %s: %d assignments", sub_name, len(assignments))
            except Exception as exc:
                log.warning("  [AzureRBAC] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureRBAC", Source.AZURE, _collect)).data
