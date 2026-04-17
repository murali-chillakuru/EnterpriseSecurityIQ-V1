"""Shared helpers and constants for RBAC evaluators."""

from __future__ import annotations


PRIVILEGED_ROLES = [
    "Owner", "Contributor", "User Access Administrator",
    "Security Admin", "Global Administrator",
    "Key Vault Administrator", "Key Vault Secrets Officer",
    "Storage Account Contributor", "Virtual Machine Contributor",
    "Network Contributor", "SQL Server Contributor",
    "SQL Security Manager", "Monitoring Contributor",
    "Log Analytics Contributor", "Automation Operator",
    "Managed Identity Operator", "Role Based Access Control Administrator",
    "Azure Kubernetes Service Cluster Admin Role",
    "Azure Kubernetes Service RBAC Admin",
]


def scope_level(scope: str) -> str:
    """Classify an ARM scope string."""
    if not scope:
        return "Unknown"
    if scope.strip() == "/":
        return "ManagementGroup"
    if "/managementGroups/" in scope:
        return "ManagementGroup"
    parts = scope.strip("/").split("/")
    if len(parts) <= 2:
        return "Subscription"
    if "/resourceGroups/" in scope or "/resourcegroups/" in scope:
        if scope.lower().rstrip("/").endswith(parts[-1].lower()) and len(parts) <= 4:
            return "ResourceGroup"
        return "Resource"
    return "Resource"


def rg_from_scope(scope: str) -> str:
    """Extract resource group name from an ARM scope."""
    parts = scope.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _extract_principal_type(ra) -> str:
    """Safely get principal_type from various SDK objects."""
    pt = getattr(ra, "principal_type", None)
    if pt is None:
        return "Unknown"
    return pt.value if hasattr(pt, "value") else str(pt)


def make_assignment(ra, role_name: str, role_type: str, status: str = "Active") -> dict:
    """Convert an SDK role assignment or eligibility to a standard dict."""
    scope = getattr(ra, "scope", "") or ""
    pid = getattr(ra, "principal_id", "") or ""
    return {
        "id": getattr(ra, "id", "") or "",
        "role_name": role_name,
        "role_definition_id": getattr(ra, "role_definition_id", "") or "",
        "principal_id": pid,
        "principal_type": _extract_principal_type(ra),
        "scope": scope,
        "scope_level": scope_level(scope),
        "status": status,
        "is_privileged": role_name in PRIVILEGED_ROLES,
        "is_custom": role_type == "CustomRole",
    }
