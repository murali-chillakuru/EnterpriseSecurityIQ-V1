"""Resource / user detail drill-down."""

from __future__ import annotations
from typing import Any
from app.auth import ComplianceCredentials
from app.logger import log


async def get_resource_detail(
    creds: ComplianceCredentials,
    resource_id: str,
) -> dict:
    """Get full details of a specific Azure resource by its resource ID."""
    from azure.mgmt.resource import ResourceManagementClient

    # Parse subscription from resource ID
    parts = resource_id.strip("/").split("/")
    try:
        sub_idx = parts.index("subscriptions")
        sub_id = parts[sub_idx + 1]
    except (ValueError, IndexError):
        return {"error": f"Cannot parse subscription from resource ID: {resource_id}"}

    client = ResourceManagementClient(creds.credential, sub_id)
    try:
        resource = await client.resources.get_by_id(resource_id, api_version="2024-03-01")
        result = {
            "id": resource.id,
            "name": resource.name,
            "type": resource.type,
            "location": resource.location,
            "tags": dict(resource.tags) if resource.tags else {},
            "sku": resource.sku.as_dict() if resource.sku else None,
            "kind": resource.kind,
            "properties": resource.properties if resource.properties else {},
        }
        return result
    except Exception as exc:
        return {"error": f"Failed to get resource details: {exc}"}
    finally:
        await client.close()


async def get_entra_user_detail(
    creds: ComplianceCredentials,
    user_id: str,
) -> dict:
    """Get detailed info about a specific Entra user."""
    graph = creds.get_graph_client()
    try:
        user = await graph.users.by_user_id(user_id).get()
        if not user:
            return {"error": f"User {user_id} not found"}

        # Get group memberships
        member_of = await graph.users.by_user_id(user_id).member_of.get()
        groups = []
        roles = []
        if member_of and member_of.value:
            for item in member_of.value:
                odata = getattr(item, "odata_type", "") or ""
                name = getattr(item, "display_name", "unknown")
                if "#microsoft.graph.group" in odata:
                    groups.append(name)
                elif "#microsoft.graph.directoryRole" in odata:
                    roles.append(name)

        result = {
            "id": user.id,
            "displayName": user.display_name,
            "userPrincipalName": user.user_principal_name,
            "accountEnabled": user.account_enabled,
            "userType": user.user_type,
            "createdDateTime": str(user.created_date_time) if user.created_date_time else None,
            "lastSignInDateTime": str(user.sign_in_activity.last_sign_in_date_time)
                if user.sign_in_activity and user.sign_in_activity.last_sign_in_date_time else None,
            "groups": groups,
            "directoryRoles": roles,
            "jobTitle": user.job_title,
            "department": user.department,
            "mfaRegistered": None,  # populated below if available
        }

        # Try to get auth methods (MFA status)
        try:
            auth_methods = await graph.users.by_user_id(user.id).authentication.methods.get()
            if auth_methods and auth_methods.value:
                method_types = [getattr(m, "odata_type", "unknown") for m in auth_methods.value]
                result["authMethods"] = method_types
                # MFA is registered if there's more than just password
                non_password = [m for m in method_types if "password" not in (m or "").lower()]
                result["mfaRegistered"] = len(non_password) > 0
        except Exception:
            pass  # scope may not be available

        return result
    except Exception as exc:
        return {"error": f"Failed to get user details: {exc}"}


# ---------------------------------------------------------------------------
# Compliance cross-reference
# ---------------------------------------------------------------------------

