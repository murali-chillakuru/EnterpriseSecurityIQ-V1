"""Inventory builders for M365 Copilot readiness reports."""

from __future__ import annotations


def _build_site_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build a consolidated site inventory from SPO evidence for the report."""
    sites = evidence_index.get("spo-site-inventory", [])
    perms_map: dict[str, dict] = {}
    for ev in evidence_index.get("spo-site-permissions", []):
        data = ev.get("Data", ev.get("data", {}))
        sid = data.get("SiteId", "")
        if sid:
            perms_map[sid] = data
    sharing_map: dict[str, dict] = {}
    for ev in evidence_index.get("spo-sharing-links", []):
        data = ev.get("Data", ev.get("data", {}))
        sid = data.get("SiteId", "")
        if sid:
            sharing_map[sid] = data

    inventory: list[dict] = []
    for ev in sites:
        data = ev.get("Data", ev.get("data", {}))
        sid = data.get("SiteId", "")
        perms = perms_map.get(sid, {})
        sharing = sharing_map.get(sid, {})
        inventory.append({
            "SiteName": data.get("SiteName", ""),
            "WebUrl": data.get("WebUrl", ""),
            "SensitivityLabel": data.get("SensitivityLabel", "") or "None",
            "IsStale": data.get("IsStale", False),
            "IsRoot": data.get("IsRoot", False),
            "DiscoveryMethod": data.get("DiscoveryMethod", ""),
            "TotalPermissions": perms.get("TotalPermissions", 0),
            "OwnerCount": perms.get("OwnerCount", 0),
            "MemberCount": perms.get("MemberCount", 0),
            "GuestCount": perms.get("GuestCount", 0),
            "ExternalUserCount": perms.get("ExternalUserCount", 0),
            "IsOvershared": perms.get("IsOvershared", False),
            "TotalSharedItems": sharing.get("TotalSharedItems", 0),
            "AnonymousLinks": sharing.get("AnonymousLinks", 0),
            "OrganizationLinks": sharing.get("OrganizationLinks", 0),
            "ExternalLinks": sharing.get("ExternalLinks", 0),
        })
    return inventory


def _build_license_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build a license/SKU inventory from subscribed SKUs evidence."""
    skus = evidence_index.get("m365-subscribed-skus", [])
    inventory: list[dict] = []
    for ev in skus:
        data = ev.get("Data", ev.get("data", {}))
        inventory.append({
            "SkuPartNumber": data.get("SkuPartNumber", ""),
            "EnabledUnits": data.get("EnabledUnits", 0),
            "ConsumedUnits": data.get("ConsumedUnits", 0),
        })
    return sorted(inventory, key=lambda x: x.get("ConsumedUnits", 0), reverse=True)


def _build_label_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build a sensitivity label inventory from individual label definitions."""
    labels = evidence_index.get("m365-sensitivity-label-definition", [])
    if not labels:
        return []
    inventory: list[dict] = []
    for ev in labels:
        data = ev.get("Data", ev.get("data", {}))
        inventory.append({
            "Name": data.get("Name", ""),
            "Priority": data.get("Priority", 0),
            "IsActive": data.get("IsActive", True),
            "ParentId": data.get("ParentId", ""),
            "ContentType": data.get("ContentType", ""),
            "Color": data.get("Color", ""),
            "IsEncryptionEnabled": data.get("IsEncryptionEnabled", False),
            "HasSiteAndGroupSettings": data.get("HasSiteAndGroupSettings", False),
        })
    return sorted(inventory, key=lambda x: x.get("Priority", 0))


def _build_app_protection_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build an App Protection Policy (MAM) inventory from Intune evidence."""
    policies = evidence_index.get("intune-app-protection-policies", [])
    if not policies:
        return []
    inventory: list[dict] = []
    for ev in policies:
        data = ev.get("Data", ev.get("data", {}))
        inventory.append({
            "PolicyName": data.get("PolicyName", data.get("DisplayName", "")),
            "Platform": data.get("Platform", ""),
            "IsActive": data.get("IsActive", True),
            "AssignedApps": data.get("AssignedApps", 0),
            "Scope": data.get("Scope", ""),
            "EncryptionRequired": data.get("EncryptionRequired", False),
            "PinRequired": data.get("PinRequired", False),
            "CopyPasteBlocked": data.get("CopyPasteBlocked", False),
        })
    return sorted(inventory, key=lambda x: (x.get("Platform", ""), x.get("PolicyName", "")))


def _build_ca_policy_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build a Conditional Access policy inventory."""
    policies = evidence_index.get("entra-conditional-access-policy", [])
    inventory: list[dict] = []
    for ev in policies:
        data = ev.get("Data", ev.get("data", {}))
        controls = data.get("GrantControls", [])
        grants = ", ".join(controls) if isinstance(controls, list) else str(controls)
        inventory.append({
            "DisplayName": data.get("DisplayName", ""),
            "State": data.get("State", ""),
            "RequiresMFA": data.get("RequiresMFA", False),
            "RequiresCompliantDevice": data.get("RequiresCompliantDevice", False),
            "TargetsAllUsers": data.get("TargetsAllUsers", False),
            "BlocksLegacyAuth": data.get("BlocksLegacyAuth", False),
            "HasLocationCondition": data.get("HasLocationCondition", False),
            "GrantControls": grants,
        })
    return sorted(inventory, key=lambda x: (x.get("State") != "enabled", x.get("DisplayName", "")))


def _build_groups_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build an M365 Groups & Teams inventory."""
    groups = evidence_index.get("m365-groups", [])
    inventory: list[dict] = []
    for ev in groups:
        data = ev.get("Data", ev.get("data", {}))
        inventory.append({
            "DisplayName": data.get("DisplayName", ""),
            "IsTeam": data.get("IsTeam", False),
            "Visibility": data.get("Visibility", "Private"),
            "MailEnabled": data.get("MailEnabled", False),
            "SecurityEnabled": data.get("SecurityEnabled", False),
            "Mail": data.get("Mail", ""),
            "CreatedDate": data.get("CreatedDate", ""),
        })
    return sorted(inventory, key=lambda x: (not x.get("IsTeam"), x.get("DisplayName", "")))


def _build_dlp_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build a DLP policy inventory from available evidence."""
    dlp = evidence_index.get("m365-dlp-policies", [])
    inventory: list[dict] = []
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        locations = data.get("locations", [])
        workloads = ", ".join(loc.get("workload", "") for loc in locations) if isinstance(locations, list) else ""
        inventory.append({
            "PolicyName": data.get("name", data.get("Name", "")),
            "State": data.get("state", data.get("State", "")),
            "Workloads": workloads,
        })
    return inventory


def _build_entra_apps_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build an Entra ID application registration inventory."""
    apps = evidence_index.get("entra-applications", [])
    inventory: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        inventory.append({
            "AppId": data.get("AppId", ""),
            "DisplayName": data.get("DisplayName", ""),
            "CreatedDate": data.get("CreatedDate", ""),
            "SignInAudience": data.get("SignInAudience", ""),
            "HasGraphAccess": data.get("HasGraphAccess", False),
            "DelegatedPermissions": data.get("DelegatedPermissions", 0),
            "ApplicationPermissions": data.get("ApplicationPermissions", 0),
            "TotalPermissions": data.get("TotalPermissions", 0),
            "CertificateCount": data.get("CertificateCount", 0),
            "SecretCount": data.get("SecretCount", 0),
        })
    return sorted(inventory, key=lambda x: x.get("TotalPermissions", 0), reverse=True)


def _build_service_principal_inventory(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Build an Entra service principal (enterprise app) inventory."""
    sps = evidence_index.get("entra-service-principals", [])
    inventory: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        inventory.append({
            "ServicePrincipalId": data.get("ServicePrincipalId", ""),
            "AppId": data.get("AppId", ""),
            "DisplayName": data.get("DisplayName", ""),
            "Type": data.get("Type", ""),
            "Enabled": data.get("Enabled", True),
            "IsEnterprise": data.get("IsEnterprise", False),
            "AppRoleAssignmentCount": data.get("AppRoleAssignmentCount", 0),
        })
    return sorted(inventory, key=lambda x: (not x.get("IsEnterprise"), x.get("DisplayName", "")))

