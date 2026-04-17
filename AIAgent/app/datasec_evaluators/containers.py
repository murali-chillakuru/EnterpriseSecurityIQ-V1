"""
Data Security — Container Security evaluator (ACR/AKS).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_container_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_acr_admin_access(evidence_index))
    findings.extend(_check_acr_vulnerability_scanning(evidence_index))
    findings.extend(_check_aks_rbac(evidence_index))
    findings.extend(_check_aks_network_policy(evidence_index))
    findings.extend(_check_acr_quarantine_policy(evidence_index))
    findings.extend(_check_aks_pod_security_standards(evidence_index))
    return findings


def _check_acr_admin_access(idx: dict) -> list[dict]:
    """Flag container registries with admin user enabled."""
    registries = idx.get("azure-containerregistry", [])
    admin_enabled: list[dict] = []
    for ev in registries:
        data = ev.get("Data", ev.get("data", {}))
        admin = data.get("AdminUserEnabled", data.get("adminUserEnabled"))
        if admin is True:
            admin_enabled.append({
                "Type": "ContainerRegistry",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if admin_enabled:
        return [_ds_finding(
            "container_security", "acr_admin_enabled",
            f"{len(admin_enabled)} container registries with admin user enabled",
            "The ACR admin account provides broad pull/push access and cannot be scoped. "
            "Use Azure AD service principals or managed identities instead.",
            "high", admin_enabled,
            {"Description": "Disable ACR admin user and use RBAC-based authentication.",
             "AzureCLI": "az acr update -n <registry> --admin-enabled false",
             "PortalSteps": [
                 "Navigate to Container Registry > Access keys",
                 "Toggle Admin user to Disabled",
             ]},
        )]
    return []


def _check_acr_vulnerability_scanning(idx: dict) -> list[dict]:
    """Flag ACR without Defender for Containers vulnerability scanning."""
    registries = idx.get("azure-containerregistry", [])
    no_scanning: list[dict] = []
    for ev in registries:
        data = ev.get("Data", ev.get("data", {}))
        policies = data.get("Policies", data.get("policies", {})) or {}
        # Defender for Containers enables automatic image scanning
        # We flag registries that don't have quarantine or trust policies
        # Note: actual Defender coverage checked at subscription level
        sku_name = (data.get("Sku", data.get("sku", {})) or {}).get("name", "").lower()
        if sku_name == "basic":
            no_scanning.append({
                "Type": "ContainerRegistry",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Sku": sku_name,
                "Reason": "Basic SKU lacks vulnerability scanning support",
            })
    if no_scanning:
        return [_ds_finding(
            "container_security", "acr_no_vulnerability_scanning",
            f"{len(no_scanning)} container registries on Basic SKU (no vulnerability scanning)",
            "Azure Container Registry on Basic SKU does not support Defender for Containers "
            "image scanning. Upgrade to Standard or Premium for vulnerability assessments.",
            "medium", no_scanning,
            {"Description": "Upgrade ACR to Standard/Premium SKU and enable Defender for Containers.",
             "AzureCLI": "az acr update -n <registry> --sku Standard"},
        )]
    return []


def _check_aks_rbac(idx: dict) -> list[dict]:
    """Flag AKS clusters without Kubernetes RBAC or Azure AD integration."""
    clusters = idx.get("azure-aks", [])
    no_rbac: list[dict] = []
    for ev in clusters:
        data = ev.get("Data", ev.get("data", {}))
        rbac_enabled = data.get("EnableRBAC", data.get("enableRBAC"))
        aad_profile = data.get("AadProfile", data.get("aadProfile"))
        issues: list[str] = []
        if rbac_enabled is False:
            issues.append("Kubernetes RBAC disabled")
        if not aad_profile:
            issues.append("No Azure AD integration")
        if issues:
            no_rbac.append({
                "Type": "AKSCluster",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Issues": ", ".join(issues),
            })
    if no_rbac:
        return [_ds_finding(
            "container_security", "aks_rbac_issues",
            f"{len(no_rbac)} AKS clusters with RBAC or Azure AD issues",
            "AKS clusters without Kubernetes RBAC and Azure AD integration "
            "cannot enforce fine-grained access control, risking unauthorized workload access.",
            "high", no_rbac,
            {"Description": "Enable Kubernetes RBAC and Azure AD integration.",
             "AzureCLI": (
                 "az aks update -g <rg> -n <cluster> --enable-aad "
                 "--aad-admin-group-object-ids <group-id>"
             ),
             "PortalSteps": [
                 "Navigate to AKS cluster > Configuration",
                 "Enable Azure Active Directory authentication",
                 "Enable Kubernetes RBAC",
             ]},
        )]
    return []


def _check_aks_network_policy(idx: dict) -> list[dict]:
    """Flag AKS clusters without network policies configured."""
    clusters = idx.get("azure-aks", [])
    no_netpol: list[dict] = []
    for ev in clusters:
        data = ev.get("Data", ev.get("data", {}))
        net_policy = data.get("NetworkPolicy", data.get("networkPolicy",
                    data.get("properties_networkProfile_networkPolicy")))
        if not net_policy:
            no_netpol.append({
                "Type": "AKSCluster",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "NetworkPlugin": data.get("NetworkPlugin", data.get("networkPlugin",
                    data.get("properties_networkProfile_networkPlugin", "Unknown"))),
            })
    if no_netpol:
        return [_ds_finding(
            "container_security", "aks_no_network_policy",
            f"{len(no_netpol)} AKS clusters without network policies",
            "Without network policies, all pods can communicate freely, "
            "allowing lateral movement if a workload is compromised. "
            "Network policies enforce micro-segmentation at the pod level.",
            "medium", no_netpol,
            {"Description": "Enable network policies on AKS clusters.",
             "AzureCLI": (
                 "# Network policy requires Azure CNI or Calico at cluster creation:\n"
                 "az aks create -g <rg> -n <cluster> --network-plugin azure "
                 "--network-policy calico"
             ),
             "PortalSteps": [
                 "Navigate to AKS cluster > Networking",
                 "Review network policy configuration (requires cluster recreation if not set)",
             ]},
        )]
    return []


def _check_acr_quarantine_policy(idx: dict) -> list[dict]:
    """Flag ACR registries without quarantine policy enabled."""
    registries = idx.get("azure-containerregistry", [])
    no_quarantine: list[dict] = []
    for ev in registries:
        data = ev.get("Data", ev.get("data", {}))
        policies = data.get("Policies", data.get("policies", {})) or {}
        quarantine = policies.get("quarantinePolicy", {}) if isinstance(policies, dict) else {}
        status = quarantine.get("status", "").lower() if isinstance(quarantine, dict) else ""
        sku_name = (data.get("Sku", data.get("sku", {})) or {}).get("name", "").lower()
        if sku_name == "premium" and status != "enabled":
            no_quarantine.append({
                "Type": "ContainerRegistry",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Sku": sku_name,
            })
    if no_quarantine:
        return [_ds_finding(
            "container_security", "acr_no_quarantine",
            f"{len(no_quarantine)} Premium ACR registries without quarantine policy",
            "Quarantine policy holds newly pushed images in quarantine until they pass "
            "vulnerability scanning, preventing unscanned images from being deployed.",
            "low", no_quarantine,
            {"Description": "Enable quarantine policy on Premium ACR registries.",
             "AzureCLI": "az acr config quarantine update -r <registry> --status Enabled"},
        )]
    return []


def _check_aks_pod_security_standards(idx: dict) -> list[dict]:
    """Flag AKS clusters without Pod Security Standards (Admission) configured."""
    clusters = idx.get("azure-aks", [])
    no_pss: list[dict] = []
    for ev in clusters:
        data = ev.get("Data", ev.get("data", {}))
        security_profile = data.get("securityProfile", data.get("SecurityProfile", {})) or {}
        workload_id = security_profile.get("workloadIdentity", {})
        defender = security_profile.get("defender", {})
        # Check if Azure Policy add-on is enabled (enforces pod security)
        addons = data.get("addonProfiles", data.get("AddonProfiles", {})) or {}
        policy_addon = addons.get("azurepolicy", addons.get("AzurePolicy", {})) or {}
        policy_enabled = policy_addon.get("enabled", False) if isinstance(policy_addon, dict) else False
        if not policy_enabled:
            no_pss.append({
                "Type": "AKSCluster",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "PolicyAddon": "Disabled",
            })
    if no_pss:
        return [_ds_finding(
            "container_security", "aks_no_pod_security",
            f"{len(no_pss)} AKS clusters without Azure Policy add-on for pod security",
            "Without the Azure Policy add-on, Pod Security Standards cannot be enforced. "
            "This allows privileged containers and other risky workload configurations.",
            "medium", no_pss,
            {"Description": "Enable Azure Policy add-on on AKS clusters.",
             "AzureCLI": "az aks enable-addons -g <rg> -n <cluster> --addons azure-policy"},
        )]
    return []


