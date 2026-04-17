"""
Data Protection Domain Evaluator
Controls: SC-8, SC-28, SC-12, SC-28(1), SC-8(1), SC-28(2), CM-7(2).
"""

from __future__ import annotations
import re
from app.models import FindingRecord, Status, Severity


def _tls_below(version: str, target: str = "1.2") -> bool:
    """Compare TLS versions numerically. Handles '1.0', '1.2', 'TLS1_0', 'TLS1_2' formats."""
    def _parse(v: str) -> tuple[int, int]:
        m = re.search(r'(\d+)[._](\d+)', v)
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return _parse(version) < _parse(target)


from app.config import ThresholdConfig


def evaluate_data_protection(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_data_in_transit_encryption": _check_data_in_transit,
        "check_data_at_rest_encryption": _check_data_at_rest,
        "check_storage_cmk": _check_storage_cmk,
        "check_keyvault_security": _check_keyvault_security,
        "check_key_vault_security": _check_keyvault_security,
        "check_keyvault_expiry": _check_keyvault_expiry,
        "check_vm_security": _check_vm_security,
        "check_webapp_security": _check_webapp_security,
        "check_sql_security": _check_sql_security,
        "check_aks_security": _check_aks_security,
        "check_ai_services_security": _check_ai_services_security,
        "check_storage_account_security": _check_storage_account_security,
        "check_container_registry_security": _check_container_registry_security,
        "check_cosmosdb_security": _check_cosmosdb_security,
        "check_database_server_security": _check_database_server_security,
        "check_storage_container_security": _check_storage_container_security,
        "check_sql_detailed_security": _check_sql_detailed_security,
        "check_database_config_security": _check_database_config_security,
        "check_function_app_security": _check_function_app_security,
        "check_messaging_security": _check_messaging_security,
        "check_redis_security": _check_redis_security,
        "check_cosmosdb_advanced_security": _check_cosmosdb_advanced_security,
        "check_data_analytics_security": _check_data_analytics_security,
        "check_purview_classification": _check_purview_classification,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", "FedRAMP"),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="data_protection", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[
            {"ResourceId": resource_id, "ResourceName": resource_name,
             "ResourceType": resource_type}
        ] if resource_name else (evidence_items or []),
    ).to_dict()


def _res(item, rtype=""):
    """Extract resource context from an evidence item for FindingRecord."""
    d = item.get("Data", {})
    ctx = item.get("Context", {})
    return dict(
        resource_id=d.get("ResourceId") or ctx.get("ResourceId") or item.get("ResourceId", ""),
        resource_name=d.get("Name") or d.get("DisplayName") or ctx.get("ResourceName", ""),
        resource_type=rtype or d.get("ResourceType") or ctx.get("ResourceType", ""),
    )


def _check_data_in_transit(cid, ctrl, evidence, idx):
    findings = []
    webapps = idx.get("azure-webapp-config", [])
    storage = idx.get("azure-storage-security", [])
    sql = idx.get("azure-sql-server", [])

    for w in webapps:
        d = w.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(w, "Microsoft.Web/sites")
        if not d.get("HttpsOnly"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Web app '{name}' does not enforce HTTPS.",
                              recommendation="Enable HTTPS-only on the web app via Configuration > General settings.", **r))
        min_tls = d.get("MinTlsVersion") or "1.0"
        if _tls_below(min_tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Web app '{name}' TLS version ({min_tls}) < 1.2.",
                              recommendation="Set minimum TLS version to 1.2 in the web app Configuration > General settings.", **r))

    for s in storage:
        d = s.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(s, "Microsoft.Storage/storageAccounts")
        if not d.get("EnableHttpsTrafficOnly"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' allows HTTP traffic.",
                              recommendation="Enable 'Secure transfer required' on the storage account to enforce HTTPS.", **r))
        tls = d.get("MinimumTlsVersion") or "TLS1_0"
        if _tls_below(tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' TLS ({tls}) < TLS1_2.",
                              recommendation="Set minimum TLS version to TLS 1.2 on the storage account.", **r))

    for q in sql:
        d = q.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(q, "Microsoft.Sql/servers")
        tls = d.get("MinimalTlsVersion") or "1.0"
        if _tls_below(tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"SQL Server '{name}' TLS ({tls}) < 1.2.",
                              recommendation="Set minimum TLS version to 1.2 on the SQL Server.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "Data in transit encryption checks passed."))
    return findings


def _check_data_at_rest(cid, ctrl, evidence, idx):
    findings = []
    vms = idx.get("azure-vm-config", [])
    sql = idx.get("azure-sql-server", [])

    for v in vms:
        d = v.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(v, "Microsoft.Compute/virtualMachines")
        if not d.get("OsDiskEncrypted"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"VM '{name}' OS disk not encrypted.",
                              recommendation="Enable Azure Disk Encryption (ADE) or host-based encryption on the VM.", **r))
        if d.get("DataDiskCount", 0) > 0 and not d.get("DataDisksEncrypted"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"VM '{name}' has unencrypted data disks.",
                              recommendation="Enable Azure Disk Encryption for all data disks on the VM.", **r))

    for q in sql:
        d = q.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(q, "Microsoft.Sql/servers")
        if not d.get("TdeEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"SQL Server '{name}' missing TDE on some databases.",
                              recommendation="Enable Transparent Data Encryption (TDE) on all databases in the SQL Server.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "Data at rest encryption checks passed."))
    return findings


def _check_storage_cmk(cid, ctrl, evidence, idx):
    findings = []
    policies = idx.get("azure-policy-assignment", [])
    cmk_policies = [p for p in policies if "cmk" in str(p.get("Data", {}).get("DisplayName", "")).lower()
                    or "customer" in str(p.get("Data", {}).get("DisplayName", "")).lower()]
    kv = idx.get("azure-keyvault", [])
    storage = idx.get("azure-storage-account", []) or idx.get("azure-storage-security", [])

    if cmk_policies:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                   f"CMK enforcement policies found ({len(cmk_policies)})."))
    elif kv and storage:
        # Check if storage accounts actually use CMK (Encryption.KeySource == Microsoft.Keyvault)
        cmk_storage = [s for s in storage
                       if s.get("Data", {}).get("EncryptionKeySource", "").lower()
                       in ("microsoft.keyvault", "keyvault")]
        if cmk_storage:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                       f"{len(cmk_storage)}/{len(storage)} storage accounts use CMK encryption."))
        else:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                       f"Key Vaults present ({len(kv)}) but no storage accounts configured with CMK encryption."))
    elif kv:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                   f"Key Vaults present ({len(kv)}) but no storage accounts to verify CMK."))
    else:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, "No CMK policies or Key Vaults found."))
    return findings


def _check_keyvault_security(cid, ctrl, evidence, idx):
    findings = []
    kvs = idx.get("azure-keyvault", [])
    for kv in kvs:
        d = kv.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(kv, "Microsoft.KeyVault/vaults")
        if not d.get("EnableSoftDelete"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Key Vault '{name}' soft delete disabled.",
                              recommendation="Enable soft delete on the Key Vault to protect against accidental deletion.", **r))
        if not d.get("EnablePurgeProtection"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Key Vault '{name}' purge protection disabled.",
                              recommendation="Enable purge protection on the Key Vault for regulatory compliance.", **r))
        if not d.get("EnableRbacAuthorization"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Key Vault '{name}' using access policies (not RBAC).",
                              recommendation="Switch Key Vault from access policies to Azure RBAC for unified access management.", **r))
        if d.get("NetworkAclsDefaultAction", "Allow") != "Deny":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Key Vault '{name}' network not restricted (default action: {d.get('NetworkAclsDefaultAction', 'Allow')}).",
                              recommendation="Configure Key Vault firewall to deny public access. Use private endpoints.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Key Vault security checks passed."))
    return findings


def _check_vm_security(cid, ctrl, evidence, idx):
    findings = []
    vms = idx.get("azure-vm-config", [])
    for v in vms:
        d = v.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(v, "Microsoft.Compute/virtualMachines")
        if not d.get("OsDiskEncrypted"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"VM '{name}' OS disk not encrypted.",
                              recommendation="Enable Azure Disk Encryption (ADE) or host-based encryption on the VM.", **r))
        if d.get("DataDiskCount", 0) > 0 and not d.get("DataDisksEncrypted"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"VM '{name}' unencrypted data disks.",
                              recommendation="Enable Azure Disk Encryption for all data disks on the VM.", **r))
        if d.get("IdentityType", "None") == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"VM '{name}' no managed identity.",
                              recommendation="Enable a system-assigned or user-assigned managed identity on the VM.", **r))
        if not d.get("BootDiagnosticsEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"VM '{name}' boot diagnostics disabled.",
                              recommendation="Enable boot diagnostics on the VM for troubleshooting support.", **r))
        if not d.get("HasMDEExtension"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"VM '{name}' no MDE extension.",
                              recommendation="Install the Microsoft Defender for Endpoint (MDE) extension on the VM.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "VM security checks passed."))
    return findings


def _check_webapp_security(cid, ctrl, evidence, idx):
    findings = []
    webapps = idx.get("azure-webapp-config", [])
    for w in webapps:
        d = w.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(w, "Microsoft.Web/sites")
        if not d.get("HttpsOnly"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"Web app '{name}' HTTPS not enforced.",
                              recommendation="Enable HTTPS-only on the web app via Configuration > General settings.", **r))
        if _tls_below(d.get("MinTlsVersion") or "1.0"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"Web app '{name}' TLS < 1.2.",
                              recommendation="Set minimum TLS version to 1.2 in the web app settings.", **r))
        if d.get("FtpsState", "") not in ("FtpsOnly", "Disabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"Web app '{name}' FTP allowed.",
                              recommendation="Disable FTP or set FTPS-only on the web app.", **r))
        if d.get("RemoteDebuggingEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"Web app '{name}' remote debugging enabled.",
                              recommendation="Disable remote debugging on the web app via Configuration > General settings.", **r))
        if d.get("ManagedIdentityType", "None") == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"Web app '{name}' no managed identity.",
                              recommendation="Enable a managed identity for the web app to authenticate to Azure services.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Web app security checks passed."))
    return findings


def _check_sql_security(cid, ctrl, evidence, idx):
    findings = []
    sql = idx.get("azure-sql-server", [])
    for q in sql:
        d = q.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(q, "Microsoft.Sql/servers")
        if not d.get("AdAdminConfigured"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"SQL '{name}' no Azure AD admin.",
                              recommendation="Configure an Azure AD administrator for the SQL Server.", **r))
        if not d.get("AuditingEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"SQL '{name}' auditing disabled.",
                              recommendation="Enable auditing on the SQL Server to track database events.", **r))
        if not d.get("TdeEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"SQL '{name}' TDE not enabled.",
                              recommendation="Enable Transparent Data Encryption (TDE) on all databases.", **r))
        if d.get("PublicNetworkAccess", "Enabled") != "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"SQL '{name}' public network access enabled.",
                              recommendation="Disable public network access on the SQL Server. Use private endpoints.", **r))
        if _tls_below(d.get("MinimalTlsVersion") or "1.0"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"SQL '{name}' TLS < 1.2.",
                              recommendation="Set minimum TLS version to 1.2 on the SQL Server.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "SQL security checks passed."))
    return findings


def _check_aks_security(cid, ctrl, evidence, idx):
    findings = []
    aks = idx.get("azure-aks-cluster", [])
    for a in aks:
        d = a.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(a, "Microsoft.ContainerService/managedClusters")
        if not d.get("RbacEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"AKS '{name}' RBAC disabled.",
                              recommendation="Enable Kubernetes RBAC on the AKS cluster.", **r))
        if not d.get("AadEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"AKS '{name}' AAD disabled.",
                              recommendation="Enable Azure AD integration on the AKS cluster.", **r))
        if not d.get("NetworkPolicy"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"AKS '{name}' no network policy.",
                              recommendation="Enable a network policy (Calico or Azure) on the AKS cluster.", **r))
        if not (d.get("PrivateCluster") or d.get("IsPrivateCluster")):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"AKS '{name}' not private cluster.",
                              recommendation="Enable private cluster mode to restrict API server access.", **r))
        if not d.get("DefenderEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT, f"AKS '{name}' Defender disabled.",
                              recommendation="Enable Microsoft Defender for Containers on the AKS cluster.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "AKS security checks passed."))
    return findings


def _default(cid, ctrl, evidence, idx):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for data_protection control ({len(evidence)} items).")]


def _check_ai_services_security(cid, ctrl, evidence, idx):
    """Check Azure Cognitive Services / OpenAI account security configuration."""
    findings = []
    accounts = idx.get("azure-cognitive-account", [])

    if not accounts:
        return [_f(cid, ctrl, Status.COMPLIANT, "No Cognitive Services accounts to evaluate.")]

    for acct in accounts:
        d = acct.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(acct, "Microsoft.CognitiveServices/accounts")

        # Check public network access
        if d.get("PublicNetworkAccess", "Enabled") != "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AI account '{name}' public network access enabled.",
                              recommendation="Disable public network access on the Cognitive Services account. Use private endpoints.", **r))
        # Check network restrictions
        if not d.get("NetworkDefaultAction") or d.get("NetworkDefaultAction") == "Allow":
            if d.get("PublicNetworkAccess", "Enabled") != "Disabled":
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"AI account '{name}' has no network restrictions (default action: Allow).",
                                  recommendation="Configure network ACLs to deny by default on the Cognitive Services account.", **r))
        # Check managed identity
        mi_type = d.get("ManagedIdentityType", "")
        if not mi_type or mi_type == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AI account '{name}' has no managed identity.",
                              recommendation="Enable a managed identity on the Cognitive Services account for secure authentication.", **r))
        # Check local auth disabled
        if not d.get("DisableLocalAuth"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AI account '{name}' local auth (API keys) enabled.",
                              recommendation="Disable local authentication on the Cognitive Services account. Use Azure AD auth.", **r))
        # Check encryption (CMK)
        if not d.get("Encryption"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AI account '{name}' not using customer-managed key encryption.",
                              recommendation="Enable customer-managed key (CMK) encryption on the Cognitive Services account.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(accounts)} AI service accounts pass security checks."))
    return findings


def _check_keyvault_expiry(cid, ctrl, evidence, idx):
    """Check for expired or soon-expiring Key Vault secrets, certificates, and keys."""
    findings = []

    for etype, label in [
        ("azure-keyvault-secret-expiry", "secrets"),
        ("azure-keyvault-cert-expiry", "certificates"),
        ("azure-keyvault-key-expiry", "keys"),
    ]:
        items = idx.get(etype, [])
        for item in items:
            d = item.get("Data", {})
            vault = d.get("VaultName", "unknown")
            r = _res(item, "Microsoft.KeyVault/vaults")
            if not r["resource_name"]:
                r["resource_name"] = vault
            expired = d.get("ExpiredSecrets", 0) or d.get("ExpiredCertificates", 0) or d.get("ExpiredKeys", 0)
            expiring = d.get("ExpiringSoon", 0)

            if expired:
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                   f"Key Vault '{vault}': {expired} expired {label}.",
                                   recommendation=f"Rotate or remove expired {label} in Key Vault '{vault}'.", **r))
            if expiring:
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                   f"Key Vault '{vault}': {expiring} {label} expiring within 30 days.",
                                   recommendation=f"Rotate {label} expiring within 30 days in Key Vault '{vault}'.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "No expired or soon-expiring Key Vault items found."))
    return findings


def _check_storage_account_security(cid, ctrl, evidence, idx):
    """Check storage account security: encryption, soft delete, TLS, network rules."""
    findings = []
    accounts = idx.get("azure-storage-account", [])

    if not accounts:
        return [_f(cid, ctrl, Status.COMPLIANT, "No storage accounts to evaluate.")]

    for acct in accounts:
        d = acct.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(acct, "Microsoft.Storage/storageAccounts")

        if not d.get("EnableHttpsTrafficOnly", True):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' allows HTTP traffic.",
                              recommendation="Enable 'Secure transfer required' on the storage account.", **r))
        if _tls_below(d.get("MinimumTlsVersion", "TLS1_0")):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' TLS below 1.2.",
                              recommendation="Set minimum TLS version to TLS 1.2.", **r))
        if d.get("AllowBlobPublicAccess"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' public blob access enabled.",
                              recommendation="Disable public blob access on the storage account.", **r))
        if not d.get("BlobSoftDeleteEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' blob soft delete not enabled.",
                              recommendation="Enable blob soft delete for data recovery.", **r))
        if not d.get("ContainerSoftDeleteEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' container soft delete not enabled.",
                              recommendation="Enable container soft delete for data recovery.", **r))
        if d.get("NetworkDefaultAction", "Allow") == "Allow":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' has no network firewall (default action: Allow).",
                              recommendation="Configure the storage account firewall to deny by default.", **r))
        if not d.get("InfrastructureEncryption"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' infrastructure encryption not enabled.",
                              recommendation="Enable infrastructure encryption (double encryption) on the storage account.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(accounts)} storage accounts pass security checks."))
    return findings


def _check_container_registry_security(cid, ctrl, evidence, idx):
    """Check ACR security: admin access, network, content trust, encryption."""
    findings = []
    registries = idx.get("azure-container-registry", [])

    if not registries:
        return [_f(cid, ctrl, Status.COMPLIANT, "No container registries to evaluate.")]

    for reg in registries:
        d = reg.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(reg, "Microsoft.ContainerRegistry/registries")

        if d.get("AdminUserEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ACR '{name}' admin user enabled.",
                              recommendation="Disable admin user on the container registry. Use Azure AD authentication.", **r))
        if d.get("PublicNetworkAccess", "Enabled") != "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ACR '{name}' public network access enabled.",
                              recommendation="Disable public network access. Use private endpoints.", **r))
        if not d.get("ContentTrustEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ACR '{name}' content trust not enabled.",
                              recommendation="Enable content trust to verify image integrity.", **r))
        if not d.get("EncryptionEnabled") and d.get("Sku") == "Premium":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ACR '{name}' (Premium) not using CMK encryption.",
                              recommendation="Enable customer-managed key encryption on the Premium ACR.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(registries)} container registries pass security checks."))
    return findings


def _check_cosmosdb_security(cid, ctrl, evidence, idx):
    """Check Cosmos DB security: network isolation, auth, encryption, backup."""
    findings = []
    accounts = idx.get("azure-cosmosdb-account", [])

    if not accounts:
        return [_f(cid, ctrl, Status.COMPLIANT, "No Cosmos DB accounts to evaluate.")]

    for acct in accounts:
        d = acct.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(acct, "Microsoft.DocumentDB/databaseAccounts")

        if d.get("PublicNetworkAccess", "Enabled") != "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' public network access enabled.",
                              recommendation="Disable public network access. Use private endpoints.", **r))
        if not d.get("DisableLocalAuth"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' local auth (keys) enabled.",
                              recommendation="Disable local authentication. Use Azure AD auth.", **r))
        if not d.get("DisableKeyBasedMetadataWriteAccess"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' key-based metadata write access enabled.",
                              recommendation="Disable key-based metadata write access to prevent key-based data plane changes.", **r))
        if not d.get("KeyVaultKeyUri"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' not using CMK encryption.",
                              recommendation="Configure customer-managed key encryption via Key Vault.", **r))
        if not d.get("EnableAutomaticFailover"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' automatic failover not enabled.",
                              recommendation="Enable automatic failover for high availability.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(accounts)} Cosmos DB accounts pass security checks."))
    return findings


def _check_database_server_security(cid, ctrl, evidence, idx):
    """Check PostgreSQL/MySQL flexible server security."""
    findings = []
    servers = idx.get("azure-database-server", [])

    if not servers:
        return [_f(cid, ctrl, Status.COMPLIANT, "No database servers to evaluate.")]

    for srv in servers:
        d = srv.get("Data", {})
        name = d.get("Name", "unknown")
        engine = d.get("Engine", "Database")
        r = _res(srv, d.get("ResourceType", "Microsoft.DB/flexibleServers"))

        if d.get("PublicNetworkAccess", "Enabled") != "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{engine} server '{name}' public network access enabled.",
                              recommendation=f"Disable public network access on the {engine} server. Use VNet integration.", **r))
        if d.get("HighAvailabilityMode", "Disabled") == "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{engine} server '{name}' high availability not configured.",
                              recommendation=f"Enable zone-redundant HA on the {engine} server.", **r))
        if d.get("GeoRedundantBackup", "Disabled") == "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{engine} server '{name}' geo-redundant backup not enabled.",
                              recommendation=f"Enable geo-redundant backup on the {engine} server.", **r))
        if d.get("BackupRetentionDays", 7) < 14:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{engine} server '{name}' backup retention ({d.get('BackupRetentionDays', 7)} days) below 14.",
                              recommendation=f"Increase backup retention to at least 14 days on the {engine} server.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(servers)} database servers pass security checks."))
    return findings


def _check_storage_container_security(cid, ctrl, evidence, idx):
    """Check per-container public access, immutability, and lifecycle rules."""
    findings = []
    containers = idx.get("azure-storage-container", [])

    if not containers:
        return [_f(cid, ctrl, Status.COMPLIANT, "No storage container data to evaluate.")]

    for item in containers:
        d = item.get("Data", {})
        name = d.get("StorageAccountName", "unknown")
        r = _res(item, "Microsoft.Storage/storageAccounts")

        pub = d.get("PublicContainers", 0)
        if pub > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' has {pub} container(s) with public access.",
                              recommendation="Set container public access level to 'Private' for all containers.", **r))
        if d.get("LifecycleRuleCount", 0) == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' has no lifecycle management rules.",
                              recommendation="Configure lifecycle management policies for data retention and tiering.", **r))
        checked = d.get("ContainersChecked", 0)
        immutable = d.get("ImmutableContainers", 0)
        if checked > 0 and immutable == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' has no containers with immutability policies.",
                              recommendation="Configure immutability policies on containers storing regulated data.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(containers)} storage accounts pass container security checks."))
    return findings


def _check_sql_detailed_security(cid, ctrl, evidence, idx):
    """Check SQL Server ATP, vulnerability assessment, per-database audit/TDE, firewall."""
    findings = []
    servers = idx.get("azure-sql-detailed", [])

    if not servers:
        return [_f(cid, ctrl, Status.COMPLIANT, "No SQL detailed data to evaluate.")]

    for srv in servers:
        d = srv.get("Data", {})
        name = d.get("ServerName", "unknown")
        r = _res(srv, "Microsoft.Sql/servers")

        if not d.get("AtpEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"SQL Server '{name}' Advanced Threat Protection not enabled.",
                              recommendation="Enable Advanced Threat Protection on the SQL Server.", **r))
        if not d.get("VulnerabilityAssessmentConfigured"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"SQL Server '{name}' vulnerability assessment not configured.",
                              recommendation="Configure SQL Vulnerability Assessment with a storage account.", **r))
        if d.get("AllowAllAzureIps"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"SQL Server '{name}' allows all Azure IPs (0.0.0.0 - 255.255.255.255).",
                              recommendation="Remove the allow-all firewall rule. Use specific IP ranges or VNet rules.", **r))
        no_audit = d.get("DatabasesWithoutAudit", 0)
        if no_audit > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"SQL Server '{name}' has {no_audit} database(s) without auditing.",
                              recommendation="Enable auditing on all databases or at server level.", **r))
        no_tde = d.get("DatabasesWithoutTde", 0)
        if no_tde > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"SQL Server '{name}' has {no_tde} database(s) without TDE.",
                              recommendation="Enable Transparent Data Encryption on all databases.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(servers)} SQL servers pass detailed security checks."))
    return findings


def _check_database_config_security(cid, ctrl, evidence, idx):
    """Check PostgreSQL/MySQL server parameters and firewall rules."""
    findings = []
    configs = idx.get("azure-database-config", [])

    if not configs:
        return [_f(cid, ctrl, Status.COMPLIANT, "No database config data to evaluate.")]

    for cfg in configs:
        d = cfg.get("Data", {})
        name = d.get("ServerName", "unknown")
        engine = d.get("Engine", "Database")
        r = _res(cfg, f"Microsoft.DB/{engine}/flexibleServers")

        secure_transport = d.get("RequireSecureTransport")
        if secure_transport and secure_transport.lower() in ("off", "0", "false"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{engine} '{name}' does not require secure transport (SSL/TLS).",
                              recommendation=f"Set require_secure_transport=ON on the {engine} server.", **r))
        if d.get("AllowAllAzureIps"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{engine} '{name}' allows all Azure IPs (0.0.0.0 - 255.255.255.255).",
                              recommendation="Remove the allow-all firewall rule. Use specific IP ranges.", **r))

        # PostgreSQL-specific
        if engine == "PostgreSQL":
            log_cp = d.get("LogCheckpoints")
            if log_cp and log_cp.lower() in ("off", "0", "false"):
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"PostgreSQL '{name}' log_checkpoints disabled.",
                                  recommendation="Enable log_checkpoints parameter.", **r))
            log_conn = d.get("LogConnections")
            if log_conn and log_conn.lower() in ("off", "0", "false"):
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"PostgreSQL '{name}' log_connections disabled.",
                                  recommendation="Enable log_connections parameter.", **r))

        # MySQL-specific
        if engine == "MySQL":
            audit_log = d.get("AuditLogEnabled")
            if audit_log and audit_log.lower() in ("off", "0", "false"):
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"MySQL '{name}' audit logging disabled.",
                                  recommendation="Enable audit_log_enabled parameter.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(configs)} database configs pass security checks."))
    return findings


# ---------------------------------------------------------------------------
# Function-app security
# ---------------------------------------------------------------------------
def _check_function_app_security(cid, ctrl, evidence, idx):
    findings = []
    apps = idx.get("azure-function-app", [])
    for item in apps:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Web/sites")
        if not d.get("HttpsOnly"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Function app '{name}' does not enforce HTTPS.",
                              recommendation="Enable HTTPS-only on the function app.", **r))
        min_tls = d.get("MinTlsVersion") or "1.0"
        if _tls_below(min_tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Function app '{name}' TLS version ({min_tls}) < 1.2.",
                              recommendation="Set minimum TLS version to 1.2.", **r))
        if not d.get("ManagedIdentityEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Function app '{name}' has no managed identity.",
                              recommendation="Enable system or user-assigned managed identity.", **r))
        runtime = d.get("LinuxFxVersion") or d.get("WindowsFxVersion") or ""
        if not runtime:
            findings.append(_f(cid, ctrl, Status.INFO,
                              f"Function app '{name}' has no runtime stack configured.",
                              recommendation="Verify runtime stack configuration.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(apps)} function apps pass security checks."))
    return findings


# ---------------------------------------------------------------------------
# Messaging (Service Bus / Event Hubs) security
# ---------------------------------------------------------------------------
def _check_messaging_security(cid, ctrl, evidence, idx):
    findings = []
    sb_ns = idx.get("azure-servicebus-namespace", [])
    eh_ns = idx.get("azure-eventhub-namespace", [])

    for item in sb_ns:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.ServiceBus/namespaces")
        if not d.get("DisableLocalAuth"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Service Bus '{name}' allows local/key auth.",
                              recommendation="Disable local auth and use Azure AD authentication.", **r))
        min_tls = d.get("MinimumTlsVersion") or "1.0"
        if _tls_below(min_tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Service Bus '{name}' TLS ({min_tls}) < 1.2.",
                              recommendation="Set minimum TLS version to 1.2.", **r))
        if d.get("PublicNetworkAccess", "").lower() == "enabled" and d.get("PrivateEndpoints", 0) == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Service Bus '{name}' public access without private endpoints.",
                              recommendation="Enable private endpoints or restrict network access.", **r))

    for item in eh_ns:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.EventHub/namespaces")
        if not d.get("DisableLocalAuth"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Event Hub '{name}' allows local/key auth.",
                              recommendation="Disable local auth and use Azure AD authentication.", **r))
        min_tls = d.get("MinimumTlsVersion") or "1.0"
        if _tls_below(min_tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Event Hub '{name}' TLS ({min_tls}) < 1.2.",
                              recommendation="Set minimum TLS version to 1.2.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(sb_ns) + len(eh_ns)} messaging namespaces pass security checks."))
    return findings


# ---------------------------------------------------------------------------
# Redis Cache security
# ---------------------------------------------------------------------------
def _check_redis_security(cid, ctrl, evidence, idx):
    findings = []
    caches = idx.get("azure-redis-cache", [])
    for item in caches:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Cache/Redis")
        if not d.get("EnableSsl"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Redis '{name}' does not enforce SSL.",
                              recommendation="Enable the non-SSL port to be disabled.", **r))
        min_tls = d.get("MinimumTlsVersion") or "1.0"
        if _tls_below(min_tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Redis '{name}' TLS ({min_tls}) < 1.2.",
                              recommendation="Set minimum TLS version to 1.2.", **r))
        if d.get("PublicNetworkAccess", "").lower() == "enabled" and d.get("PrivateEndpoints", 0) == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Redis '{name}' public access without private endpoints.",
                              recommendation="Use private endpoints for Redis access.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(caches)} Redis caches pass security checks."))
    return findings


# ---------------------------------------------------------------------------
# CosmosDB advanced (data-plane) security
# ---------------------------------------------------------------------------
def _check_cosmosdb_advanced_security(cid, ctrl, evidence, idx):
    findings = []
    accounts = idx.get("azure-cosmosdb-account", [])
    for item in accounts:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.DocumentDB/databaseAccounts")
        if not d.get("DisableLocalAuth"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' allows key-based auth.",
                              recommendation="Disable local auth; use Azure AD RBAC.", **r))
        if not d.get("DisableKeyBasedMetadataWriteAccess"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' allows key-based metadata writes.",
                              recommendation="Disable key-based metadata write access.", **r))
        min_tls = d.get("MinimumTlsVersion") or ""
        if min_tls and _tls_below(min_tls):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' TLS ({min_tls}) < 1.2.",
                              recommendation="Set minimum TLS version to Tls12.", **r))
        pub = d.get("PublicNetworkAccess", "Enabled")
        if pub == "Enabled" and not d.get("IsVirtualNetworkFilterEnabled") and d.get("PrivateEndpoints", 0) == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Cosmos DB '{name}' has unrestricted public access.",
                              recommendation="Enable VNet filtering or use private endpoints.", **r))
    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(accounts)} Cosmos DB accounts pass advanced security checks."))
    return findings


# ---------------------------------------------------------------------------
# Data Analytics (Synapse/ADF/Databricks) security
# ---------------------------------------------------------------------------
def _check_data_analytics_security(cid, ctrl, evidence, idx):
    findings = []
    synapse = idx.get("azure-synapse-workspace", [])
    adf = idx.get("azure-data-factory", [])
    dbx = idx.get("azure-databricks-workspace", [])

    for item in synapse:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Synapse/workspaces")
        if not d.get("ManagedVirtualNetwork"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Synapse '{name}' has no managed VNet.",
                              recommendation="Enable managed virtual network for Synapse workspace.", **r))
        if d.get("PublicNetworkAccess", "").lower() == "enabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Synapse '{name}' allows public network access.",
                              recommendation="Disable public network access to Synapse workspace.", **r))

    for item in adf:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.DataFactory/factories")
        if d.get("PublicNetworkAccess", "").lower() == "enabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Data Factory '{name}' allows public access.",
                              recommendation="Disable public network access for Data Factory.", **r))
        if not d.get("ManagedIdentityType"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Data Factory '{name}' has no managed identity.",
                              recommendation="Enable managed identity for Data Factory.", **r))

    for item in dbx:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Databricks/workspaces")
        params = d.get("Parameters", {})
        if isinstance(params, dict):
            no_pub_ip = params.get("enableNoPublicIp", {})
            if isinstance(no_pub_ip, dict) and not no_pub_ip.get("value", True):
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                  f"Databricks '{name}' cluster nodes have public IPs.",
                                  recommendation="Enable no-public-IP for Databricks clusters.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(synapse) + len(adf) + len(dbx)} data analytics resources pass security checks."))
    return findings


# ---------------------------------------------------------------------------
# Purview / DLP classification
# ---------------------------------------------------------------------------
def _check_purview_classification(cid, ctrl, evidence, idx):
    findings = []
    purview = idx.get("azure-purview-account", [])
    labels = idx.get("m365-sensitivity-label", [])

    for item in purview:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Purview/accounts")
        if d.get("PublicNetworkAccess", "Enabled") == "Enabled" and d.get("PrivateEndpoints", 0) == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Purview '{name}' has public access without private endpoints.",
                              recommendation="Configure private endpoints for Purview account.", **r))

    if not labels:
        findings.append(_f(cid, ctrl, Status.INFO,
                          "No sensitivity labels found. Data classification may not be configured.",
                          recommendation="Configure Microsoft Purview sensitivity labels for data classification."))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Purview/classification checks pass ({len(purview)} accounts, {len(labels)} labels)."))
    return findings
