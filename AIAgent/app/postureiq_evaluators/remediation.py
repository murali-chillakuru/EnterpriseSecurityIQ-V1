"""
Remediation Automation
Generates remediation scripts (Azure CLI / PowerShell) for common non-compliant findings.
"""

from __future__ import annotations
from typing import Any
from app.logger import log

# Map (check function name, detail pattern keywords) → remediation template
_REMEDIATION_LIBRARY: dict[str, dict[str, str]] = {
    "storage_https_not_enforced": {
        "title": "Enable HTTPS-only on Storage Account",
        "cli": "az storage account update --name {resource} --https-only true",
        "powershell": "Set-AzStorageAccount -ResourceGroupName {rg} -Name {resource} -EnableHttpsTrafficOnly $true",
    },
    "storage_public_blob_access": {
        "title": "Disable public blob access on Storage Account",
        "cli": "az storage account update --name {resource} --allow-blob-public-access false",
        "powershell": "Set-AzStorageAccount -ResourceGroupName {rg} -Name {resource} -AllowBlobPublicAccess $false",
    },
    "sql_public_network_access": {
        "title": "Disable public network access on SQL Server",
        "cli": "az sql server update --name {resource} --resource-group {rg} --set publicNetworkAccess=Disabled",
        "powershell": "Set-AzSqlServer -ServerName {resource} -ResourceGroupName {rg} -PublicNetworkAccess Disabled",
    },
    "sql_auditing_not_enabled": {
        "title": "Enable auditing on SQL Server",
        "cli": "az sql server audit-policy update --name {resource} --resource-group {rg} --state Enabled --storage-account {storage}",
        "powershell": "Set-AzSqlServerAudit -ServerName {resource} -ResourceGroupName {rg} -BlobStorageTargetState Enabled",
    },
    "nsg_unrestricted_inbound": {
        "title": "Restrict NSG inbound rule",
        "cli": "az network nsg rule update --nsg-name {resource} --resource-group {rg} --name {rule_name} --source-address-prefixes 10.0.0.0/8",
        "powershell": "# Review and restrict NSG rule {rule_name} on {resource}",
    },
    "vm_no_endpoint_protection": {
        "title": "Install endpoint protection on VM",
        "cli": "az vm extension set --vm-name {resource} --resource-group {rg} --name MDE.Linux --publisher Microsoft.Azure.AzureDefenderForServers",
        "powershell": "Set-AzVMExtension -VMName {resource} -ResourceGroupName {rg} -Name MDE.Linux -Publisher Microsoft.Azure.AzureDefenderForServers -ExtensionType MDE.Linux",
    },
    "keyvault_soft_delete_disabled": {
        "title": "Enable soft delete on Key Vault",
        "cli": "az keyvault update --name {resource} --enable-soft-delete true",
        "powershell": "Update-AzKeyVault -VaultName {resource} -EnableSoftDelete $true",
    },
}


def generate_remediation(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach remediation scripts to findings where available.

    Mutates each finding dict by adding a `remediation` key with
    title, cli, and powershell fields.  Returns all findings.
    """
    matched = 0
    for f in findings:
        detail = (f.get("detail", "") + " " + f.get("check", "")).lower()
        resource = f.get("resource", "unknown")

        # Try to match a remediation template
        for key, template in _REMEDIATION_LIBRARY.items():
            keywords = key.replace("_", " ")
            if all(kw in detail for kw in keywords.split()):
                f["remediation"] = {
                    "title": template["title"],
                    "cli": template["cli"].format(resource=resource, rg="<resource-group>",
                                                   storage="<storage-account>", rule_name="<rule-name>"),
                    "powershell": template["powershell"].format(resource=resource, rg="<resource-group>",
                                                                storage="<storage-account>", rule_name="<rule-name>"),
                }
                matched += 1
                break

    log.info("Remediation scripts attached to %d/%d finding(s)", matched, len(findings))
    return findings
