"""
Auto-Remediation Playbook Generator
For each finding, generates Azure CLI / PowerShell / Bicep remediation scripts.
Output: ``remediation/`` folder alongside reports.
"""

from __future__ import annotations
import json, pathlib
from typing import Any
from app.logger import log


# ── Remediation Templates ────────────────────────────────────────────────
# Priority: storage public access, NSG any-any rules, missing diagnostic
# settings, SQL firewall, encryption gaps, MFA enforcement.

_REMEDIATION_TEMPLATES: dict[str, dict[str, str]] = {
    # Storage public access
    "check_storage_security": {
        "title": "Disable public blob access on storage accounts",
        "risk": "Storage accounts with public access enabled may expose sensitive data.",
        "az_cli": (
            "# Disable public blob access\n"
            "az storage account update \\\n"
            "  --name {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --allow-blob-public-access false\n\n"
            "# Enforce HTTPS-only traffic\n"
            "az storage account update \\\n"
            "  --name {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --https-only true\n\n"
            "# Set minimum TLS version\n"
            "az storage account update \\\n"
            "  --name {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --min-tls-version TLS1_2"
        ),
        "powershell": (
            "# Disable public blob access\n"
            "Set-AzStorageAccount -ResourceGroupName '{resource_group}' `\n"
            "  -Name '{resource_name}' -AllowBlobPublicAccess $false\n\n"
            "# Enforce HTTPS and TLS 1.2\n"
            "Set-AzStorageAccount -ResourceGroupName '{resource_group}' `\n"
            "  -Name '{resource_name}' -EnableHttpsTrafficOnly $true `\n"
            "  -MinimumTlsVersion TLS1_2"
        ),
        "bicep": (
            "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
            "  name: '{resource_name}'\n"
            "  location: resourceGroup().location\n"
            "  properties: {\n"
            "    allowBlobPublicAccess: false\n"
            "    supportsHttpsTrafficOnly: true\n"
            "    minimumTlsVersion: 'TLS1_2'\n"
            "    networkAcls: {\n"
            "      defaultAction: 'Deny'\n"
            "    }\n"
            "  }\n"
            "}"
        ),
    },
    # NSG any-any rules
    "check_nsg_rules": {
        "title": "Remove overly permissive NSG inbound rules",
        "risk": "NSG rules allowing any-to-any inbound traffic expose all ports to the internet.",
        "az_cli": (
            "# List all inbound allow rules\n"
            "az network nsg rule list \\\n"
            "  --nsg-name {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --query \"[?direction=='Inbound' && access=='Allow']\"\n\n"
            "# Remove overly permissive rule\n"
            "az network nsg rule delete \\\n"
            "  --nsg-name {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --name {rule_name}"
        ),
        "powershell": (
            "# Get overly permissive rules\n"
            "$nsg = Get-AzNetworkSecurityGroup -Name '{resource_name}' "
            "-ResourceGroupName '{resource_group}'\n"
            "$rules = $nsg.SecurityRules | Where-Object {\n"
            "  $_.Direction -eq 'Inbound' -and $_.Access -eq 'Allow' -and\n"
            "  ($_.SourceAddressPrefix -eq '*' -or $_.SourceAddressPrefix -eq 'Internet')\n"
            "}\n\n"
            "# Remove each permissive rule\n"
            "foreach ($rule in $rules) {\n"
            "  Remove-AzNetworkSecurityRuleConfig -Name $rule.Name "
            "-NetworkSecurityGroup $nsg\n"
            "}\n"
            "$nsg | Set-AzNetworkSecurityGroup"
        ),
        "bicep": (
            "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {\n"
            "  name: '{resource_name}'\n"
            "  location: resourceGroup().location\n"
            "  properties: {\n"
            "    securityRules: [\n"
            "      {\n"
            "        name: 'DenyAllInbound'\n"
            "        properties: {\n"
            "          priority: 4096\n"
            "          direction: 'Inbound'\n"
            "          access: 'Deny'\n"
            "          protocol: '*'\n"
            "          sourceAddressPrefix: '*'\n"
            "          destinationAddressPrefix: '*'\n"
            "          sourcePortRange: '*'\n"
            "          destinationPortRange: '*'\n"
            "        }\n"
            "      }\n"
            "    ]\n"
            "  }\n"
            "}"
        ),
    },
    # Missing diagnostic settings
    "check_diagnostic_coverage": {
        "title": "Enable diagnostic settings for Azure resources",
        "risk": "Resources without diagnostic settings lack audit trails and security monitoring.",
        "az_cli": (
            "# Create diagnostic setting for a resource\n"
            "az monitor diagnostic-settings create \\\n"
            "  --name 'PostureIQ-Diagnostics' \\\n"
            "  --resource {resource_id} \\\n"
            "  --workspace {log_analytics_workspace_id} \\\n"
            "  --logs '[{{\"categoryGroup\": \"allLogs\", \"enabled\": true}}]' \\\n"
            "  --metrics '[{{\"category\": \"AllMetrics\", \"enabled\": true}}]'"
        ),
        "powershell": (
            "# Enable diagnostic settings\n"
            "$workspace = Get-AzOperationalInsightsWorkspace "
            "-ResourceGroupName '{resource_group}' -Name '{workspace_name}'\n\n"
            "Set-AzDiagnosticSetting -ResourceId '{resource_id}' `\n"
            "  -Name 'PostureIQ-Diagnostics' `\n"
            "  -WorkspaceId $workspace.ResourceId `\n"
            "  -Enabled $true"
        ),
        "bicep": (
            "resource diagnosticSetting 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
            "  name: 'PostureIQ-Diagnostics'\n"
            "  scope: existingResource\n"
            "  properties: {\n"
            "    workspaceId: logAnalyticsWorkspace.id\n"
            "    logs: [\n"
            "      {\n"
            "        categoryGroup: 'allLogs'\n"
            "        enabled: true\n"
            "      }\n"
            "    ]\n"
            "    metrics: [\n"
            "      {\n"
            "        category: 'AllMetrics'\n"
            "        enabled: true\n"
            "      }\n"
            "    ]\n"
            "  }\n"
            "}"
        ),
    },
    # SQL firewall
    "check_sql_security": {
        "title": "Harden SQL Server firewall and enable auditing",
        "risk": "SQL servers with permissive firewall rules or disabled auditing expose data.",
        "az_cli": (
            "# Remove allow-all-Azure firewall rule\n"
            "az sql server firewall-rule delete \\\n"
            "  --server {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --name AllowAllWindowsAzureIps\n\n"
            "# Enable auditing\n"
            "az sql server audit-policy update \\\n"
            "  --server {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --state Enabled \\\n"
            "  --lats Enabled \\\n"
            "  --lawri {log_analytics_workspace_id}\n\n"
            "# Enable Advanced Threat Protection\n"
            "az sql server threat-policy update \\\n"
            "  --server {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --state Enabled"
        ),
        "powershell": (
            "# Enable SQL auditing\n"
            "Set-AzSqlServerAudit -ServerName '{resource_name}' `\n"
            "  -ResourceGroupName '{resource_group}' `\n"
            "  -LogAnalyticsTargetState Enabled `\n"
            "  -WorkspaceResourceId '{workspace_id}'\n\n"
            "# Enable Advanced Threat Protection\n"
            "Enable-AzSqlServerAdvancedThreatProtection `\n"
            "  -ServerName '{resource_name}' `\n"
            "  -ResourceGroupName '{resource_group}'"
        ),
        "bicep": (
            "resource sqlAudit 'Microsoft.Sql/servers/auditingSettings@2023-05-01-preview' = {\n"
            "  name: 'default'\n"
            "  parent: sqlServer\n"
            "  properties: {\n"
            "    state: 'Enabled'\n"
            "    isAzureMonitorTargetEnabled: true\n"
            "  }\n"
            "}\n\n"
            "resource sqlThreat 'Microsoft.Sql/servers/securityAlertPolicies@2023-05-01-preview' = {\n"
            "  name: 'default'\n"
            "  parent: sqlServer\n"
            "  properties: {\n"
            "    state: 'Enabled'\n"
            "  }\n"
            "}"
        ),
    },
    # Encryption at rest
    "check_encryption_at_rest": {
        "title": "Enable encryption at rest for all data stores",
        "risk": "Unencrypted data at rest may be accessed if physical storage is compromised.",
        "az_cli": (
            "# Enable TDE on SQL database\n"
            "az sql db tde set --server {resource_name} \\\n"
            "  --database {database_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --status Enabled\n\n"
            "# Enable VM disk encryption\n"
            "az vm encryption enable \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --name {vm_name} \\\n"
            "  --disk-encryption-keyvault {keyvault_name}"
        ),
        "powershell": (
            "# Enable SQL TDE\n"
            "Set-AzSqlDatabaseTransparentDataEncryption `\n"
            "  -ServerName '{resource_name}' `\n"
            "  -DatabaseName '{database_name}' `\n"
            "  -ResourceGroupName '{resource_group}' `\n"
            "  -State Enabled\n\n"
            "# Enable VM disk encryption\n"
            "Set-AzVMDiskEncryptionExtension -ResourceGroupName '{resource_group}' `\n"
            "  -VMName '{vm_name}' -DiskEncryptionKeyVaultUrl $kvUrl `\n"
            "  -DiskEncryptionKeyVaultId $kvId"
        ),
        "bicep": (
            "resource sqlTde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-05-01-preview' = {\n"
            "  name: 'current'\n"
            "  parent: sqlDatabase\n"
            "  properties: {\n"
            "    state: 'Enabled'\n"
            "  }\n"
            "}"
        ),
    },
    # TLS enforcement
    "check_tls_enforcement": {
        "title": "Enforce TLS 1.2+ across all services",
        "risk": "Older TLS versions have known vulnerabilities and should be disabled.",
        "az_cli": (
            "# Update App Service to TLS 1.2\n"
            "az webapp config set --name {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --min-tls-version 1.2 --ftps-state Disabled\n\n"
            "# Update storage account\n"
            "az storage account update --name {resource_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --min-tls-version TLS1_2"
        ),
        "powershell": (
            "# Update App Service TLS\n"
            "Set-AzWebApp -ResourceGroupName '{resource_group}' `\n"
            "  -Name '{resource_name}' -MinTlsVersion '1.2'\n\n"
            "# Update storage account TLS\n"
            "Set-AzStorageAccount -ResourceGroupName '{resource_group}' `\n"
            "  -Name '{resource_name}' -MinimumTlsVersion TLS1_2"
        ),
        "bicep": (
            "resource webApp 'Microsoft.Web/sites/config@2023-01-01' = {\n"
            "  name: 'web'\n"
            "  parent: existingWebApp\n"
            "  properties: {\n"
            "    minTlsVersion: '1.2'\n"
            "    ftpsState: 'Disabled'\n"
            "  }\n"
            "}"
        ),
    },
    # MFA enforcement
    "check_mfa_enforcement": {
        "title": "Enforce MFA for all users via Conditional Access",
        "risk": "Accounts without MFA are vulnerable to credential theft and phishing.",
        "az_cli": (
            "# Note: Conditional Access policies require Microsoft Graph API\n"
            "# Create a CA policy requiring MFA for all users\n"
            "az rest --method POST \\\n"
            "  --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' \\\n"
            "  --body '{\n"
            "    \"displayName\": \"Require MFA for all users\",\n"
            "    \"state\": \"enabled\",\n"
            "    \"conditions\": {\n"
            "      \"users\": {\"includeUsers\": [\"All\"]},\n"
            "      \"applications\": {\"includeApplications\": [\"All\"]}\n"
            "    },\n"
            "    \"grantControls\": {\n"
            "      \"operator\": \"OR\",\n"
            "      \"builtInControls\": [\"mfa\"]\n"
            "    }\n"
            "  }'"
        ),
        "powershell": (
            "# Requires Microsoft.Graph.Identity.SignIns module\n"
            "Import-Module Microsoft.Graph.Identity.SignIns\n\n"
            "New-MgIdentityConditionalAccessPolicy -DisplayName 'Require MFA for All Users' `\n"
            "  -State 'enabled' `\n"
            "  -Conditions @{\n"
            "    Users = @{ IncludeUsers = @('All') }\n"
            "    Applications = @{ IncludeApplications = @('All') }\n"
            "  } `\n"
            "  -GrantControls @{\n"
            "    Operator = 'OR'\n"
            "    BuiltInControls = @('mfa')\n"
            "  }"
        ),
        "bicep": (
            "// Conditional Access policies cannot be deployed via Bicep.\n"
            "// Use Microsoft Graph API or PowerShell to configure MFA policies."
        ),
    },
    # Defender plans
    "check_defender_plans": {
        "title": "Enable Microsoft Defender for Cloud plans",
        "risk": "Without Defender plans, advanced threat protection is unavailable.",
        "az_cli": (
            "# Enable Defender for VMs\n"
            "az security pricing create --name VirtualMachines --tier Standard\n\n"
            "# Enable Defender for SQL\n"
            "az security pricing create --name SqlServers --tier Standard\n\n"
            "# Enable Defender for Storage\n"
            "az security pricing create --name StorageAccounts --tier Standard\n\n"
            "# Enable Defender for Key Vault\n"
            "az security pricing create --name KeyVaults --tier Standard\n\n"
            "# Enable Defender for App Service\n"
            "az security pricing create --name AppServices --tier Standard\n\n"
            "# Enable Defender for ARM\n"
            "az security pricing create --name Arm --tier Standard\n\n"
            "# Enable Defender for Containers\n"
            "az security pricing create --name Containers --tier Standard"
        ),
        "powershell": (
            "# Enable all critical Defender plans\n"
            "$plans = @('VirtualMachines','SqlServers','StorageAccounts',\n"
            "           'KeyVaults','AppServices','Arm','Containers')\n"
            "foreach ($plan in $plans) {\n"
            "  Set-AzSecurityPricing -Name $plan -PricingTier 'Standard'\n"
            "}"
        ),
        "bicep": (
            "var defenderPlans = [\n"
            "  'VirtualMachines'\n"
            "  'SqlServers'\n"
            "  'StorageAccounts'\n"
            "  'KeyVaults'\n"
            "  'AppServices'\n"
            "  'Arm'\n"
            "  'Containers'\n"
            "]\n\n"
            "resource defender 'Microsoft.Security/pricings@2024-01-01' = [for plan in defenderPlans: {\n"
            "  name: plan\n"
            "  properties: {\n"
            "    pricingTier: 'Standard'\n"
            "  }\n"
            "}]"
        ),
    },
    # Network segmentation
    "check_network_segmentation": {
        "title": "Implement network segmentation with NSGs and firewalls",
        "risk": "Flat networks allow lateral movement after an initial compromise.",
        "az_cli": (
            "# Create an NSG with deny-all default\n"
            "az network nsg create --name {resource_name}-nsg \\\n"
            "  --resource-group {resource_group}\n\n"
            "# Apply NSG to subnet\n"
            "az network vnet subnet update \\\n"
            "  --vnet-name {vnet_name} --name {subnet_name} \\\n"
            "  --resource-group {resource_group} \\\n"
            "  --network-security-group {resource_name}-nsg"
        ),
        "powershell": (
            "# Create NSG\n"
            "$nsg = New-AzNetworkSecurityGroup -Name '{resource_name}-nsg' `\n"
            "  -ResourceGroupName '{resource_group}' -Location '{location}'\n\n"
            "# Apply to subnet\n"
            "$vnet = Get-AzVirtualNetwork -Name '{vnet_name}' "
            "-ResourceGroupName '{resource_group}'\n"
            "Set-AzVirtualNetworkSubnetConfig -Name '{subnet_name}' "
            "-VirtualNetwork $vnet -NetworkSecurityGroupId $nsg.Id\n"
            "$vnet | Set-AzVirtualNetwork"
        ),
        "bicep": (
            "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {\n"
            "  name: '${vnetName}-nsg'\n"
            "  location: location\n"
            "  properties: {\n"
            "    securityRules: []\n"
            "  }\n"
            "}"
        ),
    },
}

# Fallback: generic remediation for unmapped evaluation_logic
_GENERIC_REMEDIATION = {
    "title": "Review and remediate compliance finding",
    "risk": "This finding indicates a deviation from the compliance framework requirement.",
    "az_cli": "# Review the finding details and apply appropriate remediation.\n# Refer to the control recommendation for specific guidance.",
    "powershell": "# Review the finding details and apply appropriate remediation.\n# Refer to the control recommendation for specific guidance.",
    "bicep": "// Review the finding details and apply appropriate remediation.\n// Refer to the control recommendation for specific guidance.",
}


# ── Generator ────────────────────────────────────────────────────────────

def generate_remediation_playbooks(
    results: dict[str, Any],
    output_dir: str,
) -> str:
    """Generate remediation scripts for non-compliant findings.

    Creates ``remediation/`` folder with per-finding scripts in Azure CLI,
    PowerShell, and Bicep formats.

    Returns path to the remediation directory.
    """
    rdir = pathlib.Path(output_dir) / "remediation"
    rdir.mkdir(parents=True, exist_ok=True)

    findings = results.get("findings", [])
    nc_findings = [
        f for f in findings
        if f.get("Status") in ("non_compliant", "partial")
    ]

    if not nc_findings:
        log.info("No non-compliant findings — skipping remediation playbooks")
        return str(rdir)

    # Group by evaluation_logic (deduplicate across resources)
    by_check: dict[str, list[dict]] = {}
    for f in nc_findings:
        check = f.get("Description", "").split(":")[0].strip() if ":" in f.get("Description", "") else f.get("ControlId", "unknown")
        # Use control_id as primary key
        key = f.get("ControlId", "unknown")
        by_check.setdefault(key, []).append(f)

    # Build playbook index
    playbook_index: list[dict] = []

    for control_id, findings_group in sorted(by_check.items()):
        sample = findings_group[0]
        severity = sample.get("Severity", "medium")
        domain = sample.get("Domain", "")
        recommendation = sample.get("Recommendation", "")

        # Find the best matching template from the evaluation_logic
        # (mapped from control → framework → evaluation_logic)
        eval_logic = _find_eval_logic(control_id, results)
        template = _REMEDIATION_TEMPLATES.get(eval_logic, _GENERIC_REMEDIATION)

        # Extract resource context from supporting evidence
        resources = []
        for f in findings_group:
            for se in f.get("SupportingEvidence", []):
                res_name = se.get("ResourceName") or se.get("Name", "")
                res_id = se.get("ResourceId", "")
                if res_name or res_id:
                    resources.append({
                        "name": res_name,
                        "id": res_id,
                        "type": se.get("ResourceType", ""),
                        "resource_group": _rg_from_id(res_id),
                    })

        # Deduplicate resources
        seen_ids = set()
        unique_resources = []
        for r in resources:
            key = r["id"] or r["name"]
            if key and key not in seen_ids:
                seen_ids.add(key)
                unique_resources.append(r)

        playbook = {
            "control_id": control_id,
            "title": template["title"],
            "severity": severity,
            "domain": domain,
            "risk": template["risk"],
            "recommendation": recommendation,
            "affected_resources": len(unique_resources),
            "resources": unique_resources[:20],  # cap for readability
        }
        playbook_index.append(playbook)

        # Write per-control remediation scripts
        safe_id = control_id.replace("/", "-").replace("\\", "-")
        for fmt, ext in [("az_cli", "sh"), ("powershell", "ps1"), ("bicep", "bicep")]:
            script = template.get(fmt, "")
            # Substitute resource placeholders if we have a sample resource
            if unique_resources:
                r = unique_resources[0]
                script = script.replace("{resource_name}", r["name"])
                script = script.replace("{resource_group}", r["resource_group"])
                script = script.replace("{resource_id}", r["id"])

            fpath = rdir / f"{safe_id}.{ext}"
            fpath.write_text(script, encoding="utf-8")

    # Write index JSON
    index_path = rdir / "remediation-index.json"
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(playbook_index, f, indent=2, default=str)
        f.write("\n")

    # Write summary markdown
    md_path = rdir / "REMEDIATION-PLAYBOOK.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# PostureIQ Remediation Playbook\n\n")
        f.write(f"**Total remediations:** {len(playbook_index)}\n\n")

        # Group by severity
        for sev in ("critical", "high", "medium", "low"):
            items = [p for p in playbook_index if p["severity"] == sev]
            if not items:
                continue
            f.write(f"## {sev.upper()} ({len(items)})\n\n")
            for p in items:
                f.write(f"### {p['control_id']} — {p['title']}\n\n")
                f.write(f"**Risk:** {p['risk']}\n\n")
                if p["recommendation"]:
                    f.write(f"**Recommendation:** {p['recommendation']}\n\n")
                f.write(f"**Affected resources:** {p['affected_resources']}\n\n")
                safe_id = p["control_id"].replace("/", "-").replace("\\", "-")
                f.write(f"- Azure CLI: [`{safe_id}.sh`]({safe_id}.sh)\n")
                f.write(f"- PowerShell: [`{safe_id}.ps1`]({safe_id}.ps1)\n")
                f.write(f"- Bicep: [`{safe_id}.bicep`]({safe_id}.bicep)\n\n")

    log.info("Remediation playbooks: %d controls → %s", len(playbook_index), rdir)
    return str(rdir)


def _find_eval_logic(control_id: str, results: dict) -> str:
    """Look up the evaluation_logic for a control_id from control_results."""
    # The control_results don't store eval_logic directly, so we search
    # the framework mappings.
    import json as _json
    fdir = pathlib.Path(__file__).parent.parent / "frameworks"
    for f in fdir.glob("*-mappings.json"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = _json.load(fh)
            controls = data.get("controls", data) if isinstance(data, dict) else data
            for c in controls:
                if c.get("control_id") == control_id:
                    return c.get("evaluation_logic", "")
        except Exception:
            continue
    return ""


def _rg_from_id(resource_id: str) -> str:
    """Extract resource group name from ARM resource ID."""
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""
