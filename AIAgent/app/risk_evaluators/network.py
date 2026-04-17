"""
Risk evaluator — Network attack surface analysis.

Checks: open management ports, public storage, web-app transport, SQL exposure.
"""
from __future__ import annotations

from app.risk_evaluators.finding import risk_finding as _risk_finding


def analyze_network_risk(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_open_management_ports(evidence_index))
    findings.extend(_check_public_storage(evidence_index))
    findings.extend(_check_webapp_security(evidence_index))
    findings.extend(_check_sql_exposure(evidence_index))
    return findings


def _check_open_management_ports(evidence_index: dict) -> list[dict]:
    nsgs = evidence_index.get("azure-network-security-nsg", [])
    exposed: list[dict] = []

    for ev in nsgs:
        data = ev.get("Data", ev.get("data", {}))
        for port_field, port_label in [
            ("RdpExposed", "RDP (3389)"), ("rdp_exposed", "RDP (3389)"),
            ("SshExposed", "SSH (22)"), ("ssh_exposed", "SSH (22)"),
        ]:
            if data.get(port_field):
                exposed.append({
                    "Type": "NSG",
                    "Name": data.get("NsgName", data.get("nsg_name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "ExposedPort": port_label,
                })

    if exposed:
        return [_risk_finding(
            category="network",
            subcategory="open_management_ports",
            title=f"{len(exposed)} management ports exposed to the Internet",
            description=(
                "NSG rules allow inbound RDP or SSH from the Internet — prime "
                "targets for brute-force and credential-stuffing attacks."
            ),
            severity="critical",
            affected_resources=exposed,
            remediation={
                "Description": "Restrict management port access to specific IPs or use Azure Bastion.",
                "AzureCLI": (
                    "az network nsg rule delete -g <rg> --nsg-name <nsg> -n <rule-name>\n"
                    "az network bastion create -n MyBastion -g <rg> --vnet-name <vnet> "
                    "--public-ip-address <pip>"
                ),
                "PowerShell": (
                    "Remove-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg -Name '<rule-name>'\n"
                    "$nsg | Set-AzNetworkSecurityGroup"
                ),
            },
        )]
    return []


def _check_public_storage(evidence_index: dict) -> list[dict]:
    storage = evidence_index.get("azure-storage-security", [])
    public_accounts: list[dict] = []

    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("AllowBlobPublicAccess", data.get("allow_blob_public_access")) is True:
            public_accounts.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })

    if public_accounts:
        return [_risk_finding(
            category="network",
            subcategory="public_storage",
            title=f"{len(public_accounts)} storage accounts allow public blob access",
            description="Public blob access on storage accounts may expose sensitive data.",
            severity="high",
            affected_resources=public_accounts,
            remediation={
                "Description": "Disable public blob access on all storage accounts.",
                "AzureCLI": "az storage account update -n <name> -g <rg> --allow-blob-public-access false",
                "PowerShell": "Set-AzStorageAccount -ResourceGroupName <rg> -Name <name> "
                              "-AllowBlobPublicAccess $false",
            },
        )]
    return []


def _check_webapp_security(evidence_index: dict) -> list[dict]:
    webapps = evidence_index.get("azure-webapp-config", [])
    insecure: list[dict] = []

    for ev in webapps:
        data = ev.get("Data", ev.get("data", {}))
        https_only = data.get("HttpsOnly", data.get("https_only"))
        min_tls = data.get("MinTlsVersion", data.get("min_tls_version", ""))
        issues: list[str] = []
        if https_only is False:
            issues.append("HTTPS not enforced")
        if min_tls and min_tls < "1.2":
            issues.append(f"TLS {min_tls} (< 1.2)")
        if issues:
            insecure.append({
                "Type": "WebApp",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Issues": issues,
            })

    if insecure:
        return [_risk_finding(
            category="network",
            subcategory="webapp_transport_security",
            title=f"{len(insecure)} web apps with transport security issues",
            description="Web apps without HTTPS enforcement or with outdated TLS are vulnerable to MITM attacks.",
            severity="high",
            affected_resources=insecure,
            remediation={
                "Description": "Enable HTTPS-only and set minimum TLS to 1.2.",
                "AzureCLI": "az webapp update -n <app> -g <rg> --https-only true --min-tls-version 1.2",
                "PowerShell": "Set-AzWebApp -ResourceGroupName <rg> -Name <app> -HttpsOnly $true",
            },
        )]
    return []


def _check_sql_exposure(evidence_index: dict) -> list[dict]:
    sql = evidence_index.get("azure-sql-server", [])
    exposed: list[dict] = []

    for ev in sql:
        data = ev.get("Data", ev.get("data", {}))
        for rule in data.get("FirewallRules", data.get("firewall_rules", [])):
            start_ip = rule.get("StartIpAddress", rule.get("start_ip_address", ""))
            end_ip = rule.get("EndIpAddress", rule.get("end_ip_address", ""))
            if start_ip == "0.0.0.0" and end_ip in ("255.255.255.255", "0.0.0.0"):
                exposed.append({
                    "Type": "SQLServer",
                    "Name": data.get("Name", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "FirewallRule": rule.get("Name", rule.get("name", "AllowAll")),
                })
                break

    if exposed:
        return [_risk_finding(
            category="network",
            subcategory="sql_firewall_exposure",
            title=f"{len(exposed)} SQL servers with permissive firewall rules",
            description="SQL servers with 0.0.0.0/0 rules are accessible from any Azure IP.",
            severity="high",
            affected_resources=exposed,
            remediation={
                "Description": "Remove permissive rules; use private endpoints or restrict to specific IPs.",
                "AzureCLI": (
                    "az sql server firewall-rule delete -g <rg> -s <server> -n <rule-name>\n"
                    "az network private-endpoint create -n <pe> -g <rg> --vnet-name <vnet> "
                    "--subnet <subnet> --private-connection-resource-id <sql-id> "
                    "--group-id sqlServer --connection-name <conn>"
                ),
            },
        )]
    return []
