"""
Data Security — Network Segmentation & DDoS evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_network_segmentation(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess network segmentation controls protecting data services."""
    findings: list[dict] = []
    findings.extend(_check_nsg_permissive_data_ports(evidence_index))
    findings.extend(_check_ddos_protection(evidence_index))
    findings.extend(_check_data_subnet_service_endpoints(evidence_index))
    findings.extend(_check_data_factory_managed_vnet(evidence_index))
    findings.extend(_check_synapse_managed_vnet(evidence_index))
    return findings


def _check_data_factory_managed_vnet(idx: dict) -> list[dict]:
    """Flag Data Factory instances without managed virtual network."""
    adfs = idx.get("azure-data-factory", [])
    no_mvnet: list[dict] = []
    for ev in adfs:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        managed_vnet = props.get("managedVirtualNetwork", props.get("ManagedVirtualNetwork"))
        if not managed_vnet:
            no_mvnet.append({
                "Type": "DataFactory",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_mvnet:
        return [_ds_finding(
            "network_segmentation", "adf_no_managed_vnet",
            f"{len(no_mvnet)} Data Factory instances without managed virtual network",
            "Without a managed VNet, Data Factory integration runtimes use public IPs "
            "and can exfiltrate data to arbitrary endpoints. Managed VNet restricts "
            "outbound connectivity to approved destinations only.",
            "high", no_mvnet,
            {"Description": "Enable managed virtual network on Data Factory.",
             "PortalSteps": [
                 "Azure Portal > Data Factory > Managed virtual network",
                 "Enable managed VNet for new integration runtimes",
                 "Create managed private endpoints for data sources",
             ]},
        )]
    return []


def _check_synapse_managed_vnet(idx: dict) -> list[dict]:
    """Flag Synapse workspaces without managed VNet or exfiltration protection."""
    synapse = idx.get("azure-synapse-workspace", [])
    no_protection: list[dict] = []
    for ev in synapse:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        managed_vnet = props.get("managedVirtualNetwork", "")
        exfil_protection = props.get("managedVirtualNetworkSettings", {})
        prevent_exfil = False
        if isinstance(exfil_protection, dict):
            prevent_exfil = exfil_protection.get(
                "preventDataExfiltration", False)
        if not managed_vnet or not prevent_exfil:
            no_protection.append({
                "Type": "SynapseWorkspace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "ManagedVNet": "Yes" if managed_vnet else "No",
                "ExfiltrationProtection": "Yes" if prevent_exfil else "No",
            })
    if no_protection:
        return [_ds_finding(
            "network_segmentation", "synapse_no_exfiltration_protection",
            f"{len(no_protection)} Synapse workspaces without data exfiltration protection",
            "Without managed VNet and data exfiltration protection, Synapse pipelines "
            "and Spark pools can send data to arbitrary external endpoints.",
            "high", no_protection,
            {"Description": "Enable managed VNet with data exfiltration prevention.",
             "PortalSteps": [
                 "Note: Managed VNet must be enabled at workspace creation time",
                 "For existing workspaces, recreate with managed VNet enabled",
                 "Enable 'Prevent data exfiltration' in managed VNet settings",
             ]},
        )]
    return []


def _check_nsg_permissive_data_ports(idx: dict) -> list[dict]:
    """Flag NSGs with inbound rules allowing any source to data-service ports."""
    nsgs = idx.get("azure-nsg", [])
    data_ports = {1433, 3306, 5432, 6379, 27017, 443, 445}  # SQL, MySQL, PG, Redis, Mongo, HTTPS, SMB
    permissive: list[dict] = []
    for ev in nsgs:
        data = ev.get("Data", ev.get("data", {}))
        rules = data.get("securityRules", data.get("SecurityRules", []))
        if not isinstance(rules, list):
            continue
        for rule in rules:
            props = rule.get("properties", rule) if isinstance(rule, dict) else {}
            direction = props.get("direction", "").lower()
            access = props.get("access", "").lower()
            src = props.get("sourceAddressPrefix", "")
            dst_port = props.get("destinationPortRange", "")
            if direction == "inbound" and access == "allow" and src in ("*", "0.0.0.0/0", "Internet"):
                try:
                    if dst_port == "*" or int(dst_port) in data_ports:
                        permissive.append({
                            "Type": "NetworkSecurityGroup",
                            "Name": data.get("name", "Unknown"),
                            "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                            "RuleName": rule.get("name", props.get("name", "")),
                            "DestPort": dst_port,
                            "Source": src,
                        })
                        break
                except (ValueError, TypeError):
                    if dst_port == "*":
                        permissive.append({
                            "Type": "NetworkSecurityGroup",
                            "Name": data.get("name", "Unknown"),
                            "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                            "RuleName": rule.get("name", props.get("name", "")),
                            "DestPort": dst_port,
                            "Source": src,
                        })
                        break
    if permissive:
        return [_ds_finding(
            "network_segmentation", "nsg_permissive_data_ports",
            f"{len(permissive)} NSGs allow unrestricted inbound access to data-service ports",
            "NSG rules allowing any source (*/Internet) to data ports (SQL 1433, PG 5432, "
            "MySQL 3306, Redis 6379, SMB 445) expose databases to the internet.",
            "high", permissive,
            {"Description": "Restrict NSG inbound rules to specific source IPs or VNet tags.",
             "AzureCLI": "az network nsg rule update -g <rg> --nsg-name <nsg> -n <rule> --source-address-prefixes <ip/cidr>"},
        )]
    return []


def _check_ddos_protection(idx: dict) -> list[dict]:
    """Flag VNets without DDoS Protection Plan associated."""
    vnets = idx.get("azure-vnet", [])
    no_ddos: list[dict] = []
    for ev in vnets:
        data = ev.get("Data", ev.get("data", {}))
        ddos = data.get("enableDdosProtection", data.get("EnableDdosProtection"))
        if ddos is not True:
            no_ddos.append({
                "Type": "VirtualNetwork",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_ddos:
        return [_ds_finding(
            "network_segmentation", "no_ddos_protection",
            f"{len(no_ddos)} VNets without DDoS Protection",
            "Without DDoS Protection Standard, volumetric attacks can disrupt data services. "
            "Azure DDoS Protection provides automatic mitigation and cost protection.",
            "medium", no_ddos,
            {"Description": "Enable DDoS Protection Standard on VNets hosting data services.",
             "AzureCLI": "az network ddos-protection create -g <rg> -n <plan-name> && "
                         "az network vnet update -g <rg> -n <vnet> --ddos-protection-plan <plan-id>"},
        )]
    return []


def _check_data_subnet_service_endpoints(idx: dict) -> list[dict]:
    """Flag VNets with subnets hosting data services that lack service endpoints."""
    vnets = idx.get("azure-vnet", [])
    no_se: list[dict] = []
    data_svc_endpoints = {
        "microsoft.storage", "microsoft.sql", "microsoft.keyvault",
        "microsoft.azurecosmosdb",
    }
    for ev in vnets:
        data = ev.get("Data", ev.get("data", {}))
        subnets = data.get("subnets", data.get("Subnets", []))
        if not isinstance(subnets, list):
            continue
        for subnet in subnets:
            props = subnet.get("properties", subnet) if isinstance(subnet, dict) else {}
            se_list = props.get("serviceEndpoints", [])
            configured = {
                se.get("service", "").lower()
                for se in (se_list if isinstance(se_list, list) else [])
                if isinstance(se, dict)
            }
            missing = data_svc_endpoints - configured
            if missing and props.get("addressPrefix"):
                no_se.append({
                    "Type": "Subnet",
                    "Name": f"{data.get('name', 'Unknown')}/{subnet.get('name', props.get('name', 'Unknown'))}",
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "MissingEndpoints": ", ".join(sorted(missing)),
                })
    if no_se:
        return [_ds_finding(
            "network_segmentation", "subnet_missing_service_endpoints",
            f"{len(no_se)} subnets missing service endpoints for data services",
            "Service endpoints route traffic to Azure data services over the Azure backbone "
            "instead of the public internet, reducing exposure and latency.",
            "low", no_se,
            {"Description": "Add service endpoints for data services on relevant subnets.",
             "AzureCLI": "az network vnet subnet update -g <rg> --vnet-name <vnet> -n <subnet> "
                         "--service-endpoints Microsoft.Storage Microsoft.Sql Microsoft.KeyVault"},
        )]
    return []


