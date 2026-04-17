"""
Data Security — Purview / Information Protection evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_purview_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Azure Purview (Microsoft Purview) account security posture."""
    findings: list[dict] = []
    findings.extend(_check_purview_accounts(evidence_index))
    findings.extend(_check_purview_public_access(evidence_index))
    findings.extend(_check_purview_managed_identity(evidence_index))
    findings.extend(_check_purview_private_endpoints(evidence_index))
    return findings


def _check_purview_accounts(idx: dict) -> list[dict]:
    """Flag if no Purview account exists — data governance gap."""
    purview = idx.get("azure-purview", [])
    # Only flag if we have data services but no Purview
    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
        + idx.get("azure-cosmosdb", [])
        + idx.get("azure-dbforpostgresql", [])
        + idx.get("azure-dbformysql", [])
    )
    if data_services and not purview:
        return [_ds_finding(
            "purview", "no_purview_account",
            "No Microsoft Purview account found",
            "Without a Purview account, there is no centralized data governance, "
            "classification, or lineage tracking across your data estate.",
            "medium", [],
            {"Description": "Create a Microsoft Purview account for data governance.",
             "AzureCLI": "az purview account create -n <name> -g <rg> -l <location>",
             "PortalSteps": [
                 "Azure Portal > Create a resource > Microsoft Purview",
                 "Configure managed identity and network settings",
                 "Register data sources for scanning",
             ]},
        )]
    return []


def _check_purview_public_access(idx: dict) -> list[dict]:
    purview = idx.get("azure-purview", [])
    public: list[dict] = []
    for ev in purview:
        data = ev.get("Data", ev.get("data", {}))
        pna = data.get("publicNetworkAccess", data.get("PublicNetworkAccess", "")).lower()
        if pna in ("enabled", "notyetconfigured", ""):
            public.append({
                "Type": "PurviewAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "PublicAccess": pna or "not configured",
            })
    if public:
        return [_ds_finding(
            "purview", "purview_public_access",
            f"{len(public)} Purview accounts with public network access",
            "Purview accounts accessible from the public internet risk exposing metadata catalogs.",
            "high", public,
            {"Description": "Disable public network access on Purview accounts.",
             "AzureCLI": "az purview account update -n <name> -g <rg> --public-network-access Disabled"},
        )]
    return []


def _check_purview_managed_identity(idx: dict) -> list[dict]:
    purview = idx.get("azure-purview", [])
    no_mi: list[dict] = []
    for ev in purview:
        data = ev.get("Data", ev.get("data", {}))
        identity = data.get("identity", data.get("Identity", {}))
        identity_type = ""
        if isinstance(identity, dict):
            identity_type = identity.get("type", identity.get("Type", "")).lower()
        if not identity_type or identity_type == "none":
            no_mi.append({
                "Type": "PurviewAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_mi:
        return [_ds_finding(
            "purview", "purview_no_managed_identity",
            f"{len(no_mi)} Purview accounts without managed identity",
            "Managed identity is required for Purview to securely scan data sources "
            "without storing credentials.",
            "high", no_mi,
            {"Description": "Enable system-assigned managed identity on Purview accounts.",
             "PortalSteps": [
                 "Azure Portal > Purview account > Identity",
                 "Enable system-assigned managed identity",
                 "Grant appropriate roles on data sources",
             ]},
        )]
    return []


def _check_purview_private_endpoints(idx: dict) -> list[dict]:
    purview = idx.get("azure-purview", [])
    no_pe: list[dict] = []
    for ev in purview:
        data = ev.get("Data", ev.get("data", {}))
        pe_conns = data.get("privateEndpointConnections",
                   data.get("PrivateEndpointConnections", []))
        if not pe_conns:
            no_pe.append({
                "Type": "PurviewAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_pe:
        return [_ds_finding(
            "purview", "purview_no_private_endpoint",
            f"{len(no_pe)} Purview accounts without private endpoints",
            "Without private endpoints, Purview management and data scanning traffic "
            "traverses the public internet.",
            "medium", no_pe,
            {"Description": "Create private endpoints for Purview (account, portal, ingestion).",
             "AzureCLI": "az network private-endpoint create -n <pe-name> -g <rg> "
                         "--vnet-name <vnet> --subnet <subnet> "
                         "--private-connection-resource-id <purview-id> --group-id account"},
        )]
    return []


