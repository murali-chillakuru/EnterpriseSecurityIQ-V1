"""
Data Security — Private Endpoints evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_private_endpoints(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_no_private_endpoints(evidence_index))
    findings.extend(_check_pe_pending_approval(evidence_index))
    findings.extend(_check_ai_services_network(evidence_index))
    return findings


def _check_ai_services_network(idx: dict) -> list[dict]:
    """Flag AI/Cognitive Services accounts without network restrictions."""
    ai_accounts = idx.get("azure-cognitive-account", [])
    public_ai: list[dict] = []
    for ev in ai_accounts:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        public_access = props.get("publicNetworkAccess",
                       props.get("PublicNetworkAccess", "")).lower()
        network_acls = props.get("networkAcls", props.get("NetworkAcls", {}))
        default_action = ""
        if isinstance(network_acls, dict):
            default_action = network_acls.get("defaultAction", "").lower()

        is_public = public_access != "disabled" and default_action != "deny"
        if is_public:
            public_ai.append({
                "Type": "CognitiveServicesAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "PublicAccess": public_access or "enabled",
            })
    if public_ai:
        return [_ds_finding(
            "private_endpoints", "ai_services_public_access",
            f"{len(public_ai)} AI/Cognitive Services accounts with public network access",
            "AI services processing sensitive data (OCR, speech, custom models) are "
            "publicly accessible. Restrict network access and use private endpoints "
            "to prevent data exfiltration through AI APIs.",
            "medium", public_ai,
            {"Description": "Disable public access and create private endpoints for AI services.",
             "AzureCLI": "az cognitiveservices account update -n <name> -g <rg> "
                         "--custom-domain <domain> --public-network-access Disabled"},
        )]
    return []


def _check_no_private_endpoints(idx: dict) -> list[dict]:
    """Flag data services that have no private endpoint connections."""
    pe_map = idx.get("azure-private-endpoint-connections", {})
    # pe_map can be either a list of evidence dicts or a pre-built set
    if isinstance(pe_map, list):
        resources_with_pe = set()
        for ev in pe_map:
            data = ev.get("Data", ev.get("data", {}))
            linked_rid = data.get("privateLinkServiceId",
                         data.get("PrivateLinkServiceId", "")).lower()
            if linked_rid:
                resources_with_pe.add(linked_rid)
    else:
        resources_with_pe = set()

    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
        + idx.get("azure-keyvault", [])
        + idx.get("azure-cosmosdb", [])
        + idx.get("azure-dbforpostgresql", [])
        + idx.get("azure-dbformysql", [])
    )
    no_pe: list[dict] = []
    for ev in data_services:
        rid = ev.get("ResourceId", ev.get("resource_id", "")).lower()
        data = ev.get("Data", ev.get("data", {}))
        # Skip if resource has private endpoint connections in its own properties
        pe_conns = data.get("privateEndpointConnections",
                   data.get("PrivateEndpointConnections", []))
        has_pe = bool(pe_conns) or rid in resources_with_pe
        if not has_pe:
            no_pe.append({
                "Type": data.get("type", "DataService"),
                "Name": data.get("name", "Unknown"),
                "ResourceId": rid,
            })
    if no_pe:
        return [_ds_finding(
            "private_endpoints", "no_private_endpoint",
            f"{len(no_pe)} data services with no private endpoint",
            "Data services without private endpoints are reachable over the public internet, "
            "increasing the attack surface.",
            "medium", no_pe,
            {"Description": "Create private endpoints for each data service.",
             "AzureCLI": "az network private-endpoint create -n <pe-name> -g <rg> "
                         "--vnet-name <vnet> --subnet <subnet> "
                         "--private-connection-resource-id <resource-id> --group-id <group> "
                         "--connection-name <conn>"},
        )]
    return []


def _check_pe_pending_approval(idx: dict) -> list[dict]:
    """Flag private endpoint connections stuck in Pending approval state."""
    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
        + idx.get("azure-keyvault", [])
        + idx.get("azure-cosmosdb", [])
        + idx.get("azure-dbforpostgresql", [])
        + idx.get("azure-dbformysql", [])
    )
    pending: list[dict] = []
    for ev in data_services:
        data = ev.get("Data", ev.get("data", {}))
        pe_conns = data.get("privateEndpointConnections",
                   data.get("PrivateEndpointConnections", []))
        if not pe_conns:
            continue
        for conn in pe_conns:
            state = ""
            if isinstance(conn, dict):
                pls = conn.get("properties", {}).get("privateLinkServiceConnectionState", {})
                state = pls.get("status", "").lower() if isinstance(pls, dict) else ""
            if state == "pending":
                pending.append({
                    "Type": data.get("type", "DataService"),
                    "Name": data.get("name", "Unknown"),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "ConnectionState": "Pending",
                })
                break
    if pending:
        return [_ds_finding(
            "private_endpoints", "pe_pending_approval",
            f"{len(pending)} data services with pending private endpoint connections",
            "Private endpoint connections in Pending state are not yet active, "
            "meaning the resource may still be accessible only via public endpoints.",
            "medium", pending,
            {"Description": "Approve pending private endpoint connections to complete setup.",
             "AzureCLI": "az network private-endpoint-connection approve --id <connection-id>"},
        )]
    return []


