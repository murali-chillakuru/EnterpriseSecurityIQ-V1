"""
Data Security — Azure File Sync Security evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_file_sync_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Azure File Sync / Storage Sync Services security posture."""
    findings: list[dict] = []
    findings.extend(_check_file_sync_exists(evidence_index))
    findings.extend(_check_file_sync_public_access(evidence_index))
    findings.extend(_check_file_sync_https(evidence_index))
    findings.extend(_check_file_sync_cloud_tiering(evidence_index))
    findings.extend(_check_file_sync_registered_servers(evidence_index))
    return findings


def _check_file_sync_exists(idx: dict) -> list[dict]:
    """Informational: note if Storage Sync Services exist (attack surface)."""
    sync_services = idx.get("azure-storagesync", [])
    if sync_services:
        resources = []
        for ev in sync_services:
            data = ev.get("Data", ev.get("data", {}))
            resources.append({
                "Type": "StorageSyncService",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Location": data.get("location", ""),
            })
        return [_ds_finding(
            "file_sync", "storage_sync_detected",
            f"{len(resources)} Azure File Sync (Storage Sync) service(s) detected",
            "Storage Sync Services replicate file data between on-premises and Azure. "
            "Ensure proper network and access controls are configured.",
            "informational", resources,
            {"Description": "Review network settings, registered servers, and cloud tiering policies.",
             "PortalSteps": [
                 "Azure Portal > Storage Sync Service > Registered servers",
                 "Verify each server is expected and up-to-date",
                 "Review cloud tiering date/space policies",
             ]},
        )]
    return []


def _check_file_sync_public_access(idx: dict) -> list[dict]:
    sync_services = idx.get("azure-storagesync", [])
    public: list[dict] = []
    for ev in sync_services:
        data = ev.get("Data", ev.get("data", {}))
        pna = data.get("incomingTrafficPolicy", data.get("IncomingTrafficPolicy", "")).lower()
        if pna != "allowvirtualnetworksonly":
            public.append({
                "Type": "StorageSyncService",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "TrafficPolicy": pna or "AllowAllTraffic (default)",
            })
    if public:
        return [_ds_finding(
            "file_sync", "file_sync_public_access",
            f"{len(public)} Storage Sync Services allowing public network access",
            "Sync traffic from public networks increases the attack surface for data exfiltration.",
            "high", public,
            {"Description": "Restrict incoming traffic to virtual networks only.",
             "AzureCLI": "az storagesync update -n <name> -g <rg> --incoming-traffic-policy AllowVirtualNetworksOnly"},
        )]
    return []


def _check_file_sync_https(idx: dict) -> list[dict]:
    sync_services = idx.get("azure-storagesync", [])
    no_https: list[dict] = []
    for ev in sync_services:
        data = ev.get("Data", ev.get("data", {}))
        # Check for HTTP-only endpoints (ARM property)
        pe_conns = data.get("privateEndpointConnections",
                   data.get("PrivateEndpointConnections", []))
        if not pe_conns:
            no_https.append({
                "Type": "StorageSyncService",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_https:
        return [_ds_finding(
            "file_sync", "file_sync_no_private_endpoint",
            f"{len(no_https)} Storage Sync Services without private endpoints",
            "Without private endpoints, sync registration and data traffic traverse the public internet.",
            "medium", no_https,
            {"Description": "Create private endpoints for Storage Sync Services.",
             "AzureCLI": "az network private-endpoint create -n <pe-name> -g <rg> "
                         "--vnet-name <vnet> --subnet <subnet> "
                         "--private-connection-resource-id <sync-id> --group-id afs"},
        )]
    return []


def _check_file_sync_cloud_tiering(idx: dict) -> list[dict]:
    """Flag Storage Sync Services with cloud tiering disabled or misconfigured."""
    sync_services = idx.get("azure-storagesync", [])
    no_tiering: list[dict] = []
    for ev in sync_services:
        data = ev.get("Data", ev.get("data", {}))
        ct = data.get("cloudTieringEnabled", data.get("CloudTieringEnabled"))
        free_space = data.get("volumeFreeSpacePercent", data.get("VolumeFreeSpacePercent", 0))
        if ct is False or (ct is None and not free_space):
            no_tiering.append({
                "Type": "StorageSyncService",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "CloudTiering": "Disabled" if ct is False else "Not Configured",
            })
    if no_tiering:
        return [_ds_finding(
            "file_sync", "cloud_tiering_disabled",
            f"{len(no_tiering)} Storage Sync Services without cloud tiering",
            "Cloud tiering optimizes on-premises storage by keeping only frequently accessed "
            "files locally. Without it, all files are kept on-premises, increasing storage costs "
            "and reducing the benefit of Azure File Sync.",
            "low", no_tiering,
            {"Description": "Enable cloud tiering with a suitable volume free space policy.",
             "PortalSteps": [
                 "Azure Portal > Storage Sync Service > Sync groups > Server endpoint",
                 "Enable 'Cloud Tiering' and set volume free space percentage (e.g. 20%)",
                 "Optionally set a date policy to tier files not accessed in N days",
             ]},
        )]
    return []


def _check_file_sync_registered_servers(idx: dict) -> list[dict]:
    """Flag Storage Sync Services with outdated or stale registered server agents."""
    sync_services = idx.get("azure-storagesync", [])
    stale_servers: list[dict] = []
    now = datetime.now(timezone.utc)
    for ev in sync_services:
        data = ev.get("Data", ev.get("data", {}))
        servers = data.get("registeredServers", data.get("RegisteredServers", []))
        for srv in servers:
            last_heartbeat = srv.get("lastHeartBeat", srv.get("LastHeartBeat", ""))
            agent_version = srv.get("agentVersion", srv.get("AgentVersion", ""))
            server_name = srv.get("serverName", srv.get("ServerName", "Unknown"))
            is_stale = False
            if last_heartbeat:
                try:
                    hb_dt = datetime.fromisoformat(last_heartbeat.replace("Z", "+00:00"))
                    if (now - hb_dt).days > 7:
                        is_stale = True
                except (ValueError, TypeError):
                    pass
            if is_stale:
                stale_servers.append({
                    "Type": "RegisteredServer",
                    "Name": server_name,
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "AgentVersion": agent_version or "Unknown",
                    "LastHeartbeat": last_heartbeat or "Never",
                })
    if stale_servers:
        return [_ds_finding(
            "file_sync", "stale_registered_servers",
            f"{len(stale_servers)} File Sync registered servers with stale heartbeats",
            "Registered servers that have not sent a heartbeat in over 7 days may be offline, "
            "decommissioned, or running outdated agents. Stale servers can cause sync failures "
            "and leave files unprotected.",
            "medium", stale_servers,
            {"Description": "Verify stale servers are online and update File Sync agents.",
             "PortalSteps": [
                 "Azure Portal > Storage Sync Service > Registered servers",
                 "Check server status and last heartbeat time",
                 "Update agent if version is outdated (latest version recommended)",
                 "Unregister servers that are no longer in use",
             ]},
        )]
    return []


