"""
Data Security — Managed Identity Deep Audit evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_managed_identity_deep(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Deep audit of managed identity adoption and configuration across data services."""
    findings: list[dict] = []
    findings.extend(_check_data_services_no_managed_identity(evidence_index))
    return findings


def _check_data_services_no_managed_identity(idx: dict) -> list[dict]:
    """Flag key data services (ADF, Synapse, Event Hub, Service Bus) without managed identity."""
    # Check additional service types beyond the basic check
    service_types = [
        ("azure-data-factory", "DataFactory"),
        ("azure-synapse-workspace", "SynapseWorkspace"),
        ("azure-eventhub-namespace", "EventHubNamespace"),
        ("azure-servicebus-namespace", "ServiceBusNamespace"),
    ]
    no_mi: list[dict] = []
    for evidence_key, resource_type in service_types:
        resources = idx.get(evidence_key, [])
        for ev in resources:
            data = ev.get("Data", ev.get("data", {}))
            identity = data.get("identity", {})
            id_type = ""
            if isinstance(identity, dict):
                id_type = identity.get("type", identity.get("Type", "")).lower()
            has_mi = id_type in ("systemassigned", "userassigned",
                                 "systemassigned,userassigned",
                                 "systemassigned, userassigned")
            if not has_mi:
                no_mi.append({
                    "Type": resource_type,
                    "Name": data.get("name", "Unknown"),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                })
    if no_mi:
        return [_ds_finding(
            "identity", "data_services_no_managed_identity",
            f"{len(no_mi)} data pipeline/messaging services without managed identity",
            "Services without managed identity rely on connection strings and shared "
            "keys for authentication. Managed identity provides credential-free, "
            "automatically rotated authentication with full audit trail.",
            "medium", no_mi,
            {"Description": "Enable managed identity on all data services.",
             "AzureCLI": "# Enable system-assigned MI: az resource update --ids <id> "
                         "--set identity.type=SystemAssigned"},
        )]
    return []


#    Trend Analysis                                                    


#                                                                           
# Wave A+B+C — New Service & Security Domain Checks
#                                                                           

