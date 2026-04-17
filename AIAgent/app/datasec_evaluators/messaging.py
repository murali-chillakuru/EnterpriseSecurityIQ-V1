"""
Data Security — Messaging Security evaluator (EventHub/ServiceBus).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS
from app.datasec_evaluators.data_factory import (
    _check_eventhub_local_auth,
    _check_servicebus_local_auth,
    _check_eventhub_capture_disabled,
)

log = logging.getLogger(__name__)

def analyze_messaging_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Azure messaging services (Event Hub, Service Bus) security posture."""
    findings: list[dict] = []
    findings.extend(_check_eventhub_network(evidence_index))
    findings.extend(_check_servicebus_network(evidence_index))
    findings.extend(_check_messaging_tls(evidence_index))
    findings.extend(_check_eventhub_local_auth(evidence_index))
    findings.extend(_check_servicebus_local_auth(evidence_index))
    findings.extend(_check_eventhub_capture_disabled(evidence_index))
    return findings


def _check_eventhub_network(idx: dict) -> list[dict]:
    """Flag Event Hub namespaces without network restrictions."""
    hubs = idx.get("azure-eventhub-namespace", [])
    public: list[dict] = []
    for ev in hubs:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        public_access = props.get("publicNetworkAccess",
                       props.get("PublicNetworkAccess", "")).lower()
        default_action = ""
        net_rules = props.get("networkRuleSets", props.get("NetworkRuleSets", {}))
        if isinstance(net_rules, dict):
            default_action = net_rules.get("defaultAction", "").lower()
        pe_conns = props.get("privateEndpointConnections", [])
        if public_access != "disabled" and default_action != "deny" and not pe_conns:
            public.append({
                "Type": "EventHubNamespace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "messaging", "eventhub_public_access",
            f"{len(public)} Event Hub namespaces without network restrictions",
            "Event Hubs without network restrictions accept connections from any "
            "network, risking unauthorized access to streaming data.",
            "medium", public,
            {"Description": "Restrict Event Hub network access.",
             "AzureCLI": "az eventhubs namespace network-rule-set update -g <rg> "
                         "--namespace-name <ns> --default-action Deny"},
        )]
    return []


def _check_servicebus_network(idx: dict) -> list[dict]:
    """Flag Service Bus namespaces without network restrictions."""
    buses = idx.get("azure-servicebus-namespace", [])
    public: list[dict] = []
    for ev in buses:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        public_access = props.get("publicNetworkAccess",
                       props.get("PublicNetworkAccess", "")).lower()
        default_action = ""
        net_rules = props.get("networkRuleSets", props.get("NetworkRuleSets", {}))
        if isinstance(net_rules, dict):
            default_action = net_rules.get("defaultAction", "").lower()
        pe_conns = props.get("privateEndpointConnections", [])
        if public_access != "disabled" and default_action != "deny" and not pe_conns:
            public.append({
                "Type": "ServiceBusNamespace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "messaging", "servicebus_public_access",
            f"{len(public)} Service Bus namespaces without network restrictions",
            "Service Bus namespaces without network restrictions accept connections "
            "from any network, risking unauthorized access to message queues and topics.",
            "medium", public,
            {"Description": "Restrict Service Bus network access.",
             "AzureCLI": "az servicebus namespace network-rule-set update -g <rg> "
                         "--namespace-name <ns> --default-action Deny"},
        )]
    return []


def _check_messaging_tls(idx: dict) -> list[dict]:
    """Flag messaging services using TLS versions older than 1.2."""
    services = (idx.get("azure-eventhub-namespace", [])
                + idx.get("azure-servicebus-namespace", []))
    weak_tls: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        min_tls = props.get("minimumTlsVersion",
                  props.get("MinimumTlsVersion", ""))
        if min_tls and min_tls not in ("1.2", "1.3"):
            svc_type = "EventHub" if "eventhub" in data.get("type", "").lower() else "ServiceBus"
            weak_tls.append({
                "Type": svc_type + "Namespace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "MinTLS": min_tls,
            })
    if weak_tls:
        return [_ds_finding(
            "messaging", "messaging_weak_tls",
            f"{len(weak_tls)} messaging services accepting TLS versions below 1.2",
            "Messaging services processing sensitive events and commands should "
            "require TLS 1.2 or higher to protect data in transit.",
            "medium", weak_tls,
            {"Description": "Set minimum TLS version to 1.2 on messaging namespaces.",
             "AzureCLI": "az eventhubs namespace update -n <name> -g <rg> --minimum-tls-version 1.2"},
        )]
    return []




# ── Enhanced AI Services Security ────────────────────────────────────

