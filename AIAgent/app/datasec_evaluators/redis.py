"""
Data Security — Redis Cache Security evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS
from app.datasec_evaluators.data_factory import _check_redis_no_patch_schedule, _check_redis_public_access

log = logging.getLogger(__name__)

def analyze_redis_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Azure Cache for Redis security posture."""
    findings: list[dict] = []
    findings.extend(_check_redis_tls(evidence_index))
    findings.extend(_check_redis_non_ssl_port(evidence_index))
    findings.extend(_check_redis_firewall(evidence_index))
    findings.extend(_check_redis_no_patch_schedule(evidence_index))
    findings.extend(_check_redis_public_access(evidence_index))
    return findings


def _check_redis_tls(idx: dict) -> list[dict]:
    """Flag Redis caches using TLS versions older than 1.2."""
    caches = idx.get("azure-redis-cache", [])
    weak_tls: list[dict] = []
    for ev in caches:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        min_tls = props.get("minimumTlsVersion",
                  props.get("MinimumTlsVersion", ""))
        if min_tls and min_tls not in ("1.2", "1.3"):
            weak_tls.append({
                "Type": "RedisCache",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "MinTLS": min_tls,
            })
    if weak_tls:
        return [_ds_finding(
            "redis", "redis_weak_tls",
            f"{len(weak_tls)} Redis caches accepting TLS versions below 1.2",
            "Older TLS versions have known vulnerabilities. Redis caches should "
            "require TLS 1.2 or higher for all client connections.",
            "medium", weak_tls,
            {"Description": "Set minimum TLS version to 1.2.",
             "AzureCLI": "az redis update -n <name> -g <rg> --set minimumTlsVersion=1.2"},
        )]
    return []


def _check_redis_non_ssl_port(idx: dict) -> list[dict]:
    """Flag Redis caches with non-SSL port (6379) enabled."""
    caches = idx.get("azure-redis-cache", [])
    non_ssl: list[dict] = []
    for ev in caches:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        non_ssl_enabled = props.get("enableNonSslPort",
                          props.get("EnableNonSslPort", False))
        if non_ssl_enabled is True:
            non_ssl.append({
                "Type": "RedisCache",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if non_ssl:
        return [_ds_finding(
            "redis", "redis_non_ssl_port",
            f"{len(non_ssl)} Redis caches with non-SSL port (6379) enabled",
            "The non-SSL port transmits data in plaintext, exposing cached data "
            "(sessions, tokens, PII) to network interception.",
            "high", non_ssl,
            {"Description": "Disable the non-SSL port on Redis caches.",
             "AzureCLI": "az redis update -n <name> -g <rg> --set enableNonSslPort=false"},
        )]
    return []


def _check_redis_firewall(idx: dict) -> list[dict]:
    """Flag Redis caches without firewall rules (open to all Azure IPs)."""
    caches = idx.get("azure-redis-cache", [])
    no_fw: list[dict] = []
    for ev in caches:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        fw_rules = props.get("firewallRules",
                   props.get("FirewallRules",
                   props.get("redisFirewallRules", [])))
        public_access = props.get("publicNetworkAccess",
                       props.get("PublicNetworkAccess", "")).lower()
        pe_conns = props.get("privateEndpointConnections", [])
        if not fw_rules and not pe_conns and public_access != "disabled":
            no_fw.append({
                "Type": "RedisCache",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_fw:
        return [_ds_finding(
            "redis", "redis_no_firewall",
            f"{len(no_fw)} Redis caches without firewall rules or private endpoints",
            "Without firewall rules or private endpoints, Redis caches are accessible "
            "from any Azure IP address, increasing the risk of unauthorized cache access.",
            "medium", no_fw,
            {"Description": "Configure firewall rules or deploy private endpoints.",
             "AzureCLI": "az redis firewall-rules create -n <name> -g <rg> "
                         "--rule-name AllowVNet --start-ip <ip> --end-ip <ip>"},
        )]
    return []


# ── Messaging Security ──────────────────────────────────────────────

