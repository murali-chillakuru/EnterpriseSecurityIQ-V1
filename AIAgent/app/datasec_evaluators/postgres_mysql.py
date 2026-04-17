"""
Data Security — PostgreSQL / MySQL Security evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_postgres_mysql_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_pg_mysql_ssl(evidence_index))
    findings.extend(_check_pg_mysql_public_access(evidence_index))
    findings.extend(_check_pg_mysql_open_firewall(evidence_index))
    findings.extend(_check_pg_mysql_geo_backup(evidence_index))
    findings.extend(_check_pg_mysql_ha(evidence_index))
    findings.extend(_check_pg_mysql_aad_auth(evidence_index))
    return findings


def _check_pg_mysql_aad_auth(idx: dict) -> list[dict]:
    """Flag PostgreSQL/MySQL servers without Azure AD authentication configured."""
    servers = idx.get("azure-dbforpostgresql", []) + idx.get("azure-dbformysql", [])
    no_aad: list[dict] = []
    for ev in servers:
        data = ev.get("Data", ev.get("data", {}))
        aad_admin = data.get("authConfig", data.get("AuthConfig", {}))
        has_aad = False
        if isinstance(aad_admin, dict):
            has_aad = aad_admin.get("activeDirectoryAuth", "").lower() == "enabled"
        if not has_aad:
            # Also check for Azure AD administrator set
            ad_admin = data.get("azureADAdministrator", data.get("AzureADAdministrator"))
            if ad_admin:
                has_aad = True
        if not has_aad:
            rtype = data.get("type", "")
            label = "PostgreSQL" if "postgres" in rtype.lower() else "MySQL"
            no_aad.append({
                "Type": label,
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_aad:
        return [_ds_finding(
            "pgmysql", "pg_mysql_no_aad_auth",
            f"{len(no_aad)} PostgreSQL/MySQL servers without Azure AD authentication",
            "Without Azure AD authentication, database access relies solely on local "
            "passwords. Azure AD brings MFA, Conditional Access, and centralized "
            "identity lifecycle management to database connections.",
            "medium", no_aad,
            {"Description": "Configure Azure AD authentication for PostgreSQL/MySQL.",
             "AzureCLI": "az postgres flexible-server ad-admin create -g <rg> -s <server> "
                         "--display-name <admin> --object-id <oid>"},
        )]
    return []


def _check_pg_mysql_ssl(idx: dict) -> list[dict]:
    servers = idx.get("azure-dbforpostgresql", []) + idx.get("azure-dbformysql", [])
    no_ssl: list[dict] = []
    for ev in servers:
        data = ev.get("Data", ev.get("data", {}))
        ssl = data.get("requireSecureTransport", data.get("sslEnforcement", "")).lower()
        if ssl in ("disabled", "false", "off"):
            rtype = data.get("type", "")
            label = "PostgreSQL" if "postgres" in rtype.lower() else "MySQL"
            no_ssl.append({
                "Type": label,
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_ssl:
        return [_ds_finding(
            "pgmysql", "ssl_not_enforced",
            f"{len(no_ssl)} PostgreSQL/MySQL servers without SSL enforcement",
            "Connections without SSL expose data in transit to interception.",
            "high", no_ssl,
            {"Description": "Enable require_secure_transport on the server.",
             "AzureCLI": "az postgres flexible-server parameter set -g <rg> -s <server> -n require_secure_transport -v ON"},
        )]
    return []


def _check_pg_mysql_public_access(idx: dict) -> list[dict]:
    servers = idx.get("azure-dbforpostgresql", []) + idx.get("azure-dbformysql", [])
    public: list[dict] = []
    for ev in servers:
        data = ev.get("Data", ev.get("data", {}))
        pna = data.get("publicNetworkAccess", data.get("PublicNetworkAccess", "")).lower()
        if pna == "enabled":
            rtype = data.get("type", "")
            label = "PostgreSQL" if "postgres" in rtype.lower() else "MySQL"
            public.append({
                "Type": label,
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "pgmysql", "public_access_enabled",
            f"{len(public)} PostgreSQL/MySQL servers with public network access",
            "Database servers accessible from the public internet.",
            "high", public,
            {"Description": "Disable public network access; use private endpoints.",
             "AzureCLI": "az postgres flexible-server update -g <rg> -n <server> --public-network-access disabled"},
        )]
    return []


def _check_pg_mysql_open_firewall(idx: dict) -> list[dict]:
    """Check firewall rules collected via ARM enrichment."""
    servers = idx.get("azure-dbforpostgresql", []) + idx.get("azure-dbformysql", [])
    open_fw: list[dict] = []
    for ev in servers:
        data = ev.get("Data", ev.get("data", {}))
        for rule in data.get("FirewallRules", []):
            start = rule.get("startIpAddress", rule.get("StartIpAddress", ""))
            end = rule.get("endIpAddress", rule.get("EndIpAddress", ""))
            if start == "0.0.0.0" and end in ("255.255.255.255", "0.0.0.0"):
                rtype = data.get("type", "")
                label = "PostgreSQL" if "postgres" in rtype.lower() else "MySQL"
                open_fw.append({
                    "Type": label,
                    "Name": data.get("name", "Unknown"),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                })
                break
    if open_fw:
        return [_ds_finding(
            "pgmysql", "open_firewall",
            f"{len(open_fw)} PostgreSQL/MySQL servers with 0.0.0.0/0 firewall rules",
            "Allow-all firewall rules expose the database to the entire Internet.",
            "high", open_fw,
            {"Description": "Remove the AllowAll rule; use private endpoints or specific IP ranges.",
             "AzureCLI": "az postgres flexible-server firewall-rule delete -g <rg> -s <server> -n <rule>"},
        )]
    return []


def _check_pg_mysql_geo_backup(idx: dict) -> list[dict]:
    servers = idx.get("azure-dbforpostgresql", []) + idx.get("azure-dbformysql", [])
    no_geo: list[dict] = []
    for ev in servers:
        data = ev.get("Data", ev.get("data", {}))
        geo = data.get("geoRedundantBackup", data.get("GeoRedundantBackup", "")).lower()
        if geo == "disabled":
            rtype = data.get("type", "")
            label = "PostgreSQL" if "postgres" in rtype.lower() else "MySQL"
            no_geo.append({
                "Type": label,
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_geo:
        return [_ds_finding(
            "pgmysql", "no_geo_backup",
            f"{len(no_geo)} PostgreSQL/MySQL servers without geo-redundant backup",
            "Without geo-redundant backups, a regional failure could result in data loss.",
            "medium", no_geo,
            {"Description": "Enable geo-redundant backup for disaster recovery.",
             "AzureCLI": "az postgres flexible-server update -g <rg> -n <server> --geo-redundant-backup Enabled"},
        )]
    return []


def _check_pg_mysql_ha(idx: dict) -> list[dict]:
    """Flag PG/MySQL Flexible Servers without High Availability configured."""
    servers = idx.get("azure-dbforpostgresql", []) + idx.get("azure-dbformysql", [])
    no_ha: list[dict] = []
    for ev in servers:
        data = ev.get("Data", ev.get("data", {}))
        ha = data.get("highAvailability", data.get("HighAvailability", {})) or {}
        ha_mode = ha.get("mode", ha.get("Mode", "")).lower() if isinstance(ha, dict) else ""
        if ha_mode in ("disabled", "", "none") or not ha_mode:
            rtype = data.get("type", "")
            label = "PostgreSQL" if "postgres" in rtype.lower() else "MySQL"
            no_ha.append({
                "Type": label,
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "HAMode": ha_mode or "Disabled",
            })
    if no_ha:
        return [_ds_finding(
            "pgmysql", "no_high_availability",
            f"{len(no_ha)} PostgreSQL/MySQL servers without High Availability",
            "Servers without HA are single points of failure. Zone-redundant HA "
            "provides automatic failover to a standby replica in a different AZ.",
            "medium", no_ha,
            {"Description": "Enable zone-redundant high availability.",
             "AzureCLI": "az postgres flexible-server update -g <rg> -n <server> --high-availability ZoneRedundant"},
        )]
    return []


