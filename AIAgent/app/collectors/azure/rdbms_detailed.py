"""
Azure Relational Database Detailed Collector
PostgreSQL and MySQL Flexible Server parameters, firewall rules, and configurations.
"""

from __future__ import annotations
from azure.mgmt.rdbms.postgresql_flexibleservers.aio import PostgreSQLManagementClient
from azure.mgmt.rdbms.mysql_flexibleservers.aio import MySQLManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

# Security-relevant server parameters
_PG_PARAMS = [
    "require_secure_transport", "log_checkpoints", "log_connections",
    "log_disconnections", "connection_throttling", "log_retention_days",
]
_MYSQL_PARAMS = [
    "require_secure_transport", "audit_log_enabled", "tls_version",
    "slow_query_log", "log_output",
]


@register_collector(name="rdbms_detailed", plane="data", source="azure", priority=230)
async def collect_azure_rdbms_detailed(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # PostgreSQL Flexible Servers
            try:
                pg = PostgreSQLManagementClient(creds.credential, sub_id)
                servers = await paginate_arm(pg.servers.list())
                for srv in servers:
                    rg = (srv.id or "").split("/resourceGroups/")[1].split("/")[0] if srv.id else ""
                    if not rg:
                        continue

                    # Fetch security-relevant parameters
                    params = {}
                    for pname in _PG_PARAMS:
                        try:
                            p = await pg.configurations.get(rg, srv.name, pname)
                            params[pname] = p.value if p else None
                        except Exception:
                            params[pname] = None

                    # Firewall rules
                    fw_rules = []
                    allow_all = False
                    try:
                        rules = await paginate_arm(pg.firewall_rules.list_by_server(rg, srv.name))
                        fw_rules = [
                            {"Name": r.name, "StartIp": r.start_ip_address, "EndIp": r.end_ip_address}
                            for r in rules
                        ]
                        allow_all = any(
                            r["StartIp"] == "0.0.0.0" and r["EndIp"] == "255.255.255.255"
                            for r in fw_rules
                        )
                    except Exception:
                        pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="RdbmsDetailed",
                        evidence_type="azure-database-config",
                        description=f"PostgreSQL config: {srv.name}",
                        data={
                            "ServerId": srv.id,
                            "ServerName": srv.name,
                            "Engine": "PostgreSQL",
                            "Location": srv.location,
                            "RequireSecureTransport": params.get("require_secure_transport"),
                            "LogCheckpoints": params.get("log_checkpoints"),
                            "LogConnections": params.get("log_connections"),
                            "LogDisconnections": params.get("log_disconnections"),
                            "ConnectionThrottling": params.get("connection_throttling"),
                            "LogRetentionDays": params.get("log_retention_days"),
                            "FirewallRuleCount": len(fw_rules),
                            "AllowAllAzureIps": allow_all,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=srv.id or "",
                        resource_type="Microsoft.DBforPostgreSQL/flexibleServers",
                    ))
                await pg.close()
                log.info("  [RdbmsDetailed] %s: %d PostgreSQL servers", sub_name, len(servers))
            except Exception as exc:
                log.warning("  [RdbmsDetailed] %s PostgreSQL failed: %s", sub_name, exc)

            # MySQL Flexible Servers
            try:
                mysql = MySQLManagementClient(creds.credential, sub_id)
                servers = await paginate_arm(mysql.servers.list())
                for srv in servers:
                    rg = (srv.id or "").split("/resourceGroups/")[1].split("/")[0] if srv.id else ""
                    if not rg:
                        continue

                    params = {}
                    for pname in _MYSQL_PARAMS:
                        try:
                            p = await mysql.configurations.get(rg, srv.name, pname)
                            params[pname] = p.value if p else None
                        except Exception:
                            params[pname] = None

                    fw_rules = []
                    allow_all = False
                    try:
                        rules = await paginate_arm(mysql.firewall_rules.list_by_server(rg, srv.name))
                        fw_rules = [
                            {"Name": r.name, "StartIp": r.start_ip_address, "EndIp": r.end_ip_address}
                            for r in rules
                        ]
                        allow_all = any(
                            r["StartIp"] == "0.0.0.0" and r["EndIp"] == "255.255.255.255"
                            for r in fw_rules
                        )
                    except Exception:
                        pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="RdbmsDetailed",
                        evidence_type="azure-database-config",
                        description=f"MySQL config: {srv.name}",
                        data={
                            "ServerId": srv.id,
                            "ServerName": srv.name,
                            "Engine": "MySQL",
                            "Location": srv.location,
                            "RequireSecureTransport": params.get("require_secure_transport"),
                            "AuditLogEnabled": params.get("audit_log_enabled"),
                            "TlsVersion": params.get("tls_version"),
                            "SlowQueryLog": params.get("slow_query_log"),
                            "LogOutput": params.get("log_output"),
                            "FirewallRuleCount": len(fw_rules),
                            "AllowAllAzureIps": allow_all,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=srv.id or "",
                        resource_type="Microsoft.DBforMySQL/flexibleServers",
                    ))
                await mysql.close()
                log.info("  [RdbmsDetailed] %s: %d MySQL servers", sub_name, len(servers))
            except Exception as exc:
                log.warning("  [RdbmsDetailed] %s MySQL failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("RdbmsDetailed", Source.AZURE, _collect)
    return result.data
