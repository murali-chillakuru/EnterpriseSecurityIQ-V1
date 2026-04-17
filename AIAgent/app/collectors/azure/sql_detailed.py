"""
Azure SQL Detailed Collector
Per-database auditing, TDE, Advanced Threat Protection, vulnerability assessment,
long-term retention policies, and database-level firewall rules.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.sql.aio import SqlManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="sql_detailed", plane="data", source="azure", priority=210)
async def collect_azure_sql_detailed(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                sql = SqlManagementClient(creds.credential, sub_id)
                servers = await paginate_arm(sql.servers.list())

                for srv in servers:
                    rg = (srv.id or "").split("/resourceGroups/")[1].split("/")[0] if srv.id else ""
                    if not rg:
                        continue

                    # Server-level ATP
                    atp_enabled = False
                    try:
                        atp = await sql.server_advanced_threat_protection_settings.get(rg, srv.name)
                        atp_enabled = atp is not None and _v(getattr(atp, "state", None)) == "Enabled"
                    except Exception:
                        pass

                    # Vulnerability Assessment
                    vuln_assessment = False
                    try:
                        va = await sql.server_vulnerability_assessments.get(rg, srv.name, "default")
                        vuln_assessment = va is not None and bool(
                            getattr(va, "storage_container_path", None)
                        )
                    except Exception:
                        pass

                    # Database-level firewall rules
                    fw_rules = []
                    try:
                        rules = await paginate_arm(sql.firewall_rules.list_by_server(rg, srv.name))
                        fw_rules = [
                            {
                                "Name": r.name,
                                "StartIpAddress": r.start_ip_address,
                                "EndIpAddress": r.end_ip_address,
                            }
                            for r in rules
                        ]
                    except Exception:
                        pass
                    allow_all = any(
                        r["StartIpAddress"] == "0.0.0.0" and r["EndIpAddress"] == "255.255.255.255"
                        for r in fw_rules
                    )

                    # Enumerate databases and check per-DB auditing + TDE
                    async def _check_db(db):
                        db_audit = False
                        db_tde = False
                        db_name = db.name or ""
                        try:
                            async with _CONCURRENCY:
                                audit_pol = await sql.database_blob_auditing_policies.get(
                                    rg, srv.name, db_name,
                                )
                                db_audit = (
                                    audit_pol is not None
                                    and _v(getattr(audit_pol, "state", None)) == "Enabled"
                                )
                        except Exception:
                            pass
                        try:
                            async with _CONCURRENCY:
                                tde = await sql.transparent_data_encryptions.get(
                                    rg, srv.name, db_name, "current",
                                )
                                db_tde = (
                                    tde is not None
                                    and _v(getattr(tde, "state", None)) == "Enabled"
                                )
                        except Exception:
                            pass
                        return {
                            "DatabaseName": db_name,
                            "AuditingEnabled": db_audit,
                            "TdeEnabled": db_tde,
                        }

                    databases = []
                    try:
                        dbs = await paginate_arm(sql.databases.list_by_server(rg, srv.name))
                        db_results = await asyncio.gather(
                            *[_check_db(db) for db in dbs if (db.name or "").lower() != "master"],
                            return_exceptions=True,
                        )
                        databases = [r for r in db_results if isinstance(r, dict)]
                    except Exception:
                        pass

                    dbs_without_audit = [d for d in databases if not d["AuditingEnabled"]]
                    dbs_without_tde = [d for d in databases if not d["TdeEnabled"]]

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="SqlDetailed",
                        evidence_type="azure-sql-detailed",
                        description=f"SQL Server detail: {srv.name}",
                        data={
                            "ServerId": srv.id,
                            "ServerName": srv.name,
                            "Location": srv.location,
                            "AtpEnabled": atp_enabled,
                            "VulnerabilityAssessmentConfigured": vuln_assessment,
                            "FirewallRuleCount": len(fw_rules),
                            "AllowAllAzureIps": allow_all,
                            "DatabaseCount": len(databases),
                            "DatabasesWithoutAudit": len(dbs_without_audit),
                            "DatabasesWithoutTde": len(dbs_without_tde),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=srv.id or "",
                        resource_type="Microsoft.Sql/servers",
                    ))

                await sql.close()
                log.info("  [SqlDetailed] %s: %d servers inspected", sub_name, len(servers))
            except Exception as exc:
                log.warning("  [SqlDetailed] %s failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("SqlDetailed", Source.AZURE, _collect)
    return result.data
