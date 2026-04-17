"""
Azure Sentinel (Microsoft Sentinel) Collector
Sentinel workspaces, analytics rules, incidents, data connectors,
watchlists, automation rules, and threat intelligence indicators.
Uses the Log Analytics and Security Insights APIs.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.securityinsight.aio import SecurityInsights
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="sentinel", plane="control", source="azure", priority=92)
async def collect_azure_sentinel(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                client = SecurityInsights(creds.credential, sub_id)

                # Discover Sentinel-enabled workspaces via listing incidents at subscription scope
                # We need to iterate resource groups and workspace names from Log Analytics
                from azure.mgmt.loganalytics.aio import LogAnalyticsManagementClient
                la_client = LogAnalyticsManagementClient(creds.credential, sub_id)
                workspaces = await paginate_arm(la_client.workspaces.list())
                await la_client.close()

                for ws in workspaces:
                    rg = (ws.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (ws.id or "") else ""
                    if not rg:
                        continue

                    # Check if Sentinel is enabled on this workspace
                    sentinel_enabled = False

                    # --- Data Connectors ---
                    connectors = []
                    try:
                        async with _CONCURRENCY:
                            connectors = await paginate_arm(
                                client.data_connectors.list(rg, ws.name)
                            )
                        sentinel_enabled = True
                    except Exception:
                        # Not a Sentinel workspace — skip
                        continue

                    if not sentinel_enabled:
                        continue

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureSentinel",
                        evidence_type="azure-sentinel-workspace",
                        description=f"Sentinel Workspace: {ws.name}",
                        data={
                            "WorkspaceId": ws.id,
                            "Name": ws.name,
                            "ResourceGroup": rg,
                            "Location": ws.location,
                            "RetentionInDays": getattr(ws, "retention_in_days", 0),
                            "Sku": ws.sku.name if ws.sku else "",
                            "DataConnectorCount": len(connectors),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ws.id or "", resource_type="SentinelWorkspace",
                    ))

                    # Emit data connector evidence
                    for dc in connectors:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureSentinel",
                            evidence_type="azure-sentinel-connector",
                            description=f"Data Connector: {dc.name}",
                            data={
                                "ConnectorId": dc.id,
                                "Name": dc.name,
                                "Kind": _v(getattr(dc, "kind", None)),
                                "SubscriptionId": sub_id,
                            },
                            resource_id=dc.id or "", resource_type="SentinelDataConnector",
                        ))

                    # --- Analytics Rules ---
                    try:
                        async with _CONCURRENCY:
                            rules = await paginate_arm(
                                client.alert_rules.list(rg, ws.name)
                            )
                        for rule in rules:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureSentinel",
                                evidence_type="azure-sentinel-rule",
                                description=f"Analytics Rule: {rule.name}",
                                data={
                                    "RuleId": rule.id,
                                    "Name": rule.name,
                                    "DisplayName": getattr(rule, "display_name", ""),
                                    "Kind": _v(getattr(rule, "kind", None)),
                                    "Enabled": getattr(rule, "enabled", False),
                                    "Severity": _v(getattr(rule, "severity", None)),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=rule.id or "", resource_type="SentinelAnalyticsRule",
                            ))
                    except Exception as exc:
                        log.warning("  [Sentinel] %s/%s analytics rules failed: %s", sub_name, ws.name, exc)

                    # --- Incidents (recent, capped at 200) ---
                    try:
                        async with _CONCURRENCY:
                            incidents = await paginate_arm(
                                client.incidents.list(
                                    rg, ws.name, top=200,
                                    order_by="properties/createdTimeUtc desc",
                                )
                            )
                        for inc in incidents[:200]:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureSentinel",
                                evidence_type="azure-sentinel-incident",
                                description=f"Incident: {getattr(inc, 'title', inc.name)}",
                                data={
                                    "IncidentId": inc.id,
                                    "Name": inc.name,
                                    "Title": getattr(inc, "title", ""),
                                    "Severity": _v(getattr(inc, "severity", None)),
                                    "Status": _v(getattr(inc, "status", None)),
                                    "Classification": _v(getattr(inc, "classification", None)),
                                    "Owner": getattr(getattr(inc, "owner", None), "assigned_to", "") if getattr(inc, "owner", None) else "",
                                    "AlertCount": getattr(getattr(inc, "additional_data", None), "alerts_count", 0) if getattr(inc, "additional_data", None) else 0,
                                    "CreatedTimeUtc": str(getattr(inc, "created_time_utc", "")),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=inc.id or "", resource_type="SentinelIncident",
                            ))
                    except Exception as exc:
                        log.warning("  [Sentinel] %s/%s incidents failed: %s", sub_name, ws.name, exc)

                    # --- Automation Rules ---
                    try:
                        async with _CONCURRENCY:
                            auto_rules = await paginate_arm(
                                client.automation_rules.list(rg, ws.name)
                            )
                        for ar in auto_rules:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureSentinel",
                                evidence_type="azure-sentinel-automation",
                                description=f"Automation Rule: {ar.name}",
                                data={
                                    "RuleId": ar.id,
                                    "Name": ar.name,
                                    "DisplayName": getattr(ar, "display_name", ""),
                                    "Order": getattr(ar, "order", 0),
                                    "IsEnabled": True,
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=ar.id or "", resource_type="SentinelAutomationRule",
                            ))
                    except Exception as exc:
                        log.warning("  [Sentinel] %s/%s automation rules failed: %s", sub_name, ws.name, exc)

                    # --- Watchlists ---
                    try:
                        async with _CONCURRENCY:
                            watchlists = await paginate_arm(
                                client.watchlists.list(rg, ws.name)
                            )
                        for wl in watchlists:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureSentinel",
                                evidence_type="azure-sentinel-watchlist",
                                description=f"Watchlist: {wl.name}",
                                data={
                                    "WatchlistId": wl.id,
                                    "Name": wl.name,
                                    "DisplayName": getattr(wl, "display_name", ""),
                                    "Provider": getattr(wl, "provider", ""),
                                    "NumberOfLinesToSkip": getattr(wl, "number_of_lines_to_skip", 0),
                                    "ItemsSearchKey": getattr(wl, "items_search_key", ""),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=wl.id or "", resource_type="SentinelWatchlist",
                            ))
                    except Exception as exc:
                        log.warning("  [Sentinel] %s/%s watchlists failed: %s", sub_name, ws.name, exc)

                await client.close()
                log.info("  [Sentinel] %s: processed %d workspaces", sub_name, len(workspaces))
            except Exception as exc:
                log.warning("  [Sentinel] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureSentinel", Source.AZURE, _collect)).data
