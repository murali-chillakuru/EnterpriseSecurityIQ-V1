"""
Azure Monitoring Collector
Log Analytics workspaces, alert rules, action groups.
"""

from __future__ import annotations
from azure.mgmt.monitor.aio import MonitorManagementClient
from azure.mgmt.loganalytics.aio import LogAnalyticsManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="monitoring", plane="control", source="azure", priority=110)
async def collect_azure_monitoring(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                # Log Analytics
                la_client = LogAnalyticsManagementClient(creds.credential, sub_id)
                workspaces = await paginate_arm(la_client.workspaces.list())
                for ws in workspaces:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureMonitoring",
                        evidence_type="azure-log-analytics",
                        description=f"Log Analytics: {ws.name}",
                        data={
                            "WorkspaceId": ws.id, "Name": ws.name,
                            "Location": ws.location,
                            "RetentionInDays": ws.retention_in_days or 30,
                            "Sku": _v(ws.sku.name, "PerGB2018") if ws.sku and ws.sku.name else "PerGB2018",
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=ws.id or "", resource_type="LogAnalytics",
                    ))
                await la_client.close()

                # Alert Rules + Action Groups
                monitor = MonitorManagementClient(creds.credential, sub_id)

                alerts = await paginate_arm(monitor.metric_alerts.list_by_subscription())
                for alert in alerts:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureMonitoring",
                        evidence_type="azure-alert-rule",
                        description=f"Alert: {alert.name}",
                        data={
                            "AlertId": alert.id, "Name": alert.name,
                            "Severity": alert.severity,
                            "Enabled": alert.enabled,
                            "AlertType": "MetricAlert",
                            "ActionGroupIds": [a.action_group_id for a in (alert.actions or [])],
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=alert.id or "", resource_type="AlertRule",
                    ))

                # Activity log alerts (security, administrative, service health)
                try:
                    activity_alerts = await paginate_arm(
                        monitor.activity_log_alerts.list_by_subscription_id()
                    )
                    for aa in activity_alerts:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureMonitoring",
                            evidence_type="azure-alert-rule",
                            description=f"Activity alert: {aa.name}",
                            data={
                                "AlertId": aa.id, "Name": aa.name,
                                "Enabled": aa.enabled,
                                "AlertType": "ActivityLogAlert",
                                "ActionGroupIds": [
                                    a.action_group_id
                                    for a in (aa.actions.action_groups if aa.actions else [])
                                ],
                                "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                            },
                            resource_id=aa.id or "", resource_type="AlertRule",
                        ))
                    alerts.extend(activity_alerts)
                except Exception as exc:
                    log.debug("  [AzureMonitoring] Activity log alerts for %s: %s", sub_name, exc)

                # Scheduled query rules (log-based alerts)
                try:
                    query_alerts = await paginate_arm(
                        monitor.scheduled_query_rules.list_by_subscription()
                    )
                    for qa in query_alerts:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureMonitoring",
                            evidence_type="azure-alert-rule",
                            description=f"Query alert: {qa.name}",
                            data={
                                "AlertId": qa.id, "Name": qa.name,
                                "Severity": getattr(qa, "severity", None),
                                "Enabled": getattr(qa, "enabled", None),
                                "AlertType": "ScheduledQueryRule",
                                "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                            },
                            resource_id=qa.id or "", resource_type="AlertRule",
                        ))
                    alerts.extend(query_alerts)
                except Exception as exc:
                    log.debug("  [AzureMonitoring] Scheduled query rules for %s: %s", sub_name, exc)

                action_groups = await paginate_arm(monitor.action_groups.list_by_subscription_id())
                for ag in action_groups:
                    email_count = len(ag.email_receivers or [])
                    sms_count = len(ag.sms_receivers or [])
                    webhook_count = len(ag.webhook_receivers or [])
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureMonitoring",
                        evidence_type="azure-action-group",
                        description=f"Action group: {ag.name}",
                        data={
                            "ActionGroupId": ag.id, "Name": ag.name,
                            "Enabled": ag.enabled,
                            "EmailReceiverCount": email_count,
                            "SmsReceiverCount": sms_count,
                            "WebhookReceiverCount": webhook_count,
                            "TotalReceivers": email_count + sms_count + webhook_count,
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=ag.id or "", resource_type="ActionGroup",
                    ))

                await monitor.close()
                log.info("  [AzureMonitoring] %s: %d workspaces, %d alerts, %d action groups",
                         sub_name, len(workspaces), len(alerts), len(action_groups))
            except Exception as exc:
                log.warning("  [AzureMonitoring] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureMonitoring", Source.AZURE, _collect)).data
