"""
Azure Activity Logs + Resource Locks Collector
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from azure.mgmt.monitor.aio import MonitorManagementClient
from azure.mgmt.resource.locks.aio import ManagementLockClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

# Configurable limits — increase for large tenants
MAX_EVENTS_PER_SUB = 10_000       # was 5000
MAX_FAILED_EVENTS_PER_SUB = 200   # was 50
MAX_DELETE_EVENTS_PER_SUB = 100   # was 20
LOOKBACK_DAYS = 90


@register_collector(name="activity_logs", plane="control", source="azure", priority=50)
async def collect_azure_activity_logs(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=LOOKBACK_DAYS)
        odata_filter = (
            f"eventTimestamp ge '{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}' "
            f"and eventTimestamp le '{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
        )

        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                monitor = MonitorManagementClient(creds.credential, sub_id)
                logs = []
                count = 0
                async for entry in monitor.activity_logs.list(filter=odata_filter):
                    if count >= MAX_EVENTS_PER_SUB:
                        break
                    logs.append(entry)
                    count += 1

                stats = {
                    "TotalEvents": len(logs),
                    "FailedOps": sum(1 for l in logs if l.status and _v(l.status) == "Failed"),
                    "WriteOps": sum(1 for l in logs if l.operation_name and _v(l.operation_name) and "/write" in _v(l.operation_name).lower()),
                    "DeleteOps": sum(1 for l in logs if l.operation_name and _v(l.operation_name) and "/delete" in _v(l.operation_name).lower()),
                    "SubscriptionId": sub_id,
                    "SubscriptionName": sub_name,
                }
                evidence.append(make_evidence(
                    source=Source.AZURE, collector="AzureActivityLogs",
                    evidence_type="azure-activity-log",
                    description=f"Activity logs summary for {sub_name}",
                    data=stats,
                    resource_id=f"/subscriptions/{sub_id}", resource_type="ActivityLog",
                ))

                # Emit individual event-level evidence for significant events
                failed_events = [
                    l for l in logs
                    if l.status and _v(l.status) == "Failed"
                ]
                delete_events = [
                    l for l in logs
                    if l.operation_name and _v(l.operation_name)
                    and "/delete" in _v(l.operation_name).lower()
                ]
                for evt in failed_events[:MAX_FAILED_EVENTS_PER_SUB]:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureActivityLogs",
                        evidence_type="azure-activity-event",
                        description=f"Failed op: {_v(evt.operation_name, 'unknown')}",
                        data={
                            "OperationName": _v(evt.operation_name),
                            "Status": "Failed",
                            "Caller": evt.caller or "",
                            "EventTimestamp": evt.event_timestamp.isoformat() if evt.event_timestamp else "",
                            "ResourceId": evt.resource_id or "",
                            "ResourceType": _v(evt.resource_type),
                            "Category": _v(evt.category),
                            "Level": _v(evt.level),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=evt.resource_id or f"/subscriptions/{sub_id}",
                        resource_type="ActivityEvent",
                    ))
                for evt in delete_events[:MAX_DELETE_EVENTS_PER_SUB]:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureActivityLogs",
                        evidence_type="azure-activity-event",
                        description=f"Delete op: {_v(evt.operation_name, 'unknown')}",
                        data={
                            "OperationName": _v(evt.operation_name),
                            "Status": _v(evt.status),
                            "Caller": evt.caller or "",
                            "EventTimestamp": evt.event_timestamp.isoformat() if evt.event_timestamp else "",
                            "ResourceId": evt.resource_id or "",
                            "ResourceType": _v(evt.resource_type),
                            "Category": _v(evt.category),
                            "Level": _v(evt.level),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=evt.resource_id or f"/subscriptions/{sub_id}",
                        resource_type="ActivityEvent",
                    ))
                await monitor.close()

                # Resource Locks
                lock_client = ManagementLockClient(creds.credential, sub_id)
                locks = await paginate_arm(lock_client.management_locks.list_at_subscription_level())
                for lock in locks:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureActivityLogs",
                        evidence_type="azure-resource-lock",
                        description=f"Lock: {lock.name} ({lock.level})",
                        data={
                            "LockId": lock.id,
                            "Name": lock.name,
                            "Level": _v(lock.level, "Unknown"),
                            "Scope": lock.id.rsplit("/providers/Microsoft.Authorization", 1)[0] if lock.id else "",
                            "Notes": lock.notes or "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=lock.id or "", resource_type="ResourceLock",
                    ))
                await lock_client.close()
                log.info("  [AzureActivityLogs] %s: %d events, %d locks", sub_name, len(logs), len(locks))
            except Exception as exc:
                log.warning("  [AzureActivityLogs] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureActivityLogs", Source.AZURE, _collect)).data
