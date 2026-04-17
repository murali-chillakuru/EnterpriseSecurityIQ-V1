"""
Azure Service Bus & Event Hubs Collector
Service Bus namespaces, queues, topics, subscriptions.
Event Hubs namespaces, event hubs, consumer groups, schema registry.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.servicebus.aio import ServiceBusManagementClient
from azure.mgmt.eventhub.aio import EventHubManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="messaging", plane="control", source="azure", priority=145)
async def collect_azure_messaging(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Service Bus Namespaces ---
            try:
                sb_client = ServiceBusManagementClient(creds.credential, sub_id)
                namespaces = await paginate_arm(sb_client.namespaces.list())
                for ns in namespaces:
                    rg = (ns.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (ns.id or "") else ""
                    queues = []
                    topics = []
                    if rg:
                        async with _CONCURRENCY:
                            try:
                                queues = await paginate_arm(sb_client.queues.list_by_namespace(rg, ns.name))
                            except Exception:
                                pass
                            try:
                                topics = await paginate_arm(sb_client.topics.list_by_namespace(rg, ns.name))
                            except Exception:
                                pass

                    net_rules = getattr(ns, "network_rule_set", None)
                    encryption = getattr(ns, "encryption", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureMessaging",
                        evidence_type="azure-servicebus-namespace",
                        description=f"Service Bus: {ns.name}",
                        data={
                            "NamespaceId": ns.id,
                            "Name": ns.name,
                            "Location": ns.location,
                            "SkuName": ns.sku.name if ns.sku else "",
                            "SkuTier": _v(getattr(ns.sku, "tier", None)) if ns.sku else "",
                            "ProvisioningState": getattr(ns, "provisioning_state", ""),
                            "Status": getattr(ns, "status", ""),
                            "ServiceBusEndpoint": getattr(ns, "service_bus_endpoint", ""),
                            "MinimumTlsVersion": getattr(ns, "minimum_tls_version", ""),
                            "PublicNetworkAccess": _v(getattr(ns, "public_network_access", None), "Enabled"),
                            "DisableLocalAuth": getattr(ns, "disable_local_auth", False),
                            "ZoneRedundant": getattr(ns, "zone_redundant", False),
                            "EncryptionEnabled": bool(encryption),
                            "DefaultAction": _v(getattr(net_rules, "default_action", None)) if net_rules else "",
                            "PrivateEndpoints": len(getattr(ns, "private_endpoint_connections", []) or []),
                            "QueueCount": len(queues),
                            "TopicCount": len(topics),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ns.id or "", resource_type="ServiceBusNamespace",
                    ))

                    # Emit queue evidence
                    for q in queues:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureMessaging",
                            evidence_type="azure-servicebus-queue",
                            description=f"SB Queue: {ns.name}/{q.name}",
                            data={
                                "QueueId": q.id,
                                "Name": q.name,
                                "NamespaceName": ns.name,
                                "Status": _v(getattr(q, "status", None)),
                                "MaxSizeInMegabytes": getattr(q, "max_size_in_megabytes", 0),
                                "MessageCount": getattr(q, "message_count", 0),
                                "DeadLetterCount": getattr(q, "count_details", type("C", (), {"dead_letter_message_count": 0})()).dead_letter_message_count or 0,
                                "LockDuration": str(getattr(q, "lock_duration", "")),
                                "RequiresDuplicateDetection": getattr(q, "requires_duplicate_detection", False),
                                "RequiresSession": getattr(q, "requires_session", False),
                                "EnablePartitioning": getattr(q, "enable_partitioning", False),
                                "ForwardTo": getattr(q, "forward_to", ""),
                                "SubscriptionId": sub_id,
                            },
                            resource_id=q.id or "", resource_type="ServiceBusQueue",
                        ))

                    # Emit topic evidence
                    for t in topics:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureMessaging",
                            evidence_type="azure-servicebus-topic",
                            description=f"SB Topic: {ns.name}/{t.name}",
                            data={
                                "TopicId": t.id,
                                "Name": t.name,
                                "NamespaceName": ns.name,
                                "Status": _v(getattr(t, "status", None)),
                                "MaxSizeInMegabytes": getattr(t, "max_size_in_megabytes", 0),
                                "SubscriptionCount": getattr(t, "subscription_count", 0),
                                "EnablePartitioning": getattr(t, "enable_partitioning", False),
                                "RequiresDuplicateDetection": getattr(t, "requires_duplicate_detection", False),
                                "SubscriptionId": sub_id,
                            },
                            resource_id=t.id or "", resource_type="ServiceBusTopic",
                        ))

                await sb_client.close()
                log.info("  [Messaging] %s: %d service bus namespaces", sub_name, len(namespaces))
            except Exception as exc:
                log.warning("  [Messaging] %s Service Bus failed: %s", sub_name, exc)

            # --- Event Hubs Namespaces ---
            try:
                eh_client = EventHubManagementClient(creds.credential, sub_id)
                namespaces = await paginate_arm(eh_client.namespaces.list())
                for ns in namespaces:
                    rg = (ns.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (ns.id or "") else ""
                    hubs = []
                    if rg:
                        async with _CONCURRENCY:
                            try:
                                hubs = await paginate_arm(eh_client.event_hubs.list_by_namespace(rg, ns.name))
                            except Exception:
                                pass

                    net_rules = getattr(ns, "network_rule_set", None)
                    encryption = getattr(ns, "encryption", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureMessaging",
                        evidence_type="azure-eventhub-namespace",
                        description=f"Event Hub: {ns.name}",
                        data={
                            "NamespaceId": ns.id,
                            "Name": ns.name,
                            "Location": ns.location,
                            "SkuName": ns.sku.name if ns.sku else "",
                            "SkuTier": _v(getattr(ns.sku, "tier", None)) if ns.sku else "",
                            "SkuCapacity": getattr(ns.sku, "capacity", 0) if ns.sku else 0,
                            "ProvisioningState": getattr(ns, "provisioning_state", ""),
                            "Status": getattr(ns, "status", ""),
                            "IsAutoInflateEnabled": getattr(ns, "is_auto_inflate_enabled", False),
                            "MaximumThroughputUnits": getattr(ns, "maximum_throughput_units", 0),
                            "KafkaEnabled": getattr(ns, "kafka_enabled", False),
                            "MinimumTlsVersion": getattr(ns, "minimum_tls_version", ""),
                            "PublicNetworkAccess": _v(getattr(ns, "public_network_access", None), "Enabled"),
                            "DisableLocalAuth": getattr(ns, "disable_local_auth", False),
                            "ZoneRedundant": getattr(ns, "zone_redundant", False),
                            "EncryptionEnabled": bool(encryption),
                            "PrivateEndpoints": len(getattr(ns, "private_endpoint_connections", []) or []),
                            "EventHubCount": len(hubs),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ns.id or "", resource_type="EventHubNamespace",
                    ))

                    # Emit individual event hub evidence
                    for hub in hubs:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureMessaging",
                            evidence_type="azure-eventhub",
                            description=f"Event Hub: {ns.name}/{hub.name}",
                            data={
                                "EventHubId": hub.id,
                                "Name": hub.name,
                                "NamespaceName": ns.name,
                                "Status": _v(getattr(hub, "status", None)),
                                "PartitionCount": getattr(hub, "partition_count", 0),
                                "MessageRetentionInDays": getattr(hub, "message_retention_in_days", 0),
                                "CaptureEnabled": bool(getattr(hub, "capture_description", None) and getattr(hub.capture_description, "enabled", False)),
                                "SubscriptionId": sub_id,
                            },
                            resource_id=hub.id or "", resource_type="EventHub",
                        ))

                await eh_client.close()
                log.info("  [Messaging] %s: %d event hub namespaces", sub_name, len(namespaces))
            except Exception as exc:
                log.warning("  [Messaging] %s Event Hubs failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureMessaging", Source.AZURE, _collect)).data
