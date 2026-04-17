"""
Azure Redis, IoT Hub, and Logic Apps Collector
Redis Cache instances, IoT Hubs, and Logic App workflows.
"""

from __future__ import annotations
from azure.mgmt.redis.aio import RedisManagementClient
from azure.mgmt.iothub.aio import IotHubClient
from azure.mgmt.logic.aio import LogicManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="redis_iot_logic", plane="control", source="azure", priority=155)
async def collect_azure_redis_iot_logic(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Redis Cache ---
            try:
                redis_client = RedisManagementClient(creds.credential, sub_id)
                caches = await paginate_arm(redis_client.redis.list_by_subscription())
                for cache in caches:
                    props = cache.properties if hasattr(cache, "properties") else cache
                    access_keys_auth = getattr(props, "disable_access_key_authentication", False) if hasattr(props, "disable_access_key_authentication") else False

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureRedisIoTLogic",
                        evidence_type="azure-redis-cache",
                        description=f"Redis Cache: {cache.name}",
                        data={
                            "CacheId": cache.id,
                            "Name": cache.name,
                            "Location": cache.location,
                            "SkuName": cache.sku.name if cache.sku else "",
                            "SkuFamily": cache.sku.family if cache.sku else "",
                            "SkuCapacity": cache.sku.capacity if cache.sku else 0,
                            "ProvisioningState": _v(getattr(cache, "provisioning_state", None)),
                            "RedisVersion": getattr(cache, "redis_version", ""),
                            "EnableNonSslPort": getattr(cache, "enable_non_ssl_port", False),
                            "MinimumTlsVersion": getattr(cache, "minimum_tls_version", ""),
                            "PublicNetworkAccess": _v(getattr(cache, "public_network_access", None), "Enabled"),
                            "DisableAccessKeyAuth": access_keys_auth,
                            "PrivateEndpoints": len(getattr(cache, "private_endpoint_connections", []) or []),
                            "LinkedServers": len(getattr(cache, "linked_servers", []) or []),
                            "ReplicasPerMaster": getattr(cache, "replicas_per_master", 0),
                            "ShardCount": getattr(cache, "shard_count", 0),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=cache.id or "", resource_type="RedisCache",
                    ))
                await redis_client.close()
                log.info("  [RedisIoTLogic] %s: %d redis caches", sub_name, len(caches))
            except Exception as exc:
                log.warning("  [RedisIoTLogic] %s Redis failed: %s", sub_name, exc)

            # --- IoT Hubs ---
            try:
                iot_client = IotHubClient(creds.credential, sub_id)
                hubs = await paginate_arm(iot_client.iot_hub_resource.list_by_subscription())
                for hub in hubs:
                    props = hub.properties or type("P", (), {})()
                    ip_filter = getattr(props, "ip_filter_rules", []) or []
                    endpoints = getattr(props, "routing", None)
                    net_sets = getattr(props, "network_rule_sets", None)
                    identity = hub.identity or type("I", (), {"type": None})()

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureRedisIoTLogic",
                        evidence_type="azure-iot-hub",
                        description=f"IoT Hub: {hub.name}",
                        data={
                            "HubId": hub.id,
                            "Name": hub.name,
                            "Location": hub.location,
                            "SkuName": hub.sku.name if hub.sku else "",
                            "SkuTier": _v(getattr(hub.sku, "tier", None)) if hub.sku else "",
                            "SkuCapacity": getattr(hub.sku, "capacity", 0) if hub.sku else 0,
                            "State": getattr(props, "state", ""),
                            "HostName": getattr(props, "host_name", ""),
                            "PublicNetworkAccess": _v(getattr(props, "public_network_access", None), "Enabled"),
                            "DisableLocalAuth": getattr(props, "disable_local_auth", False),
                            "DisableDeviceSAS": getattr(props, "disable_device_s_a_s", False),
                            "DisableModuleSAS": getattr(props, "disable_module_s_a_s", False),
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "IpFilterRuleCount": len(ip_filter),
                            "NetworkRuleDefaultAction": _v(getattr(net_sets, "default_action", None)) if net_sets else "",
                            "MinimumTlsVersion": getattr(props, "min_tls_version", ""),
                            "PrivateEndpoints": len(getattr(props, "private_endpoint_connections", []) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=hub.id or "", resource_type="IoTHub",
                    ))
                await iot_client.close()
                log.info("  [RedisIoTLogic] %s: %d IoT hubs", sub_name, len(hubs))
            except Exception as exc:
                log.warning("  [RedisIoTLogic] %s IoT Hub failed: %s", sub_name, exc)

            # --- Logic Apps ---
            try:
                logic_client = LogicManagementClient(creds.credential, sub_id)
                workflows = await paginate_arm(logic_client.workflows.list_by_subscription())
                for wf in workflows:
                    identity = wf.identity or type("I", (), {"type": None})()
                    access_control = getattr(wf, "access_control", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureRedisIoTLogic",
                        evidence_type="azure-logic-app",
                        description=f"Logic App: {wf.name}",
                        data={
                            "WorkflowId": wf.id,
                            "Name": wf.name,
                            "Location": wf.location,
                            "State": _v(getattr(wf, "state", None)),
                            "ProvisioningState": _v(getattr(wf, "provisioning_state", None)),
                            "SkuName": wf.sku.name if wf.sku else "",
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "HasAccessControl": bool(access_control),
                            "IntegrationAccountId": getattr(getattr(wf, "integration_account", None), "id", "") if getattr(wf, "integration_account", None) else "",
                            "CreatedTime": str(getattr(wf, "created_time", "")),
                            "ChangedTime": str(getattr(wf, "changed_time", "")),
                            "Version": getattr(wf, "version", ""),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=wf.id or "", resource_type="LogicApp",
                    ))
                await logic_client.close()
                log.info("  [RedisIoTLogic] %s: %d logic apps", sub_name, len(workflows))
            except Exception as exc:
                log.warning("  [RedisIoTLogic] %s Logic Apps failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureRedisIoTLogic", Source.AZURE, _collect)).data
