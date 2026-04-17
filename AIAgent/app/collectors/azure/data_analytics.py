"""
Azure Data Analytics Collector
Synapse workspaces, Data Factory instances, Databricks workspaces,
SQL pools, Spark pools, pipelines, linked services.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.synapse.aio import SynapseManagementClient
from azure.mgmt.datafactory.aio import DataFactoryManagementClient
from azure.mgmt.databricks.aio import AzureDatabricksManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="data_analytics", plane="control", source="azure", priority=150)
async def collect_azure_data_analytics(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Synapse Workspaces ---
            try:
                syn_client = SynapseManagementClient(creds.credential, sub_id)
                workspaces = await paginate_arm(syn_client.workspaces.list())
                for ws in workspaces:
                    rg = (ws.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (ws.id or "") else ""
                    identity = ws.identity or type("I", (), {"type": None})()
                    encryption = getattr(ws, "encryption", None)
                    managed_vnet = getattr(ws, "managed_virtual_network_settings", None)

                    sql_pools = []
                    spark_pools = []
                    if rg:
                        async with _CONCURRENCY:
                            try:
                                sql_pools = await paginate_arm(syn_client.sql_pools.list_by_workspace(rg, ws.name))
                            except Exception:
                                pass
                            try:
                                spark_pools = await paginate_arm(syn_client.big_data_pools.list_by_workspace(rg, ws.name))
                            except Exception:
                                pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDataAnalytics",
                        evidence_type="azure-synapse-workspace",
                        description=f"Synapse Workspace: {ws.name}",
                        data={
                            "WorkspaceId": ws.id,
                            "Name": ws.name,
                            "Location": ws.location,
                            "ProvisioningState": getattr(ws, "provisioning_state", ""),
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "ManagedVirtualNetwork": bool(managed_vnet and getattr(managed_vnet, "prevent_data_exfiltration", False)),
                            "PreventDataExfiltration": getattr(managed_vnet, "prevent_data_exfiltration", False) if managed_vnet else False,
                            "EncryptionEnabled": bool(encryption),
                            "PublicNetworkAccess": _v(getattr(ws, "public_network_access", None), "Enabled"),
                            "SqlAdminLogin": getattr(ws, "sql_administrator_login", ""),
                            "ConnectivityEndpoints": dict(getattr(ws, "connectivity_endpoints", {}) or {}),
                            "PrivateEndpoints": len(getattr(ws, "private_endpoint_connections", []) or []),
                            "SqlPoolCount": len(sql_pools),
                            "SparkPoolCount": len(spark_pools),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ws.id or "", resource_type="SynapseWorkspace",
                    ))

                    for pool in sql_pools:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDataAnalytics",
                            evidence_type="azure-synapse-sql-pool",
                            description=f"SQL Pool: {ws.name}/{pool.name}",
                            data={
                                "PoolId": pool.id,
                                "Name": pool.name,
                                "WorkspaceName": ws.name,
                                "Status": _v(getattr(pool, "status", None)),
                                "SkuName": pool.sku.name if pool.sku else "",
                                "MaxSizeBytes": getattr(pool, "max_size_bytes", 0),
                                "Collation": getattr(pool, "collation", ""),
                                "SubscriptionId": sub_id,
                            },
                            resource_id=pool.id or "", resource_type="SynapseSqlPool",
                        ))

                    for pool in spark_pools:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDataAnalytics",
                            evidence_type="azure-synapse-spark-pool",
                            description=f"Spark Pool: {ws.name}/{pool.name}",
                            data={
                                "PoolId": pool.id,
                                "Name": pool.name,
                                "WorkspaceName": ws.name,
                                "ProvisioningState": getattr(pool, "provisioning_state", ""),
                                "NodeSize": _v(getattr(pool, "node_size", None)),
                                "NodeCount": getattr(pool, "node_count", 0),
                                "AutoScaleEnabled": getattr(getattr(pool, "auto_scale", None), "enabled", False) if getattr(pool, "auto_scale", None) else False,
                                "AutoPauseEnabled": getattr(getattr(pool, "auto_pause", None), "enabled", False) if getattr(pool, "auto_pause", None) else False,
                                "SparkVersion": getattr(pool, "spark_version", ""),
                                "SubscriptionId": sub_id,
                            },
                            resource_id=pool.id or "", resource_type="SynapseSparkPool",
                        ))

                await syn_client.close()
                log.info("  [DataAnalytics] %s: %d synapse workspaces", sub_name, len(workspaces))
            except Exception as exc:
                log.warning("  [DataAnalytics] %s Synapse failed: %s", sub_name, exc)

            # --- Data Factory ---
            try:
                adf_client = DataFactoryManagementClient(creds.credential, sub_id)
                factories = await paginate_arm(adf_client.factories.list())
                for factory in factories:
                    rg = (factory.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (factory.id or "") else ""
                    identity = factory.identity or type("I", (), {"type": None})()
                    encryption = getattr(factory, "encryption", None)

                    pipeline_count = 0
                    linked_service_count = 0
                    if rg:
                        async with _CONCURRENCY:
                            try:
                                pipelines = await paginate_arm(adf_client.pipelines.list_by_factory(rg, factory.name))
                                pipeline_count = len(pipelines)
                            except Exception:
                                pass
                            try:
                                linked_services = await paginate_arm(adf_client.linked_services.list_by_factory(rg, factory.name))
                                linked_service_count = len(linked_services)
                            except Exception:
                                pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDataAnalytics",
                        evidence_type="azure-data-factory",
                        description=f"Data Factory: {factory.name}",
                        data={
                            "FactoryId": factory.id,
                            "Name": factory.name,
                            "Location": factory.location,
                            "ProvisioningState": getattr(factory, "provisioning_state", ""),
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "PublicNetworkAccess": _v(getattr(factory, "public_network_access", None), "Enabled"),
                            "EncryptionEnabled": bool(encryption),
                            "PurviewAccountName": getattr(getattr(factory, "purview_configuration", None), "purview_resource_id", "") if getattr(factory, "purview_configuration", None) else "",
                            "GitConfigured": bool(getattr(factory, "repo_configuration", None)),
                            "PipelineCount": pipeline_count,
                            "LinkedServiceCount": linked_service_count,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=factory.id or "", resource_type="DataFactory",
                    ))

                await adf_client.close()
                log.info("  [DataAnalytics] %s: %d data factories", sub_name, len(factories))
            except Exception as exc:
                log.warning("  [DataAnalytics] %s Data Factory failed: %s", sub_name, exc)

            # --- Databricks Workspaces ---
            try:
                dbr_client = AzureDatabricksManagementClient(creds.credential, sub_id)
                workspaces = await paginate_arm(dbr_client.workspaces.list_by_subscription())
                for ws in workspaces:
                    params = getattr(ws, "parameters", None)
                    encryption = getattr(params, "prepare_encryption", None) if params else None
                    managed_rg = getattr(ws, "managed_resource_group_id", "")

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDataAnalytics",
                        evidence_type="azure-databricks-workspace",
                        description=f"Databricks Workspace: {ws.name}",
                        data={
                            "WorkspaceId": ws.id,
                            "Name": ws.name,
                            "Location": ws.location,
                            "ProvisioningState": _v(getattr(ws, "provisioning_state", None)),
                            "Sku": ws.sku.name if ws.sku else "",
                            "ManagedResourceGroupId": managed_rg,
                            "WorkspaceUrl": getattr(ws, "workspace_url", ""),
                            "PublicNetworkAccess": _v(getattr(ws, "public_network_access", None), "Enabled"),
                            "RequiredNsgRules": _v(getattr(ws, "required_nsg_rules", None)),
                            "PrivateEndpoints": len(getattr(ws, "private_endpoint_connections", []) or []),
                            "EnableNoPublicIp": getattr(getattr(params, "enable_no_public_ip", None), "value", False) if params and getattr(params, "enable_no_public_ip", None) else False,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ws.id or "", resource_type="DatabricksWorkspace",
                    ))

                await dbr_client.close()
                log.info("  [DataAnalytics] %s: %d databricks workspaces", sub_name, len(workspaces))
            except Exception as exc:
                log.warning("  [DataAnalytics] %s Databricks failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureDataAnalytics", Source.AZURE, _collect)).data
