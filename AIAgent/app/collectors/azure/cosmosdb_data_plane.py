"""
Azure Cosmos DB Data-Plane Collector
Database-level security: throughput, consistency, keys, RBAC configs,
container-level partition keys, indexing policies, TTL settings.
"""

from __future__ import annotations
import asyncio
import aiohttp
from azure.mgmt.cosmosdb.aio import CosmosDBManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="cosmosdb_data_plane", plane="data", source="azure", priority=215)
async def collect_azure_cosmosdb_data_plane(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                client = CosmosDBManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(client.database_accounts.list())

                for acct in accounts:
                    rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (acct.id or "") else ""
                    if not rg:
                        continue

                    props = acct.properties if hasattr(acct, "properties") else acct
                    identity = acct.identity or type("I", (), {"type": None})()
                    locations = getattr(props, "read_locations", []) or getattr(props, "locations", []) or []
                    write_locations = getattr(props, "write_locations", []) or []
                    consistency = getattr(props, "consistency_policy", None)
                    cors_rules = getattr(props, "cors", []) or []
                    network_rules = getattr(props, "virtual_network_rules", []) or []
                    ip_rules = getattr(props, "ip_rules", []) or []
                    capabilities = getattr(props, "capabilities", []) or []

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureCosmosDBDataPlane",
                        evidence_type="azure-cosmosdb-account",
                        description=f"Cosmos DB: {acct.name}",
                        data={
                            "AccountId": acct.id,
                            "Name": acct.name,
                            "Location": acct.location,
                            "Kind": _v(getattr(acct, "kind", None)),
                            "ProvisioningState": getattr(props, "provisioning_state", ""),
                            "DocumentEndpoint": getattr(props, "document_endpoint", ""),
                            "DatabaseAccountOfferType": getattr(props, "database_account_offer_type", ""),
                            "ConsistencyLevel": _v(getattr(consistency, "default_consistency_level", None)) if consistency else "",
                            "MaxStalenessPrefix": getattr(consistency, "max_staleness_prefix", 0) if consistency else 0,
                            "MaxIntervalInSeconds": getattr(consistency, "max_interval_in_seconds", 0) if consistency else 0,
                            "EnableAutomaticFailover": getattr(props, "enable_automatic_failover", False),
                            "EnableMultipleWriteLocations": getattr(props, "enable_multiple_write_locations", False),
                            "IsVirtualNetworkFilterEnabled": getattr(props, "is_virtual_network_filter_enabled", False),
                            "PublicNetworkAccess": _v(getattr(props, "public_network_access", None), "Enabled"),
                            "DisableLocalAuth": getattr(props, "disable_local_auth", False),
                            "DisableKeyBasedMetadataWriteAccess": getattr(props, "disable_key_based_metadata_write_access", False),
                            "EnableAnalyticalStorage": getattr(props, "enable_analytical_storage", False),
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "MinimumTlsVersion": _v(getattr(props, "minimal_tls_version", None)),
                            "ReadLocationCount": len(locations),
                            "WriteLocationCount": len(write_locations),
                            "ReadLocations": [_v(getattr(loc, "location_name", None)) for loc in locations],
                            "WriteLocations": [_v(getattr(loc, "location_name", None)) for loc in write_locations],
                            "VirtualNetworkRuleCount": len(network_rules),
                            "IpRuleCount": len(ip_rules),
                            "CorsRuleCount": len(cors_rules),
                            "Capabilities": [_v(getattr(c, "name", None)) for c in capabilities],
                            "PrivateEndpoints": len(getattr(props, "private_endpoint_connections", []) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="CosmosDBAccount",
                    ))

                    # --- SQL Databases and Containers ---
                    try:
                        async with _CONCURRENCY:
                            databases = await paginate_arm(
                                client.sql_resources.list_sql_databases(rg, acct.name)
                            )
                        for db in databases:
                            db_name = db.name or ""
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureCosmosDBDataPlane",
                                evidence_type="azure-cosmosdb-database",
                                description=f"Cosmos DB Database: {acct.name}/{db_name}",
                                data={
                                    "DatabaseId": db.id,
                                    "Name": db_name,
                                    "AccountName": acct.name,
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=db.id or "", resource_type="CosmosDBDatabase",
                            ))

                            # List containers
                            try:
                                async with _CONCURRENCY:
                                    containers = await paginate_arm(
                                        client.sql_resources.list_sql_containers(rg, acct.name, db_name)
                                    )
                                for ctr in containers:
                                    resource = getattr(ctr, "resource", None) or ctr
                                    pk = getattr(resource, "partition_key", None)
                                    idx_policy = getattr(resource, "indexing_policy", None)
                                    ttl = getattr(resource, "default_ttl", None)

                                    evidence.append(make_evidence(
                                        source=Source.AZURE, collector="AzureCosmosDBDataPlane",
                                        evidence_type="azure-cosmosdb-container",
                                        description=f"Container: {acct.name}/{db_name}/{ctr.name}",
                                        data={
                                            "ContainerId": ctr.id,
                                            "Name": ctr.name,
                                            "DatabaseName": db_name,
                                            "AccountName": acct.name,
                                            "PartitionKeyPaths": getattr(pk, "paths", []) if pk else [],
                                            "PartitionKeyKind": _v(getattr(pk, "kind", None)) if pk else "",
                                            "IndexingMode": _v(getattr(idx_policy, "indexing_mode", None)) if idx_policy else "",
                                            "DefaultTtl": ttl if ttl is not None else -1,
                                            "HasTtl": ttl is not None and ttl >= 0,
                                            "SubscriptionId": sub_id,
                                        },
                                        resource_id=ctr.id or "", resource_type="CosmosDBContainer",
                                    ))
                            except Exception as exc:
                                log.debug("  [CosmosDBDataPlane] Containers for %s/%s failed: %s", acct.name, db_name, exc)
                    except Exception as exc:
                        log.debug("  [CosmosDBDataPlane] SQL databases for %s failed: %s", acct.name, exc)

                    # --- Role Assignments (Cosmos DB RBAC) ---
                    try:
                        async with _CONCURRENCY:
                            role_assignments = await paginate_arm(
                                client.sql_resources.list_sql_role_assignments(rg, acct.name)
                            )
                        for ra in role_assignments:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureCosmosDBDataPlane",
                                evidence_type="azure-cosmosdb-role-assignment",
                                description=f"Cosmos RBAC: {acct.name}/{ra.name}",
                                data={
                                    "AssignmentId": ra.id,
                                    "Name": ra.name,
                                    "AccountName": acct.name,
                                    "PrincipalId": getattr(ra, "principal_id", ""),
                                    "RoleDefinitionId": getattr(ra, "role_definition_id", ""),
                                    "Scope": getattr(ra, "scope", ""),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=ra.id or "", resource_type="CosmosDBRoleAssignment",
                            ))
                    except Exception as exc:
                        log.debug("  [CosmosDBDataPlane] Role assignments for %s failed: %s", acct.name, exc)

                await client.close()
                log.info("  [CosmosDBDataPlane] %s: %d cosmos accounts", sub_name, len(accounts))
            except Exception as exc:
                log.warning("  [CosmosDBDataPlane] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureCosmosDBDataPlane", Source.AZURE, _collect)).data
