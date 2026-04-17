"""
Azure Database Services Collector
Cosmos DB accounts, PostgreSQL/MySQL flexible servers.
"""

from __future__ import annotations
from azure.mgmt.cosmosdb.aio import CosmosDBManagementClient
from azure.mgmt.rdbms.postgresql_flexibleservers.aio import PostgreSQLManagementClient
from azure.mgmt.rdbms.mysql_flexibleservers.aio import MySQLManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="databases", plane="control", source="azure", priority=160)
async def collect_azure_databases(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # Cosmos DB Accounts
            try:
                cosmos_client = CosmosDBManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(cosmos_client.database_accounts.list())
                for acct in accounts:
                    props = acct
                    fw_rules = getattr(props, "ip_rules", None) or []
                    pe_conns = getattr(props, "private_endpoint_connections", None) or []
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDatabases",
                        evidence_type="azure-cosmosdb-account",
                        description=f"Cosmos DB Account: {acct.name}",
                        data={
                            "AccountId": acct.id,
                            "Name": acct.name,
                            "Location": acct.location,
                            "Kind": _v(getattr(acct, "kind", None), "GlobalDocumentDB"),
                            "DatabaseAccountOfferType": _v(getattr(props, "database_account_offer_type", None), "Standard"),
                            "PublicNetworkAccess": _v(getattr(props, "public_network_access", None), "Enabled"),
                            "IsVirtualNetworkFilterEnabled": getattr(props, "is_virtual_network_filter_enabled", False),
                            "IpRuleCount": len(fw_rules),
                            "PrivateEndpointCount": len(pe_conns),
                            "EnableAutomaticFailover": getattr(props, "enable_automatic_failover", False),
                            "EnableMultipleWriteLocations": getattr(props, "enable_multiple_write_locations", False),
                            "DisableLocalAuth": getattr(props, "disable_local_auth", False),
                            "DisableKeyBasedMetadataWriteAccess": getattr(props, "disable_key_based_metadata_write_access", False),
                            "BackupPolicy": _v(getattr(getattr(props, "backup_policy", None), "type", None), "Periodic"),
                            "MinimalTlsVersion": _v(getattr(props, "minimal_tls_version", None), ""),
                            "KeyVaultKeyUri": getattr(props, "key_vault_key_uri", None) or "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="Microsoft.DocumentDB/databaseAccounts",
                    ))
                await cosmos_client.close()
                log.info("  [AzureDatabases] %s: %d Cosmos DB accounts", sub_name, len(accounts))
            except Exception as exc:
                log.warning("  [AzureDatabases] %s Cosmos DB failed: %s", sub_name, exc)

            # PostgreSQL Flexible Servers
            try:
                pg_client = PostgreSQLManagementClient(creds.credential, sub_id)
                servers = await paginate_arm(pg_client.servers.list())
                for srv in servers:
                    net = getattr(srv, "network", None)
                    ha = getattr(srv, "high_availability", None)
                    backup = getattr(srv, "backup", None)
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDatabases",
                        evidence_type="azure-database-server",
                        description=f"PostgreSQL Flexible Server: {srv.name}",
                        data={
                            "ServerId": srv.id,
                            "Name": srv.name,
                            "Location": srv.location,
                            "Engine": "PostgreSQL",
                            "Version": _v(getattr(srv, "version", None), ""),
                            "Sku": srv.sku.name if srv.sku else "Unknown",
                            "SkuTier": _v(srv.sku.tier, "Unknown") if srv.sku else "Unknown",
                            "PublicNetworkAccess": _v(getattr(net, "public_network_access", None), "Enabled") if net else "Enabled",
                            "DelegatedSubnetId": getattr(net, "delegated_subnet_resource_id", "") or "" if net else "",
                            "HighAvailabilityMode": _v(getattr(ha, "mode", None), "Disabled") if ha else "Disabled",
                            "BackupRetentionDays": getattr(backup, "backup_retention_days", 7) if backup else 7,
                            "GeoRedundantBackup": _v(getattr(backup, "geo_redundant_backup", None), "Disabled") if backup else "Disabled",
                            "SslEnforcement": True,  # Always enforced for flexible servers
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=srv.id or "", resource_type="Microsoft.DBforPostgreSQL/flexibleServers",
                    ))
                await pg_client.close()
                log.info("  [AzureDatabases] %s: %d PostgreSQL flexible servers", sub_name, len(servers))
            except Exception as exc:
                log.warning("  [AzureDatabases] %s PostgreSQL failed: %s", sub_name, exc)

            # MySQL Flexible Servers
            try:
                mysql_client = MySQLManagementClient(creds.credential, sub_id)
                servers = await paginate_arm(mysql_client.servers.list())
                for srv in servers:
                    net = getattr(srv, "network", None)
                    ha = getattr(srv, "high_availability", None)
                    backup = getattr(srv, "backup", None)
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDatabases",
                        evidence_type="azure-database-server",
                        description=f"MySQL Flexible Server: {srv.name}",
                        data={
                            "ServerId": srv.id,
                            "Name": srv.name,
                            "Location": srv.location,
                            "Engine": "MySQL",
                            "Version": _v(getattr(srv, "version", None), ""),
                            "Sku": srv.sku.name if srv.sku else "Unknown",
                            "SkuTier": _v(srv.sku.tier, "Unknown") if srv.sku else "Unknown",
                            "PublicNetworkAccess": _v(getattr(net, "public_network_access", None), "Enabled") if net else "Enabled",
                            "DelegatedSubnetId": getattr(net, "delegated_subnet_resource_id", "") or "" if net else "",
                            "HighAvailabilityMode": _v(getattr(ha, "mode", None), "Disabled") if ha else "Disabled",
                            "BackupRetentionDays": getattr(backup, "backup_retention_days", 7) if backup else 7,
                            "GeoRedundantBackup": _v(getattr(backup, "geo_redundant_backup", None), "Disabled") if backup else "Disabled",
                            "SslEnforcement": True,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=srv.id or "", resource_type="Microsoft.DBforMySQL/flexibleServers",
                    ))
                await mysql_client.close()
                log.info("  [AzureDatabases] %s: %d MySQL flexible servers", sub_name, len(servers))
            except Exception as exc:
                log.warning("  [AzureDatabases] %s MySQL failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("AzureDatabases", Source.AZURE, _collect)
    return result.data
