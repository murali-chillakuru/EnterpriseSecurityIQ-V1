"""
Azure Additional Services Collector
Private Endpoints, Backup Vaults, Disk Encryption Sets.
"""

from __future__ import annotations
from azure.mgmt.network.aio import NetworkManagementClient
from azure.mgmt.recoveryservices.aio import RecoveryServicesClient
from azure.mgmt.compute.aio import ComputeManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="additional_services", plane="control", source="azure", priority=120)
async def collect_azure_additional_services(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # Private Endpoints
            try:
                net_client = NetworkManagementClient(creds.credential, sub_id)
                endpoints = await paginate_arm(net_client.private_endpoints.list_by_subscription())
                for pe in endpoints:
                    connections = pe.private_link_service_connections or []
                    manual_connections = pe.manual_private_link_service_connections or []
                    all_conns = connections + manual_connections
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAdditionalServices",
                        evidence_type="azure-private-endpoint",
                        description=f"Private Endpoint: {pe.name}",
                        data={
                            "EndpointId": pe.id, "Name": pe.name,
                            "Location": pe.location,
                            "ProvisioningState": pe.provisioning_state or "",
                            "ConnectionCount": len(all_conns),
                            "LinkedServiceIds": [
                                c.private_link_service_id or ""
                                for c in all_conns
                                if c.private_link_service_id
                            ],
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=pe.id or "", resource_type="PrivateEndpoint",
                    ))
                await net_client.close()
                log.info("  [AzureAdditionalServices] %s: %d private endpoints", sub_name, len(endpoints))
            except Exception as exc:
                log.warning("  [AzureAdditionalServices] %s Private Endpoints failed: %s", sub_name, exc)

            # Recovery Services Vaults (Backup Vaults)
            try:
                recovery_client = RecoveryServicesClient(creds.credential, sub_id)
                vaults = await paginate_arm(recovery_client.vaults.list_by_subscription_id())
                for vault in vaults:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAdditionalServices",
                        evidence_type="azure-recovery-vault",
                        description=f"Recovery Vault: {vault.name}",
                        data={
                            "VaultId": vault.id, "Name": vault.name,
                            "Location": vault.location,
                            "Sku": vault.sku.name if vault.sku else "Unknown",
                            "ProvisioningState": vault.properties.provisioning_state if vault.properties else "",
                            "SoftDeleteEnabled": (
                                vault.properties.security_settings.soft_delete_settings.soft_delete_state == "Enabled"
                                if vault.properties
                                and vault.properties.security_settings
                                and vault.properties.security_settings.soft_delete_settings
                                else False
                            ),
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=vault.id or "", resource_type="RecoveryServicesVault",
                    ))
                await recovery_client.close()
                log.info("  [AzureAdditionalServices] %s: %d recovery vaults", sub_name, len(vaults))
            except Exception as exc:
                log.warning("  [AzureAdditionalServices] %s Recovery Vaults failed: %s", sub_name, exc)

            # Disk Encryption Sets
            try:
                compute_client = ComputeManagementClient(creds.credential, sub_id)
                des_list = await paginate_arm(compute_client.disk_encryption_sets.list())
                for des in des_list:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAdditionalServices",
                        evidence_type="azure-disk-encryption-set",
                        description=f"Disk Encryption Set: {des.name}",
                        data={
                            "DesId": des.id, "Name": des.name,
                            "Location": des.location,
                            "EncryptionType": _v(des.encryption_type, "Unknown"),
                            "KeyVaultKeyUrl": (
                                des.active_key.key_url if des.active_key else ""
                            ),
                            "ProvisioningState": des.provisioning_state or "",
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=des.id or "", resource_type="DiskEncryptionSet",
                    ))
                await compute_client.close()
                log.info("  [AzureAdditionalServices] %s: %d disk encryption sets", sub_name, len(des_list))
            except Exception as exc:
                log.warning("  [AzureAdditionalServices] %s Disk Encryption Sets failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureAdditionalServices", Source.AZURE, _collect)).data
