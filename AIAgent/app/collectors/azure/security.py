"""
Azure Security Collector
Key Vaults (management + data-plane expiry), managed identities.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from azure.mgmt.keyvault.aio import KeyVaultManagementClient
from azure.mgmt.resource.resources.aio import ResourceManagementClient
from azure.keyvault.secrets.aio import SecretClient
from azure.keyvault.certificates.aio import CertificateClient
from azure.keyvault.keys.aio import KeyClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


async def _audit_vault_dataplane(
    creds: ComplianceCredentials,
    vault_name: str,
    vault_uri: str,
    sub_id: str,
    sub_name: str,
    now: datetime,
    soon: datetime,
) -> list[dict]:
    """Audit secrets, certificates, and keys for expiry via data-plane."""
    evidence = []
    credential = creds.credential

    # --- Secrets ---
    try:
        sc = SecretClient(vault_url=vault_uri, credential=credential)
        expired_secrets = 0
        expiring_secrets = 0
        total_secrets = 0
        async for secret_props in sc.list_properties_of_secrets():
            total_secrets += 1
            exp = secret_props.expires_on
            if exp:
                if exp <= now:
                    expired_secrets += 1
                elif exp <= soon:
                    expiring_secrets += 1
        await sc.close()
        if total_secrets:
            evidence.append(make_evidence(
                source=Source.AZURE, collector="AzureSecurity",
                evidence_type="azure-keyvault-secret-expiry",
                description=f"Key Vault '{vault_name}' secret expiry audit",
                data={
                    "VaultName": vault_name,
                    "TotalSecrets": total_secrets,
                    "ExpiredSecrets": expired_secrets,
                    "ExpiringSoon": expiring_secrets,
                    "SubscriptionId": sub_id,
                    "SubscriptionName": sub_name,
                },
                resource_id=vault_uri, resource_type="KeyVaultSecrets",
            ))
    except Exception as exc:
        log.debug("  [AzureSecurity] Secrets audit for %s: %s", vault_name, exc)

    # --- Certificates ---
    try:
        cc = CertificateClient(vault_url=vault_uri, credential=credential)
        expired_certs = 0
        expiring_certs = 0
        total_certs = 0
        async for cert_props in cc.list_properties_of_certificates():
            total_certs += 1
            exp = cert_props.expires_on
            if exp:
                if exp <= now:
                    expired_certs += 1
                elif exp <= soon:
                    expiring_certs += 1
        await cc.close()
        if total_certs:
            evidence.append(make_evidence(
                source=Source.AZURE, collector="AzureSecurity",
                evidence_type="azure-keyvault-cert-expiry",
                description=f"Key Vault '{vault_name}' certificate expiry audit",
                data={
                    "VaultName": vault_name,
                    "TotalCertificates": total_certs,
                    "ExpiredCertificates": expired_certs,
                    "ExpiringSoon": expiring_certs,
                    "SubscriptionId": sub_id,
                    "SubscriptionName": sub_name,
                },
                resource_id=vault_uri, resource_type="KeyVaultCertificates",
            ))
    except Exception as exc:
        log.debug("  [AzureSecurity] Certs audit for %s: %s", vault_name, exc)

    # --- Keys ---
    try:
        kc = KeyClient(vault_url=vault_uri, credential=credential)
        expired_keys = 0
        expiring_keys = 0
        total_keys = 0
        async for key_props in kc.list_properties_of_keys():
            total_keys += 1
            exp = key_props.expires_on
            if exp:
                if exp <= now:
                    expired_keys += 1
                elif exp <= soon:
                    expiring_keys += 1
        await kc.close()
        if total_keys:
            evidence.append(make_evidence(
                source=Source.AZURE, collector="AzureSecurity",
                evidence_type="azure-keyvault-key-expiry",
                description=f"Key Vault '{vault_name}' key expiry audit",
                data={
                    "VaultName": vault_name,
                    "TotalKeys": total_keys,
                    "ExpiredKeys": expired_keys,
                    "ExpiringSoon": expiring_keys,
                    "SubscriptionId": sub_id,
                    "SubscriptionName": sub_name,
                },
                resource_id=vault_uri, resource_type="KeyVaultKeys",
            ))
    except Exception as exc:
        log.debug("  [AzureSecurity] Keys audit for %s: %s", vault_name, exc)

    return evidence


@register_collector(name="security", plane="control", source="azure", priority=60)
async def collect_azure_security(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        now = datetime.now(timezone.utc)
        soon = now + timedelta(days=30)

        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                kv_client = KeyVaultManagementClient(creds.credential, sub_id)
                vaults = await paginate_arm(kv_client.vaults.list_by_subscription())
                for vault in vaults:
                    props = vault.properties
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureSecurity",
                        evidence_type="azure-keyvault",
                        description=f"Key Vault: {vault.name}",
                        data={
                            "VaultName": vault.name,
                            "VaultId": vault.id,
                            "Location": vault.location,
                            "EnableSoftDelete": getattr(props, "enable_soft_delete", False) or False,
                            "EnablePurgeProtection": getattr(props, "enable_purge_protection", False) or False,
                            "EnableRbacAuthorization": getattr(props, "enable_rbac_authorization", False) or False,
                            "NetworkAclsDefaultAction": (
                                _v(props.network_acls.default_action, "Allow")
                                if props and props.network_acls and props.network_acls.default_action
                                else "Allow"
                            ),
                            "SkuName": _v(props.sku.name, "standard") if props and props.sku else "standard",
                            "TenantId": str(props.tenant_id) if props else "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=vault.id or "", resource_type="Microsoft.KeyVault/vaults",
                    ))
                await kv_client.close()

                # Data-plane audit for each vault
                for vault in vaults:
                    vault_uri = f"https://{vault.name}.vault.azure.net"
                    dp_evidence = await _audit_vault_dataplane(
                        creds, vault.name, vault_uri, sub_id, sub_name, now, soon,
                    )
                    evidence.extend(dp_evidence)

                # Managed Identities
                res_client = ResourceManagementClient(creds.credential, sub_id)
                identities = []
                async for r in res_client.resources.list(
                    filter="resourceType eq 'Microsoft.ManagedIdentity/userAssignedIdentities'"
                ):
                    identities.append(r)
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureSecurity",
                        evidence_type="azure-managed-identity",
                        description=f"Managed Identity: {r.name}",
                        data={
                            "ResourceId": r.id, "Name": r.name,
                            "Location": r.location,
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=r.id, resource_type="ManagedIdentity",
                    ))
                await res_client.close()
                log.info("  [AzureSecurity] %s: %d vaults, %d identities", sub_name, len(vaults), len(identities))
            except Exception as exc:
                log.warning("  [AzureSecurity] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureSecurity", Source.AZURE, _collect)).data
