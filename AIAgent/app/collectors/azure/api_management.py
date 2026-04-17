"""
Azure API Management Collector
APIM instance security configuration.
"""

from __future__ import annotations
from azure.mgmt.apimanagement.aio import ApiManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="api_management", plane="control", source="azure", priority=180)
async def collect_azure_api_management(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                client = ApiManagementClient(creds.credential, sub_id)
                services = await paginate_arm(client.api_management_service.list())
                for svc in services:
                    identity = getattr(svc, "identity", None)
                    vnet_cfg = getattr(svc, "virtual_network_configuration", None)
                    protocols = getattr(svc, "custom_properties", None) or {}
                    pe_conns = getattr(svc, "private_endpoint_connections", None) or []

                    # Check TLS settings from custom properties
                    tls10_fe = protocols.get("Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10", "False")
                    tls11_fe = protocols.get("Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11", "False")
                    ssl30_fe = protocols.get("Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30", "False")
                    backend_tls10 = protocols.get("Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10", "False")
                    backend_tls11 = protocols.get("Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11", "False")
                    backend_ssl30 = protocols.get("Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30", "False")

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureApiManagement",
                        evidence_type="azure-apim-instance",
                        description=f"API Management: {svc.name}",
                        data={
                            "ServiceId": svc.id,
                            "Name": svc.name,
                            "Location": svc.location,
                            "Sku": _v(svc.sku.name, "Unknown") if svc.sku else "Unknown",
                            "SkuCapacity": svc.sku.capacity if svc.sku else 0,
                            "PublisherEmail": svc.publisher_email or "",
                            "VirtualNetworkType": _v(getattr(svc, "virtual_network_type", None), "None"),
                            "VNetConfigured": vnet_cfg is not None,
                            "ManagedIdentityType": _v(getattr(identity, "type", None), "None") if identity else "None",
                            "PrivateEndpointCount": len(pe_conns),
                            "PublicNetworkAccess": getattr(svc, "public_network_access", "Enabled") or "Enabled",
                            "PlatformVersion": _v(getattr(svc, "platform_version", None), ""),
                            "Tls10Enabled": str(tls10_fe).lower() == "true",
                            "Tls11Enabled": str(tls11_fe).lower() == "true",
                            "Ssl30Enabled": str(ssl30_fe).lower() == "true",
                            "BackendTls10Enabled": str(backend_tls10).lower() == "true",
                            "BackendTls11Enabled": str(backend_tls11).lower() == "true",
                            "BackendSsl30Enabled": str(backend_ssl30).lower() == "true",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=svc.id or "", resource_type="Microsoft.ApiManagement/service",
                    ))
                await client.close()
                log.info("  [AzureApiManagement] %s: %d APIM instances", sub_name, len(services))
            except Exception as exc:
                log.warning("  [AzureApiManagement] %s failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("AzureApiManagement", Source.AZURE, _collect)
    return result.data
