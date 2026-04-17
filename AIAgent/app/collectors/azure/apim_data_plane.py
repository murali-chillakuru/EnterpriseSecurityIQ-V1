"""
Azure API Management Data-Plane Collector
Deep config: APIs, products, subscriptions, policies, certificates,
named values, diagnostic settings, backends, and user counts.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.apimanagement.aio import ApiManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="apim_data_plane", plane="data", source="azure", priority=220)
async def collect_azure_apim_data_plane(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = ApiManagementClient(creds.credential, sub_id)
                services = await paginate_arm(client.api_management_service.list())

                for svc in services:
                    rg = (svc.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (svc.id or "") else ""
                    if not rg:
                        continue

                    identity = svc.identity or type("I", (), {"type": None})()
                    net_cfg = svc.virtual_network_configuration or type("V", (), {"subnet_resource_id": None})()
                    hostname_cfgs = svc.hostname_configurations or []

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAPIMDataPlane",
                        evidence_type="azure-apim-service",
                        description=f"APIM service: {svc.name}",
                        data={
                            "ServiceId": svc.id,
                            "Name": svc.name,
                            "Location": svc.location,
                            "SkuName": _v(getattr(svc.sku, "name", None)) if svc.sku else "",
                            "SkuCapacity": getattr(svc.sku, "capacity", 0) if svc.sku else 0,
                            "GatewayUrl": svc.gateway_url or "",
                            "PortalUrl": svc.portal_url or "",
                            "ManagementApiUrl": svc.management_api_url or "",
                            "PublicIpAddresses": svc.public_ip_addresses or [],
                            "PrivateIpAddresses": svc.private_ip_addresses or [],
                            "VirtualNetworkType": _v(getattr(svc, "virtual_network_type", None), "None"),
                            "SubnetId": getattr(net_cfg, "subnet_resource_id", ""),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "HostnameCount": len(hostname_cfgs),
                            "PlatformVersion": _v(getattr(svc, "platform_version", None)),
                            "PublisherEmail": svc.publisher_email or "",
                            "ProvisioningState": svc.provisioning_state or "",
                            "DisableGateway": getattr(svc, "disable_gateway", False),
                            "EnableClientCertificate": getattr(svc, "enable_client_certificate", False),
                            "MinApiVersion": getattr(svc, "api_version_constraint", type("C", (), {"min_api_version": None})()).min_api_version or "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=svc.id or "", resource_type="APIMService",
                    ))

                    # --- APIs ---
                    try:
                        async with _CONCURRENCY:
                            apis = await paginate_arm(
                                client.api.list_by_service(rg, svc.name)
                            )
                        for api in apis:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAPIMDataPlane",
                                evidence_type="azure-apim-api",
                                description=f"APIM API: {svc.name}/{api.name}",
                                data={
                                    "ApiId": api.id,
                                    "Name": api.name,
                                    "DisplayName": api.display_name or "",
                                    "ServiceName": svc.name,
                                    "Path": api.path or "",
                                    "Protocols": [_v(p) for p in (api.protocols or [])],
                                    "ApiType": _v(getattr(api, "api_type", None)),
                                    "ServiceUrl": api.service_url or "",
                                    "IsCurrent": getattr(api, "is_current", False),
                                    "SubscriptionRequired": getattr(api, "subscription_required", True),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=api.id or "", resource_type="APIMAPI",
                            ))
                    except Exception as exc:
                        log.debug("  [APIMDataPlane] APIs for %s failed: %s", svc.name, exc)

                    # --- Products ---
                    try:
                        async with _CONCURRENCY:
                            products = await paginate_arm(
                                client.product.list_by_service(rg, svc.name)
                            )
                        for prod in products:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAPIMDataPlane",
                                evidence_type="azure-apim-product",
                                description=f"APIM product: {svc.name}/{prod.name}",
                                data={
                                    "ProductId": prod.id,
                                    "Name": prod.name,
                                    "DisplayName": prod.display_name or "",
                                    "ServiceName": svc.name,
                                    "State": _v(getattr(prod, "state", None)),
                                    "SubscriptionRequired": getattr(prod, "subscription_required", True),
                                    "ApprovalRequired": getattr(prod, "approval_required", False),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=prod.id or "", resource_type="APIMProduct",
                            ))
                    except Exception as exc:
                        log.debug("  [APIMDataPlane] Products for %s failed: %s", svc.name, exc)

                    # --- Subscriptions (api keys) ---
                    try:
                        async with _CONCURRENCY:
                            subs = await paginate_arm(
                                client.subscription.list(rg, svc.name)
                            )
                        for s in subs:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAPIMDataPlane",
                                evidence_type="azure-apim-subscription",
                                description=f"APIM subscription: {svc.name}/{s.name}",
                                data={
                                    "SubscriptionResId": s.id,
                                    "Name": s.name,
                                    "DisplayName": s.display_name or "",
                                    "ServiceName": svc.name,
                                    "State": _v(getattr(s, "state", None)),
                                    "Scope": getattr(s, "scope", ""),
                                    "AllowTracing": getattr(s, "allow_tracing", False),
                                    "CreatedDate": str(getattr(s, "created_date", "")),
                                    "ExpirationDate": str(getattr(s, "expiration_date", "")),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=s.id or "", resource_type="APIMSubscription",
                            ))
                    except Exception as exc:
                        log.debug("  [APIMDataPlane] Subscriptions for %s failed: %s", svc.name, exc)

                    # --- Certificates ---
                    try:
                        async with _CONCURRENCY:
                            certs = await paginate_arm(
                                client.certificate.list_by_service(rg, svc.name)
                            )
                        for cert in certs:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAPIMDataPlane",
                                evidence_type="azure-apim-certificate",
                                description=f"APIM cert: {svc.name}/{cert.name}",
                                data={
                                    "CertId": cert.id,
                                    "Name": cert.name,
                                    "ServiceName": svc.name,
                                    "Subject": getattr(cert, "subject", ""),
                                    "Thumbprint": getattr(cert, "thumbprint", ""),
                                    "ExpirationDate": str(getattr(cert, "expiration_date", "")),
                                    "KeyVaultId": getattr(getattr(cert, "key_vault", None), "secret_identifier", "") if getattr(cert, "key_vault", None) else "",
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=cert.id or "", resource_type="APIMCertificate",
                            ))
                    except Exception as exc:
                        log.debug("  [APIMDataPlane] Certificates for %s failed: %s", svc.name, exc)

                    # --- Named Values ---
                    try:
                        async with _CONCURRENCY:
                            named_vals = await paginate_arm(
                                client.named_value.list_by_service(rg, svc.name)
                            )
                        for nv in named_vals:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAPIMDataPlane",
                                evidence_type="azure-apim-named-value",
                                description=f"APIM named value: {svc.name}/{nv.name}",
                                data={
                                    "NamedValueId": nv.id,
                                    "Name": nv.name,
                                    "DisplayName": nv.display_name or "",
                                    "ServiceName": svc.name,
                                    "Secret": getattr(nv, "secret", False),
                                    "KeyVaultId": getattr(getattr(nv, "key_vault", None), "secret_identifier", "") if getattr(nv, "key_vault", None) else "",
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=nv.id or "", resource_type="APIMNamedValue",
                            ))
                    except Exception as exc:
                        log.debug("  [APIMDataPlane] Named values for %s failed: %s", svc.name, exc)

                    # --- Backends ---
                    try:
                        async with _CONCURRENCY:
                            backends = await paginate_arm(
                                client.backend.list_by_service(rg, svc.name)
                            )
                        for be in backends:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAPIMDataPlane",
                                evidence_type="azure-apim-backend",
                                description=f"APIM backend: {svc.name}/{be.name}",
                                data={
                                    "BackendId": be.id,
                                    "Name": be.name,
                                    "ServiceName": svc.name,
                                    "Protocol": _v(getattr(be, "protocol", None)),
                                    "Url": be.url or "",
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=be.id or "", resource_type="APIMBackend",
                            ))
                    except Exception as exc:
                        log.debug("  [APIMDataPlane] Backends for %s failed: %s", svc.name, exc)

                await client.close()
                log.info("  [APIMDataPlane] %s: %d APIM services", sub_name, len(services))
            except Exception as exc:
                log.warning("  [APIMDataPlane] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureAPIMDataPlane", Source.AZURE, _collect)).data
