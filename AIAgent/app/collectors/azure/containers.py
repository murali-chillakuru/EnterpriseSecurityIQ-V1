"""
Azure Container Services Collector
Container Registry (ACR) and Container Apps.
"""

from __future__ import annotations
from azure.mgmt.containerregistry.aio import ContainerRegistryManagementClient
from azure.mgmt.appcontainers.aio import ContainerAppsAPIClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="containers", plane="control", source="azure", priority=150)
async def collect_azure_containers(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # Container Registries
            try:
                acr_client = ContainerRegistryManagementClient(creds.credential, sub_id)
                registries = await paginate_arm(acr_client.registries.list())
                for reg in registries:
                    policies = getattr(reg, "policies", None)
                    net = getattr(reg, "network_rule_set", None)
                    enc = getattr(reg, "encryption", None)
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureContainers",
                        evidence_type="azure-container-registry",
                        description=f"Container Registry: {reg.name}",
                        data={
                            "RegistryId": reg.id,
                            "Name": reg.name,
                            "Location": reg.location,
                            "Sku": reg.sku.name if reg.sku else "Unknown",
                            "AdminUserEnabled": getattr(reg, "admin_user_enabled", False),
                            "PublicNetworkAccess": _v(getattr(reg, "public_network_access", None), "Enabled"),
                            "NetworkDefaultAction": _v(getattr(net, "default_action", None), "Allow") if net else "Allow",
                            "ZoneRedundancy": _v(getattr(reg, "zone_redundancy", None), "Disabled"),
                            "ContentTrustEnabled": bool(
                                policies and getattr(policies, "trust_policy", None)
                                and getattr(policies.trust_policy, "status", "") == "enabled"
                            ),
                            "QuarantineEnabled": bool(
                                policies and getattr(policies, "quarantine_policy", None)
                                and getattr(policies.quarantine_policy, "status", "") == "enabled"
                            ),
                            "RetentionDays": (
                                getattr(policies.retention_policy, "days", 0)
                                if policies and getattr(policies, "retention_policy", None) else 0
                            ),
                            "EncryptionEnabled": bool(enc and _v(getattr(enc, "status", None), "") == "enabled"),
                            "PrivateEndpointCount": len(getattr(reg, "private_endpoint_connections", None) or []),
                            "DataEndpointEnabled": getattr(reg, "data_endpoint_enabled", False),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=reg.id or "", resource_type="Microsoft.ContainerRegistry/registries",
                    ))
                await acr_client.close()
                log.info("  [AzureContainers] %s: %d container registries", sub_name, len(registries))
            except Exception as exc:
                log.warning("  [AzureContainers] %s ACR failed: %s", sub_name, exc)

            # Container Apps
            try:
                ca_client = ContainerAppsAPIClient(creds.credential, sub_id)
                apps = await paginate_arm(ca_client.container_apps.list_by_subscription())
                for app in apps:
                    cfg = getattr(app, "configuration", None)
                    ingress = getattr(cfg, "ingress", None) if cfg else None
                    tmpl = getattr(app, "template", None)
                    identity = getattr(app, "identity", None)
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureContainers",
                        evidence_type="azure-container-app",
                        description=f"Container App: {app.name}",
                        data={
                            "ContainerAppId": app.id,
                            "Name": app.name,
                            "Location": app.location,
                            "ManagedEnvironmentId": getattr(app, "managed_environment_id", "") or "",
                            "ProvisioningState": _v(getattr(app, "provisioning_state", None), ""),
                            "IngressEnabled": ingress is not None,
                            "IngressExternal": getattr(ingress, "external", False) if ingress else False,
                            "IngressTransport": _v(getattr(ingress, "transport", None), "auto") if ingress else "none",
                            "IngressAllowInsecure": getattr(ingress, "allow_insecure", False) if ingress else False,
                            "IngressTargetPort": getattr(ingress, "target_port", 0) if ingress else 0,
                            "ManagedIdentityType": _v(getattr(identity, "type", None), "None") if identity else "None",
                            "ContainerCount": len(getattr(tmpl, "containers", None) or []) if tmpl else 0,
                            "ScaleMinReplicas": (
                                getattr(tmpl.scale, "min_replicas", 0)
                                if tmpl and getattr(tmpl, "scale", None) else 0
                            ),
                            "ScaleMaxReplicas": (
                                getattr(tmpl.scale, "max_replicas", 10)
                                if tmpl and getattr(tmpl, "scale", None) else 10
                            ),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=app.id or "", resource_type="Microsoft.App/containerApps",
                    ))
                await ca_client.close()
                log.info("  [AzureContainers] %s: %d container apps", sub_name, len(apps))
            except Exception as exc:
                log.warning("  [AzureContainers] %s Container Apps failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("AzureContainers", Source.AZURE, _collect)
    return result.data
