"""
Azure Kubernetes Service Deep Configuration Collector
AKS-specific deep config: RBAC, network policies, pod security,
addon profiles, node pools, API server access, and secrets.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.containerservice.aio import ContainerServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="aks_in_cluster", plane="control", source="azure", priority=160)
async def collect_azure_aks_in_cluster(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = ContainerServiceClient(creds.credential, sub_id)
                clusters = await paginate_arm(client.managed_clusters.list())

                for cluster in clusters:
                    rg = (cluster.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (cluster.id or "") else ""
                    if not rg:
                        continue

                    net_profile = cluster.network_profile or type("N", (), {
                        "network_plugin": None, "network_policy": None,
                        "service_cidr": None, "dns_service_ip": None,
                        "pod_cidr": None, "load_balancer_sku": None,
                        "outbound_type": None,
                    })()

                    api_server = cluster.api_server_access_profile or type("A", (), {
                        "authorized_ip_ranges": None, "enable_private_cluster": None,
                        "private_dns_zone": None,
                    })()

                    aad_profile = cluster.aad_profile or type("AD", (), {
                        "managed": None, "enable_azure_rbac": None,
                        "admin_group_object_i_ds": None,
                    })()

                    identity_type = _v(getattr(cluster.identity, "type", None)) if cluster.identity else ""
                    addon_profiles = cluster.addon_profiles or {}
                    security_profile = cluster.security_profile or type("S", (), {
                        "defender": None, "workload_identity": None,
                    })()

                    auto_upgrade = cluster.auto_upgrade_profile or type("U", (), {"upgrade_channel": None})()
                    oidc_issuer = cluster.oidc_issuer_profile or type("O", (), {"enabled": None, "issuer_url": None})()

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAKSInCluster",
                        evidence_type="azure-aks-cluster-config",
                        description=f"AKS cluster config: {cluster.name}",
                        data={
                            "ClusterId": cluster.id,
                            "Name": cluster.name,
                            "Location": cluster.location,
                            "KubernetesVersion": cluster.kubernetes_version,
                            "ProvisioningState": cluster.provisioning_state,
                            "PowerState": _v(getattr(cluster.power_state, "code", None)) if cluster.power_state else "",
                            "Sku": _v(getattr(cluster.sku, "name", None)) if cluster.sku else "",
                            "SkuTier": _v(getattr(cluster.sku, "tier", None)) if cluster.sku else "",
                            "IdentityType": identity_type,
                            "EnableRBAC": getattr(cluster, "enable_rbac", True),
                            "AadManaged": getattr(aad_profile, "managed", False),
                            "AadEnableAzureRbac": getattr(aad_profile, "enable_azure_rbac", False),
                            "AadAdminGroups": getattr(aad_profile, "admin_group_object_i_ds", []) or [],
                            "NetworkPlugin": _v(getattr(net_profile, "network_plugin", None)),
                            "NetworkPolicy": _v(getattr(net_profile, "network_policy", None)),
                            "ServiceCidr": getattr(net_profile, "service_cidr", ""),
                            "DnsServiceIp": getattr(net_profile, "dns_service_ip", ""),
                            "PodCidr": getattr(net_profile, "pod_cidr", ""),
                            "LoadBalancerSku": _v(getattr(net_profile, "load_balancer_sku", None)),
                            "OutboundType": _v(getattr(net_profile, "outbound_type", None)),
                            "PrivateCluster": getattr(api_server, "enable_private_cluster", False),
                            "AuthorizedIpRanges": getattr(api_server, "authorized_ip_ranges", []) or [],
                            "PrivateDnsZone": getattr(api_server, "private_dns_zone", ""),
                            "OidcIssuerEnabled": getattr(oidc_issuer, "enabled", False),
                            "OidcIssuerUrl": getattr(oidc_issuer, "issuer_url", ""),
                            "AutoUpgradeChannel": _v(getattr(auto_upgrade, "upgrade_channel", None)),
                            "DefenderEnabled": getattr(getattr(security_profile, "defender", None), "security_monitoring", type("X", (), {"enabled": False})()).enabled if getattr(security_profile, "defender", None) else False,
                            "WorkloadIdentityEnabled": getattr(getattr(security_profile, "workload_identity", None), "enabled", False) if getattr(security_profile, "workload_identity", None) else False,
                            "AddonCount": len(addon_profiles),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=cluster.id or "", resource_type="AKSCluster",
                    ))

                    # Addon Profiles
                    for addon_key, addon_val in addon_profiles.items():
                        enabled = getattr(addon_val, "enabled", False)
                        config = getattr(addon_val, "config", {}) or {}
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureAKSInCluster",
                            evidence_type="azure-aks-addon",
                            description=f"AKS addon: {cluster.name}/{addon_key}",
                            data={
                                "ClusterId": cluster.id,
                                "ClusterName": cluster.name,
                                "AddonName": addon_key,
                                "Enabled": enabled,
                                "Config": config,
                                "SubscriptionId": sub_id,
                            },
                            resource_id=cluster.id or "", resource_type="AKSAddon",
                        ))

                    # Node Pools
                    try:
                        async with _CONCURRENCY:
                            node_pools = await paginate_arm(
                                client.agent_pools.list(rg, cluster.name)
                            )
                        for pool in node_pools:
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAKSInCluster",
                                evidence_type="azure-aks-node-pool",
                                description=f"AKS node pool: {cluster.name}/{pool.name}",
                                data={
                                    "PoolId": pool.id,
                                    "Name": pool.name,
                                    "ClusterName": cluster.name,
                                    "VmSize": pool.vm_size or "",
                                    "OsType": _v(getattr(pool, "os_type", None)),
                                    "OsSku": _v(getattr(pool, "os_sku", None)),
                                    "Mode": _v(getattr(pool, "mode", None)),
                                    "Count": getattr(pool, "count", 0),
                                    "MinCount": getattr(pool, "min_count", None),
                                    "MaxCount": getattr(pool, "max_count", None),
                                    "EnableAutoScaling": getattr(pool, "enable_auto_scaling", False),
                                    "MaxPods": getattr(pool, "max_pods", 30),
                                    "OsDiskSizeGB": getattr(pool, "os_disk_size_gb", 0),
                                    "OsDiskType": _v(getattr(pool, "os_disk_type", None)),
                                    "EnableNodePublicIP": getattr(pool, "enable_node_public_ip", False),
                                    "EnableEncryptionAtHost": getattr(pool, "enable_encryption_at_host", False),
                                    "EnableFIPS": getattr(pool, "enable_fips", False),
                                    "KubernetesVersion": pool.orchestrator_version or "",
                                    "ProvisioningState": pool.provisioning_state or "",
                                    "AvailabilityZones": getattr(pool, "availability_zones", []) or [],
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=pool.id or "", resource_type="AKSNodePool",
                            ))
                    except Exception as exc:
                        log.debug("  [AKSInCluster] Node pools for %s failed: %s", cluster.name, exc)

                await client.close()
                log.info("  [AKSInCluster] %s: %d clusters", sub_name, len(clusters))
            except Exception as exc:
                log.warning("  [AKSInCluster] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureAKSInCluster", Source.AZURE, _collect)).data
