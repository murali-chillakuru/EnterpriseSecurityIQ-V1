"""
Azure Arc & Hybrid Collector
Arc-enabled servers, Arc-enabled Kubernetes clusters, and extensions.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.hybridcompute.aio import HybridComputeManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="arc_hybrid", plane="control", source="azure", priority=180)
async def collect_azure_arc(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                client = HybridComputeManagementClient(creds.credential, sub_id)

                # --- Arc-enabled Servers (Machines) ---
                machines = await paginate_arm(client.machines.list_by_subscription())
                for m in machines:
                    rg = (m.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (m.id or "") else ""
                    identity = m.identity or type("I", (), {"type": None})()
                    os_profile = getattr(m, "os_profile", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureArcHybrid",
                        evidence_type="azure-arc-server",
                        description=f"Arc server: {m.name}",
                        data={
                            "MachineId": m.id,
                            "Name": m.name,
                            "Location": m.location,
                            "ResourceGroup": rg,
                            "Status": _v(getattr(m, "status", None)),
                            "ProvisioningState": getattr(m, "provisioning_state", ""),
                            "OsName": getattr(m, "os_name", ""),
                            "OsVersion": getattr(m, "os_version", ""),
                            "OsType": getattr(m, "os_type", ""),
                            "AgentVersion": getattr(m, "agent_version", ""),
                            "MachineFqdn": getattr(m, "machine_fqdn", ""),
                            "DomainName": getattr(m, "domain_name", ""),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "LinuxPatchSettingsMode": getattr(getattr(os_profile, "linux_configuration", None), "patch_settings", {}) if os_profile else "",
                            "WindowsPatchSettingsMode": getattr(getattr(os_profile, "windows_configuration", None), "patch_settings", {}) if os_profile else "",
                            "ExtensionCount": len(getattr(m, "extensions", []) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=m.id or "", resource_type="ArcServer",
                    ))

                    # --- Extensions per machine ---
                    try:
                        exts = await paginate_arm(client.machine_extensions.list(rg, m.name))
                        for ext in exts:
                            ext_props = ext.properties or type("P", (), {})()
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureArcHybrid",
                                evidence_type="azure-arc-extension",
                                description=f"Arc extension: {ext.name} on {m.name}",
                                data={
                                    "ExtensionId": ext.id,
                                    "Name": ext.name,
                                    "MachineName": m.name,
                                    "Publisher": getattr(ext_props, "publisher", ""),
                                    "Type": getattr(ext_props, "type", ""),
                                    "TypeHandlerVersion": getattr(ext_props, "type_handler_version", ""),
                                    "ProvisioningState": getattr(ext_props, "provisioning_state", ""),
                                    "AutoUpgradeMinorVersion": getattr(ext_props, "auto_upgrade_minor_version", False),
                                    "ResourceGroup": rg,
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=ext.id or "", resource_type="ArcExtension",
                            ))
                    except Exception as ext_exc:
                        log.debug("  [ArcHybrid] extensions for %s: %s", m.name, ext_exc)

                log.info("  [ArcHybrid] %s: %d arc servers", sub_name, len(machines))
                await client.close()
            except Exception as exc:
                log.warning("  [ArcHybrid] %s failed: %s", sub_name, exc)

            # --- Arc-enabled Kubernetes (via ARM REST) ---
            try:
                from azure.mgmt.resource.resources.aio import ResourceManagementClient
                res_client = ResourceManagementClient(creds.credential, sub_id)
                k8s_clusters = []
                async for r in res_client.resources.list(
                    filter="resourceType eq 'Microsoft.Kubernetes/connectedClusters'"
                ):
                    k8s_clusters.append(r)

                for cluster in k8s_clusters:
                    rg = (cluster.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (cluster.id or "") else ""
                    props = cluster.properties or {}

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureArcHybrid",
                        evidence_type="azure-arc-kubernetes",
                        description=f"Arc K8s: {cluster.name}",
                        data={
                            "ClusterId": cluster.id,
                            "Name": cluster.name,
                            "Location": cluster.location,
                            "ResourceGroup": rg,
                            "KubernetesVersion": props.get("kubernetesVersion", ""),
                            "Distribution": props.get("distribution", ""),
                            "Infrastructure": props.get("infrastructure", ""),
                            "AgentPublicKeyCertificate": bool(props.get("agentPublicKeyCertificate")),
                            "ConnectivityStatus": props.get("connectivityStatus", ""),
                            "ProvisioningState": props.get("provisioningState", ""),
                            "TotalNodeCount": props.get("totalNodeCount", 0),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=cluster.id or "", resource_type="ArcKubernetes",
                    ))
                log.info("  [ArcHybrid] %s: %d arc k8s clusters", sub_name, len(k8s_clusters))
                await res_client.close()
            except Exception as exc:
                log.warning("  [ArcHybrid] %s arc k8s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureArcHybrid", Source.AZURE, _collect)).data
