"""
Azure Machine Learning & Cognitive Services Collector
ML workspaces, compute instances, Cognitive Services extended details.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.machinelearningservices.aio import MachineLearningServicesMgmtClient
from azure.mgmt.cognitiveservices.aio import CognitiveServicesManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="ml_cognitive_services", plane="control", source="azure", priority=175)
async def collect_azure_ml_cognitive(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- ML Workspaces ---
            try:
                ml_client = MachineLearningServicesMgmtClient(creds.credential, sub_id)
                workspaces = await paginate_arm(ml_client.workspaces.list_by_subscription())
                for ws in workspaces:
                    rg = (ws.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (ws.id or "") else ""
                    identity = ws.identity or type("I", (), {"type": None})()
                    enc = getattr(ws, "encryption", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureMLCognitive",
                        evidence_type="azure-ml-workspace",
                        description=f"ML workspace: {ws.name}",
                        data={
                            "WorkspaceId": ws.id,
                            "Name": ws.name,
                            "Location": ws.location,
                            "ResourceGroup": rg,
                            "ProvisioningState": getattr(ws, "provisioning_state", ""),
                            "PublicNetworkAccess": _v(getattr(ws, "public_network_access", None), "Enabled"),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "HbiWorkspace": getattr(ws, "hbi_workspace", False),
                            "StorageAccount": getattr(ws, "storage_account", ""),
                            "KeyVault": getattr(ws, "key_vault", ""),
                            "ContainerRegistry": getattr(ws, "container_registry", ""),
                            "ApplicationInsights": getattr(ws, "application_insights", ""),
                            "EncryptionStatus": "Enabled" if enc else "Disabled",
                            "EncryptionKeyVaultKeyId": getattr(getattr(enc, "key_vault_properties", None), "key_identifier", "") if enc else "",
                            "ImageBuildComputeTarget": getattr(ws, "image_build_compute", "") or "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ws.id or "", resource_type="MLWorkspace",
                    ))

                    # --- ML Compute Instances ---
                    try:
                        computes = await paginate_arm(ml_client.compute.list(rg, ws.name))
                        for c in computes:
                            props = c.properties or type("P", (), {"compute_type": None})()
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureMLCognitive",
                                evidence_type="azure-ml-compute",
                                description=f"ML compute: {c.name}",
                                data={
                                    "ComputeId": c.id,
                                    "Name": c.name,
                                    "WorkspaceName": ws.name,
                                    "ComputeType": _v(getattr(props, "compute_type", None)),
                                    "ProvisioningState": _v(getattr(props, "provisioning_state", None)),
                                    "IsAttachedCompute": bool(getattr(props, "resource_id", "")),
                                    "Location": getattr(c, "location", ws.location),
                                    "ResourceGroup": rg,
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=c.id or "", resource_type="MLCompute",
                            ))
                    except Exception as ce:
                        log.debug("  [MLCognitive] compute list for %s/%s: %s", rg, ws.name, ce)

                log.info("  [MLCognitive] %s: %d ML workspaces", sub_name, len(workspaces))
                await ml_client.close()
            except Exception as exc:
                log.warning("  [MLCognitive] %s ML workspaces failed: %s", sub_name, exc)

            # --- Cognitive Services Accounts (extended) ---
            try:
                cog_client = CognitiveServicesManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(cog_client.accounts.list())
                for acct in accounts:
                    rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (acct.id or "") else ""
                    props = acct.properties or type("P", (), {})()
                    identity = acct.identity or type("I", (), {"type": None})()
                    enc = getattr(props, "encryption", None)
                    net = getattr(props, "network_acls", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureMLCognitive",
                        evidence_type="azure-cognitive-account",
                        description=f"Cognitive Services: {acct.name}",
                        data={
                            "AccountId": acct.id,
                            "Name": acct.name,
                            "Location": acct.location,
                            "ResourceGroup": rg,
                            "Kind": acct.kind or "",
                            "Sku": getattr(acct.sku, "name", "") if acct.sku else "",
                            "ProvisioningState": getattr(props, "provisioning_state", ""),
                            "PublicNetworkAccess": _v(getattr(props, "public_network_access", None), "Enabled"),
                            "CustomSubDomainName": getattr(props, "custom_sub_domain_name", "") or "",
                            "DisableLocalAuth": getattr(props, "disable_local_auth", False),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "EncryptionKeySource": _v(getattr(enc, "key_source", None)) if enc else "",
                            "NetworkDefaultAction": _v(getattr(net, "default_action", None)) if net else "",
                            "VirtualNetworkRuleCount": len(getattr(net, "virtual_network_rules", []) or []) if net else 0,
                            "IpRuleCount": len(getattr(net, "ip_rules", []) or []) if net else 0,
                            "PrivateEndpointCount": len(getattr(props, "private_endpoint_connections", []) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="CognitiveServicesAccount",
                    ))
                log.info("  [MLCognitive] %s: %d cognitive accounts", sub_name, len(accounts))
                await cog_client.close()
            except Exception as exc:
                log.warning("  [MLCognitive] %s cognitive accounts failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureMLCognitive", Source.AZURE, _collect)).data
