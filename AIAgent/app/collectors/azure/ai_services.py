"""
Azure AI Services Collector
Cognitive Services accounts (incl. Azure OpenAI), ML Workspaces,
model deployments, network rules, managed identity, and content filters.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.cognitiveservices.aio import CognitiveServicesManagementClient
try:
    from azure.mgmt.machinelearningservices.aio import AzureMachineLearningWorkspaces
except ImportError:
    from azure.mgmt.machinelearningservices.aio import MachineLearningServicesMgmtClient as AzureMachineLearningWorkspaces
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="ai_services", plane="control", source="azure", priority=130)
async def collect_azure_ai_services(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Cognitive Services accounts (Azure OpenAI, Speech, Vision, etc.) ---
            try:
                cs_client = CognitiveServicesManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(cs_client.accounts.list())
                for acct in accounts:
                    props = acct.properties or type("P", (), {})()
                    net_rules = getattr(props, "network_acls", None)
                    identity = acct.identity or type("I", (), {"type": None})()

                    evidence.append(make_evidence(
                        source=Source.AZURE,
                        collector="AzureAIServices",
                        evidence_type="azure-cognitive-account",
                        description=f"Cognitive Services: {acct.name}",
                        data={
                            "AccountId": acct.id,
                            "Name": acct.name,
                            "Kind": getattr(acct, "kind", ""),
                            "SkuName": acct.sku.name if acct.sku else "",
                            "Location": acct.location,
                            "ProvisioningState": _v(getattr(props, "provisioning_state", None)),
                            "Endpoint": getattr(props, "endpoint", ""),
                            "PublicNetworkAccess": _v(getattr(props, "public_network_access", None), "Enabled"),
                            "NetworkDefaultAction": _v(getattr(net_rules, "default_action", None)) if net_rules else "",
                            "VirtualNetworkRules": len(getattr(net_rules, "virtual_network_rules", None) or []) if net_rules else 0,
                            "IpRules": len(getattr(net_rules, "ip_rules", None) or []) if net_rules else 0,
                            "PrivateEndpoints": len(getattr(props, "private_endpoint_connections", None) or []),
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "DisableLocalAuth": getattr(props, "disable_local_auth", False),
                            "Encryption": bool(getattr(props, "encryption", None)),
                            "CustomSubDomainName": getattr(props, "custom_sub_domain_name", ""),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "",
                        resource_type="CognitiveServicesAccount",
                    ))

                    # Collect deployments for OpenAI-kind accounts
                    kind = (getattr(acct, "kind", "") or "").lower()
                    if kind in ("openai", "azureopenai", "cognitiveservices"):
                        try:
                            rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (acct.id or "") else ""
                            if rg:
                                async with _CONCURRENCY:
                                    deployments = await paginate_arm(
                                        cs_client.deployments.list(rg, acct.name)
                                    )
                                for dep in deployments:
                                    dep_props = dep.properties or type("D", (), {})()
                                    model = getattr(dep_props, "model", None) or type("M", (), {"name": "", "version": "", "format": ""})()
                                    evidence.append(make_evidence(
                                        source=Source.AZURE,
                                        collector="AzureAIServices",
                                        evidence_type="azure-ai-deployment",
                                        description=f"AI Deployment: {dep.name} on {acct.name}",
                                        data={
                                            "DeploymentId": dep.id,
                                            "DeploymentName": dep.name,
                                            "AccountName": acct.name,
                                            "ModelName": getattr(model, "name", ""),
                                            "ModelVersion": getattr(model, "version", ""),
                                            "ModelFormat": getattr(model, "format", ""),
                                            "ProvisioningState": _v(getattr(dep_props, "provisioning_state", None)),
                                            "ScaleType": _v(getattr(getattr(dep_props, "scale_settings", None), "scale_type", None)),
                                            "RateLimits": bool(getattr(dep_props, "rate_limits", None)),
                                            "ContentFilter": getattr(dep_props, "rai_policy_name", "") or "",
                                            "SubscriptionId": sub_id,
                                            "SubscriptionName": sub_name,
                                        },
                                        resource_id=dep.id or "",
                                        resource_type="AIDeployment",
                                    ))
                        except Exception as dep_exc:
                            log.warning("  [AzureAIServices] %s deployment listing failed for %s: %s",
                                        sub_name, acct.name, dep_exc)

                await cs_client.close()
                log.info("  [AzureAIServices] %s: %d cognitive accounts",
                         sub_name, len(accounts))
            except Exception as exc:
                log.warning("  [AzureAIServices] %s Cognitive Services failed: %s", sub_name, exc)

            # --- Machine Learning Workspaces ---
            try:
                ml_client = AzureMachineLearningWorkspaces(creds.credential, sub_id)
                workspaces = await paginate_arm(ml_client.workspaces.list_by_subscription())
                for ws in workspaces:
                    identity = ws.identity or type("I", (), {"type": None})()
                    evidence.append(make_evidence(
                        source=Source.AZURE,
                        collector="AzureAIServices",
                        evidence_type="azure-ml-workspace",
                        description=f"ML Workspace: {ws.name}",
                        data={
                            "WorkspaceId": ws.id,
                            "Name": ws.name,
                            "Location": ws.location,
                            "ProvisioningState": ws.provisioning_state or "",
                            "PublicNetworkAccess": _v(getattr(ws, "public_network_access", None), "Enabled"),
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "HbiWorkspace": getattr(ws, "hbi_workspace", False),
                            "Encryption": bool(getattr(ws, "encryption", None)),
                            "StorageAccount": getattr(ws, "storage_account", ""),
                            "KeyVault": getattr(ws, "key_vault", ""),
                            "ApplicationInsights": getattr(ws, "application_insights", ""),
                            "ContainerRegistry": getattr(ws, "container_registry", ""),
                            "PrivateEndpoints": len(getattr(ws, "private_endpoint_connections", None) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ws.id or "",
                        resource_type="MachineLearningWorkspace",
                    ))
                await ml_client.close()
                log.info("  [AzureAIServices] %s: %d ML workspaces", sub_name, len(workspaces))
            except Exception as exc:
                log.warning("  [AzureAIServices] %s ML Workspaces failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("AzureAIServices", Source.AZURE, _collect)
    return result.data
