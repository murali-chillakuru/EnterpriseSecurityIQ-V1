"""
Azure OpenAI Content Safety & AI Governance Collector
Content safety configurations, responsible AI policies, content filters,
model deployments with safety settings, and AI service diagnostics.
"""

from __future__ import annotations
import asyncio
import aiohttp
from azure.mgmt.cognitiveservices.aio import CognitiveServicesManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="ai_content_safety", plane="data", source="azure", priority=210)
async def collect_azure_ai_content_safety(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                cs_client = CognitiveServicesManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(cs_client.accounts.list())

                for acct in accounts:
                    kind = (getattr(acct, "kind", "") or "").lower()
                    if kind not in ("openai", "azureopenai", "cognitiveservices", "contentsafety"):
                        continue

                    rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (acct.id or "") else ""
                    if not rg:
                        continue

                    props = acct.properties or type("P", (), {})()
                    endpoint = getattr(props, "endpoint", "")

                    # --- Content filter configurations via ARM ---
                    try:
                        async with _CONCURRENCY:
                            deployments = await paginate_arm(
                                cs_client.deployments.list(rg, acct.name)
                            )
                        for dep in deployments:
                            dep_props = dep.properties or type("D", (), {})()
                            model = getattr(dep_props, "model", None)
                            rai_policy = getattr(dep_props, "rai_policy_name", None)
                            version_upgrade_option = getattr(dep_props, "version_upgrade_option", None)

                            # Check for content filter/RAI policy
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureAIContentSafety",
                                evidence_type="azure-ai-deployment-safety",
                                description=f"AI Deployment Safety: {acct.name}/{dep.name}",
                                data={
                                    "DeploymentId": dep.id,
                                    "DeploymentName": dep.name,
                                    "AccountName": acct.name,
                                    "AccountKind": kind,
                                    "ModelName": getattr(model, "name", "") if model else "",
                                    "ModelVersion": getattr(model, "version", "") if model else "",
                                    "ModelFormat": getattr(model, "format", "") if model else "",
                                    "RaiPolicyName": rai_policy or "",
                                    "HasContentFilter": bool(rai_policy),
                                    "VersionUpgradeOption": _v(version_upgrade_option) if version_upgrade_option else "",
                                    "ProvisioningState": _v(getattr(dep_props, "provisioning_state", None)),
                                    "ScaleType": _v(getattr(getattr(dep_props, "scale_settings", None), "scale_type", None)) if getattr(dep_props, "scale_settings", None) else "",
                                    "Capacity": getattr(getattr(dep_props, "scale_settings", None), "capacity", 0) if getattr(dep_props, "scale_settings", None) else 0,
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=dep.id or "", resource_type="AIDeploymentSafety",
                            ))
                    except Exception as exc:
                        log.debug("  [AIContentSafety] Deployments for %s failed: %s", acct.name, exc)

                    # --- Account-level safety configuration ---
                    disable_local_auth = getattr(props, "disable_local_auth", False)
                    net_rules = getattr(props, "network_acls", None)
                    restrict_outbound = getattr(props, "restrict_outbound_network_access", False)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAIContentSafety",
                        evidence_type="azure-ai-governance",
                        description=f"AI Governance: {acct.name}",
                        data={
                            "AccountId": acct.id,
                            "AccountName": acct.name,
                            "Kind": kind,
                            "DisableLocalAuth": disable_local_auth,
                            "PublicNetworkAccess": _v(getattr(props, "public_network_access", None), "Enabled"),
                            "NetworkDefaultAction": _v(getattr(net_rules, "default_action", None)) if net_rules else "",
                            "RestrictOutboundAccess": restrict_outbound,
                            "PrivateEndpoints": len(getattr(props, "private_endpoint_connections", None) or []),
                            "Encryption": bool(getattr(props, "encryption", None)),
                            "CustomerManagedKey": bool(
                                getattr(props, "encryption", None)
                                and getattr(getattr(props, "encryption", None), "key_vault_properties", None)
                            ),
                            "DynamicThrottlingEnabled": getattr(props, "dynamic_throttling_enabled", False),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="AIGovernance",
                    ))

                    # --- RAI Blocklist check via REST (if Content Safety kind) ---
                    if kind == "contentsafety" and endpoint:
                        try:
                            from azure.identity.aio import DefaultAzureCredential as AsyncCred
                            token = await creds.credential.get_token("https://cognitiveservices.azure.com/.default")
                            headers = {"Authorization": f"Bearer {token.token}", "Content-Type": "application/json"}
                            async with aiohttp.ClientSession() as session:
                                url = f"{endpoint.rstrip('/')}/contentsafety/text/blocklists?api-version=2024-09-01"
                                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                                    if resp.status == 200:
                                        data = await resp.json()
                                        blocklists = data.get("value", [])
                                        for bl in blocklists:
                                            evidence.append(make_evidence(
                                                source=Source.AZURE, collector="AzureAIContentSafety",
                                                evidence_type="azure-content-safety-blocklist",
                                                description=f"Content Safety Blocklist: {bl.get('blocklistName', '')}",
                                                data={
                                                    "BlocklistName": bl.get("blocklistName", ""),
                                                    "Description": bl.get("description", ""),
                                                    "AccountName": acct.name,
                                                    "SubscriptionId": sub_id,
                                                },
                                                resource_id=acct.id or "", resource_type="ContentSafetyBlocklist",
                                            ))
                        except Exception as exc:
                            log.debug("  [AIContentSafety] Blocklists for %s failed: %s", acct.name, exc)

                await cs_client.close()
                log.info("  [AIContentSafety] %s: processed AI accounts", sub_name)
            except Exception as exc:
                log.warning("  [AIContentSafety] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureAIContentSafety", Source.AZURE, _collect)).data
