"""
Microsoft Purview & Data Loss Prevention Collector
Purview accounts, data classification, sensitivity labels,
and governance policies.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.purview.aio import PurviewManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, paginate_graph, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="purview_dlp", plane="control", source="azure", priority=170)
async def collect_azure_purview_dlp(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []

        # --- Azure Purview (Microsoft Purview) Accounts ---
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = PurviewManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(client.accounts.list_by_subscription())

                for acct in accounts:
                    rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (acct.id or "") else ""
                    identity = acct.identity or type("I", (), {"type": None})()
                    endpoints = getattr(acct, "endpoints", None)
                    managed_resources = getattr(acct, "managed_resources", None)
                    net_cfg = getattr(acct, "public_network_access", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzurePurviewDLP",
                        evidence_type="azure-purview-account",
                        description=f"Purview account: {acct.name}",
                        data={
                            "AccountId": acct.id,
                            "Name": acct.name,
                            "Location": acct.location,
                            "ResourceGroup": rg,
                            "ProvisioningState": getattr(acct, "provisioning_state", ""),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "PublicNetworkAccess": _v(net_cfg, "Enabled"),
                            "CatalogEndpoint": getattr(endpoints, "catalog", "") if endpoints else "",
                            "ScanEndpoint": getattr(endpoints, "scan", "") if endpoints else "",
                            "GuardianEndpoint": getattr(endpoints, "guardian", "") if endpoints else "",
                            "ManagedResourceGroup": getattr(managed_resources, "resource_group", "") if managed_resources else "",
                            "ManagedStorageAccount": getattr(managed_resources, "storage_account", "") if managed_resources else "",
                            "ManagedEventHubNamespace": getattr(managed_resources, "event_hub_namespace", "") if managed_resources else "",
                            "PrivateEndpoints": len(getattr(acct, "private_endpoint_connections", []) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="PurviewAccount",
                    ))

                await client.close()
                log.info("  [PurviewDLP] %s: %d purview accounts", sub_name, len(accounts))
            except Exception as exc:
                log.warning("  [PurviewDLP] %s Purview accounts failed: %s", sub_name, exc)

        # --- Microsoft 365 Sensitivity Labels (via Graph) ---
        try:
            graph = creds.get_graph_client()
            labels = await paginate_graph(
                graph.information_protection.policy.labels
            )
            for label in labels:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="AzurePurviewDLP",
                    evidence_type="m365-sensitivity-label",
                    description=f"Sensitivity label: {getattr(label, 'name', '')}",
                    data={
                        "LabelId": getattr(label, "id", ""),
                        "Name": getattr(label, "name", ""),
                        "Description": getattr(label, "description", ""),
                        "Color": getattr(label, "color", ""),
                        "Sensitivity": getattr(label, "sensitivity", 0),
                        "IsActive": getattr(label, "is_active", True),
                        "ParentId": getattr(label, "parent", {}).get("id", "") if isinstance(getattr(label, "parent", None), dict) else getattr(getattr(label, "parent", None), "id", "") if getattr(label, "parent", None) else "",
                    },
                    resource_id=getattr(label, "id", ""), resource_type="SensitivityLabel",
                ))
            log.info("  [PurviewDLP] %d sensitivity labels", len(labels))
        except Exception as exc:
            log.warning("  [PurviewDLP] Sensitivity labels failed (may need Information Protection license): %s", exc)

        # --- DLP Policies (via Graph Security) ---
        try:
            graph = creds.get_graph_client()
            # Use security.information_protection if available
            try:
                dlp_policies_resp = await graph.security.information_protection.sensitivity_labels.get()
                dlp_labels = getattr(dlp_policies_resp, "value", []) or []
                for lbl in dlp_labels:
                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="AzurePurviewDLP",
                        evidence_type="m365-dlp-sensitivity-label",
                        description=f"DLP sensitivity label: {getattr(lbl, 'name', '')}",
                        data={
                            "LabelId": getattr(lbl, "id", ""),
                            "Name": getattr(lbl, "name", ""),
                            "Description": getattr(lbl, "description", ""),
                            "Color": getattr(lbl, "color", ""),
                            "IsActive": getattr(lbl, "is_active", True),
                            "ContentFormats": getattr(lbl, "content_formats", []) or [],
                        },
                        resource_id=getattr(lbl, "id", ""), resource_type="DLPSensitivityLabel",
                    ))
                log.info("  [PurviewDLP] %d DLP sensitivity labels", len(dlp_labels))
            except Exception:
                log.debug("  [PurviewDLP] Security sensitivity labels not available")
        except Exception as exc:
            log.warning("  [PurviewDLP] DLP collection failed: %s", exc)

        return evidence

    return (await run_collector("AzurePurviewDLP", Source.AZURE, _collect)).data
