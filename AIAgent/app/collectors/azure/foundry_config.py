"""
Microsoft Foundry & Azure AI Services Security Collector
Collects: Foundry projects/hubs, Azure OpenAI configurations,
content safety filters, managed identity usage, network isolation,
model deployments, API key management.

Uses Azure Resource Manager APIs and Azure AI services endpoints.
"""

from __future__ import annotations
import asyncio
import aiohttp
from app.models import Source
from app.collectors.base import (
    run_collector,
    paginate_arm,
    make_evidence,
    AccessDeniedError,
    _v,
)
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


async def _arm_get(creds: ComplianceCredentials, url: str) -> dict | None:
    """Make an authenticated GET to ARM."""
    token = await creds.credential.get_token("https://management.azure.com/.default")
    headers = {"Authorization": f"Bearer {token.token}", "Accept": "application/json"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status in (401, 403):
                raise AccessDeniedError(api=url, status=resp.status)
            if resp.status == 404:
                return None
            resp.raise_for_status()
            return await resp.json()


@register_collector(name="foundry_config", plane="control", source="azure", priority=188)
async def collect_foundry_config(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    """Collect Microsoft Foundry, Azure OpenAI, and AI Services security configuration."""

    async def _collect():
        evidence: list[dict] = []
        access_denied_count = 0

        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # ── 1. Azure AI Services / Cognitive Services accounts ────
            try:
                from azure.mgmt.cognitiveservices.aio import CognitiveServicesManagementClient
                client = CognitiveServicesManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(client.accounts.list())

                for acct in accounts:
                    props = acct.properties or type("P", (), {})()
                    network_rules = getattr(props, "network_acls", None)
                    endpoint = getattr(props, "endpoint", "") or ""
                    kind = acct.kind or ""
                    sku_name = acct.sku.name if acct.sku else ""

                    is_openai = kind.lower() in ("openai", "azureopenai")
                    disable_local_auth = getattr(props, "disable_local_auth", False)
                    public_access = getattr(props, "public_network_access", "Enabled")
                    encryption = getattr(props, "encryption", None)
                    has_cmk = bool(getattr(encryption, "key_vault_properties", None)) if encryption else False
                    private_eps = len(getattr(props, "private_endpoint_connections", []) or [])

                    default_action = ""
                    if network_rules:
                        default_action = _v(getattr(network_rules, "default_action", ""), "Allow")

                    rg = ""
                    if acct.id and "/resourceGroups/" in acct.id:
                        rg = acct.id.split("/resourceGroups/")[1].split("/")[0]

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="FoundryConfig",
                        evidence_type="azure-ai-service",
                        description=f"AI Service: {acct.name} ({kind})",
                        data={
                            "AccountId": acct.id,
                            "Name": acct.name,
                            "Kind": kind,
                            "IsOpenAI": is_openai,
                            "SkuName": sku_name,
                            "Location": acct.location,
                            "ResourceGroup": rg,
                            "Endpoint": endpoint,
                            "DisableLocalAuth": disable_local_auth,
                            "PublicNetworkAccess": str(public_access),
                            "NetworkDefaultAction": default_action,
                            "HasCMK": has_cmk,
                            "PrivateEndpoints": private_eps,
                            "HasPrivateEndpoints": private_eps > 0,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="AzureAIService",
                    ))

                await client.close()
                log.info("  [FoundryConfig] %s: %d AI service accounts", sub_name, len(accounts))

            except ImportError:
                log.warning("  [FoundryConfig] azure-mgmt-cognitiveservices not installed")
            except Exception as exc:
                log.warning("  [FoundryConfig] %s AI services failed: %s", sub_name, exc)

            # ── 2. Microsoft Foundry workspaces (Machine Learning) ────
            try:
                from azure.mgmt.machinelearningservices.aio import MachineLearningServicesMgmtClient
                ml_client = MachineLearningServicesMgmtClient(creds.credential, sub_id)
                workspaces = await paginate_arm(ml_client.workspaces.list_by_subscription())

                for ws in workspaces:
                    ws_props = ws
                    ws_kind = getattr(ws, "kind", "") or ""
                    is_hub = ws_kind.lower() == "hub"
                    is_project = ws_kind.lower() == "project"

                    # Detect hub linkage for Classic vs New differentiation
                    hub_resource_id = getattr(ws, "hub_resource_id", None) or ""
                    if not hub_resource_id:
                        hub_resource_id = getattr(ws, "hubResourceId", None) or ""

                    # Classify resource variant:
                    #   classic-hub      – Hub workspace (Classic architecture)
                    #   classic-project  – Project under a hub (Classic)
                    #   foundry-project  – Standalone project (New Foundry)
                    #   standalone-ml    – Default/legacy ML workspace
                    if is_hub:
                        resource_variant = "classic-hub"
                    elif is_project and hub_resource_id:
                        resource_variant = "classic-project"
                    elif is_project:
                        resource_variant = "foundry-project"
                    else:
                        resource_variant = "standalone-ml"

                    identity_type = ""
                    if ws.identity:
                        identity_type = _v(getattr(ws.identity, "type", None))

                    public_access = getattr(ws, "public_network_access", "Enabled")
                    managed_network = getattr(ws, "managed_network", None)
                    isolation_mode = ""
                    if managed_network:
                        isolation_mode = getattr(managed_network, "isolation_mode", "") or ""

                    rg = ""
                    if ws.id and "/resourceGroups/" in ws.id:
                        rg = ws.id.split("/resourceGroups/")[1].split("/")[0]

                    # CMK / encryption
                    ws_encryption = getattr(ws, "encryption", None)
                    has_cmk = bool(getattr(ws_encryption, "key_vault_properties", None)) if ws_encryption else False

                    # Managed network outbound rules
                    outbound_rules: list[dict] = []
                    managed_network_status = ""
                    if managed_network:
                        managed_network_status = getattr(managed_network, "status", None) or ""
                        if hasattr(managed_network, "status"):
                            managed_network_status = str(getattr(managed_network, "status", {}))
                        raw_rules = getattr(managed_network, "outbound_rules", None) or {}
                        if isinstance(raw_rules, dict):
                            for rule_name, rule_obj in raw_rules.items():
                                outbound_rules.append({
                                    "Name": rule_name,
                                    "Type": getattr(rule_obj, "type", "") if hasattr(rule_obj, "type") else str(type(rule_obj).__name__),
                                    "Destination": getattr(rule_obj, "destination", "") if hasattr(rule_obj, "destination") else "",
                                })

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="FoundryConfig",
                        evidence_type="azure-ai-workspace",
                        description=f"AI Workspace: {ws.name} ({ws_kind})",
                        data={
                            "WorkspaceId": ws.id,
                            "Name": ws.name,
                            "Kind": ws_kind,
                            "IsHub": is_hub,
                            "IsProject": is_project,
                            "ResourceVariant": resource_variant,
                            "HubResourceId": hub_resource_id,
                            "Location": ws.location,
                            "ResourceGroup": rg,
                            "IdentityType": identity_type,
                            "HasManagedIdentity": "systemassigned" in identity_type.lower() if identity_type else False,
                            "PublicNetworkAccess": str(public_access),
                            "IsolationMode": isolation_mode,
                            "HasNetworkIsolation": isolation_mode.lower() in ("allowinternetoutbound", "allowonlyapprovedoutbound"),
                            "HasCMK": has_cmk,
                            "OutboundRules": outbound_rules,
                            "OutboundRuleCount": len(outbound_rules),
                            "ManagedNetworkStatus": managed_network_status,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=ws.id or "", resource_type="AzureAIWorkspace",
                    ))

                await ml_client.close()
                log.info("  [FoundryConfig] %s: %d AI workspaces", sub_name, len(workspaces))

            except ImportError:
                log.warning("  [FoundryConfig] azure-mgmt-machinelearningservices not installed")
            except Exception as exc:
                log.warning("  [FoundryConfig] %s AI workspaces failed: %s", sub_name, exc)

            # ── 3. Azure OpenAI deployments (per account) ────────────
            openai_accounts = [
                ev for ev in evidence
                if ev.get("EvidenceType") == "azure-ai-service"
                and (ev.get("Data", ev.get("data", {})).get("IsOpenAI"))
                and (ev.get("Data", ev.get("data", {})).get("SubscriptionId") == sub_id)
            ]

            for acct_ev in openai_accounts:
                acct_data = acct_ev.get("Data", acct_ev.get("data", {}))
                acct_id = acct_data.get("AccountId", "")
                acct_name = acct_data.get("Name", "")

                async with _CONCURRENCY:
                    try:
                        deploy_url = (
                            f"https://management.azure.com{acct_id}"
                            f"/deployments?api-version=2024-10-01"
                        )
                        deploy_resp = await _arm_get(creds, deploy_url)
                        deployments = (deploy_resp or {}).get("value", [])

                        for dep in deployments:
                            dep_props = dep.get("properties", {})
                            model = dep_props.get("model", {})
                            rai_policy = dep_props.get("raiPolicy", "")

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-openai-deployment",
                                description=f"OpenAI deployment: {dep.get('name', '')} on {acct_name}",
                                data={
                                    "DeploymentId": dep.get("id", ""),
                                    "DeploymentName": dep.get("name", ""),
                                    "AccountId": acct_id,
                                    "AccountName": acct_name,
                                    "ModelName": model.get("name", ""),
                                    "ModelVersion": model.get("version", ""),
                                    "ModelFormat": model.get("format", ""),
                                    "SkuName": dep.get("sku", {}).get("name", ""),
                                    "SkuCapacity": dep.get("sku", {}).get("capacity", 0),
                                    "RAIPolicy": rai_policy,
                                    "HasContentFilter": bool(rai_policy),
                                    "ProvisioningState": dep_props.get("provisioningState", ""),
                                    "SubscriptionId": sub_id,
                                },
                                resource_id=dep.get("id", ""), resource_type="OpenAIDeployment",
                            ))

                        log.info(
                            "  [FoundryConfig] %s/%s: %d deployments",
                            sub_name, acct_name, len(deployments),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Deployments access denied for %s", acct_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Deployments for %s failed: %s", acct_name, exc)

            # ── 4. Content safety filters (per OpenAI account) ───────
            for acct_ev in openai_accounts:
                acct_data = acct_ev.get("Data", acct_ev.get("data", {}))
                acct_id = acct_data.get("AccountId", "")
                acct_name = acct_data.get("Name", "")

                async with _CONCURRENCY:
                    try:
                        rai_url = (
                            f"https://management.azure.com{acct_id}"
                            f"/raiPolicies?api-version=2024-10-01"
                        )
                        rai_resp = await _arm_get(creds, rai_url)
                        policies = (rai_resp or {}).get("value", [])

                        for pol in policies:
                            pol_props = pol.get("properties", {})
                            content_filters = pol_props.get("contentFilters", [])
                            blocking_filters = [
                                cf for cf in content_filters
                                if cf.get("enabled", False) and cf.get("blocking", False)
                            ]

                            # Prompt Shield / jailbreak detection
                            custom_blocklists = pol_props.get("customBlocklists", [])
                            # Check for prompt-shield source in content filters
                            has_prompt_shield = any(
                                cf.get("source", "").lower() == "prompt"
                                and cf.get("enabled", False)
                                for cf in content_filters
                            )
                            has_jailbreak_filter = any(
                                "jailbreak" in cf.get("name", "").lower()
                                and cf.get("enabled", False)
                                for cf in content_filters
                            )

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-openai-content-filter",
                                description=f"Content filter: {pol.get('name', '')} on {acct_name}",
                                data={
                                    "PolicyId": pol.get("id", ""),
                                    "PolicyName": pol.get("name", ""),
                                    "AccountId": acct_id,
                                    "AccountName": acct_name,
                                    "TotalFilters": len(content_filters),
                                    "BlockingFilters": len(blocking_filters),
                                    "AllFiltersBlocking": len(blocking_filters) == len(content_filters) and len(content_filters) > 0,
                                    "FilterCategories": [cf.get("name", "") for cf in content_filters],
                                    "HasPromptShield": has_prompt_shield,
                                    "HasJailbreakFilter": has_jailbreak_filter,
                                    "CustomBlocklistCount": len(custom_blocklists),
                                },
                                resource_id=pol.get("id", ""), resource_type="ContentFilter",
                            ))

                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Content filters access denied for %s", acct_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] RAI policies for %s failed: %s", acct_name, exc)

            # ── 5-11. Per-workspace resources ────────────────────────
            workspace_evs = [
                ev for ev in evidence
                if ev.get("EvidenceType") == "azure-ai-workspace"
                and (ev.get("Data", ev.get("data", {})).get("SubscriptionId") == sub_id)
            ]

            for ws_ev in workspace_evs:
                ws_data = ws_ev.get("Data", ws_ev.get("data", {}))
                ws_id = ws_data.get("WorkspaceId", "")
                ws_name = ws_data.get("Name", "")
                if not ws_id:
                    continue

                # ── 5. Compute instances ─────────────────────────────
                async with _CONCURRENCY:
                    try:
                        url = (
                            f"https://management.azure.com{ws_id}"
                            f"/computes?api-version=2024-04-01"
                        )
                        resp = await _arm_get(creds, url)
                        computes = (resp or {}).get("value", [])

                        for c in computes:
                            c_props = c.get("properties", {})
                            inner = c_props.get("properties", {})
                            ssh_settings = inner.get("sshSettings", {})
                            ssh_access = str(ssh_settings.get("sshPublicAccess", "")).lower()
                            idle_shutdown = inner.get("idleTimeBeforeShutdown", "")
                            connectivity = inner.get("connectivityEndpoints", {})
                            has_public_ip = bool(connectivity.get("publicIpAddress"))
                            if not has_public_ip:
                                has_public_ip = ssh_access in ("enabled", "")

                            # Compute identity
                            c_identity = c.get("identity", {})
                            c_identity_type = (c_identity.get("type", "") or "") if c_identity else ""

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-ai-compute",
                                description=f"AI compute: {c.get('name', '')} in {ws_name}",
                                data={
                                    "ComputeId": c.get("id", ""),
                                    "Name": c.get("name", ""),
                                    "WorkspaceName": ws_name,
                                    "WorkspaceId": ws_id,
                                    "ComputeType": c_props.get("computeType", ""),
                                    "VmSize": inner.get("vmSize", ""),
                                    "HasPublicIP": has_public_ip,
                                    "SSHEnabled": ssh_access in ("enabled", ""),
                                    "IdleShutdownEnabled": bool(idle_shutdown),
                                    "IdleShutdownMinutes": idle_shutdown,
                                    "IdentityType": c_identity_type,
                                    "HasManagedIdentity": "systemassigned" in c_identity_type.lower() if c_identity_type else False,
                                    "ProvisioningState": c_props.get("provisioningState", ""),
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=c.get("id", ""), resource_type="AICompute",
                            ))

                        log.info(
                            "  [FoundryConfig] %s/%s: %d compute instances",
                            sub_name, ws_name, len(computes),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Compute access denied for %s/%s", sub_name, ws_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Compute for %s/%s failed: %s", sub_name, ws_name, exc)

                # ── 6. Datastores ────────────────────────────────────
                async with _CONCURRENCY:
                    try:
                        url = (
                            f"https://management.azure.com{ws_id}"
                            f"/datastores?api-version=2024-04-01"
                        )
                        resp = await _arm_get(creds, url)
                        datastores = (resp or {}).get("value", [])

                        _CRED_MAP = {
                            "AccountKey": "account_key",
                            "Sas": "sas",
                            "ServicePrincipal": "service_principal",
                        }
                        for ds in datastores:
                            ds_props = ds.get("properties", {})
                            creds_info = ds_props.get("credentials", {})
                            raw_cred = creds_info.get("credentialsType", "None")
                            cred_type = _CRED_MAP.get(raw_cred, raw_cred.lower())

                            # Resolve storage encryption from backing account
                            storage_encrypted = None  # unknown until proven
                            ds_acct_name = ds_props.get("accountName", "")
                            if ds_acct_name:
                                try:
                                    # Try to find storage account in same sub
                                    sa_url = (
                                        f"https://management.azure.com/subscriptions/{sub_id}"
                                        f"/providers/Microsoft.Storage/storageAccounts"
                                        f"?api-version=2023-05-01"
                                    )
                                    sa_resp = await _arm_get(creds, sa_url)
                                    for sa in (sa_resp or {}).get("value", []):
                                        if sa.get("name", "").lower() == ds_acct_name.lower():
                                            sa_enc = sa.get("properties", {}).get("encryption", {})
                                            blob_svc = sa_enc.get("services", {}).get("blob", {})
                                            storage_encrypted = blob_svc.get("enabled", False)
                                            break
                                except Exception:
                                    pass  # fallback to None (unknown)

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-ai-datastore",
                                description=f"AI datastore: {ds.get('name', '')} in {ws_name}",
                                data={
                                    "DatastoreId": ds.get("id", ""),
                                    "Name": ds.get("name", ""),
                                    "WorkspaceName": ws_name,
                                    "WorkspaceId": ws_id,
                                    "DatastoreType": ds_props.get("datastoreType", ""),
                                    "CredentialType": cred_type,
                                    "AccountName": ds_acct_name,
                                    "ContainerName": ds_props.get("containerName", ""),
                                    "StorageEncrypted": storage_encrypted,
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=ds.get("id", ""), resource_type="AIDatastore",
                            ))

                        log.info(
                            "  [FoundryConfig] %s/%s: %d datastores",
                            sub_name, ws_name, len(datastores),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Datastores access denied for %s/%s", sub_name, ws_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Datastores for %s/%s failed: %s", sub_name, ws_name, exc)

                # ── 7. Online endpoints ──────────────────────────────
                async with _CONCURRENCY:
                    try:
                        url = (
                            f"https://management.azure.com{ws_id}"
                            f"/onlineEndpoints?api-version=2024-04-01"
                        )
                        resp = await _arm_get(creds, url)
                        endpoints = (resp or {}).get("value", [])

                        for ep in endpoints:
                            ep_props = ep.get("properties", {})
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-ai-endpoint",
                                description=f"AI endpoint: {ep.get('name', '')} in {ws_name}",
                                data={
                                    "EndpointId": ep.get("id", ""),
                                    "Name": ep.get("name", ""),
                                    "WorkspaceName": ws_name,
                                    "WorkspaceId": ws_id,
                                    "EndpointType": "Online",
                                    "PublicNetworkAccess": ep_props.get("publicNetworkAccess", ""),
                                    "AuthMode": ep_props.get("authMode", ""),
                                    "ProvisioningState": ep_props.get("provisioningState", ""),
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=ep.get("id", ""), resource_type="AIEndpoint",
                            ))

                        # Also collect batch endpoints
                        batch_url = (
                            f"https://management.azure.com{ws_id}"
                            f"/batchEndpoints?api-version=2024-04-01"
                        )
                        batch_resp = await _arm_get(creds, batch_url)
                        batch_eps = (batch_resp or {}).get("value", [])

                        for ep in batch_eps:
                            ep_props = ep.get("properties", {})
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-ai-endpoint",
                                description=f"AI batch endpoint: {ep.get('name', '')} in {ws_name}",
                                data={
                                    "EndpointId": ep.get("id", ""),
                                    "Name": ep.get("name", ""),
                                    "WorkspaceName": ws_name,
                                    "WorkspaceId": ws_id,
                                    "EndpointType": "Batch",
                                    "PublicNetworkAccess": ep_props.get("publicNetworkAccess", ""),
                                    "AuthMode": ep_props.get("authMode", ""),
                                    "ProvisioningState": ep_props.get("provisioningState", ""),
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=ep.get("id", ""), resource_type="AIEndpoint",
                            ))

                        total_eps = len(endpoints) + len(batch_eps)
                        log.info(
                            "  [FoundryConfig] %s/%s: %d endpoints (%d online, %d batch)",
                            sub_name, ws_name, total_eps, len(endpoints), len(batch_eps),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Endpoints access denied for %s/%s", sub_name, ws_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Endpoints for %s/%s failed: %s", sub_name, ws_name, exc)

                # ── 8. Connections ────────────────────────────────────
                async with _CONCURRENCY:
                    try:
                        url = (
                            f"https://management.azure.com{ws_id}"
                            f"/connections?api-version=2024-04-01"
                        )
                        resp = await _arm_get(creds, url)
                        connections = (resp or {}).get("value", [])

                        for conn in connections:
                            conn_props = conn.get("properties", {})
                            auth_type = conn_props.get("authType", "")
                            has_creds = auth_type.lower() in (
                                "apikey", "pat", "customkeys", "accountkey",
                                "serviceprincipal", "accesskey",
                            )
                            expiry = conn_props.get("expiryTime", "")

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-ai-connection",
                                description=f"AI connection: {conn.get('name', '')} in {ws_name}",
                                data={
                                    "ConnectionId": conn.get("id", ""),
                                    "Name": conn.get("name", ""),
                                    "WorkspaceName": ws_name,
                                    "WorkspaceId": ws_id,
                                    "AuthType": auth_type,
                                    "Category": conn_props.get("category", ""),
                                    "Target": conn_props.get("target", ""),
                                    "HasCredentials": has_creds,
                                    "IsSharedToAll": conn_props.get("isSharedToAll", False),
                                    "ExpiryTime": expiry,
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=conn.get("id", ""), resource_type="AIConnection",
                            ))

                        log.info(
                            "  [FoundryConfig] %s/%s: %d connections",
                            sub_name, ws_name, len(connections),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Connections access denied for %s/%s", sub_name, ws_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Connections for %s/%s failed: %s", sub_name, ws_name, exc)

                # ── 9. Serverless endpoints (MaaS) ───────────────────
                async with _CONCURRENCY:
                    try:
                        url = (
                            f"https://management.azure.com{ws_id}"
                            f"/serverlessEndpoints?api-version=2024-04-01"
                        )
                        resp = await _arm_get(creds, url)
                        serverless = (resp or {}).get("value", [])

                        for sep in serverless:
                            sep_props = sep.get("properties", {})
                            model_settings = sep_props.get("modelSettings", {})
                            content_safety = sep_props.get("contentSafety", {})
                            inference = sep_props.get("inferenceEndpoint", {})

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="azure-ai-serverless-endpoint",
                                description=f"Serverless endpoint: {sep.get('name', '')} in {ws_name}",
                                data={
                                    "EndpointId": sep.get("id", ""),
                                    "Name": sep.get("name", ""),
                                    "WorkspaceName": ws_name,
                                    "WorkspaceId": ws_id,
                                    "ModelId": model_settings.get("modelId", ""),
                                    "AuthMode": sep_props.get("authMode", ""),
                                    "ContentSafetyEnabled": str(
                                        content_safety.get("contentSafetyStatus", "")
                                    ).lower() == "enabled",
                                    "InferenceUri": inference.get("uri", ""),
                                    "ProvisioningState": sep_props.get("provisioningState", ""),
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=sep.get("id", ""), resource_type="ServerlessEndpoint",
                            ))

                        log.info(
                            "  [FoundryConfig] %s/%s: %d serverless endpoints",
                            sub_name, ws_name, len(serverless),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Serverless access denied for %s/%s", sub_name, ws_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Serverless for %s/%s failed: %s", sub_name, ws_name, exc)

                # ── 10. Workspace diagnostic settings ────────────────
                async with _CONCURRENCY:
                    try:
                        url = (
                            f"https://management.azure.com{ws_id}"
                            f"/providers/Microsoft.Insights/diagnosticSettings"
                            f"?api-version=2021-05-01-preview"
                        )
                        resp = await _arm_get(creds, url)
                        diag_settings = (resp or {}).get("value", [])

                        enabled_logs: list[str] = []
                        enabled_metrics: list[str] = []
                        has_log_analytics = False
                        has_storage = False
                        for ds in diag_settings:
                            ds_props = ds.get("properties", {})
                            if ds_props.get("workspaceId"):
                                has_log_analytics = True
                            if ds_props.get("storageAccountId"):
                                has_storage = True
                            for log_entry in ds_props.get("logs", []):
                                if log_entry.get("enabled"):
                                    cat = log_entry.get("category", "")
                                    if cat and cat not in enabled_logs:
                                        enabled_logs.append(cat)
                            for metric_entry in ds_props.get("metrics", []):
                                if metric_entry.get("enabled"):
                                    cat = metric_entry.get("category", "")
                                    if cat and cat not in enabled_metrics:
                                        enabled_metrics.append(cat)

                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="FoundryConfig",
                            evidence_type="azure-ai-workspace-diagnostics",
                            description=f"Diagnostics for workspace: {ws_name}",
                            data={
                                "WorkspaceId": ws_id,
                                "WorkspaceName": ws_name,
                                "HasDiagnostics": len(diag_settings) > 0,
                                "DiagnosticsCount": len(diag_settings),
                                "HasLogAnalytics": has_log_analytics,
                                "HasStorageAccount": has_storage,
                                "EnabledLogs": enabled_logs,
                                "EnabledMetrics": enabled_metrics,
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=ws_id, resource_type="AIWorkspaceDiagnostics",
                        ))

                        log.info(
                            "  [FoundryConfig] %s/%s: %d diagnostic settings",
                            sub_name, ws_name, len(diag_settings),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Diagnostics access denied for %s/%s", sub_name, ws_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Diagnostics for %s/%s failed: %s", sub_name, ws_name, exc)

            # ── 11. Model registries (subscription-level) ────────────
            try:
                reg_url = (
                    f"https://management.azure.com/subscriptions/{sub_id}"
                    f"/providers/Microsoft.MachineLearningServices/registries"
                    f"?api-version=2024-04-01"
                )
                resp = await _arm_get(creds, reg_url)
                registries = (resp or {}).get("value", [])

                for reg in registries:
                    reg_props = reg.get("properties", {})

                    # Query RBAC role assignments on the registry
                    has_rbac = False
                    reg_id = reg.get("id", "")
                    if reg_id:
                        try:
                            rbac_url = (
                                f"https://management.azure.com{reg_id}"
                                f"/providers/Microsoft.Authorization/roleAssignments"
                                f"?api-version=2022-04-01"
                            )
                            rbac_resp = await _arm_get(creds, rbac_url)
                            rbac_assignments = (rbac_resp or {}).get("value", [])
                            has_rbac = len(rbac_assignments) > 0
                        except Exception:
                            pass  # fallback to False (unknown)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="FoundryConfig",
                        evidence_type="azure-ai-registry",
                        description=f"AI registry: {reg.get('name', '')}",
                        data={
                            "RegistryId": reg_id,
                            "Name": reg.get("name", ""),
                            "Location": reg.get("location", ""),
                            "PublicNetworkAccess": reg_props.get("publicNetworkAccess", ""),
                            "HasRBACAssignments": has_rbac,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=reg.get("id", ""), resource_type="AIRegistry",
                    ))

                log.info("  [FoundryConfig] %s: %d registries", sub_name, len(registries))
            except AccessDeniedError:
                access_denied_count += 1
                log.warning("  [FoundryConfig] Registries access denied for %s", sub_name)
            except Exception as exc:
                log.warning("  [FoundryConfig] Registries for %s failed: %s", sub_name, exc)

            # ── 12. Foundry projects (CognitiveServices subresources) ─
            ai_services_accounts = [
                ev for ev in evidence
                if ev.get("EvidenceType") == "azure-ai-service"
                and (ev.get("Data", ev.get("data", {})).get("SubscriptionId") == sub_id)
                and str(ev.get("Data", ev.get("data", {})).get("Kind", "")).lower() in ("aiservices", "openai", "azureopenai")
            ]

            for acct_ev in ai_services_accounts:
                acct_data = acct_ev.get("Data", acct_ev.get("data", {}))
                acct_id = acct_data.get("AccountId", "")
                acct_name = acct_data.get("Name", "")
                if not acct_id:
                    continue

                # ── 12a. List projects under this account ────────────
                async with _CONCURRENCY:
                    try:
                        proj_url = (
                            f"https://management.azure.com{acct_id}"
                            f"/projects?api-version=2025-04-01-preview"
                        )
                        proj_resp = await _arm_get(creds, proj_url)
                        projects = (proj_resp or {}).get("value", [])

                        for proj in projects:
                            proj_props = proj.get("properties", {})
                            proj_identity = proj.get("identity", {})
                            identity_type = (proj_identity.get("type", "") or "") if proj_identity else ""

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="foundry-project",
                                description=f"Foundry project: {proj.get('name', '')} on {acct_name}",
                                data={
                                    "ProjectId": proj.get("id", ""),
                                    "Name": proj.get("name", ""),
                                    "AccountId": acct_id,
                                    "AccountName": acct_name,
                                    "Location": proj.get("location", ""),
                                    "IdentityType": identity_type,
                                    "HasManagedIdentity": "systemassigned" in identity_type.lower() if identity_type else False,
                                    "ProvisioningState": proj_props.get("provisioningState", ""),
                                    "AgentCount": proj_props.get("agentCount", 0),
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=proj.get("id", ""), resource_type="FoundryProject",
                            ))

                            # ── 12b. Agent Applications under project ─
                            proj_id = proj.get("id", "")
                            if proj_id:
                                try:
                                    app_url = (
                                        f"https://management.azure.com{proj_id}"
                                        f"/applications?api-version=2025-04-01-preview"
                                    )
                                    app_resp = await _arm_get(creds, app_url)
                                    applications = (app_resp or {}).get("value", [])

                                    for app in applications:
                                        app_props = app.get("properties", {})

                                        # Check RBAC on application
                                        has_rbac = False
                                        app_id = app.get("id", "")
                                        if app_id:
                                            try:
                                                rbac_url = (
                                                    f"https://management.azure.com{app_id}"
                                                    f"/providers/Microsoft.Authorization/roleAssignments"
                                                    f"?api-version=2022-04-01"
                                                )
                                                rbac_resp = await _arm_get(creds, rbac_url)
                                                rbac_assignments = (rbac_resp or {}).get("value", [])
                                                has_rbac = len(rbac_assignments) > 0
                                            except Exception:
                                                pass

                                        evidence.append(make_evidence(
                                            source=Source.AZURE, collector="FoundryConfig",
                                            evidence_type="foundry-agent-application",
                                            description=f"Agent app: {app.get('name', '')} in {proj.get('name', '')}",
                                            data={
                                                "ApplicationId": app_id,
                                                "Name": app.get("name", ""),
                                                "ProjectId": proj_id,
                                                "ProjectName": proj.get("name", ""),
                                                "AccountName": acct_name,
                                                "EndpointUrl": app_props.get("endpointUrl", ""),
                                                "Protocol": app_props.get("protocol", ""),
                                                "AuthenticationType": app_props.get("authenticationType", ""),
                                                "IsPublicEndpoint": str(app_props.get("publicNetworkAccess", "Enabled")).lower() != "disabled",
                                                "HasRBACAssignments": has_rbac,
                                                "ProvisioningState": app_props.get("provisioningState", ""),
                                                "SubscriptionId": sub_id,
                                            },
                                            resource_id=app_id, resource_type="AgentApplication",
                                        ))

                                        # ── 12c. Agent Deployments ───
                                        if app_id:
                                            try:
                                                dep_url = (
                                                    f"https://management.azure.com{app_id}"
                                                    f"/agentDeployments?api-version=2025-04-01-preview"
                                                )
                                                dep_resp = await _arm_get(creds, dep_url)
                                                agent_deploys = (dep_resp or {}).get("value", [])

                                                for adep in agent_deploys:
                                                    adep_props = adep.get("properties", {})
                                                    evidence.append(make_evidence(
                                                        source=Source.AZURE, collector="FoundryConfig",
                                                        evidence_type="foundry-agent-deployment",
                                                        description=f"Agent deployment: {adep.get('name', '')} in {app.get('name', '')}",
                                                        data={
                                                            "DeploymentId": adep.get("id", ""),
                                                            "Name": adep.get("name", ""),
                                                            "ApplicationId": app_id,
                                                            "ApplicationName": app.get("name", ""),
                                                            "ProjectId": proj_id,
                                                            "ProvisioningState": adep_props.get("provisioningState", ""),
                                                            "SubscriptionId": sub_id,
                                                        },
                                                        resource_id=adep.get("id", ""), resource_type="AgentDeployment",
                                                    ))
                                            except AccessDeniedError:
                                                access_denied_count += 1
                                                log.warning("  [FoundryConfig] Agent deployments access denied for %s/%s", proj.get("name", ""), app.get("name", ""))
                                            except Exception as exc:
                                                log.warning("  [FoundryConfig] Agent deployments for %s/%s failed: %s", proj.get("name", ""), app.get("name", ""), exc)

                                except AccessDeniedError:
                                    access_denied_count += 1
                                    log.warning("  [FoundryConfig] Agent apps access denied for %s/%s", acct_name, proj.get("name", ""))
                                except Exception as exc:
                                    log.warning("  [FoundryConfig] Agent apps for %s/%s failed: %s", acct_name, proj.get("name", ""), exc)

                        log.info(
                            "  [FoundryConfig] %s/%s: %d Foundry projects",
                            sub_name, acct_name, len(projects),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Foundry projects access denied for %s/%s", sub_name, acct_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Foundry projects for %s/%s failed: %s", sub_name, acct_name, exc)


            # ── 12. Foundry projects (CognitiveServices subresources) ─
            ai_services_accounts = [
                ev for ev in evidence
                if ev.get("EvidenceType") == "azure-ai-service"
                and (ev.get("Data", ev.get("data", {})).get("SubscriptionId") == sub_id)
                and str(ev.get("Data", ev.get("data", {})).get("Kind", "")).lower() in ("aiservices", "openai", "azureopenai")
            ]

            for acct_ev in ai_services_accounts:
                acct_data = acct_ev.get("Data", acct_ev.get("data", {}))
                acct_id = acct_data.get("AccountId", "")
                acct_name = acct_data.get("Name", "")
                if not acct_id:
                    continue

                # ── 12a. List projects under this account ────────────
                async with _CONCURRENCY:
                    try:
                        proj_url = (
                            f"https://management.azure.com{acct_id}"
                            f"/projects?api-version=2025-04-01-preview"
                        )
                        proj_resp = await _arm_get(creds, proj_url)
                        projects = (proj_resp or {}).get("value", [])

                        for proj in projects:
                            proj_props = proj.get("properties", {})
                            proj_identity = proj.get("identity", {})
                            identity_type = (proj_identity.get("type", "") or "") if proj_identity else ""

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="foundry-project",
                                description=f"Foundry project: {proj.get('name', '')} on {acct_name}",
                                data={
                                    "ProjectId": proj.get("id", ""),
                                    "Name": proj.get("name", ""),
                                    "AccountId": acct_id,
                                    "AccountName": acct_name,
                                    "Location": proj.get("location", ""),
                                    "IdentityType": identity_type,
                                    "HasManagedIdentity": "systemassigned" in identity_type.lower() if identity_type else False,
                                    "ProvisioningState": proj_props.get("provisioningState", ""),
                                    "AgentCount": proj_props.get("agentCount", 0),
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=proj.get("id", ""), resource_type="FoundryProject",
                            ))

                            # ── 12b. Agent Applications under project ─
                            proj_id = proj.get("id", "")
                            if proj_id:
                                try:
                                    app_url = (
                                        f"https://management.azure.com{proj_id}"
                                        f"/applications?api-version=2025-04-01-preview"
                                    )
                                    app_resp = await _arm_get(creds, app_url)
                                    applications = (app_resp or {}).get("value", [])

                                    for app in applications:
                                        app_props = app.get("properties", {})

                                        # Check RBAC on application
                                        has_rbac = False
                                        app_id = app.get("id", "")
                                        if app_id:
                                            try:
                                                rbac_url = (
                                                    f"https://management.azure.com{app_id}"
                                                    f"/providers/Microsoft.Authorization/roleAssignments"
                                                    f"?api-version=2022-04-01"
                                                )
                                                rbac_resp = await _arm_get(creds, rbac_url)
                                                rbac_assignments = (rbac_resp or {}).get("value", [])
                                                has_rbac = len(rbac_assignments) > 0
                                            except Exception:
                                                pass

                                        evidence.append(make_evidence(
                                            source=Source.AZURE, collector="FoundryConfig",
                                            evidence_type="foundry-agent-application",
                                            description=f"Agent app: {app.get('name', '')} in {proj.get('name', '')}",
                                            data={
                                                "ApplicationId": app_id,
                                                "Name": app.get("name", ""),
                                                "ProjectId": proj_id,
                                                "ProjectName": proj.get("name", ""),
                                                "AccountName": acct_name,
                                                "EndpointUrl": app_props.get("endpointUrl", ""),
                                                "Protocol": app_props.get("protocol", ""),
                                                "AuthenticationType": app_props.get("authenticationType", ""),
                                                "IsPublicEndpoint": str(app_props.get("publicNetworkAccess", "Enabled")).lower() != "disabled",
                                                "HasRBACAssignments": has_rbac,
                                                "ProvisioningState": app_props.get("provisioningState", ""),
                                                "SubscriptionId": sub_id,
                                            },
                                            resource_id=app_id, resource_type="AgentApplication",
                                        ))

                                        # ── 12c. Agent Deployments ───
                                        if app_id:
                                            try:
                                                dep_url = (
                                                    f"https://management.azure.com{app_id}"
                                                    f"/agentDeployments?api-version=2025-04-01-preview"
                                                )
                                                dep_resp = await _arm_get(creds, dep_url)
                                                agent_deploys = (dep_resp or {}).get("value", [])

                                                for adep in agent_deploys:
                                                    adep_props = adep.get("properties", {})
                                                    evidence.append(make_evidence(
                                                        source=Source.AZURE, collector="FoundryConfig",
                                                        evidence_type="foundry-agent-deployment",
                                                        description=f"Agent deployment: {adep.get('name', '')} in {app.get('name', '')}",
                                                        data={
                                                            "DeploymentId": adep.get("id", ""),
                                                            "Name": adep.get("name", ""),
                                                            "ApplicationId": app_id,
                                                            "ApplicationName": app.get("name", ""),
                                                            "ProjectId": proj_id,
                                                            "ProvisioningState": adep_props.get("provisioningState", ""),
                                                            "SubscriptionId": sub_id,
                                                        },
                                                        resource_id=adep.get("id", ""), resource_type="AgentDeployment",
                                                    ))
                                            except AccessDeniedError:
                                                access_denied_count += 1
                                                log.warning("  [FoundryConfig] Agent deployments access denied for %s/%s", proj.get("name", ""), app.get("name", ""))
                                            except Exception as exc:
                                                log.warning("  [FoundryConfig] Agent deployments for %s/%s failed: %s", proj.get("name", ""), app.get("name", ""), exc)

                                except AccessDeniedError:
                                    access_denied_count += 1
                                    log.warning("  [FoundryConfig] Agent apps access denied for %s/%s", acct_name, proj.get("name", ""))
                                except Exception as exc:
                                    log.warning("  [FoundryConfig] Agent apps for %s/%s failed: %s", acct_name, proj.get("name", ""), exc)

                        log.info(
                            "  [FoundryConfig] %s/%s: %d Foundry projects",
                            sub_name, acct_name, len(projects),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Foundry projects access denied for %s/%s", sub_name, acct_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Foundry projects for %s/%s failed: %s", sub_name, acct_name, exc)

        # ── 13. Capability Hosts (Hosted Agent infrastructure) ───────
        ai_accounts = [
            (
                (d := ev.get("Data", ev.get("data", {}))).get("SubscriptionId", ""),
                d.get("SubscriptionName", ""),
                d.get("Name", ""),
                d.get("AccountId", ""),
            )
            for ev in evidence
            if ev.get("EvidenceType") == "azure-ai-service"
            and str(ev.get("Data", ev.get("data", {})).get("Kind", "")).lower()
            in ("aiservices", "openai", "azureopenai")
        ]
        for sub_id, sub_name, acct_name, acct_id in ai_accounts:
            if not acct_id:
                continue
            try:
                ch_url = (
                    f"https://management.azure.com{acct_id}"
                    f"/capabilityHosts?api-version=2025-04-01-preview"
                )
                ch_resp = await _arm_get(creds, ch_url)
                cap_hosts = (ch_resp or {}).get("value", [])
                for ch in cap_hosts:
                    ch_props = ch.get("properties", {})
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="FoundryConfig",
                        evidence_type="foundry-capability-host",
                        description=f"Capability host: {ch.get('name', '')} in {acct_name}",
                        data={
                            "CapabilityHostId": ch.get("id", ""),
                            "Name": ch.get("name", ""),
                            "AccountName": acct_name,
                            "AccountId": acct_id,
                            "ProvisioningState": ch_props.get("provisioningState", ""),
                            "ContainerRegistryId": ch_props.get("containerRegistryId", ""),
                            "AcrRegistryName": ch_props.get("acrRegistryName", ""),
                            "StorageAccountId": ch_props.get("storageAccountId", ""),
                            "HasVNetConfig": bool(ch_props.get("virtualNetworkConfiguration")),
                            "ComputeType": ch_props.get("computeType", ""),
                            "ReplicaCount": ch_props.get("replicaCount"),
                            "SubscriptionId": sub_id,
                        },
                        resource_id=ch.get("id", ""), resource_type="CapabilityHost",
                    ))
                log.info(
                    "  [FoundryConfig] %s/%s: %d capability hosts",
                    sub_name, acct_name, len(cap_hosts),
                )
            except AccessDeniedError:
                access_denied_count += 1
                log.warning("  [FoundryConfig] Capability hosts access denied for %s/%s", sub_name, acct_name)
            except Exception as exc:
                log.warning("  [FoundryConfig] Capability hosts for %s/%s failed: %s", sub_name, acct_name, exc)

        # ── Summary ──────────────────────────────────────────────────
        ai_svc_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-service")
        openai_count = sum(
            1 for e in evidence
            if e.get("EvidenceType") == "azure-ai-service"
            and (e.get("Data", e.get("data", {})).get("IsOpenAI"))
        )
        ws_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-workspace")
        deploy_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-openai-deployment")

        compute_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-compute")
        datastore_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-datastore")
        endpoint_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-endpoint")
        registry_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-registry")
        connection_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-connection")
        serverless_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-serverless-endpoint")
        foundry_proj_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-project")
        agent_app_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-application")
        agent_deploy_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-deployment")
        cap_host_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-capability-host")
        foundry_proj_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-project")
        agent_app_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-application")
        agent_deploy_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-deployment")

        # Variant counts for Classic vs New differentiation
        ws_evs = [e for e in evidence if e.get("EvidenceType") == "azure-ai-workspace"]
        classic_hub_count = sum(1 for e in ws_evs if (e.get("Data") or e.get("data", {})).get("ResourceVariant") == "classic-hub")
        classic_project_count = sum(1 for e in ws_evs if (e.get("Data") or e.get("data", {})).get("ResourceVariant") == "classic-project")
        foundry_project_count = sum(1 for e in ws_evs if (e.get("Data") or e.get("data", {})).get("ResourceVariant") == "foundry-project")
        standalone_ml_count = sum(1 for e in ws_evs if (e.get("Data") or e.get("data", {})).get("ResourceVariant") == "standalone-ml")

        evidence.append(make_evidence(
            source=Source.AZURE, collector="FoundryConfig",
            evidence_type="foundry-config-summary",
            description="Microsoft Foundry & OpenAI configuration summary",
            data={
                "TotalAIServices": ai_svc_count,
                "OpenAIAccounts": openai_count,
                "AIWorkspaces": ws_count,
                "OpenAIDeployments": deploy_count,
                "ContentFilterPolicies": sum(
                    1 for e in evidence if e.get("EvidenceType") == "azure-openai-content-filter"
                ),
                "ComputeInstances": compute_count,
                "Datastores": datastore_count,
                "Endpoints": endpoint_count,
                "Registries": registry_count,
                "Connections": connection_count,
                "ServerlessEndpoints": serverless_count,
                "FoundryProjectsNew": foundry_proj_count,
                "AgentApplications": agent_app_count,
                "AgentDeployments": agent_deploy_count,
                "CapabilityHosts": cap_host_count,
                "AccessDeniedErrors": access_denied_count,
                "ClassicHubs": classic_hub_count,
                "ClassicProjects": classic_project_count,
                "FoundryProjects": foundry_project_count,
                "StandaloneML": standalone_ml_count,
            },
            resource_id="foundry-config-summary", resource_type="FoundryConfigSummary",
        ))

        log.info(
            "  [FoundryConfig] Collection complete: %d total evidence records",
            len(evidence),
        )
        return evidence

    return (await run_collector("FoundryConfig", Source.AZURE, _collect)).data
