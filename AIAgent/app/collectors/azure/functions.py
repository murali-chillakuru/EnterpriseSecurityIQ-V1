"""
Azure Functions Collector
Function Apps, hosting plans, configurations, deployment slots, and function-level details.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.web.aio import WebSiteManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="functions", plane="control", source="azure", priority=135)
async def collect_azure_functions(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = WebSiteManagementClient(creds.credential, sub_id)
                apps = await paginate_arm(client.web_apps.list())
                func_apps = [a for a in apps if (getattr(a, "kind", "") or "").lower().startswith("functionapp")]

                for app in func_apps:
                    rg = (app.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (app.id or "") else ""
                    site_config = None
                    auth_settings = None
                    slots = []
                    functions_list = []

                    if rg:
                        async with _CONCURRENCY:
                            # Fetch site configuration
                            try:
                                site_config = await client.web_apps.get_configuration(rg, app.name)
                            except Exception as exc:
                                log.debug("  [Functions] Config for %s failed: %s", app.name, exc)

                            # Fetch auth settings
                            try:
                                auth_settings = await client.web_apps.get_auth_settings_v2(rg, app.name)
                            except Exception as exc:
                                log.debug("  [Functions] Auth for %s failed: %s", app.name, exc)

                            # Fetch deployment slots
                            try:
                                slots = await paginate_arm(client.web_apps.list_slots(rg, app.name))
                            except Exception as exc:
                                log.debug("  [Functions] Slots for %s failed: %s", app.name, exc)

                            # Fetch individual functions
                            try:
                                functions_list = await paginate_arm(client.web_apps.list_functions(rg, app.name))
                            except Exception as exc:
                                log.debug("  [Functions] Functions list for %s failed: %s", app.name, exc)

                    props = app.site_config or type("S", (), {})()
                    identity = app.identity or type("I", (), {"type": None})()
                    sc = site_config or type("SC", (), {})()

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureFunctions",
                        evidence_type="azure-function-app",
                        description=f"Function App: {app.name}",
                        data={
                            "AppId": app.id,
                            "Name": app.name,
                            "Kind": getattr(app, "kind", ""),
                            "Location": app.location,
                            "State": _v(getattr(app, "state", None)),
                            "DefaultHostName": getattr(app, "default_host_name", ""),
                            "HttpsOnly": getattr(app, "https_only", False),
                            "ClientCertEnabled": getattr(app, "client_cert_enabled", False),
                            "ManagedIdentityType": _v(getattr(identity, "type", None)),
                            "RuntimeStack": getattr(sc, "linux_fx_version", "") or getattr(sc, "net_framework_version", ""),
                            "FtpsState": _v(getattr(sc, "ftps_state", None)),
                            "MinTlsVersion": getattr(sc, "min_tls_version", ""),
                            "Http20Enabled": getattr(sc, "http20_enabled", False),
                            "RemoteDebuggingEnabled": getattr(sc, "remote_debugging_enabled", False),
                            "AlwaysOn": getattr(sc, "always_on", False),
                            "FunctionRuntime": getattr(sc, "app_settings", {}).get("FUNCTIONS_WORKER_RUNTIME", ""),
                            "FunctionExtensionVersion": getattr(sc, "app_settings", {}).get("FUNCTIONS_EXTENSION_VERSION", ""),
                            "VnetIntegration": bool(getattr(app, "virtual_network_subnet_id", None)),
                            "PublicNetworkAccess": _v(getattr(app, "public_network_access", None), "Enabled"),
                            "AuthEnabled": bool(auth_settings and getattr(auth_settings, "platform", None)),
                            "SlotCount": len(slots),
                            "FunctionCount": len(functions_list),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=app.id or "", resource_type="FunctionApp",
                    ))

                    # Emit individual function evidence
                    for func in functions_list:
                        func_config = getattr(func, "config", {}) or {}
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureFunctions",
                            evidence_type="azure-function-detail",
                            description=f"Function: {app.name}/{func.name}",
                            data={
                                "FunctionId": func.id or "",
                                "FunctionName": func.name,
                                "AppName": app.name,
                                "Language": func_config.get("language", ""),
                                "IsDisabled": func_config.get("disabled", False),
                                "Bindings": func_config.get("bindings", []),
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=func.id or "", resource_type="Function",
                        ))

                    # Emit slot evidence
                    for slot in slots:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureFunctions",
                            evidence_type="azure-function-slot",
                            description=f"Slot: {app.name}/{slot.name}",
                            data={
                                "SlotId": slot.id or "",
                                "SlotName": slot.name,
                                "AppName": app.name,
                                "State": _v(getattr(slot, "state", None)),
                                "HttpsOnly": getattr(slot, "https_only", False),
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=slot.id or "", resource_type="FunctionAppSlot",
                        ))

                await client.close()
                log.info("  [AzureFunctions] %s: %d function apps", sub_name, len(func_apps))
            except Exception as exc:
                log.warning("  [AzureFunctions] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureFunctions", Source.AZURE, _collect)).data
