"""
Azure Web App Detailed Collector
Authentication settings, IP restrictions, CORS, diagnostic logging.
"""

from __future__ import annotations
from azure.mgmt.web.aio import WebSiteManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="webapp_detailed", plane="data", source="azure", priority=220)
async def collect_azure_webapp_detailed(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                web = WebSiteManagementClient(creds.credential, sub_id)
                apps = await paginate_arm(web.web_apps.list())

                for app in apps:
                    rg = (app.id or "").split("/resourceGroups/")[1].split("/")[0] if app.id else ""
                    if not rg:
                        continue

                    # Authentication settings
                    auth_enabled = False
                    auth_provider = "None"
                    try:
                        auth = await web.web_apps.get_auth_settings_v2(rg, app.name)
                        if auth and auth.platform:
                            auth_enabled = getattr(auth.platform, "enabled", False) or False
                        if auth and auth.identity_providers:
                            providers = []
                            if getattr(auth.identity_providers, "azure_active_directory", None):
                                providers.append("AzureAD")
                            if getattr(auth.identity_providers, "google", None):
                                providers.append("Google")
                            if getattr(auth.identity_providers, "github", None):
                                providers.append("GitHub")
                            auth_provider = ",".join(providers) if providers else "None"
                    except Exception:
                        pass

                    # Full site config for IP restrictions, CORS, and diagnostics
                    ip_restriction_count = 0
                    scm_ip_restriction_count = 0
                    cors_allowed_origins = 0
                    cors_allow_all = False
                    http20_enabled = False
                    always_on = False
                    try:
                        cfg = await web.web_apps.get_configuration(rg, app.name)
                        if cfg:
                            ip_restrictions = getattr(cfg, "ip_security_restrictions", None) or []
                            ip_restriction_count = len(ip_restrictions)
                            scm_restrictions = getattr(cfg, "scm_ip_security_restrictions", None) or []
                            scm_ip_restriction_count = len(scm_restrictions)
                            cors = getattr(cfg, "cors", None)
                            if cors and getattr(cors, "allowed_origins", None):
                                origins = cors.allowed_origins
                                cors_allowed_origins = len(origins)
                                cors_allow_all = "*" in origins
                            http20_enabled = getattr(cfg, "http20_enabled", False) or False
                            always_on = getattr(cfg, "always_on", False) or False
                    except Exception:
                        pass

                    # Diagnostic logs configuration
                    app_logs_enabled = False
                    http_logs_enabled = False
                    try:
                        diag = await web.web_apps.get_diagnostic_logs_configuration(rg, app.name)
                        if diag:
                            app_log = getattr(diag, "application_logs", None)
                            if app_log:
                                fs = getattr(app_log, "file_system", None)
                                blob = getattr(app_log, "azure_blob_storage", None)
                                app_logs_enabled = bool(
                                    (fs and getattr(fs, "level", "Off") != "Off")
                                    or (blob and getattr(blob, "level", "Off") != "Off")
                                )
                            http_log = getattr(diag, "http_logs", None)
                            if http_log:
                                fs = getattr(http_log, "file_system", None)
                                blob = getattr(http_log, "azure_blob_storage", None)
                                app_logs_http = bool(
                                    (fs and getattr(fs, "enabled", False))
                                    or (blob and getattr(blob, "enabled", False))
                                )
                                http_logs_enabled = app_logs_http
                    except Exception:
                        pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="WebAppDetailed",
                        evidence_type="azure-webapp-detailed",
                        description=f"Web App detail: {app.name}",
                        data={
                            "AppId": app.id,
                            "Name": app.name,
                            "Location": app.location,
                            "AuthEnabled": auth_enabled,
                            "AuthProvider": auth_provider,
                            "IpRestrictionCount": ip_restriction_count,
                            "ScmIpRestrictionCount": scm_ip_restriction_count,
                            "CorsAllowedOrigins": cors_allowed_origins,
                            "CorsAllowAll": cors_allow_all,
                            "Http20Enabled": http20_enabled,
                            "AlwaysOn": always_on,
                            "ApplicationLogsEnabled": app_logs_enabled,
                            "HttpLogsEnabled": http_logs_enabled,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=app.id or "",
                        resource_type="Microsoft.Web/sites",
                    ))

                await web.close()
                log.info("  [WebAppDetailed] %s: %d apps inspected", sub_name, len(apps))
            except Exception as exc:
                log.warning("  [WebAppDetailed] %s failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("WebAppDetailed", Source.AZURE, _collect)
    return result.data
