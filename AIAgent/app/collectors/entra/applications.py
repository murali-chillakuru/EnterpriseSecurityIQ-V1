"""
Entra Applications Collector
App registrations + service principals, credential expiry.
"""

from __future__ import annotations
from datetime import datetime, timezone
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="applications", plane="control", source="entra", priority=60)
async def collect_entra_applications(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()
        now = datetime.now(timezone.utc)

        # App registrations
        apps = await paginate_graph(graph.applications)
        for app in apps:
            app_id = getattr(app, "app_id", "") or ""
            display = getattr(app, "display_name", "") or ""
            audience = getattr(app, "sign_in_audience", "") or ""

            # Credentials
            key_creds = getattr(app, "key_credentials", []) or []
            pwd_creds = getattr(app, "password_credentials", []) or []
            total_creds = len(key_creds) + len(pwd_creds)
            has_expired = False
            expires_soon = False

            for cred in list(key_creds) + list(pwd_creds):
                end = getattr(cred, "end_date_time", None)
                if end:
                    if end < now:
                        has_expired = True
                    elif (end - now).days <= 30:
                        expires_soon = True

            evidence.append(make_evidence(
                source=Source.ENTRA, collector="EntraApplications",
                evidence_type="entra-application",
                description=f"App: {display}",
                data={
                    "AppId": app_id,
                    "ObjectId": getattr(app, "id", ""),
                    "DisplayName": display,
                    "SignInAudience": audience,
                    "TotalCredentials": total_creds,
                    "HasExpiredCredentials": has_expired,
                    "HasExpiringCredentials": expires_soon,
                    "KeyCredentialCount": len(key_creds),
                    "PasswordCredentialCount": len(pwd_creds),
                    "IsMultiTenant": audience in [
                        "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount",
                    ],
                },
                resource_id=getattr(app, "id", ""), resource_type="Application",
            ))

        log.info("  [EntraApplications] %d app registrations", len(apps))

        # Service principals
        sps = await paginate_graph(graph.service_principals)
        for sp in sps:
            sp_type = getattr(sp, "service_principal_type", "") or ""
            display = getattr(sp, "display_name", "") or ""
            app_id = getattr(sp, "app_id", "") or ""

            key_creds = getattr(sp, "key_credentials", []) or []
            pwd_creds = getattr(sp, "password_credentials", []) or []
            total_creds = len(key_creds) + len(pwd_creds)
            has_expired = False
            for cred in list(key_creds) + list(pwd_creds):
                end = getattr(cred, "end_date_time", None)
                if end and end < now:
                    has_expired = True

            evidence.append(make_evidence(
                source=Source.ENTRA, collector="EntraApplications",
                evidence_type="entra-service-principal",
                description=f"SP: {display}",
                data={
                    "ObjectId": getattr(sp, "id", ""),
                    "AppId": app_id,
                    "DisplayName": display,
                    "ServicePrincipalType": sp_type,
                    "AccountEnabled": getattr(sp, "account_enabled", True),
                    "TotalCredentials": total_creds,
                    "HasExpiredCredentials": has_expired,
                },
                resource_id=getattr(sp, "id", ""), resource_type="ServicePrincipal",
            ))

        log.info("  [EntraApplications] %d service principals", len(sps))
        return evidence

    return (await run_collector("EntraApplications", Source.ENTRA, _collect)).data
