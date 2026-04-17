"""
Entra Workload Identity Federation Collector
Federated identity credentials on app registrations & managed identities,
workload identity federation policies, service principal configurations.
"""

from __future__ import annotations
from datetime import datetime, timezone
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="workload_identity", plane="control", source="entra", priority=65)
async def collect_entra_workload_identity(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()
        now = datetime.now(timezone.utc)

        # --- Federated Identity Credentials on App Registrations ---
        apps = await paginate_graph(graph.applications)
        for app in apps:
            app_id = getattr(app, "app_id", "") or ""
            obj_id = getattr(app, "id", "") or ""
            display = getattr(app, "display_name", "") or ""

            if not obj_id:
                continue

            try:
                fics = await paginate_graph(
                    graph.applications.by_application_id(obj_id).federated_identity_credentials
                )
                for fic in fics:
                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="EntraWorkloadIdentity",
                        evidence_type="entra-federated-credential",
                        description=f"Federated Credential: {display}/{getattr(fic, 'name', '')}",
                        data={
                            "CredentialId": getattr(fic, "id", ""),
                            "Name": getattr(fic, "name", ""),
                            "AppDisplayName": display,
                            "AppId": app_id,
                            "AppObjectId": obj_id,
                            "Issuer": getattr(fic, "issuer", ""),
                            "Subject": getattr(fic, "subject", ""),
                            "Description": getattr(fic, "description", ""),
                            "Audiences": list(getattr(fic, "audiences", []) or []),
                        },
                        resource_id=getattr(fic, "id", ""), resource_type="FederatedIdentityCredential",
                    ))
            except Exception:
                pass  # App has no federated credentials or access denied

        log.info("  [EntraWorkloadIdentity] Scanned %d apps for federated credentials", len(apps))

        # --- Service Principals with Federated Credentials ---
        sps = await paginate_graph(graph.service_principals)
        managed_identity_sps = []
        workload_identity_sps = []

        for sp in sps:
            sp_type = (getattr(sp, "service_principal_type", "") or "").lower()
            display = getattr(sp, "display_name", "") or ""
            app_id = getattr(sp, "app_id", "") or ""
            sp_id = getattr(sp, "id", "") or ""

            # Track managed identities
            if sp_type == "managedidentity":
                tags = list(getattr(sp, "tags", []) or [])
                alt_names = list(getattr(sp, "alternative_names", []) or [])

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraWorkloadIdentity",
                    evidence_type="entra-managed-identity-sp",
                    description=f"Managed Identity SP: {display}",
                    data={
                        "ServicePrincipalId": sp_id,
                        "DisplayName": display,
                        "AppId": app_id,
                        "ServicePrincipalType": sp_type,
                        "Tags": tags,
                        "AlternativeNames": alt_names,
                        "AccountEnabled": getattr(sp, "account_enabled", True),
                    },
                    resource_id=sp_id, resource_type="ManagedIdentityServicePrincipal",
                ))
                managed_identity_sps.append(sp)

            # Track app-type SPs with credentials for workload identity review
            elif sp_type == "application":
                key_creds = getattr(sp, "key_credentials", []) or []
                pwd_creds = getattr(sp, "password_credentials", []) or []
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

                if total_creds > 0:
                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="EntraWorkloadIdentity",
                        evidence_type="entra-workload-credential-review",
                        description=f"Workload Credential Review: {display}",
                        data={
                            "ServicePrincipalId": sp_id,
                            "DisplayName": display,
                            "AppId": app_id,
                            "TotalCredentials": total_creds,
                            "HasExpiredCredentials": has_expired,
                            "HasExpiringCredentials": expires_soon,
                            "KeyCredentialCount": len(key_creds),
                            "PasswordCredentialCount": len(pwd_creds),
                            "CouldUseFederation": total_creds > 0,
                            "AccountEnabled": getattr(sp, "account_enabled", True),
                        },
                        resource_id=sp_id, resource_type="WorkloadCredentialReview",
                    ))
                    workload_identity_sps.append(sp)

        log.info("  [EntraWorkloadIdentity] %d managed identity SPs, %d workload SPs with credentials",
                 len(managed_identity_sps), len(workload_identity_sps))

        return evidence

    return (await run_collector("EntraWorkloadIdentity", Source.ENTRA, _collect)).data
