"""
Entra Tenant Collector
Organization info, verified domains, assigned plans, hybrid sync.
"""

from __future__ import annotations
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="tenant", plane="control", source="entra", priority=10)
async def collect_entra_tenant(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()

        try:
            orgs = await graph.organization.get()
            for org in (orgs.value or []):
                tenant_id = getattr(org, "id", "")
                display = getattr(org, "display_name", "")
                domains = getattr(org, "verified_domains", []) or []
                plans = getattr(org, "assigned_plans", []) or []

                domain_list = []
                for d in domains:
                    domain_list.append({
                        "Name": getattr(d, "name", ""),
                        "IsDefault": getattr(d, "is_default", False),
                        "IsInitial": getattr(d, "is_initial", False),
                    })

                license_plans = []
                for p in plans:
                    if getattr(p, "capability_status", "") == "Enabled":
                        license_plans.append(getattr(p, "service", ""))

                has_p2 = any("AAD_PREMIUM_P2" in str(p) for p in plans)
                has_p1 = any("AAD_PREMIUM" in str(p) for p in plans)

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraTenant",
                    evidence_type="entra-tenant-info",
                    description=f"Tenant: {display}",
                    data={
                        "TenantId": tenant_id,
                        "DisplayName": display,
                        "VerifiedDomains": domain_list,
                        "LicensePlans": list(set(license_plans)),
                        "HasP2License": has_p2,
                        "HasP1License": has_p1,
                        "OnPremisesSyncEnabled": getattr(org, "on_premises_sync_enabled", False) or False,
                        "TechnicalNotificationMails": getattr(org, "technical_notification_mails", []) or [],
                    },
                    resource_id=tenant_id, resource_type="Tenant",
                ))
                log.info("  [EntraTenant] Tenant: %s (%s)", display, tenant_id)
        except Exception as exc:
            log.warning("  [EntraTenant] Organization info failed: %s", exc)

        return evidence

    return (await run_collector("EntraTenant", Source.ENTRA, _collect)).data
