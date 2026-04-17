"""
SharePoint Online & OneDrive Governance Collector
Collects: site inventory, permissions/membership, sharing links,
content lifecycle (stale sites), sensitivity labels on sites,
anonymous link settings, oversharing indicators.

Uses Microsoft Graph API v1.0 and beta endpoints.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timezone, timedelta
from app.models import Source
from app.collectors.base import (
    run_collector,
    paginate_graph,
    make_evidence,
    AccessDeniedError,
)
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)

# Sites idle for >180 days may be considered stale
_STALE_THRESHOLD_DAYS = 180


@register_collector(name="sharepoint_onedrive", plane="control", source="azure", priority=180)
async def collect_sharepoint_onedrive(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:  # noqa: ARG001
    """Collect SharePoint Online & OneDrive governance data via Graph API."""

    async def _collect():
        evidence: list[dict] = []

        graph = creds.get_graph_client()
        beta = creds.get_graph_beta_client()
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(days=_STALE_THRESHOLD_DAYS)

        # ── 1. SharePoint Sites inventory ────────────────────────────
        # Multi-tier discovery: search=* → root + group-connected sites
        sites: list = []
        discovery_method = "none"

        # Tier 1: search=* (full discovery — works on many tenants)
        try:
            from msgraph.generated.sites.sites_request_builder import SitesRequestBuilder
            query = SitesRequestBuilder.SitesRequestBuilderGetQueryParameters(search="*")
            config = SitesRequestBuilder.SitesRequestBuilderGetRequestConfiguration(
                query_parameters=query,
            )
            page = await graph.sites.get(request_configuration=config)
            if page and page.value:
                sites.extend(page.value)
            while page and page.odata_next_link:
                page = await graph.sites.with_url(page.odata_next_link).get()
                if page and page.value:
                    sites.extend(page.value)
            if sites:
                discovery_method = "search"
                log.info("  [SPO] Discovered %d SharePoint sites (search=*)", len(sites))
        except Exception as exc:
            err_str = str(exc)
            is_syntax_err = "400" in err_str or "BadRequest" in err_str or "Syntax error" in err_str
            is_access_err = "403" in err_str or "accessDenied" in err_str or "Access denied" in err_str
            if is_syntax_err:
                log.info("  [SPO] search=* rejected (400) — falling back to root + group sites")
            elif is_access_err:
                log.info("  [SPO] search=* denied (403) — Sites.Read.All scope likely missing, falling back")
            else:
                log.warning("  [SPO] search=* failed: %s — falling back", exc)

        # Tier 2: Root site + M365 group-connected sites (partial discovery)
        if not sites:
            seen_ids: set[str] = set()
            try:
                root = await graph.sites.by_site_id("root").get()
                if root and getattr(root, "id", ""):
                    sites.append(root)
                    seen_ids.add(getattr(root, "id", ""))
                    log.info("  [SPO] Got root site: %s", getattr(root, "display_name", ""))
            except Exception as exc:
                log.debug("  [SPO] Root site failed: %s", exc)

            try:
                groups = await paginate_graph(graph.groups, top=999)
                m365_groups = [
                    g for g in groups
                    if "Unified" in (getattr(g, "group_types", []) or [])
                ]
                log.info("  [SPO] Found %d M365 groups — probing connected sites", len(m365_groups))
                for g in m365_groups:
                    gid = getattr(g, "id", "")
                    if not gid:
                        continue
                    try:
                        site_coll = await graph.groups.by_group_id(gid).sites.by_site_id("root").get()
                        if site_coll:
                            sid = getattr(site_coll, "id", "")
                            if sid and sid not in seen_ids:
                                sites.append(site_coll)
                                seen_ids.add(sid)
                    except Exception:
                        pass
                if len(seen_ids) > 1:
                    log.info("  [SPO] Discovered %d sites via group-site fallback", len(sites))
            except Exception as exc:
                log.debug("  [SPO] Group-site fallback failed: %s", exc)

            if sites:
                discovery_method = "fallback"
            else:
                discovery_method = "none"

        # Convert site objects → evidence records
        for site in sites:
            try:
                site_id = getattr(site, "id", "") or ""
                site_name = getattr(site, "display_name", "") or getattr(site, "name", "") or ""
                web_url = getattr(site, "web_url", "") or ""
                created = getattr(site, "created_date_time", None)
                modified = getattr(site, "last_modified_date_time", None)

                is_stale = False
                if modified:
                    try:
                        mod_dt = modified if isinstance(modified, datetime) else datetime.fromisoformat(str(modified).replace("Z", "+00:00"))
                        is_stale = mod_dt < stale_cutoff
                    except (ValueError, TypeError):
                        pass

                sensitivity_label = ""
                sensitivity_label_id = ""
                try:
                    sl = getattr(site, "sensitivity_label", None)
                    if sl:
                        sensitivity_label_id = getattr(sl, "label_id", "") or ""
                        sensitivity_label = getattr(sl, "display_name", "") or ""
                except Exception:
                    pass

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="SharePointOneDrive",
                    evidence_type="spo-site-inventory",
                    description=f"SharePoint site: {site_name}",
                    data={
                        "SiteId": site_id,
                        "SiteName": site_name,
                        "WebUrl": web_url,
                        "CreatedDateTime": str(created) if created else "",
                        "LastModifiedDateTime": str(modified) if modified else "",
                        "IsStale": is_stale,
                        "StaleDays": _STALE_THRESHOLD_DAYS,
                        "SensitivityLabelId": sensitivity_label_id,
                        "SensitivityLabel": sensitivity_label,
                        "IsRoot": getattr(site, "is_personal_site", False) is False and "/sites/" not in web_url,
                        "DiscoveryMethod": discovery_method,
                    },
                    resource_id=site_id, resource_type="SharePointSite",
                ))
            except Exception as exc:
                log.debug("  [SPO] Failed to process site: %s", exc)

        # Emit scope warning when using fallback (partial data)
        site_count = sum(1 for ev in evidence if ev.get("EvidenceType") == "spo-site-inventory")
        if discovery_method == "fallback" and site_count > 0:
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="SharePointOneDrive",
                evidence_type="spo-scope-warning",
                description=(
                    "SharePoint site discovery used fallback — Sites.Read.All "
                    "scope not available in the current token"
                ),
                data={
                    "Warning": "SitesReadAllScopeMissing",
                    "DiscoveryMethod": "fallback",
                    "SitesDiscovered": site_count,
                    "Impact": (
                        "Only the root site and M365-group-connected sites were "
                        "discovered. Standalone sites created outside groups are "
                        "not included. Oversharing analysis is partial."
                    ),
                    "RequiredScope": "Sites.Read.All",
                    "Explanation": (
                        "The Azure CLI first-party app does not include "
                        "Sites.Read.All in its pre-consented scope set. "
                        "Use a custom app registration with Sites.Read.All "
                        "granted, or run with application-level credentials."
                    ),
                },
                resource_id="spo-scope-warning", resource_type="CollectionWarning",
            ))
        elif site_count == 0:
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="SharePointOneDrive",
                evidence_type="spo-collection-warning",
                description="No SharePoint sites discovered — Sites.Read.All scope missing from token",
                data={
                    "Warning": "ZeroSitesDiscovered",
                    "Impact": "Oversharing risk, site label coverage, and content lifecycle cannot be assessed.",
                    "RequiredScope": "Sites.Read.All",
                    "Recommendation": (
                        "The Azure CLI token does not include Sites.Read.All. "
                        "Use a custom app registration with Sites.Read.All "
                        "granted, or run with application-level credentials."
                    ),
                },
                resource_id="spo-zero-sites", resource_type="CollectionWarning",
            ))

        # ── 2. Site permissions / membership (sample up to 50 sites) ─
        site_sample = [
            ev for ev in evidence if ev.get("EvidenceType") == "spo-site-inventory"
        ][:50]

        async def _fetch_site_permissions(ev: dict):
            async with _CONCURRENCY:
                data = ev.get("Data", ev.get("data", {}))
                sid = data.get("SiteId", "")
                sname = data.get("SiteName", "")
                if not sid:
                    return

                try:
                    perms = await paginate_graph(
                        graph.sites.by_site_id(sid).permissions, top=999
                    )
                    owner_count = 0
                    member_count = 0
                    guest_count = 0
                    external_count = 0

                    for perm in perms:
                        roles = getattr(perm, "roles", []) or []
                        granted_to = getattr(perm, "granted_to_v2", None) or getattr(perm, "granted_to", None)
                        if granted_to:
                            user = getattr(granted_to, "user", None)
                            if user:
                                email = getattr(user, "email", "") or ""
                                if "owner" in [r.lower() for r in roles]:
                                    owner_count += 1
                                else:
                                    member_count += 1
                                if "#ext#" in email.lower() or getattr(user, "user_type", "") == "Guest":
                                    guest_count += 1
                                    external_count += 1

                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="SharePointOneDrive",
                        evidence_type="spo-site-permissions",
                        description=f"Permissions for site: {sname}",
                        data={
                            "SiteId": sid,
                            "SiteName": sname,
                            "TotalPermissions": len(perms),
                            "OwnerCount": owner_count,
                            "MemberCount": member_count,
                            "GuestCount": guest_count,
                            "ExternalUserCount": external_count,
                            "IsOvershared": (owner_count + member_count) > 50 or guest_count > 10,
                        },
                        resource_id=sid, resource_type="SharePointSitePermissions",
                    ))
                except Exception as exc:
                    log.debug("  [SPO] Permissions for '%s' failed: %s", sname, exc)

        await asyncio.gather(
            *[_fetch_site_permissions(ev) for ev in site_sample],
            return_exceptions=True,
        )

        # ── 3. Sharing links / anonymous links on sites ──────────────
        async def _fetch_sharing_links(ev: dict):
            async with _CONCURRENCY:
                data = ev.get("Data", ev.get("data", {}))
                sid = data.get("SiteId", "")
                sname = data.get("SiteName", "")
                if not sid:
                    return
                try:
                    # Get drive items with sharing info via /sites/{id}/drive/root/children
                    drive = await graph.sites.by_site_id(sid).drive.get()
                    if not drive:
                        return
                    drive_id = getattr(drive, "id", "")
                    if not drive_id:
                        return

                    items = await paginate_graph(
                        graph.sites.by_site_id(sid).drive.root.children, top=200
                    )

                    anonymous_links = 0
                    org_links = 0
                    external_links = 0
                    total_shared = 0

                    for item in items:
                        shared = getattr(item, "shared", None)
                        if shared:
                            total_shared += 1
                            scope = getattr(shared, "scope", "") or ""
                            if scope.lower() == "anonymous":
                                anonymous_links += 1
                            elif scope.lower() == "organization":
                                org_links += 1
                            else:
                                external_links += 1

                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="SharePointOneDrive",
                        evidence_type="spo-sharing-links",
                        description=f"Sharing links for site: {sname}",
                        data={
                            "SiteId": sid,
                            "SiteName": sname,
                            "TotalItems": len(items),
                            "TotalSharedItems": total_shared,
                            "AnonymousLinks": anonymous_links,
                            "OrganizationLinks": org_links,
                            "ExternalLinks": external_links,
                            "HasAnonymousLinks": anonymous_links > 0,
                        },
                        resource_id=sid, resource_type="SharePointSharingLinks",
                    ))
                except Exception as exc:
                    log.debug("  [SPO] Sharing links for '%s' failed: %s", sname, exc)

        await asyncio.gather(
            *[_fetch_sharing_links(ev) for ev in site_sample[:30]],
            return_exceptions=True,
        )

        # ── 4. OneDrive settings (org-level sharing config) ─────────
        try:
            # Beta endpoint: admin/sharepoint/settings
            settings = await beta.admin.sharepoint.settings.get()
            if settings:
                sharing_cap = getattr(settings, "sharing_capability", None)
                sharing_domain_restriction = getattr(settings, "sharing_domain_restriction_mode", None)

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="SharePointOneDrive",
                    evidence_type="spo-tenant-sharing-config",
                    description="SPO/OneDrive tenant sharing configuration",
                    data={
                        "SharingCapability": str(sharing_cap) if sharing_cap else "Unknown",
                        "SharingDomainRestrictionMode": str(sharing_domain_restriction) if sharing_domain_restriction else "Unknown",
                        "IsAnonymousSharingEnabled": str(sharing_cap).lower() in ("externaluserandguestsharingon", "anyone"),
                        "IsExternalSharingEnabled": str(sharing_cap).lower() != "disabled",
                    },
                    resource_id="tenant-spo-config", resource_type="SPOTenantConfig",
                ))
                log.info("  [SPO] Tenant sharing config collected")
        except Exception as exc:
            log.warning("  [SPO] Tenant sharing settings failed: %s", exc)
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="SharePointOneDrive",
                evidence_type="spo-collection-warning",
                description=f"Tenant sharing settings collection failed: {exc}",
                data={
                    "Warning": "TenantSharingSettingsFailed",
                    "Error": str(exc),
                    "Impact": "External sharing posture could not be evaluated.",
                    "Recommendation": "Ensure the service principal has SharePointTenantSettings.Read.All permission.",
                },
                resource_id="spo-tenant-config-failure", resource_type="CollectionWarning",
            ))

        # ── 5. Site sensitivity label summary ────────────────────────
        labeled_sites = sum(
            1 for ev in evidence
            if ev.get("EvidenceType") == "spo-site-inventory"
            and (ev.get("Data", ev.get("data", {})).get("SensitivityLabelId") or "")
        )
        total_sites = sum(
            1 for ev in evidence
            if ev.get("EvidenceType") == "spo-site-inventory"
        )

        evidence.append(make_evidence(
            source=Source.ENTRA, collector="SharePointOneDrive",
            evidence_type="spo-label-summary",
            description="SharePoint site sensitivity label coverage",
            data={
                "TotalSites": total_sites,
                "LabeledSites": labeled_sites,
                "UnlabeledSites": total_sites - labeled_sites,
                "LabelCoverage": round(labeled_sites / max(total_sites, 1) * 100, 1),
            },
            resource_id="spo-label-summary", resource_type="SPOLabelSummary",
        ))

        log.info(
            "  [SPO] Collection complete: %d total evidence records",
            len(evidence),
        )
        return evidence

    return (await run_collector("SharePointOneDrive", Source.ENTRA, _collect)).data
