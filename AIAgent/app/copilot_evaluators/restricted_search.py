"""Restricted SharePoint Search evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


def analyze_restricted_search(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Restricted SharePoint Search (RSS) and Restricted Content Discoverability (RCD) for Copilot scoping."""
    findings: list[dict] = []
    findings.extend(_check_rss_configuration(evidence_index))
    findings.extend(_check_rcd_configuration(evidence_index))
    return findings


def _check_rss_configuration(idx: dict) -> list[dict]:
    """Check if Restricted SharePoint Search is configured for Copilot scoping."""
    # RSS limits which sites Copilot can index
    # Evidence from: spo-tenant-sharing-config or dedicated RSS evidence
    config = idx.get("spo-tenant-sharing-config", [])
    sites = idx.get("spo-site-inventory", [])

    total_sites = len(sites)
    if total_sites > 20:
        return [_cr_finding(
            "restricted_search", "rss_not_configured",
            f"Large tenant ({total_sites} sites) — Restricted SharePoint Search recommended for Copilot",
            "Restricted SharePoint Search (RSS) limits which SharePoint sites M365 Copilot "
            "can index and surface content from. For large tenants, RSS provides a phased "
            "rollout approach — start with a curated allow-list of sites.",
            "medium",
            [{"Type": "SearchConfig", "Name": "Restricted SharePoint Search",
              "ResourceId": "spo-rss-config", "TotalSites": total_sites}],
            {"Description": "Enable Restricted SharePoint Search and create an allow-list of "
             "vetted sites for Copilot indexing.",
             "PowerShell": (
                 "# Enable Restricted SharePoint Search\n"
                 "Set-SPOTenant -IsRestrictedSharePointSearchEnabled $true\n"
                 "# Add allowed sites\n"
                 "Add-SPOTenantRestrictedSearchAllowedList -SiteUrl <SiteUrl>"
             )},
            compliance_status="gap",
        )]
    return []


def _check_rcd_configuration(idx: dict) -> list[dict]:
    """Check if Restricted Content Discoverability (RCD) is configured.

    RCD is separate from RSS: RSS limits which sites Copilot *searches*,
    while RCD limits which content Copilot can *discover and surface* in
    responses, recommendations, and Copilot-generated summaries — even
    for content the user technically has permission to access.
    """
    config = idx.get("spo-tenant-sharing-config", [])
    sites = idx.get("spo-site-inventory", [])

    # Check if RCD is explicitly configured in tenant config
    rcd_enabled = False
    for ev in config:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsRestrictedContentDiscoverabilityEnabled", False):
            rcd_enabled = True
            break

    total_sites = len(sites)
    if total_sites > 20 and not rcd_enabled:
        return [_cr_finding(
            "restricted_search", "rcd_not_configured",
            f"Restricted Content Discoverability (RCD) not configured — Copilot may surface sensitive content",
            "Restricted Content Discoverability (RCD) controls which content M365 Copilot can "
            "discover and surface in responses. Unlike Restricted SharePoint Search (RSS) which "
            "limits site-level indexing, RCD operates at the content level — preventing Copilot "
            "from proactively surfacing documents in recommendations, summaries, and chat responses "
            "even when the user has access permissions. Without RCD, Copilot may surface sensitive "
            "HR, legal, or financial documents that users have inherited permissions to but should "
            "not be actively discovering.",
            "medium",
            [{"Type": "SearchConfig", "Name": "Restricted Content Discoverability",
              "ResourceId": "spo-rcd-config", "TotalSites": total_sites}],
            {"Description": "Enable Restricted Content Discoverability to control what content "
             "Copilot proactively surfaces, complementing RSS site-level restrictions.",
             "PowerShell": (
                 "# Enable Restricted Content Discoverability\n"
                 "Set-SPOTenant -IsRestrictedContentDiscoverabilityEnabled $true\n"
                 "# Configure content discovery allow-list\n"
                 "Add-SPOTenantRestrictedContentDiscoverabilityAllowedList -SiteUrl <SiteUrl>"
             ),
             "PortalSteps": [
                 "Go to SharePoint admin center > Settings > Restricted Content Discoverability",
                 "Enable RCD and configure the allow-list of sites whose content Copilot may surface",
                 "Start with low-sensitivity sites and progressively add more as content is reviewed",
                 "Monitor Copilot interactions to verify content scoping is effective",
             ]},
            compliance_status="gap",
        )]
    return []

