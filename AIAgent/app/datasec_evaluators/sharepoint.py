"""
Data Security — SharePoint / OneDrive Governance evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_sharepoint_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess SharePoint Online & OneDrive governance posture."""
    findings: list[dict] = []
    findings.extend(_check_spo_overshared_sites(evidence_index))
    findings.extend(_check_spo_anonymous_links(evidence_index))
    findings.extend(_check_spo_external_sharing_config(evidence_index))
    findings.extend(_check_spo_stale_sites(evidence_index))
    findings.extend(_check_spo_unlabeled_sites(evidence_index))
    findings.extend(_check_spo_guest_permissions(evidence_index))
    return findings


def _check_spo_overshared_sites(idx: dict) -> list[dict]:
    """Flag SharePoint sites with excessively broad membership/permissions."""
    perms = idx.get("spo-site-permissions", [])
    overshared: list[dict] = []
    for ev in perms:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsOvershared"):
            overshared.append({
                "Type": "SharePointSite",
                "Name": data.get("SiteName", "Unknown"),
                "ResourceId": data.get("SiteId", ""),
                "TotalPermissions": data.get("TotalPermissions", 0),
                "OwnerCount": data.get("OwnerCount", 0),
                "MemberCount": data.get("MemberCount", 0),
                "GuestCount": data.get("GuestCount", 0),
            })
    if overshared:
        return [_ds_finding(
            "sharepoint_governance", "overshared_sites",
            f"{len(overshared)} SharePoint sites have excessively broad permissions",
            "Sites with too many members (>50) or excessive guest users (>10) increase "
            "the risk of data oversharing and accidental exposure of sensitive content. "
            "This is critical for M365 Copilot readiness as Copilot surfaces content "
            "based on user permissions.",
            "high", overshared,
            {"Description": "Review and tighten site membership. Remove stale guest accounts. "
             "Use security groups instead of individual permissions.",
             "PowerShell": (
                 "# Remove external user from site\n"
                 "Remove-SPOExternalUser -UniqueIDs <ExternalUserId>"
             )},
        )]
    return []


def _check_spo_anonymous_links(idx: dict) -> list[dict]:
    """Flag sites with anonymous (Anyone) sharing links."""
    sharing = idx.get("spo-sharing-links", [])
    anon_sites: list[dict] = []
    total_anon = 0
    for ev in sharing:
        data = ev.get("Data", ev.get("data", {}))
        anon_count = data.get("AnonymousLinks", 0)
        if anon_count > 0:
            total_anon += anon_count
            anon_sites.append({
                "Type": "SharePointSite",
                "Name": data.get("SiteName", "Unknown"),
                "ResourceId": data.get("SiteId", ""),
                "AnonymousLinks": anon_count,
                "TotalSharedItems": data.get("TotalSharedItems", 0),
            })
    if anon_sites:
        return [_ds_finding(
            "sharepoint_governance", "anonymous_sharing_links",
            f"{total_anon} anonymous sharing links found across {len(anon_sites)} sites",
            "Anonymous (Anyone) links allow unauthenticated access to shared content. "
            "These links bypass identity verification and cannot be audited effectively. "
            "For highly sensitive sites, anonymous links must be disabled.",
            "critical", anon_sites,
            {"Description": "Disable anonymous link sharing at tenant or site level. "
             "Convert existing anonymous links to organization or specific-people links.",
             "PowerShell": (
                 "# Disable anonymous sharing for a site\n"
                 "Set-SPOSite -Identity <SiteUrl> -SharingCapability ExternalUserSharingOnly"
             )},
        )]
    return []


def _check_spo_external_sharing_config(idx: dict) -> list[dict]:
    """Flag tenant-level sharing configuration that allows anonymous sharing."""
    config = idx.get("spo-tenant-sharing-config", [])
    findings_list: list[dict] = []
    for ev in config:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsAnonymousSharingEnabled"):
            findings_list.append({
                "Type": "TenantConfig",
                "Name": "SharePoint/OneDrive Tenant Sharing",
                "ResourceId": "tenant-spo-config",
                "SharingCapability": data.get("SharingCapability", ""),
            })
    if findings_list:
        return [_ds_finding(
            "sharepoint_governance", "anonymous_sharing_enabled",
            "Tenant allows anonymous (Anyone) link sharing for SharePoint/OneDrive",
            "When anonymous sharing is enabled at the tenant level, any user can create "
            "Anyone links that provide unauthenticated access to content. This is the "
            "most permissive sharing setting and poses significant data leakage risk.",
            "critical", findings_list,
            {"Description": "Restrict tenant sharing to 'External users must sign in' or more restrictive.",
             "PowerShell": (
                 "# Restrict to authenticated external users only\n"
                 "Set-SPOTenant -SharingCapability ExternalUserSharingOnly\n"
                 "# Or disable external sharing entirely\n"
                 "Set-SPOTenant -SharingCapability Disabled"
             )},
        )]
    return []


def _check_spo_stale_sites(idx: dict) -> list[dict]:
    """Flag SharePoint sites that have not been modified recently (stale content)."""
    sites = idx.get("spo-site-inventory", [])
    stale: list[dict] = []
    for ev in sites:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsStale"):
            stale.append({
                "Type": "SharePointSite",
                "Name": data.get("SiteName", "Unknown"),
                "ResourceId": data.get("SiteId", ""),
                "LastModified": data.get("LastModifiedDateTime", ""),
                "WebUrl": data.get("WebUrl", ""),
            })
    if stale:
        return [_ds_finding(
            "sharepoint_governance", "stale_sites",
            f"{len(stale)} SharePoint sites appear stale (no activity in 180+ days)",
            "Stale sites accumulate outdated content that may contain sensitive data "
            "without active oversight. Unused sites should be archived or deleted to "
            "reduce the data surface area, especially before enabling M365 Copilot.",
            "medium", stale,
            {"Description": "Review stale sites for archival or deletion. "
             "Implement a site lifecycle policy.",
             "PowerShell": (
                 "# Set site to read-only\n"
                 "Set-SPOSite -Identity <SiteUrl> -LockState ReadOnly"
             )},
        )]
    return []


def _check_spo_unlabeled_sites(idx: dict) -> list[dict]:
    """Flag SharePoint sites without sensitivity labels."""
    summary = idx.get("spo-label-summary", [])
    for ev in summary:
        data = ev.get("Data", ev.get("data", {}))
        unlabeled = data.get("UnlabeledSites", 0)
        total = data.get("TotalSites", 0)
        coverage = data.get("LabelCoverage", 0)
        if unlabeled > 0 and coverage < 80:
            return [_ds_finding(
                "sharepoint_governance", "unlabeled_sites",
                f"{unlabeled}/{total} SharePoint sites lack sensitivity labels ({coverage}% coverage)",
                "Sites without sensitivity labels cannot enforce label-based protections "
                "(encryption, access restrictions, DLP). Complete label coverage is a "
                "prerequisite for M365 Copilot data governance.",
                "high" if coverage < 50 else "medium",
                [{"Type": "SPOLabelGap", "Name": "Label Coverage",
                  "ResourceId": "spo-label-summary",
                  "UnlabeledSites": unlabeled, "Coverage": f"{coverage}%"}],
                {"Description": "Apply sensitivity labels to all SharePoint sites. "
                 "Enable mandatory labeling for new sites.",
                 "PowerShell": (
                     "# Apply a sensitivity label to a site\n"
                     "Set-SPOSite -Identity <SiteUrl> -SensitivityLabel <LabelId>"
                 )},
            )]
    return []


def _check_spo_guest_permissions(idx: dict) -> list[dict]:
    """Flag sites with high numbers of external/guest users."""
    perms = idx.get("spo-site-permissions", [])
    guest_heavy: list[dict] = []
    for ev in perms:
        data = ev.get("Data", ev.get("data", {}))
        guest_count = data.get("GuestCount", 0)
        external_count = data.get("ExternalUserCount", 0)
        if guest_count > 5 or external_count > 5:
            guest_heavy.append({
                "Type": "SharePointSite",
                "Name": data.get("SiteName", "Unknown"),
                "ResourceId": data.get("SiteId", ""),
                "GuestCount": guest_count,
                "ExternalUserCount": external_count,
            })
    if guest_heavy:
        return [_ds_finding(
            "sharepoint_governance", "excessive_guest_access",
            f"{len(guest_heavy)} SharePoint sites have significant guest/external user access",
            "Sites with many guest users increase the risk of sensitive data being accessible "
            "to external parties. Guest access should be time-bounded and reviewed regularly.",
            "medium", guest_heavy,
            {"Description": "Review guest access across sites. Implement guest access reviews "
             "using Azure AD Access Reviews. Set expiration policies for guest accounts.",
             "PowerShell": (
                 "# Review external users on a site\n"
                 "Get-SPOExternalUser -SiteUrl <SiteUrl>"
             )},
        )]
    return []


