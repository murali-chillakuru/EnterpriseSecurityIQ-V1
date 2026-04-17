"""Oversharing risk evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


def analyze_oversharing_risk(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess oversharing risks that impact M365 Copilot data exposure."""
    findings: list[dict] = []

    # B1: If no SPO site/permissions evidence, emit an unable-to-assess finding
    has_spo_sites = bool(evidence_index.get("spo-site-inventory"))
    has_spo_perms = bool(evidence_index.get("spo-site-permissions"))
    has_warnings = bool(evidence_index.get("spo-collection-warning"))
    has_scope_warning = bool(evidence_index.get("spo-scope-warning"))

    if not has_spo_sites and not has_spo_perms:
        reason = "SharePoint site data was not collected"
        if has_warnings:
            warns = evidence_index.get("spo-collection-warning", [])
            reasons = [w.get("Data", w.get("data", {})).get("Warning", "") for w in warns]
            reason += f" ({', '.join(r for r in reasons if r)})"
        findings.append(_cr_finding(
            "oversharing_risk", "unable_to_assess",
            "Oversharing risk could not be assessed — no SharePoint data collected",
            f"{reason}. The Azure CLI token does not include Sites.Read.All. "
            "Use a custom app registration with Sites.Read.All granted, "
            "or run with application-level credentials.",
            "high",
            compliance_status="gap",
            remediation={
                "Description": (
                    "The Sites.Read.All OAuth scope is not available in the Azure CLI "
                    "first-party app token. Use a custom app registration or service "
                    "principal with Sites.Read.All granted."
                ),
                "PortalSteps": [
                    "Go to Entra admin center > App registrations > your app > API permissions",
                    "Add Microsoft Graph > Application > Sites.Read.All",
                    "Add SharePoint > Application > Sites.Read.All",
                    "Grant admin consent",
                    "Re-run the Copilot Readiness assessment",
                ],
            },
        ))
        return findings

    # B2: Partial data from fallback — warn about incomplete coverage
    if has_scope_warning:
        scope_warns = evidence_index.get("spo-scope-warning", [])
        site_count = sum(
            int(w.get("Data", w.get("data", {})).get("SitesDiscovered", 0))
            for w in scope_warns
        )
        findings.append(_cr_finding(
            "oversharing_risk", "partial_site_discovery",
            f"SharePoint site discovery is partial — only {site_count} site(s) "
            "found via fallback (Sites.Read.All scope missing)",
            "The Azure CLI token does not include Sites.Read.All. "
            "Only the root site and M365-group-connected sites were discovered. "
            "Standalone sites created outside groups are not included. "
            "Use a custom app registration with Sites.Read.All for full coverage.",
            "medium",
            compliance_status="partial",
            affected_resources=[
                {"Type": "ScopeGap", "Name": "Sites.Read.All", "SitesDiscovered": site_count}
            ],
            remediation={
                "Description": (
                    "Grant Sites.Read.All scope via a custom app registration "
                    "for complete site discovery."
                ),
                "PortalSteps": [
                    "Register a custom app in Entra admin center",
                    "Add Microsoft Graph > Delegated > Sites.Read.All",
                    "Grant admin consent",
                    "Re-run using the custom app credentials",
                ],
            },
        ))

    findings.extend(_check_broad_site_membership(evidence_index))
    findings.extend(_check_everyone_permissions(evidence_index))
    findings.extend(_check_anonymous_link_exposure(evidence_index))
    findings.extend(_check_external_sharing_posture(evidence_index))
    findings.extend(_check_sharepoint_advanced_management(evidence_index))
    findings.extend(_check_sam_restricted_access_control(evidence_index))
    findings.extend(_check_sam_site_lifecycle_policy(evidence_index))
    findings.extend(_check_sam_data_access_governance(evidence_index))
    # Phase 4 enhancements
    findings.extend(_check_permission_blast_radius(evidence_index))
    findings.extend(_check_external_sharing_scorecard(evidence_index))
    return findings


def _check_broad_site_membership(idx: dict) -> list[dict]:
    """Flag sites with very broad membership that Copilot could surface."""
    perms = idx.get("spo-site-permissions", [])
    broad: list[dict] = []
    for ev in perms:
        data = ev.get("Data", ev.get("data", {}))
        total = data.get("TotalPermissions", 0)
        if total > 100:
            broad.append({
                "Type": "SharePointSite",
                "Name": data.get("SiteName", "Unknown"),
                "ResourceId": data.get("SiteId", ""),
                "TotalPermissions": total,
            })
    if broad:
        return [_cr_finding(
            "oversharing_risk", "broad_site_membership",
            f"{len(broad)} sites have 100+ permission entries — high Copilot exposure risk",
            "Sites with very broad membership mean M365 Copilot can surface their content "
            "to a large number of users. Review membership before enabling Copilot.",
            "high", broad,
            {"Description": "Reduce site membership to least-privilege. Remove stale permissions.",
             "PowerShell": "Get-SPOSite -Limit All | ForEach-Object { Get-SPOSiteGroup -Site $_.Url }",
             "PortalSteps": ["Go to SharePoint admin center > Sites > Active sites", "Select the flagged site > Permissions tab", "Review and remove unnecessary members and groups", "Switch to security-group based access"]},
        )]
    return []


def _check_everyone_permissions(idx: dict) -> list[dict]:
    """Flag if 'Everyone' or 'Everyone except external users' groups are used."""
    perms = idx.get("spo-site-permissions", [])
    everyone_sites: list[dict] = []
    for ev in perms:
        data = ev.get("Data", ev.get("data", {}))
        mem_count = data.get("MemberCount", 0)
        total = data.get("TotalPermissions", 0)
        # Heuristic: if member count is very high relative to total, likely 'Everyone' group
        if mem_count > 200:
            everyone_sites.append({
                "Type": "SharePointSite",
                "Name": data.get("SiteName", "Unknown"),
                "ResourceId": data.get("SiteId", ""),
                "MemberCount": mem_count,
            })
    if everyone_sites:
        return [_cr_finding(
            "oversharing_risk", "everyone_permissions",
            f"{len(everyone_sites)} sites may use 'Everyone' groups — Copilot will surface all content",
            "When 'Everyone' or 'Everyone except external users' has access to a site, "
            "M365 Copilot can surface all of that site's content to every user in the org.",
            "critical", everyone_sites,
            {"Description": "Remove 'Everyone' group from site permissions. Use targeted security groups.",
             "PowerShell": "Remove-SPOUser -Site <SiteUrl> -LoginName 'c:0(.s|true'",
             "PortalSteps": ["Go to SharePoint admin center > Sites > Active sites", "Select the flagged site > Permissions tab", "Find 'Everyone' or 'Everyone except external users' group", "Remove the group and replace with targeted security groups"]},
        )]
    return []


def _check_anonymous_link_exposure(idx: dict) -> list[dict]:
    """Assess anonymous link exposure for Copilot context."""
    sharing = idx.get("spo-sharing-links", [])
    total_anon = sum(
        ev.get("Data", ev.get("data", {})).get("AnonymousLinks", 0)
        for ev in sharing
    )
    if total_anon > 0:
        return [_cr_finding(
            "oversharing_risk", "anonymous_link_exposure",
            f"{total_anon} anonymous sharing links create uncontrolled data exposure",
            "Anonymous links bypass all identity checks. While Copilot respects "
            "permissions, anonymous links indicate poor link governance that should "
            "be addressed before Copilot deployment.",
            "high",
            [{"Type": "SharingLinks", "Name": "Anonymous Links", "ResourceId": "org-wide",
              "AnonymousLinkCount": total_anon}],
            {"Description": "Disable anonymous link creation. Convert existing links.",
             "PowerShell": "Set-SPOTenant -SharingCapability ExternalUserSharingOnly",
             "PortalSteps": ["Go to SharePoint admin center > Policies > Sharing", "Set 'External sharing' to 'Existing guests' or lower", "Under 'File and folder links', select 'Specific people'", "Review and remove existing anonymous links"]},
        )]
    return []


def _check_external_sharing_posture(idx: dict) -> list[dict]:
    """Assess tenant-level external sharing configuration for Copilot readiness."""
    config = idx.get("spo-tenant-sharing-config", [])
    for ev in config:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsAnonymousSharingEnabled"):
            return [_cr_finding(
                "oversharing_risk", "external_sharing_posture",
                "Tenant external sharing allows anonymous access — not Copilot ready",
                "The most permissive sharing level is enabled. This must be tightened "
                "before M365 Copilot deployment to prevent unintended data surfacing.",
                "critical",
                [{"Type": "TenantConfig", "Name": "Sharing Policy",
                  "ResourceId": "tenant-spo-config",
                  "SharingCapability": data.get("SharingCapability", "")}],
                {"Description": "Set sharing to 'Existing guests' or 'Only people in organization'.",
             "PowerShell": "Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly",
             "PortalSteps": ["Go to SharePoint admin center > Policies > Sharing", "Set external sharing to 'Existing guests' or 'Only people in your organization'", "Click Save"]},
            )]
    return []


def _check_sharepoint_advanced_management(idx: dict) -> list[dict]:
    """Check if SharePoint Advanced Management (SAM) is available for Data Access Governance."""
    skus = idx.get("m365-subscribed-skus", [])
    if not skus:
        return []  # SKU evidence not available — don't emit false finding

    sam_keywords = ("sharepointdeskless", "sharepoint_advanced_management",
                    "syntex", "sharepoint_premium", "spe_")
    # E5 includes SAM capabilities at no extra cost
    e5_keywords = ("m365_e5", "microsoft_365_e5", "spe_e5", "enterprisepremium")

    has_sam = False
    for ev in skus:
        sku_name = (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
        if any(kw in sku_name for kw in sam_keywords + e5_keywords):
            has_sam = True
            break

    if not has_sam:
        return [_cr_finding(
            "oversharing_risk", "no_sharepoint_advanced_management",
            "SharePoint Advanced Management (SAM) not detected — Data Access Governance reports unavailable",
            "SAM provides Data Access Governance (DAG) reports showing overshared sites, "
            "inactive sites, and sites with sensitive content. Without SAM, you lack "
            "automated oversharing detection critical for Copilot readiness.",
            "medium",
            [{"Type": "License", "Name": "SharePoint Advanced Management",
              "ResourceId": "m365-sam-license"}],
            {"Description": "Enable SharePoint Advanced Management for DAG oversharing reports.",
             "PortalSteps": [
                 "Verify your license includes SAM (M365 E5, SharePoint Premium, or add-on)",
                 "Go to SharePoint admin center > Reports > Data access governance",
                 "If unavailable, purchase SharePoint Advanced Management add-on",
                 "Enable DAG reports for oversharing and inactive site detection",
                 "Review site access review recommendations before Copilot deployment",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_sam_restricted_access_control(idx: dict) -> list[dict]:
    """Check if SAM Restricted Access Control policy is configured for sensitive sites."""
    rac_evidence = idx.get("spo-restricted-access-control", [])
    # Only meaningful if SAM is available
    skus = idx.get("m365-subscribed-skus", [])
    sam_keywords = ("sharepointdeskless", "sharepoint_advanced_management",
                    "syntex", "sharepoint_premium", "spe_",
                    "m365_e5", "microsoft_365_e5", "spe_e5", "enterprisepremium")
    has_sam = any(
        any(kw in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
            for kw in sam_keywords)
        for ev in skus
    )
    if not has_sam:
        return []  # SAM not available — already flagged by _check_sharepoint_advanced_management

    if rac_evidence:
        configured = any(
            ev.get("Data", {}).get("Enabled") or ev.get("Data", {}).get("IsEnabled")
            for ev in rac_evidence
        )
        if configured:
            return []

    return [_cr_finding(
        "oversharing_risk", "no_sam_restricted_access_control",
        "SAM Restricted Access Control not configured — sensitive sites accessible to all Copilot users",
        "SharePoint Advanced Management Restricted Access Control limits site access to "
        "specific security groups. Without it, any licensed user's Copilot can surface "
        "content from sensitive sites if they have default access.",
        "medium",
        [{"Type": "SAMFeature", "Name": "Restricted Access Control",
          "ResourceId": "spo-restricted-access-control"}],
        {"Description": "Configure Restricted Access Control for sensitive SharePoint sites.",
         "PortalSteps": [
             "Go to SharePoint admin center > Sites > Active sites",
             "Select a sensitive site > Settings > Restricted Access Control",
             "Enable and add the security group allowed to access the site",
             "Repeat for each site containing sensitive data",
             "PowerShell: Set-SPOSite -Identity <url> -RestrictedAccessControl $true",
         ]},
        compliance_status="gap",
    )]


def _check_sam_site_lifecycle_policy(idx: dict) -> list[dict]:
    """Check if SAM inactive site policies are configured."""
    lifecycle_evidence = idx.get("spo-site-lifecycle-policy", [])
    skus = idx.get("m365-subscribed-skus", [])
    sam_keywords = ("sharepointdeskless", "sharepoint_advanced_management",
                    "syntex", "sharepoint_premium", "spe_",
                    "m365_e5", "microsoft_365_e5", "spe_e5", "enterprisepremium")
    has_sam = any(
        any(kw in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
            for kw in sam_keywords)
        for ev in skus
    )
    if not has_sam:
        return []

    if lifecycle_evidence:
        configured = any(
            ev.get("Data", {}).get("Enabled") or ev.get("Data", {}).get("IsEnabled")
            for ev in lifecycle_evidence
        )
        if configured:
            return []

    return [_cr_finding(
        "oversharing_risk", "no_sam_site_lifecycle_policy",
        "SAM site lifecycle policy not configured — inactive sites remain indexable by Copilot",
        "SharePoint Advanced Management site lifecycle policies automatically detect "
        "inactive sites and notify owners. Without this, stale sites with outdated or "
        "sensitive content remain accessible to Copilot indefinitely.",
        "low",
        [{"Type": "SAMFeature", "Name": "Site Lifecycle Policy",
          "ResourceId": "spo-site-lifecycle-policy"}],
        {"Description": "Configure SAM site lifecycle policies for inactive site management.",
         "PortalSteps": [
             "Go to SharePoint admin center > Policies > Site lifecycle management",
             "Enable inactive site policy",
             "Set inactivity threshold (e.g., 180 days)",
             "Configure notification to site owners",
             "Set auto-archival action for sites with no owner response",
         ]},
        compliance_status="gap",
    )]


def _check_sam_data_access_governance(idx: dict) -> list[dict]:
    """Check if SAM Data Access Governance reports have been run."""
    dag_evidence = idx.get("spo-data-access-governance", [])
    skus = idx.get("m365-subscribed-skus", [])
    sam_keywords = ("sharepointdeskless", "sharepoint_advanced_management",
                    "syntex", "sharepoint_premium", "spe_",
                    "m365_e5", "microsoft_365_e5", "spe_e5", "enterprisepremium")
    has_sam = any(
        any(kw in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
            for kw in sam_keywords)
        for ev in skus
    )
    if not has_sam:
        return []

    if dag_evidence:
        has_reports = any(
            ev.get("Data", {}).get("ReportCount", 0) > 0 or ev.get("Data", {}).get("HasReports")
            for ev in dag_evidence
        )
        if has_reports:
            return []

    return [_cr_finding(
        "oversharing_risk", "no_sam_dag_reports",
        "SAM Data Access Governance reports not available — oversharing sites not identified",
        "Data Access Governance (DAG) reports in SharePoint Advanced Management identify "
        "sites with overshared content, sites shared with 'Everyone', and sites with "
        "sensitive information. These reports are essential for targeted Copilot "
        "readiness remediation.",
        "medium",
        [{"Type": "SAMFeature", "Name": "Data Access Governance",
          "ResourceId": "spo-data-access-governance"}],
        {"Description": "Generate Data Access Governance reports in SharePoint admin center.",
         "PortalSteps": [
             "Go to SharePoint admin center > Reports > Data access governance",
             "Review 'Oversharing' report for sites shared with large audiences",
             "Review 'Sensitive content' report for sites with sensitive info types",
             "Review 'Everyone links' report for sites with org-wide sharing links",
             "Use the findings to prioritize permission remediation before Copilot",
         ]},
        compliance_status="gap",
    )]


# ── Phase 4: Over-Permission & External Sharing Enhancements ───────

def _check_permission_blast_radius(idx: dict) -> list[dict]:
    """Score sites by permission blast radius — how many users Copilot could surface content to."""
    perms = idx.get("spo-site-permissions", [])
    sites = idx.get("spo-site-inventory", [])
    if not perms or not sites:
        return []
    # Build a risk-scored list of sites
    high_blast: list[dict] = []
    for ev in perms:
        data = ev.get("Data", ev.get("data", {}))
        total_perms = data.get("TotalPermissions", 0)
        member_count = data.get("MemberCount", 0)
        guest_count = data.get("GuestCount", 0)
        external_count = data.get("ExternalUserCount", 0)
        # Blast radius score: weighted sum of permission breadth indicators
        score = (total_perms * 1.0) + (member_count * 2.0) + (guest_count * 5.0) + (external_count * 5.0)
        if score > 500:
            high_blast.append({
                "Type": "SharePointSite",
                "Name": data.get("SiteName", "Unknown"),
                "ResourceId": data.get("SiteId", ""),
                "BlastRadiusScore": round(score, 1),
                "TotalPermissions": total_perms,
                "MemberCount": member_count,
                "GuestCount": guest_count,
                "ExternalUserCount": external_count,
            })
    high_blast.sort(key=lambda x: x["BlastRadiusScore"], reverse=True)
    if high_blast:
        return [_cr_finding(
            "oversharing_risk", "high_permission_blast_radius",
            f"{len(high_blast)} sites have high permission blast radius — Copilot data exposure hotspots",
            "These sites combine broad membership, guest access, and external sharing, "
            "creating a high blast radius if Copilot surfaces their content. Prioritize "
            "permission remediation on these sites first.",
            "high" if len(high_blast) > 5 else "medium",
            high_blast[:20],
            {"Description": "Remediate permissions on high blast-radius sites first.",
             "PortalSteps": [
                 "Focus remediation on the top-scored sites",
                 "Remove guest and external access where not required",
                 "Reduce membership to targeted security groups",
                 "Apply SAM Restricted Access Control for the most sensitive sites",
                 "Re-run assessment to verify blast radius reduction",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_external_sharing_scorecard(idx: dict) -> list[dict]:
    """Composite external sharing abuse scorecard."""
    sharing = idx.get("spo-sharing-links", [])
    config = idx.get("spo-tenant-sharing-config", [])
    if not sharing and not config:
        return []
    total_anon = 0
    total_org = 0
    total_external = 0
    total_shared_items = 0
    for ev in sharing:
        data = ev.get("Data", ev.get("data", {}))
        total_anon += data.get("AnonymousLinks", 0)
        total_org += data.get("OrganizationLinks", 0)
        total_external += data.get("ExternalLinks", 0)
        total_shared_items += data.get("TotalSharedItems", 0)

    # Composite risk score
    risk_score = (total_anon * 10) + (total_external * 5) + (total_org * 1)
    if risk_score == 0:
        return []

    severity = "critical" if risk_score > 500 else "high" if risk_score > 100 else "medium"
    return [_cr_finding(
        "oversharing_risk", "external_sharing_risk_score",
        f"External sharing risk score: {risk_score} — "
        f"{total_anon} anonymous, {total_external} external, {total_org} org-wide links",
        "This composite score reflects the overall external sharing exposure. "
        "Anonymous links carry the highest risk (bypass identity), followed by "
        "external guest links, and organization-wide links. All contribute to "
        "Copilot's data surface area.",
        severity,
        [{"Type": "SharingRisk", "Name": "External Sharing Scorecard",
          "ResourceId": "spo-external-sharing-scorecard",
          "RiskScore": risk_score,
          "AnonymousLinks": total_anon,
          "ExternalLinks": total_external,
          "OrganizationLinks": total_org,
          "TotalSharedItems": total_shared_items}],
        {"Description": "Reduce external sharing links. Prioritize anonymous link elimination.",
         "PortalSteps": [
             "Eliminate anonymous links: Set-SPOTenant -SharingCapability ExternalUserSharingOnly",
             "Review and remove external guest links on sensitive sites",
             "Convert org-wide links to specific-people links where possible",
             "Enable link expiration policies",
             "Monitor sharing activity via SharePoint admin center reports",
         ]},
        compliance_status="gap",
    )]

