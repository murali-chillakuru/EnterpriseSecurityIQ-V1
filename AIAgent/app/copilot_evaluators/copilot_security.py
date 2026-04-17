"""Copilot-specific security evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


def analyze_copilot_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Copilot-specific security controls."""
    findings: list[dict] = []
    findings.extend(_check_copilot_plugins(evidence_index))
    findings.extend(_check_data_residency(evidence_index))
    findings.extend(_check_ediscovery_readiness(evidence_index))
    findings.extend(_check_insider_risk(evidence_index))
    findings.extend(_check_communication_compliance(evidence_index))
    findings.extend(_check_dspm_for_ai(evidence_index))
    # Phase 2/3 enhancements
    findings.extend(_check_copilot_agent_inventory(evidence_index))
    findings.extend(_check_agent_permission_boundary(evidence_index))
    findings.extend(_check_regulatory_mapping(evidence_index))
    findings.extend(_check_data_residency_deep(evidence_index))
    findings.extend(_check_rai_policy(evidence_index))
    # Phase 6: Checklist gap closure
    findings.extend(_check_cross_tenant_access(evidence_index))
    findings.extend(_check_agent_approval_workflow(evidence_index))
    findings.extend(_check_external_connector_governance(evidence_index))
    findings.extend(_check_prompt_guardrails(evidence_index))
    return findings


def _check_copilot_plugins(idx: dict) -> list[dict]:
    """Check if Copilot plugin/connector restrictions are configured."""
    settings = idx.get("m365-copilot-settings", [])
    warnings = idx.get("m365-copilot-settings-warning", [])

    # If we couldn't read settings at all, emit a finding
    if not settings and not warnings:
        return [_cr_finding(
            "copilot_security", "copilot_plugins_unrestricted",
            "Copilot plugin and connector restrictions could not be verified",
            "Unable to determine whether Copilot plugins and third-party connectors "
            "are restricted. Uncontrolled plugins can exfiltrate sensitive data "
            "surfaced by Copilot to external services.",
            "medium",
            [{"Type": "CopilotPlugins", "Name": "Plugin Restrictions",
              "ResourceId": "m365-copilot-plugins"}],
            {"Description": "Review and restrict Copilot plugins in M365 admin center.",
             "PortalSteps": [
                 "Go to Microsoft 365 admin center > Settings > Copilot",
                 "Review 'Plugins and connectors' settings",
                 "Disable third-party plugins that are not approved",
                 "Enable only vetted connectors for your organization",
             ]},
            compliance_status="gap",
        )]

    if warnings:
        return [_cr_finding(
            "copilot_security", "copilot_plugins_unrestricted",
            "Copilot settings inaccessible — plugin restrictions cannot be verified",
            "The assessment could not access Copilot admin settings due to "
            "insufficient Graph API scopes (OrgSettings.Read.All required). "
            "Verify plugin restrictions manually.",
            "informational",
            [{"Type": "CopilotPlugins", "Name": "Plugin Restrictions",
              "ResourceId": "m365-copilot-plugins",
              "RequiredScope": "OrgSettings.Read.All"}],
            {"Description": "Verify plugin restrictions manually in M365 admin center.",
             "PortalSteps": [
                 "Go to Microsoft 365 admin center > Settings > Copilot",
                 "Review 'Plugins and connectors' settings",
                 "Disable unapproved plugins and connectors",
             ]},
            compliance_status="partial",
        )]
    return []


def _check_data_residency(idx: dict) -> list[dict]:
    """Check organization data residency configuration."""
    org = idx.get("m365-organization-info", [])
    if not org:
        return [_cr_finding(
            "copilot_security", "data_residency_unverified",
            "Data residency configuration could not be verified for Copilot compliance",
            "Copilot processes data in Microsoft data centers. Verify that your "
            "organization's data residency settings align with regulatory requirements "
            "for where Copilot can process and store interaction data.",
            "informational",
            [{"Type": "DataResidency", "Name": "Org Data Location",
              "ResourceId": "m365-organization-info"}],
            {"Description": "Verify data residency in M365 admin center and Microsoft Trust Center.",
             "PortalSteps": [
                 "Go to Microsoft 365 admin center > Settings > Org settings > Organization profile",
                 "Check 'Data location' for your tenant",
                 "Review Microsoft Trust Center for Copilot data processing locations",
                 "If Multi-Geo is enabled, verify Copilot respects geo boundaries",
             ]},
            compliance_status="partial",
        )]

    data = org[0].get("Data", org[0].get("data", {}))
    location = data.get("PreferredDataLocation", "")
    country = data.get("CountryLetterCode", "")
    if location or country:
        return []  # Data residency is configured — PASS
    return [_cr_finding(
        "copilot_security", "data_residency_unverified",
        "Organization data residency location is not explicitly configured",
        "No preferred data location is set for the organization. "
        "Ensure Copilot data processing meets your regulatory requirements.",
        "informational",
        [{"Type": "DataResidency", "Name": "Org Data Location",
          "ResourceId": "m365-organization-info",
          "CountryLetterCode": country,
          "PreferredDataLocation": location}],
        {"Description": "Review and configure data residency settings.",
         "PortalSteps": [
             "Go to Microsoft 365 admin center > Settings > Org settings > Organization profile",
             "Verify 'Data location' settings",
         ]},
        compliance_status="partial",
    )]


def _check_ediscovery_readiness(idx: dict) -> list[dict]:
    """Check if eDiscovery is configured to search Copilot interactions."""
    cases = idx.get("m365-ediscovery-cases", [])
    if not cases:
        return [_cr_finding(
            "copilot_security", "no_ediscovery_configured",
            "No eDiscovery cases detected — Copilot interactions may not be discoverable",
            "eDiscovery enables legal and compliance teams to search, hold, and export "
            "Copilot interaction data for investigations and litigation. Without active "
            "eDiscovery configuration, this data may not be readily accessible.",
            "medium",
            [{"Type": "eDiscovery", "Name": "eDiscovery Cases",
              "ResourceId": "m365-ediscovery-cases"}],
            {"Description": "Configure eDiscovery to include Copilot interaction data.",
             "PortalSteps": [
                 "Go to Microsoft Purview compliance portal > eDiscovery > Standard/Premium",
                 "Verify your organization has eDiscovery licenses (E5 or E5 Compliance)",
                 "Create a test case to verify Copilot data is searchable",
                 "Search for 'CopilotInteraction' content types",
                 "Ensure legal hold policies cover Copilot data locations",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_insider_risk(idx: dict) -> list[dict]:
    """Check if Insider Risk Management covers Copilot usage patterns."""
    irm = idx.get("m365-insider-risk-policies", [])
    if not irm:
        return [_cr_finding(
            "copilot_security", "no_insider_risk_policies",
            "No Insider Risk Management policies detected for Copilot activity monitoring",
            "Insider Risk Management detects anomalous user behaviors including "
            "excessive Copilot usage, bulk data extraction via Copilot summaries, "
            "and potential data exfiltration patterns.",
            "medium",
            [{"Type": "InsiderRisk", "Name": "IRM Policies",
              "ResourceId": "m365-insider-risk-policies"}],
            {"Description": "Configure Insider Risk Management for Copilot activity.",
             "PortalSteps": [
                 "Go to Microsoft Purview compliance portal > Insider risk management",
                 "Create a policy using 'Data leaks' or 'Security policy violations' template",
                 "Include Copilot interaction signals as indicators",
                 "Configure alert thresholds and notification rules",
                 "Note: Requires Microsoft 365 E5 Insider Risk Management add-on",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_communication_compliance(idx: dict) -> list[dict]:
    """Check if Communication Compliance policies cover Copilot-generated content."""
    cc = idx.get("m365-communication-compliance", [])
    if not cc:
        return [_cr_finding(
            "copilot_security", "no_communication_compliance",
            "No Communication Compliance policies detected for Copilot-generated content",
            "Communication Compliance scans messages and Copilot-generated content for "
            "inappropriate language, regulatory violations, and sensitive information. "
            "Without it, non-compliant content generated by Copilot goes undetected.",
            "medium",
            [{"Type": "CommunicationCompliance", "Name": "CC Policies",
              "ResourceId": "m365-communication-compliance"}],
            {"Description": "Configure Communication Compliance policies for Copilot content.",
             "PortalSteps": [
                 "Go to Microsoft Purview compliance portal > Communication compliance",
                 "Click 'Create policy'",
                 "Select 'Detect inappropriate content' or a custom template",
                 "Include M365 Copilot interactions in the policy scope",
                 "Configure reviewers and escalation workflows",
                 "Note: Requires Microsoft 365 E5 Compliance or Communication Compliance add-on",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_dspm_for_ai(idx: dict) -> list[dict]:
    """Check if Data Security Posture Management (DSPM) for AI is configured."""
    findings: list[dict] = []

    # DSPM for AI is surfaced through Purview — check for the feature via
    # insider-risk or DSPM-specific evidence keys.
    dspm_evidence = idx.get("m365-dspm-for-ai", [])
    irm = idx.get("m365-insider-risk-policies", [])

    # Check if DSPM for AI is enabled (dedicated evidence key)
    if dspm_evidence:
        # Evidence exists — check if it's actually configured
        configured = any(
            (ev.get("Data", {}).get("Enabled") or ev.get("Data", {}).get("Status", "").lower() == "enabled")
            for ev in dspm_evidence
        )
        if configured:
            return []  # DSPM for AI is enabled — PASS

    # No DSPM evidence → emit finding
    findings.append(_cr_finding(
        "copilot_security", "no_dspm_for_ai",
        "Data Security Posture Management (DSPM) for AI is not configured",
        "DSPM for AI in Microsoft Purview provides visibility into sensitive data "
        "risks specific to AI usage. It detects oversharing patterns, sensitive data "
        "in AI-accessible locations, and user interactions with Copilot that involve "
        "sensitive content. Without DSPM for AI, you lack proactive monitoring of "
        "AI-related data security risks.",
        "medium",
        [{"Type": "DSPM", "Name": "DSPM for AI",
          "ResourceId": "purview-dspm-for-ai"}],
        {"Description": "Enable DSPM for AI in Microsoft Purview to monitor AI data security risks.",
         "PortalSteps": [
             "Go to Microsoft Purview portal > Data Security Posture Management",
             "Select 'DSPM for AI' or navigate to Data security > AI security",
             "Enable the DSPM for AI feature",
             "Review the 'Oversharing' and 'Sensitive data in AI' reports",
             "Configure policies for sensitive data detection in Copilot interactions",
             "Note: Requires Microsoft 365 E5 or E5 Compliance license",
         ]},
        compliance_status="gap",
    ))

    # Additional check: DSPM oversharing assessment
    # If SAM is available, DSPM leverages it for oversharing detection
    skus = idx.get("m365-subscribed-skus", [])
    has_e5 = any(
        any(kw in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
            for kw in ("m365_e5", "microsoft_365_e5", "spe_e5", "enterprisepremium"))
        for ev in skus
    )
    if has_e5 and not dspm_evidence:
        findings.append(_cr_finding(
            "copilot_security", "dspm_oversharing_not_reviewed",
            "DSPM oversharing assessment not run — E5 license available but DSPM unused",
            "Your tenant has E5 licensing which includes DSPM for AI capabilities. "
            "The DSPM oversharing assessment identifies SharePoint sites, OneDrive accounts, "
            "and Teams with sensitive content accessible to Copilot. Running this assessment "
            "provides targeted remediation recommendations.",
            "low",
            [{"Type": "DSPM", "Name": "DSPM Oversharing Assessment",
              "ResourceId": "purview-dspm-oversharing"}],
            {"Description": "Run the DSPM oversharing assessment in Purview.",
             "PortalSteps": [
                 "Go to Microsoft Purview portal > DSPM for AI > Oversharing assessment",
                 "Select 'New assessment' to scan for overshared content",
                 "Review identified sites and remediate access issues",
                 "Set up recurring assessments before Copilot rollout",
             ]},
            compliance_status="partial",
        ))

    return findings


# ── Phase 2/3: Copilot Security Enhancements ───────────────────────

def _check_copilot_agent_inventory(idx: dict) -> list[dict]:
    """Check if Copilot Studio agents/bots are inventoried."""
    agents = idx.get("copilot-studio-bots", [])
    if not agents:
        return []  # No agents found or collector didn't run — no finding needed

    unmanaged: list[dict] = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        owner = data.get("Owner", "")
        published = data.get("IsPublished", False)
        if published and not owner:
            unmanaged.append({
                "Type": "CopilotAgent",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
                "IsPublished": published,
            })
    if unmanaged:
        return [_cr_finding(
            "copilot_security", "unmanaged_copilot_agents",
            f"{len(unmanaged)} published Copilot Studio agents have no identified owner",
            "Published agents without owners may have been created during pilots or by "
            "departed employees. These agents can access organizational data via Copilot "
            "connectors with no accountability for their configuration.",
            "medium",
            unmanaged[:20],
            {"Description": "Assign owners to all published Copilot Studio agents.",
             "PortalSteps": [
                 "Go to Copilot Studio > Agents",
                 "Identify agents without assigned owners",
                 "Assign owners from the security or governance team",
                 "Unpublish agents that are no longer needed",
                 "Add agent creation governance via Power Platform admin controls",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_agent_permission_boundary(idx: dict) -> list[dict]:
    """Check if Copilot agents have bounded API permissions."""
    agents = idx.get("copilot-studio-bots", [])
    apps = idx.get("entra-applications", [])
    if not agents or not apps:
        return []
    # Build a map of app registrations by appId
    app_map: dict[str, dict] = {}
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        app_id = data.get("AppId", "")
        if app_id:
            app_map[app_id] = data

    over_permissioned: list[dict] = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        bot_app_id = data.get("AppId", "")
        if bot_app_id and bot_app_id in app_map:
            app_data = app_map[bot_app_id]
            app_perms = app_data.get("ApplicationPermissions", 0)
            if app_perms > 5:
                over_permissioned.append({
                    "Type": "CopilotAgent",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("BotId", ""),
                    "AppId": bot_app_id,
                    "ApplicationPermissions": app_perms,
                })
    if over_permissioned:
        return [_cr_finding(
            "copilot_security", "agent_over_permissioned",
            f"{len(over_permissioned)} Copilot agents have excessive API permissions (>5 application roles)",
            "Copilot agents with broad application permissions can access data beyond "
            "their intended scope. Each agent should follow least-privilege principles "
            "with only the specific Graph permissions needed for its function.",
            "high",
            over_permissioned[:15],
            {"Description": "Reduce agent API permissions to the minimum required.",
             "PortalSteps": [
                 "Go to Entra admin center > App registrations",
                 "Find the app registration for each flagged agent",
                 "Review API permissions and remove unnecessary ones",
                 "Switch from application permissions to delegated where possible",
                 "Re-consent with reduced permissions",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_regulatory_mapping(idx: dict) -> list[dict]:
    """Check if Copilot controls are mapped to regulatory frameworks."""
    regulatory = idx.get("m365-compliance-manager-assessments", [])
    if not regulatory:
        return [_cr_finding(
            "copilot_security", "no_regulatory_framework_mapping",
            "No Compliance Manager assessments detected — Copilot controls not mapped to regulatory frameworks",
            "Mapping Copilot security controls to regulatory frameworks (ISO 27001, SOC 2, "
            "GDPR, HIPAA, PCI-DSS) provides auditable evidence of compliance. Without this "
            "mapping, demonstrating regulatory compliance for AI deployments is manual.",
            "low",
            [{"Type": "ComplianceManager", "Name": "Regulatory Mapping",
              "ResourceId": "m365-compliance-manager"}],
            {"Description": "Create Compliance Manager assessments for Copilot.",
             "PortalSteps": [
                 "Go to Microsoft Purview > Compliance Manager > Assessments",
                 "Click '+ Add assessment'",
                 "Select relevant templates (ISO 27001, SOC 2, GDPR, etc.)",
                 "Map Copilot security controls to assessment actions",
                 "Track improvement score and evidence collection",
             ]},
            compliance_status="partial",
        )]
    return []


def _check_data_residency_deep(idx: dict) -> list[dict]:
    """Deep check on data residency — multi-geo and preferred data location."""
    org = idx.get("m365-organization-info", [])
    if not org:
        return []  # _check_data_residency already handles missing org info
    data = org[0].get("Data", org[0].get("data", {}))
    tenant_type = data.get("TenantType", "")
    pref_loc = data.get("PreferredDataLocation", "")
    country = data.get("CountryLetterCode", "")

    # Flag multi-geo concerns
    multi_geo = idx.get("m365-multi-geo-config", [])
    if multi_geo:
        locations = [ev.get("Data", {}).get("Location", "") for ev in multi_geo]
        unique_locs = list(set(loc for loc in locations if loc))
        if len(unique_locs) > 1:
            return [_cr_finding(
                "copilot_security", "multi_geo_copilot_residency",
                f"Multi-Geo detected with {len(unique_locs)} data locations — "
                "verify Copilot respects geo boundaries",
                "Multi-Geo deployments store data in different regions. Verify that Copilot "
                "processes and stores interaction data in the user's assigned geo-location "
                "and does not cross geo boundaries during semantic index operations.",
                "medium",
                [{"Type": "DataResidency", "Name": "Multi-Geo Configuration",
                  "ResourceId": "m365-multi-geo",
                  "Locations": unique_locs,
                  "Country": country}],
                {"Description": "Verify Copilot compliance with Multi-Geo data residency.",
                 "PortalSteps": [
                     "Go to Microsoft 365 admin center > Settings > Org settings > Organization profile",
                     "Review Multi-Geo configuration",
                     "Verify each user's Preferred Data Location matches their regulatory requirements",
                     "Check Microsoft's Copilot data processing documentation for geo compliance",
                 ]},
                compliance_status="partial",
            )]
    return []


def _check_rai_policy(idx: dict) -> list[dict]:
    """Check if Responsible AI policies are in place for Copilot usage."""
    rai = idx.get("m365-rai-policies", [])
    # Look for labels that indicate RAI governance
    labels = idx.get("m365-sensitivity-label-definition", [])
    rai_labels = [
        ev for ev in labels
        if any(kw in (ev.get("Data", {}).get("Name", "") or "").lower()
               for kw in ("responsible ai", "rai", "ai ethics", "ai governance"))
    ]
    if not rai and not rai_labels:
        return [_cr_finding(
            "copilot_security", "no_rai_policy",
            "No Responsible AI (RAI) policies detected for Copilot governance",
            "Responsible AI policies establish guardrails for how Copilot should be used — "
            "including prohibited use cases, content generation boundaries, and ethical "
            "use guidelines. Without RAI policies, users lack governance guidance.",
            "low",
            [{"Type": "RAIPolicy", "Name": "Responsible AI Policies",
              "ResourceId": "m365-rai-policies"}],
            {"Description": "Establish Responsible AI policies for Copilot usage.",
             "PortalSteps": [
                 "Create an RAI policy document covering Copilot acceptable use",
                 "Define prohibited Copilot use cases (e.g., automated decision-making without human review)",
                 "Create sensitivity labels for AI-generated content (e.g., 'AI Generated — Review Required')",
                 "Publish guidelines via SharePoint and reference in user training",
                 "Consider using Microsoft Purview Communication Compliance for RAI monitoring",
             ]},
            compliance_status="partial",
        )]
    return []


# ── Phase 6: Checklist Gap Closure ──────────────────────────────────

def _check_cross_tenant_access(idx: dict) -> list[dict]:
    """Check if cross-tenant access policies restrict B2B collaboration for Copilot."""
    cta = idx.get("entra-cross-tenant-access", [])
    if not cta:
        return [_cr_finding(
            "copilot_security", "cross_tenant_access_not_assessed",
            "Cross-tenant access policies could not be assessed",
            "Cross-tenant access settings control B2B collaboration boundaries. "
            "Without properly configured inbound/outbound policies, Copilot may "
            "surface content shared from or to external tenants without adequate "
            "governance controls.",
            "medium",
            [{"Type": "CrossTenantAccess", "Name": "Cross-Tenant Access Policy",
              "ResourceId": "entra-cross-tenant-access"}],
            {"Description": "Configure cross-tenant access policies in Microsoft Entra.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > External Identities > Cross-tenant access settings",
                 "Review default inbound and outbound access settings",
                 "Restrict B2B collaboration to approved partner tenants only",
                 "Block B2B direct-connect for unapproved tenants",
                 "Review tenant restrictions v2 for Copilot data boundary enforcement",
             ]},
            compliance_status="gap",
        )]
    # Check if default policy is overly permissive
    default_pol = [ev for ev in cta
                   if (ev.get("Data", {}).get("IsDefault", False))]
    if default_pol:
        data = default_pol[0].get("Data", {})
        inbound = data.get("InboundAllowed", True)
        outbound = data.get("OutboundAllowed", True)
        if inbound and outbound:
            return [_cr_finding(
                "copilot_security", "cross_tenant_access_permissive",
                "Default cross-tenant access policy allows unrestricted B2B collaboration",
                "The default cross-tenant access policy allows both inbound and outbound "
                "B2B collaboration with all external tenants. This means Copilot may index "
                "and surface content shared from any external organization.",
                "medium",
                [{"Type": "CrossTenantAccess", "Name": "Default CTA Policy",
                  "ResourceId": data.get("PolicyId", "default"),
                  "InboundAllowed": inbound, "OutboundAllowed": outbound}],
                {"Description": "Restrict default cross-tenant access to block-by-default.",
                 "PortalSteps": [
                     "Go to Microsoft Entra admin center > External Identities > Cross-tenant access settings",
                     "Set default inbound access to 'Block'",
                     "Add organizational settings for approved partner tenants only",
                     "Ensure outbound access is scoped to specific users/groups",
                 ]},
                compliance_status="gap",
            )]
    return []


def _check_hybrid_identity_accounts(idx: dict) -> list[dict]:
    """Detect non-cloud (on-premises-only) accounts lacking Entra ID sync."""
    users = idx.get("entra-user-details", [])
    if not users:
        return []
    onprem_only: list[dict] = []
    for ev in users:
        data = ev.get("Data", ev.get("data", {}))
        on_prem_sync = data.get("OnPremisesSyncEnabled", False)
        on_prem_dn = data.get("OnPremisesDistinguishedName", "")
        cloud_sync = data.get("OnPremisesLastSyncDateTime", "")
        upn = data.get("UserPrincipalName", "")
        enabled = data.get("AccountEnabled", True)
        if not enabled:
            continue
        # Flag accounts that are synced from on-prem but have stale sync
        if on_prem_sync and not cloud_sync:
            onprem_only.append({
                "Type": "UserAccount", "Name": upn,
                "ResourceId": data.get("UserId", ""),
                "OnPremSync": on_prem_sync, "LastSync": cloud_sync,
            })
    if onprem_only:
        return [_cr_finding(
            "access_governance", "hybrid_accounts_stale_sync",
            f"{len(onprem_only)} hybrid accounts have stale or missing Entra ID sync",
            "Accounts synced from on-premises Active Directory that have not completed "
            "a recent sync cycle may have outdated permissions in Entra ID. Copilot "
            "relies on Entra ID permissions — stale sync means Copilot may use outdated access.",
            "medium",
            onprem_only[:20],
            {"Description": "Ensure all hybrid accounts have active Entra Connect sync.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Entra Connect > Sync status",
                 "Verify Entra Connect Health is reporting healthy sync cycles",
                 "Investigate accounts showing stale or missing sync timestamps",
                 "Consider cloud-only accounts for new Copilot-licensed users",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_copilot_license_segmentation(idx: dict) -> list[dict]:
    """Check if Copilot licenses are segmented into pilot vs production groups."""
    skus = idx.get("m365-subscribed-skus", [])
    copilot_skus = [
        ev for ev in skus
        if "copilot" in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower()
    ]
    if not copilot_skus:
        return []  # No Copilot licenses — other checks handle this
    # Check group-based license assignments for segmentation
    groups = idx.get("m365-groups", [])
    copilot_groups = [
        ev for ev in groups
        if any(kw in (ev.get("Data", {}).get("DisplayName", "") or "").lower()
               for kw in ("copilot", "pilot", "early adopter", "wave", "ring"))
    ]
    if len(copilot_groups) < 2:
        return [_cr_finding(
            "access_governance", "no_copilot_license_segmentation",
            "Copilot license assignment lacks pilot/production group segmentation",
            "Best practice is to segment Copilot license assignment into separate "
            "groups (e.g., 'Copilot-Pilot', 'Copilot-Production') for phased rollout. "
            "Without segmentation, all licensed users get Copilot simultaneously, "
            "increasing risk of data exposure before governance controls are validated.",
            "low",
            [{"Type": "LicenseSegmentation", "Name": "Copilot License Groups",
              "ResourceId": "m365-copilot-license-groups",
              "CopilotGroupsFound": len(copilot_groups)}],
            {"Description": "Create separate groups for phased Copilot deployment.",
             "PortalSteps": [
                 "Create Entra security groups: 'Copilot-Pilot' and 'Copilot-Production'",
                 "Assign Copilot licenses via group-based licensing to the Pilot group first",
                 "Validate data governance controls with Pilot users",
                 "Expand to Production group after pilot validation period",
             ]},
            compliance_status="partial",
        )]
    return []


def _check_agent_approval_workflow(idx: dict) -> list[dict]:
    """Check if Copilot agent creation requires admin approval."""
    settings = idx.get("m365-copilot-settings", [])
    if not settings:
        return []  # Copilot settings not accessible — other checks handle this
    for ev in settings:
        data = ev.get("Data", ev.get("data", {}))
        # Check if plugin/agent deployment requires admin approval
        agent_approval = data.get("AgentApprovalRequired", None)
        user_agents = data.get("AllowUsersToCreateAgents", None)
        if user_agents is True and agent_approval is not True:
            return [_cr_finding(
                "copilot_security", "no_agent_approval_workflow",
                "Copilot agent creation does not require admin approval",
                "Users can create and publish Copilot agents without an admin approval "
                "workflow. Without approval gates, agents may be created with excessive "
                "permissions, access sensitive data sources, or violate organizational "
                "data boundaries.",
                "medium",
                [{"Type": "AgentGovernance", "Name": "Agent Approval Settings",
                  "ResourceId": "m365-copilot-agent-approval",
                  "AllowUserAgents": user_agents,
                  "ApprovalRequired": agent_approval}],
                {"Description": "Enable admin approval for Copilot agent creation.",
                 "PortalSteps": [
                     "Go to Microsoft 365 admin center > Settings > Copilot",
                     "Enable 'Require admin approval for agent publishing'",
                     "Define an agent approval workflow via Power Automate or Teams Admin Center",
                     "Assign agent reviewers from the security or governance team",
                     "Document approved data sources and connector policies for agents",
                 ]},
                compliance_status="gap",
            )]
    return []


def _check_external_connector_governance(idx: dict) -> list[dict]:
    """Check if Graph connectors and external data connections are governed."""
    connectors = idx.get("m365-graph-connectors", [])
    apps = idx.get("entra-applications", [])
    # Count apps with broad Graph application permissions (potential connector abuse)
    high_perm_apps = [
        ev for ev in apps
        if (ev.get("Data", {}).get("ApplicationPermissions", 0) or 0) > 5
    ]
    if connectors:
        ungoverned = [
            ev for ev in connectors
            if not ev.get("Data", {}).get("HasOwner", False)
        ]
        if ungoverned:
            return [_cr_finding(
                "copilot_security", "ungoverned_external_connectors",
                f"{len(ungoverned)} Graph connectors lack ownership or governance review",
                "Microsoft Graph connectors bring external data into the M365 search index "
                "and Copilot. Connectors without assigned owners or governance review may "
                "expose sensitive external data to Copilot without appropriate access controls.",
                "medium",
                [{"Type": "GraphConnector", "Name": ev.get("Data", {}).get("Name", "Unknown"),
                  "ResourceId": ev.get("Data", {}).get("ConnectorId", "")}
                 for ev in ungoverned[:10]],
                {"Description": "Review and assign owners to all Graph connectors.",
                 "PortalSteps": [
                     "Go to Microsoft 365 admin center > Settings > Search & intelligence > Data sources",
                     "Review all configured Graph connectors",
                     "Assign an owner and data classification to each connector",
                     "Remove connectors that are no longer needed",
                     "Document data sensitivity classification for each connector's content",
                 ]},
                compliance_status="gap",
            )]
    elif high_perm_apps:
        return [_cr_finding(
            "copilot_security", "external_connector_review_needed",
            f"{len(high_perm_apps)} apps have elevated Graph permissions — "
            "review for external connector usage",
            "Applications with more than 5 Graph application permissions may be acting as "
            "data connectors or indexing agents. These should be reviewed to ensure they "
            "are not feeding uncontrolled data into the Copilot search index.",
            "low",
            [{"Type": "EntraApp", "Name": ev.get("Data", {}).get("DisplayName", ""),
              "ResourceId": ev.get("Data", {}).get("AppId", ""),
              "ApplicationPermissions": ev.get("Data", {}).get("ApplicationPermissions", 0)}
             for ev in high_perm_apps[:10]],
            {"Description": "Review high-permission apps for connector or indexing activity.",
             "PortalSteps": [
                 "Go to Entra admin center > Applications > App registrations",
                 "Filter apps with >5 application permissions",
                 "Verify each app's purpose and whether it feeds data to M365 search",
                 "Apply least-privilege principles — remove unnecessary permissions",
             ]},
            compliance_status="partial",
        )]
    return []


def _check_defender_copilot_incidents(idx: dict) -> list[dict]:
    """Check if Defender has detected Copilot-related security incidents."""
    incidents = idx.get("m365-defender-copilot-incidents", [])
    alerts = idx.get("m365-alert-policies", [])
    if not incidents and not alerts:
        return []  # No security data available — other checks handle monitoring
    if incidents:
        high_sev = [
            ev for ev in incidents
            if (ev.get("Data", {}).get("Severity", "") or "").lower() in ("high", "critical")
        ]
        if high_sev:
            return [_cr_finding(
                "audit_monitoring", "copilot_security_incidents_detected",
                f"{len(high_sev)} high/critical Copilot-related security incidents detected",
                "Microsoft Defender has flagged security incidents related to Copilot usage. "
                "These may include data exfiltration attempts, prompt injection attacks, or "
                "anomalous Copilot access patterns that require immediate investigation.",
                "high",
                [{"Type": "SecurityIncident",
                  "Name": ev.get("Data", {}).get("Title", "Unknown"),
                  "ResourceId": ev.get("Data", {}).get("IncidentId", ""),
                  "Severity": ev.get("Data", {}).get("Severity", "")}
                 for ev in high_sev[:10]],
                {"Description": "Investigate and remediate Copilot security incidents.",
                 "PortalSteps": [
                     "Go to Microsoft Defender portal > Incidents & alerts",
                     "Filter for Copilot-related incidents",
                     "Investigate each high/critical incident",
                     "Execute incident response playbook",
                     "Review affected users' Copilot access and permissions",
                 ]},
                compliance_status="gap",
            )]
    # Informational: no incidents detected = good
    return []


def _check_prompt_guardrails(idx: dict) -> list[dict]:
    """Check if Copilot admin has configured prompt guardrail restrictions."""
    settings = idx.get("m365-copilot-settings", [])
    if not settings:
        return []  # Copilot settings not accessible — other checks handle this
    for ev in settings:
        data = ev.get("Data", ev.get("data", {}))
        web_search = data.get("WebSearchEnabled", None)
        # If all features are wide-open and no restrictions are set
        restrictions = data.get("PromptRestrictions", None)
        content_filters = data.get("ContentFilterEnabled", None)
        if restrictions is None and content_filters is None and web_search is True:
            return [_cr_finding(
                "copilot_security", "no_prompt_guardrails",
                "No prompt guardrail restrictions configured for Copilot",
                "Copilot is operating with default settings and no additional prompt "
                "guardrails. Without content filters or prompt restrictions, users may "
                "inadvertently prompt Copilot to generate sensitive, regulated, or "
                "inappropriate content.",
                "low",
                [{"Type": "PromptGuardrails", "Name": "Copilot Prompt Settings",
                  "ResourceId": "m365-copilot-prompt-guardrails",
                  "WebSearchEnabled": web_search,
                  "PromptRestrictions": restrictions,
                  "ContentFilterEnabled": content_filters}],
                {"Description": "Configure prompt guardrails for Copilot usage.",
                 "PortalSteps": [
                     "Go to Microsoft 365 admin center > Settings > Copilot",
                     "Review and configure web search grounding options",
                     "Enable content filtering if available",
                     "Define organizational guidelines for acceptable prompt categories",
                     "Consider Microsoft Purview Communication Compliance for prompt monitoring",
                 ]},
                compliance_status="partial",
            )]
    return []

