"""Shadow AI risk evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


# AI service indicators for app detection
_AI_SERVICE_KEYWORDS = (
    "openai", "chatgpt", "anthropic", "claude", "gemini", "google ai",
    "bard", "midjourney", "stability", "hugging face", "huggingface",
    "cohere", "replicate", "together ai", "perplexity", "jasper",
    "writesonic", "copy.ai", "notion ai", "grammarly ai",
)

_AI_API_RESOURCE_IDS = (
    # Well-known AI service resource app IDs
    "0365d428-90b3-4d37-8c51-80e0a5e79b06",  # Azure OpenAI
)


def analyze_shadow_ai(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Shadow AI risks for Copilot deployment."""
    findings: list[dict] = []
    findings.extend(_check_unauthorized_ai_apps(evidence_index))
    findings.extend(_check_ai_consent_grants(evidence_index))
    findings.extend(_check_shadow_copilot_agents(evidence_index))
    findings.extend(_check_ai_app_governance(evidence_index))
    findings.extend(_check_ai_app_permissions(evidence_index))
    findings.extend(_check_ai_dlp_restrictions(evidence_index))
    return findings


def _check_unauthorized_ai_apps(idx: dict) -> list[dict]:
    """Scan Entra app registrations for unauthorized AI service integrations."""
    apps = idx.get("entra-applications", [])
    if not apps:
        return []
    ai_apps = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        name = (data.get("DisplayName", "") or "").lower()
        if any(kw in name for kw in _AI_SERVICE_KEYWORDS):
            ai_apps.append({
                "Type": "EntraApplication",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "Permissions": data.get("TotalPermissions", 0),
                "HasGraphAccess": data.get("HasGraphAccess", False),
            })
    if ai_apps:
        return [_cr_finding(
            "shadow_ai", "unauthorized_ai_apps_detected",
            f"{len(ai_apps)} AI-related app registration(s) detected in Entra ID",
            f"Found {len(ai_apps)} application registration(s) with names matching known "
            "AI services (OpenAI, Anthropic, Google AI, etc.). These may indicate shadow AI "
            "adoption where users or teams have integrated AI tools without IT approval. "
            "These apps may have access to organizational data that Copilot also indexes, "
            "creating parallel data exposure channels.",
            "high" if any(a.get("HasGraphAccess") for a in ai_apps) else "medium",
            ai_apps[:50],
            {"Description": "Review and govern AI-related app registrations.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Applications > App registrations",
                 "Filter for AI-related app names and review their permissions",
                 "Revoke registrations that were not formally approved",
                 "Configure 'User can register applications' to 'No' to prevent future shadow registrations",
                 "Establish an AI app approval workflow via IT service desk",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_ai_consent_grants(idx: dict) -> list[dict]:
    """Check for OAuth consent grants given to AI-related service principals."""
    sps = idx.get("entra-service-principals", [])
    if not sps:
        return []
    ai_sps = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        name = (data.get("DisplayName", "") or "").lower()
        sp_type = (data.get("Type", "") or "").lower()
        if any(kw in name for kw in _AI_SERVICE_KEYWORDS):
            ai_sps.append({
                "Type": "ServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("ServicePrincipalId", ""),
                "Enabled": data.get("Enabled", True),
                "IsEnterprise": data.get("IsEnterprise", False),
                "RoleAssignments": data.get("AppRoleAssignmentCount", 0),
            })
    if ai_sps:
        return [_cr_finding(
            "shadow_ai", "ai_consent_grants_detected",
            f"{len(ai_sps)} AI service principal(s) with consent grants detected",
            f"Found {len(ai_sps)} enterprise application(s) matching AI services with "
            "active consent grants. This indicates users have authorized AI tools to "
            "access organizational data, potentially creating data leakage paths "
            "outside of Copilot's governed access model.",
            "high" if any(s.get("RoleAssignments", 0) > 0 for s in ai_sps) else "medium",
            ai_sps[:50],
            {"Description": "Audit and revoke unauthorized AI service consent grants.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Applications > Enterprise applications",
                 "Filter by AI service names and review consent grants",
                 "Under each app > Permissions, review and revoke unauthorized grants",
                 "Configure consent settings: Users > User settings > Consent and permissions",
                 "Set 'Users can consent to apps' to 'No' or restrict to admin-approved apps",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_shadow_copilot_agents(idx: dict) -> list[dict]:
    """Check for user-created Copilot agents that bypass admin governance."""
    agents = idx.get("m365-copilot-agents", [])
    if not agents:
        return []
    ungoverned = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        owner = data.get("Owner", data.get("CreatedBy", ""))
        published = data.get("Published", data.get("IsPublished", False))
        if not published:
            ungoverned.append({
                "Type": "CopilotAgent",
                "Name": data.get("DisplayName", data.get("Name", "Unknown")),
                "ResourceId": data.get("AgentId", data.get("Id", "")),
                "Owner": owner,
            })
    if ungoverned:
        return [_cr_finding(
            "shadow_ai", "shadow_copilot_agents_detected",
            f"{len(ungoverned)} unpublished user-created Copilot agent(s) detected",
            f"Found {len(ungoverned)} Copilot agent(s) created by users that have not "
            "gone through admin publishing or approval. These personal agents may access "
            "organizational data without governance controls, create data leakage risks, "
            "or produce outputs that violate compliance policies.",
            "medium",
            ungoverned[:50],
            {"Description": "Review and govern user-created Copilot agents.",
             "PortalSteps": [
                 "Go to Microsoft 365 admin center > Settings > Copilot",
                 "Review agent creation permissions under 'Agents'",
                 "Restrict who can create and publish agents",
                 "Enable admin approval workflow for agent publishing",
                 "Review existing agents and retire ungoverned ones",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_ai_app_governance(idx: dict) -> list[dict]:
    """Check if AI app governance policies are in place (Defender for Cloud Apps / App Governance)."""
    mcas = idx.get("m365-defender-cloud-apps", [])
    skus = idx.get("m365-subscribed-skus", [])
    # Check for MCAS / App Governance SKUs
    has_mcas = bool(mcas)
    mcas_keywords = ("cloud_app_security", "defender_for_cloud_apps", "aad_premium",
                     "ems_e5", "m365_e5", "microsoft_365_e5")
    if not has_mcas:
        for ev in skus:
            data = ev.get("Data", ev.get("data", {}))
            sku = (data.get("SkuPartNumber", "") or "").lower().replace(" ", "_").replace("-", "_")
            if any(kw in sku for kw in mcas_keywords):
                has_mcas = True
                break
    if not has_mcas:
        return [_cr_finding(
            "shadow_ai", "no_ai_app_governance",
            "No AI app governance capability detected — shadow AI discovery unavailable",
            "Microsoft Defender for Cloud Apps with App Governance provides automated "
            "discovery of unsanctioned AI applications, OAuth app risk scoring, and "
            "policy-based controls. Without this, the organization cannot detect "
            "shadow AI SaaS usage or govern AI app behavior.",
            "medium",
            [{"Type": "AppGovernance", "Name": "AI App Governance",
              "ResourceId": "m365-app-governance"}],
            {"Description": "Enable Defender for Cloud Apps with App Governance for AI discovery.",
             "PortalSteps": [
                 "Go to Microsoft Defender portal > Cloud Apps > Cloud app catalog",
                 "Search for AI services and review discovery data",
                 "Create app discovery policies for AI categories",
                 "Enable App Governance in Defender portal > Cloud Apps > App governance",
                 "Create policies for high-privilege AI app detection",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_ai_app_permissions(idx: dict) -> list[dict]:
    """Check if AI-related apps have excessive permissions."""
    apps = idx.get("entra-applications", [])
    if not apps:
        return []
    overpermissioned = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        name = (data.get("DisplayName", "") or "").lower()
        if not any(kw in name for kw in _AI_SERVICE_KEYWORDS):
            continue
        app_perms = data.get("ApplicationPermissions", 0) or 0
        total_perms = data.get("TotalPermissions", 0) or 0
        has_graph = data.get("HasGraphAccess", False)
        if has_graph and (app_perms >= 3 or total_perms >= 10):
            overpermissioned.append({
                "Type": "EntraApplication",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "ApplicationPermissions": app_perms,
                "TotalPermissions": total_perms,
                "HasGraphAccess": has_graph,
            })
    if overpermissioned:
        return [_cr_finding(
            "shadow_ai", "ai_apps_overpermissioned",
            f"{len(overpermissioned)} AI app(s) with excessive Graph API permissions",
            f"Found {len(overpermissioned)} AI-related application(s) with high-privilege "
            "Graph API access (3+ application permissions or 10+ total). These apps can "
            "read organizational data including emails, files, and user profiles — the same "
            "data Copilot indexes — creating a parallel, ungoverned data access path.",
            "high",
            overpermissioned[:50],
            {"Description": "Review and reduce AI app permissions to least privilege.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Applications > App registrations",
                 "Review each AI app's API permissions",
                 "Remove unnecessary application-level permissions",
                 "Convert application permissions to delegated where possible",
                 "Require admin consent for remaining application permissions",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_ai_dlp_restrictions(idx: dict) -> list[dict]:
    """Check if DLP or web filtering restricts data flow to AI service domains."""
    dlp = idx.get("m365-dlp-policies", [])
    endpoint_dlp = False
    for ev in dlp:
        data = ev.get("Data", ev.get("data", {}))
        workloads = str(data.get("Workloads", data.get("Locations", ""))).lower()
        if "endpoint" in workloads or "device" in workloads:
            endpoint_dlp = True
            break
    if not endpoint_dlp:
        return [_cr_finding(
            "shadow_ai", "no_ai_dlp_web_restrictions",
            "No Endpoint DLP or web content filtering detected for AI service data protection",
            "Without Endpoint DLP covering devices, users can copy/paste sensitive "
            "organizational data into third-party AI services (ChatGPT, Claude, etc.) "
            "via web browsers. This bypasses Copilot's governed access model and creates "
            "data exfiltration risks to external AI platforms.",
            "medium",
            [{"Type": "EndpointDLP", "Name": "AI Data Exfiltration Prevention",
              "ResourceId": "m365-endpoint-dlp"}],
            {"Description": "Configure Endpoint DLP to restrict data flow to AI services.",
             "PortalSteps": [
                 "Go to Microsoft Purview > Data Loss Prevention > Policies",
                 "Create a policy with Endpoint DLP scope",
                 "Under 'Content contains', select sensitive info types relevant to your org",
                 "Under 'Actions', block or audit paste to restricted browsers/apps",
                 "Optionally configure web categories to block AI service domains via Defender for Endpoint",
             ]},
            compliance_status="gap",
        )]
    return []

