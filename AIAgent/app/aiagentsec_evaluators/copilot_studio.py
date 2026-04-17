"""Copilot Studio agent security evaluators — authentication, connectors, logging, channels."""

from __future__ import annotations

from .finding import _as_finding


def analyze_cs_authentication(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Copilot Studio agent authentication posture."""
    findings: list[dict] = []
    findings.extend(_check_cs_auth_enforcement(evidence_index))
    findings.extend(_check_cs_auth_providers(evidence_index))
    findings.extend(_check_cs_stale_auth_config(evidence_index))
    return findings


def _check_cs_auth_enforcement(idx: dict) -> list[dict]:
    """Flag Copilot Studio bots that do not require authentication."""
    bots = idx.get("copilot-studio-bot", [])
    unauthenticated: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("RequiresAuthentication"):
            unauthenticated.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
                "EnvironmentName": data.get("EnvironmentName", ""),
                "AuthMode": data.get("AuthMode", "None"),
            })
    if unauthenticated:
        return [_as_finding(
            "cs_authentication", "no_auth_required",
            f"{len(unauthenticated)} Copilot Studio agents do not require authentication",
            "Agents without authentication allow anonymous access, enabling unauthorized "
            "users to interact with the agent and potentially access sensitive data or "
            "trigger actions without accountability.",
            "critical", "copilot_studio", unauthenticated,
            {"Description": "Enable authentication on all Copilot Studio agents. "
             "Use Azure AD as the authentication provider.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent", "Go to Settings > Security > Authentication", "Set authentication to 'Authenticate with Microsoft'", "Save and publish the agent"]},
        )]
    return []


def _check_cs_auth_providers(idx: dict) -> list[dict]:
    """Check if Copilot Studio bots use secure authentication providers."""
    bots = idx.get("copilot-studio-bot", [])
    weak_auth: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("RequiresAuthentication"):
            providers = data.get("AllowedAuthProviders", [])
            # Check for non-Azure AD providers (less secure)
            if providers and not any("azure" in str(p).lower() or "microsoft" in str(p).lower()
                                     for p in providers):
                weak_auth.append({
                    "Type": "CopilotStudioBot",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("BotId", ""),
                    "AuthProviders": str(providers),
                })
    if weak_auth:
        return [_as_finding(
            "cs_authentication", "non_aad_auth",
            f"{len(weak_auth)} agents use non-Azure AD authentication providers",
            "Using external or less-secure authentication providers may bypass "
            "organizational security policies and Conditional Access controls.",
            "medium", "copilot_studio", weak_auth,
            {"Description": "Configure Azure AD as the primary authentication provider.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent", "Go to Settings > Security > Authentication", "Under 'Service provider', select 'Azure Active Directory v2'", "Configure the required app registration settings"]},
        )]
    return []


def _check_cs_stale_auth_config(idx: dict) -> list[dict]:
    """Flag agents whose auth config has not been updated in >180 days."""
    from datetime import datetime, timezone, timedelta
    bots = idx.get("copilot-studio-bot", [])
    cutoff = datetime.now(timezone.utc) - timedelta(days=180)
    stale: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("RequiresAuthentication"):
            continue
        mod_str = data.get("ModifiedTime", "")
        if not mod_str:
            continue
        try:
            mod_dt = datetime.fromisoformat(mod_str.replace("Z", "+00:00"))
            if mod_dt < cutoff:
                stale.append({
                    "Type": "CopilotStudioBot",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("BotId", ""),
                    "LastModified": mod_str,
                })
        except (ValueError, TypeError):
            continue
    if stale:
        return [_as_finding(
            "cs_authentication", "stale_auth_config",
            f"{len(stale)} agents have auth configuration unchanged for >180 days",
            "Authentication settings that have not been reviewed in over six months "
            "may reference stale app registrations or outdated providers.",
            "low", "copilot_studio", stale,
            {"Description": "Review and rotate authentication configuration regularly.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Go to Settings > Security > Authentication",
                             "Verify the app registration is current",
                             "Re-publish the agent after any changes"]},
        )]
    return []


# ── 2. Data Connector Security ───────────────────────────────────────

def analyze_cs_data_connectors(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess DLP and connector governance for Copilot Studio agents."""
    findings: list[dict] = []
    findings.extend(_check_cs_dlp_policies(evidence_index))
    findings.extend(_check_cs_environment_security(evidence_index))
    return findings


def _check_cs_dlp_policies(idx: dict) -> list[dict]:
    """Check if DLP policies are applied to Power Platform environments."""
    summary = idx.get("copilot-studio-summary", [])
    for ev in summary:
        data = ev.get("Data", ev.get("data", {}))
        dlp_count = data.get("DLPPolicies", 0)
        if dlp_count == 0:
            return [_as_finding(
                "cs_data_connectors", "no_pp_dlp_policies",
                "No DLP policies on Power Platform — Copilot Studio agents unrestricted",
                "Without DLP policies, Copilot Studio agents can use any connector, "
                "including those that access external or sensitive data sources.",
                "high", "copilot_studio",
                [{"Type": "PPConfig", "Name": "DLP Policies",
                  "ResourceId": "pp-dlp", "DLPPolicyCount": 0}],
                {"Description": "Create DLP policies in Power Platform admin center to "
                 "restrict connector usage for Copilot Studio environments.",
                 "PortalSteps": ["Go to Power Platform admin center > Policies > Data policies", "Click '+ New policy'", "Select 'Block' for non-business connectors", "Add only approved connectors to 'Business' group", "Apply to target environments"]},
            )]
    return []


def _check_cs_environment_security(idx: dict) -> list[dict]:
    """Check if Power Platform environments use security groups and managed environments."""
    envs = idx.get("pp-environment", [])
    unmanaged: list[dict] = []
    no_security_group: list[dict] = []
    for ev in envs:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("IsManagedEnvironment"):
            unmanaged.append({
                "Type": "PowerPlatformEnvironment",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("EnvironmentId", ""),
            })
        if not data.get("HasSecurityGroup"):
            no_security_group.append({
                "Type": "PowerPlatformEnvironment",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("EnvironmentId", ""),
            })

    results: list[dict] = []
    if unmanaged:
        results.append(_as_finding(
            "cs_data_connectors", "unmanaged_environments",
            f"{len(unmanaged)} Power Platform environments are not managed",
            "Managed Environments provide enhanced governance including DLP enforcement, "
            "usage analytics, and maker controls. Copilot Studio agents in unmanaged "
            "environments have fewer security controls.",
            "medium", "copilot_studio", unmanaged,
            {"Description": "Convert environments to Managed Environments in Power Platform admin center.",
             "PortalSteps": ["Go to Power Platform admin center > Environments", "Select the target environment > Edit", "Enable 'Managed Environment' toggle", "Configure governance settings (solution checker, sharing limits)"]},
        ))
    if no_security_group:
        results.append(_as_finding(
            "cs_data_connectors", "no_security_group",
            f"{len(no_security_group)} environments lack security group restrictions",
            "Environments without security groups allow any user in the tenant to access "
            "them. Restrict environment access using Azure AD security groups.",
            "medium", "copilot_studio", no_security_group,
            {"Description": "Assign security groups to Power Platform environments.",
             "PortalSteps": ["Go to Power Platform admin center > Environments", "Select the target environment > Edit", "Under 'Security group', click Edit and select an Azure AD security group", "Save changes"]},
        ))
    return results


# ── 3. Conversation Logging ──────────────────────────────────────────

def analyze_cs_logging(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess conversation logging for Copilot Studio agents."""
    findings: list[dict] = []
    findings.extend(_check_cs_conversation_logging(evidence_index))
    findings.extend(_check_cs_environment_audit_disabled(evidence_index))
    return findings


def _check_cs_conversation_logging(idx: dict) -> list[dict]:
    """Flag agents without conversation logging enabled."""
    bots = idx.get("copilot-studio-bot", [])
    no_logging: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasConversationLogging"):
            no_logging.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
                "EnvironmentName": data.get("EnvironmentName", ""),
            })
    if no_logging:
        return [_as_finding(
            "cs_logging", "no_conversation_logging",
            f"{len(no_logging)} Copilot Studio agents lack conversation logging",
            "Conversation logging provides an audit trail of agent interactions, "
            "which is essential for compliance, incident investigation, and detecting "
            "sensitive content exposure.",
            "high", "copilot_studio", no_logging,
            {"Description": "Enable conversation logging in Copilot Studio agent settings.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent", "Go to Settings > Security", "Enable 'Conversation transcripts' and 'Activity logging'", "Configure Dataverse audit settings for the environment"]},
        )]
    return []


def _check_cs_environment_audit_disabled(idx: dict) -> list[dict]:
    """Flag when M365 unified audit logging is disabled or inaccessible."""
    audit_records = idx.get("m365-audit-config", [])
    if not audit_records:
        return []
    for ev in audit_records:
        data = ev.get("Data", ev.get("data", {}))
        status = data.get("UnifiedAuditLogEnabled")
        if status is False or status == "unknown":
            return [_as_finding(
                "cs_logging", "environment_audit_disabled",
                "Unified audit logging is not confirmed as enabled",
                "M365 unified audit logging captures Copilot Studio interactions, "
                "admin changes, and data access events. Without it, incident "
                "investigation and compliance reporting are severely limited.",
                "high", "copilot_studio",
                [{"Type": "AuditConfig", "Name": "M365 Unified Audit Log",
                  "ResourceId": "m365-audit-config", "Status": str(status)}],
                {"Description": "Enable unified audit logging in Microsoft Purview.",
                 "PortalSteps": ["Go to Microsoft Purview compliance portal > Audit",
                                 "Click 'Start recording user and admin activity'",
                                 "Assign Security Reader role for assessment access",
                                 "Re-run the assessment to confirm logging status"]},
            )]
    return []


# ── 4. Channel Security ─────────────────────────────────────────────

def analyze_cs_channels(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess channel security for Copilot Studio agents."""
    findings: list[dict] = []
    findings.extend(_check_cs_web_channel_exposure(evidence_index))
    findings.extend(_check_cs_teams_channel_no_sso(evidence_index))
    return findings


def _check_cs_web_channel_exposure(idx: dict) -> list[dict]:
    """Flag agents with web channel enabled (publicly accessible)."""
    bots = idx.get("copilot-studio-bot", [])
    web_exposed: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("WebChannel") and not data.get("RequiresAuthentication"):
            web_exposed.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
                "WebChannel": True,
                "RequiresAuth": False,
            })
    if web_exposed:
        return [_as_finding(
            "cs_channels", "unauthenticated_web_channel",
            f"{len(web_exposed)} agents have web channel enabled without authentication",
            "Web channel exposes the agent to the public internet. Without authentication, "
            "anyone can interact with the agent and potentially extract sensitive information.",
            "critical", "copilot_studio", web_exposed,
            {"Description": "Either disable web channel or enable authentication for web-exposed agents.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent", "Go to Channels > Custom website", "Either remove the web channel or go to Settings > Security > Authentication", "Enable 'Authenticate with Microsoft' before publishing"]},
        )]
    return []


def _check_cs_teams_channel_no_sso(idx: dict) -> list[dict]:
    """Flag agents with Teams channel enabled but SSO not configured."""
    bots = idx.get("copilot-studio-bot", [])
    no_sso: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("TeamsChannel") and not data.get("TeamsSSOEnabled"):
            no_sso.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
            })
    if no_sso:
        return [_as_finding(
            "cs_channels", "teams_channel_no_sso",
            f"{len(no_sso)} agents have Teams channel without SSO enabled",
            "Teams SSO provides seamless authentication using the user's existing "
            "Teams identity. Without SSO, users face extra sign-in prompts or the "
            "agent cannot verify user identity within Teams.",
            "medium", "copilot_studio", no_sso,
            {"Description": "Enable SSO for Teams channel to improve security and UX.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Go to Channels > Microsoft Teams",
                             "Enable 'Single sign-on (SSO)'",
                             "Register the bot in Azure AD and configure the SSO connection"]},
        )]
    return []

