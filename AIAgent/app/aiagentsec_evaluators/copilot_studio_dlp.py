"""Copilot Studio DLP depth, environment governance, advanced security, audit, Dataverse, and readiness cross-check."""

from __future__ import annotations

from .finding import _as_finding


def analyze_cs_dlp_depth(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Deep assessment of DLP policies governing Copilot Studio virtual connectors."""
    findings: list[dict] = []
    findings.extend(_check_cs_dlp_no_auth_connector(evidence_index))
    findings.extend(_check_cs_dlp_knowledge_source_unrestricted(evidence_index))
    findings.extend(_check_cs_dlp_channel_unrestricted(evidence_index))
    findings.extend(_check_cs_dlp_skills_unrestricted(evidence_index))
    findings.extend(_check_cs_dlp_default_group(evidence_index))
    findings.extend(_check_cs_dlp_no_tenant_policy(evidence_index))
    findings.extend(_check_cs_dlp_http_unrestricted(evidence_index))
    return findings


def _cs_dlp_blocked_connectors(idx: dict) -> set:
    """Gather all blocked connector display names from DLP policies."""
    blocked: set = set()
    for ev in idx.get("pp-dlp-policy", []):
        data = ev.get("Data", ev.get("data", {}))
        # Prefer BlockedConnectorNames (list of strings from updated collector)
        names = data.get("BlockedConnectorNames", [])
        if isinstance(names, list):
            for c in names:
                name = c if isinstance(c, str) else c.get("DisplayName", c.get("name", ""))
                if name:
                    blocked.add(name.lower().strip())
        # Fall back to BlockedConnectors if it is a list (test data format)
        bc = data.get("BlockedConnectors", 0)
        if isinstance(bc, list):
            for c in bc:
                name = c if isinstance(c, str) else c.get("DisplayName", c.get("name", ""))
                if name:
                    blocked.add(name.lower().strip())
    return blocked


def _check_cs_dlp_no_auth_connector(idx: dict) -> list[dict]:
    """DLP must block 'Chat without Microsoft Entra ID authentication in Copilot Studio'."""
    blocked = _cs_dlp_blocked_connectors(idx)
    target = "chat without microsoft entra id authentication in copilot studio"
    if target not in blocked and "chat without entra" not in " ".join(blocked):
        policies = idx.get("pp-dlp-policy", [])
        if not policies and not idx.get("copilot-studio-summary", []):
            return []
        return [_as_finding(
            "cs_dlp_depth", "cs_dlp_no_auth_connector_allowed",
            "DLP does not block unauthenticated Copilot Studio agents",
            "The 'Chat without Microsoft Entra ID authentication' virtual connector "
            "is not blocked in any DLP policy.  Makers can publish agents that do not "
            "require user sign-in, exposing organizational data to anonymous users.",
            "critical", "copilot_studio",
            [{"Type": "DLPPolicy", "Name": "MissingBlock",
              "ResourceId": "virtual-connector-no-auth"}],
            {"Description": "Block the 'Chat without Microsoft Entra ID authentication in "
             "Copilot Studio' connector in your DLP policy.",
             "PortalSteps": ["Go to Power Platform admin center > Security > Data and privacy",
                             "Edit or create a Data policy",
                             "Find 'Chat without Microsoft Entra ID authentication in Copilot Studio'",
                             "Move it to the Blocked group",
                             "Save and apply to all Copilot Studio environments"]},
        )]
    return []


def _check_cs_dlp_knowledge_source_unrestricted(idx: dict) -> list[dict]:
    """Check if knowledge-source virtual connectors are classified in DLP."""
    blocked = _cs_dlp_blocked_connectors(idx)
    ks_connectors = [
        "knowledge source with sharepoint and onedrive in copilot studio",
        "knowledge source with public websites and data in copilot studio",
        "knowledge source with documents in copilot studio",
    ]
    unclassified = [k for k in ks_connectors if k not in blocked]
    policies = idx.get("pp-dlp-policy", [])
    if not policies and not idx.get("copilot-studio-summary", []):
        return []
    if len(unclassified) == len(ks_connectors):
        return [_as_finding(
            "cs_dlp_depth", "cs_dlp_knowledge_source_unrestricted",
            "No knowledge-source virtual connectors blocked in DLP",
            "Copilot Studio knowledge-source connectors (SharePoint, public websites, "
            "documents) are not restricted by any DLP policy. Makers can connect agents "
            "to any knowledge source without governance.",
            "high", "copilot_studio",
            [{"Type": "DLPPolicy", "Name": c, "ResourceId": "virtual-connector-ks"}
             for c in unclassified],
            {"Description": "Add knowledge-source virtual connectors to blocked or business group.",
             "PortalSteps": ["Edit DLP policy in Power Platform admin center",
                             "Classify knowledge-source connectors appropriately",
                             "Block 'Knowledge source with public websites' for sensitive environments"]},
        )]
    return []


def _check_cs_dlp_channel_unrestricted(idx: dict) -> list[dict]:
    """Check if channel virtual connectors are classified in DLP."""
    blocked = _cs_dlp_blocked_connectors(idx)
    channel_connectors = [
        "direct line channels in copilot studio",
        "facebook channel in copilot studio",
        "whatsapp channel in copilot studio",
    ]
    unclassified = [c for c in channel_connectors if c not in blocked]
    policies = idx.get("pp-dlp-policy", [])
    if not policies and not idx.get("copilot-studio-summary", []):
        return []
    if len(unclassified) == len(channel_connectors):
        return [_as_finding(
            "cs_dlp_depth", "cs_dlp_channel_unrestricted",
            "External channel connectors not restricted in DLP",
            "Channel connectors for Direct Line, Facebook, and WhatsApp are not blocked. "
            "Makers can publish agents to external channels without admin approval.",
            "medium", "copilot_studio",
            [{"Type": "DLPPolicy", "Name": c, "ResourceId": "virtual-connector-channel"}
             for c in unclassified],
            {"Description": "Block external channel connectors in DLP for regulated environments.",
             "PortalSteps": ["Edit DLP policy", "Block Direct Line, Facebook, WhatsApp connectors",
                             "Allow only Teams + M365 channel for internal agents"]},
        )]
    return []


def _check_cs_dlp_skills_unrestricted(idx: dict) -> list[dict]:
    """Check if Skills connector is blocked in DLP."""
    blocked = _cs_dlp_blocked_connectors(idx)
    policies = idx.get("pp-dlp-policy", [])
    if not policies and not idx.get("copilot-studio-summary", []):
        return []
    if "skills with copilot studio" not in blocked:
        return [_as_finding(
            "cs_dlp_depth", "cs_dlp_skills_unrestricted",
            "Skills connector not blocked — agents can call arbitrary skills",
            "The 'Skills with Copilot Studio' virtual connector is not blocked. "
            "Agents can be extended with external skills that may access sensitive APIs.",
            "medium", "copilot_studio",
            [{"Type": "DLPPolicy", "Name": "Skills with Copilot Studio",
              "ResourceId": "virtual-connector-skills"}],
            {"Description": "Block the Skills connector in DLP or restrict to specific skills.",
             "PortalSteps": ["Edit DLP policy",
                             "Find 'Skills with Copilot Studio'",
                             "Move to Blocked group"]},
        )]
    return []


def _check_cs_dlp_default_group(idx: dict) -> list[dict]:
    """Check if DLP default group for new connectors is set to Blocked."""
    policies = idx.get("pp-dlp-policy", [])
    if not policies:
        return []
    for ev in policies:
        data = ev.get("Data", ev.get("data", {}))
        env_type = str(data.get("EnvironmentType", "")).lower()
        if env_type in ("onlyenvironments", "exceptenvironments", "allenvironments", ""):
            has_blocked = data.get("HasBlockedConnectors", False)
            bc = data.get("BlockedConnectors", 0)
            blocked_count = bc if isinstance(bc, int) else len(bc) if isinstance(bc, list) else 0
            if not has_blocked and blocked_count == 0:
                return [_as_finding(
                    "cs_dlp_depth", "cs_dlp_default_group_not_blocked",
                    "DLP default group for new connectors is not set to Blocked",
                    "When the default group is Non-Business, any newly added connector "
                    "is automatically allowed. Set the default to Blocked so new connectors "
                    "require explicit admin classification.",
                    "high", "copilot_studio",
                    [{"Type": "DLPPolicy", "Name": data.get("DisplayName", ""),
                      "ResourceId": data.get("PolicyId", "")}],
                    {"Description": "Change default data group for new connectors to Blocked.",
                     "PortalSteps": ["Edit DLP policy in Power Platform admin center",
                                     "Go to Prebuilt connectors page",
                                     "Set 'Default group' to Blocked"]},
                )]
    return []


def _check_cs_dlp_no_tenant_policy(idx: dict) -> list[dict]:
    """Check if there is at least one tenant-scope DLP policy."""
    policies = idx.get("pp-dlp-policy", [])
    if not policies:
        return []
    has_tenant = False
    for ev in policies:
        data = ev.get("Data", ev.get("data", {}))
        env_type = str(data.get("EnvironmentType", "")).lower()
        if env_type in ("allenvironments", "exceptenvironments", ""):
            has_tenant = True
            break
    if not has_tenant:
        return [_as_finding(
            "cs_dlp_depth", "cs_dlp_no_tenant_policy",
            "No tenant-scope DLP policy — only environment-level policies exist",
            "Without a tenant-scope DLP policy, makers who create new environments "
            "may operate without any DLP governance until an admin notices.",
            "high", "copilot_studio",
            [{"Type": "DLPPolicy", "Name": "TenantScope", "ResourceId": "tenant-dlp"}],
            {"Description": "Create a tenant-wide DLP policy as a baseline.",
             "PortalSteps": ["Go to Power Platform admin center > Data policies",
                             "Create a new policy",
                             "Under Scope, select 'Add all environments'",
                             "Configure connector classifications",
                             "Save"]},
        )]
    return []


def _check_cs_dlp_http_unrestricted(idx: dict) -> list[dict]:
    """Check if HTTP connector is blocked or endpoint-filtered."""
    blocked = _cs_dlp_blocked_connectors(idx)
    policies = idx.get("pp-dlp-policy", [])
    if not policies and not idx.get("copilot-studio-summary", []):
        return []
    http_terms = {"http", "http connector", "http webhook"}
    if not http_terms.intersection(blocked):
        return [_as_finding(
            "cs_dlp_depth", "cs_dlp_http_unrestricted",
            "HTTP connector not blocked — agents can make arbitrary HTTP requests",
            "The HTTP connector allows Copilot Studio agents to call any URL. "
            "Without blocking or endpoint filtering, agents can exfiltrate data "
            "to external services.",
            "high", "copilot_studio",
            [{"Type": "DLPPolicy", "Name": "HTTP Connector",
              "ResourceId": "http-connector"}],
            {"Description": "Block the HTTP connector or configure endpoint filtering.",
             "PortalSteps": ["Edit DLP policy",
                             "Block HTTP connector or configure endpoint filtering",
                             "Allow only approved endpoints if HTTP is needed"]},
        )]
    return []


# ── Phase M: Environment Governance & Tenant Security ────────────────

def analyze_cs_environment_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Power Platform environment governance and tenant security settings."""
    findings: list[dict] = []
    findings.extend(_check_cs_bots_in_default_env(evidence_index))
    findings.extend(_check_cs_bots_in_dev_env(evidence_index))
    findings.extend(_check_cs_sandbox_for_production(evidence_index))
    findings.extend(_check_cs_env_no_tenant_isolation(evidence_index))
    findings.extend(_check_cs_env_gen_ai_unrestricted(evidence_index))
    return findings


def _check_cs_bots_in_default_env(idx: dict) -> list[dict]:
    """Flag Copilot Studio bots running in the default environment."""
    bots = idx.get("copilot-studio-bot", [])
    envs = {ev.get("Data", ev.get("data", {})).get("EnvironmentId", ""): ev
            for ev in idx.get("pp-environment", [])}
    in_default: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        env_id = data.get("EnvironmentId", "")
        env_data = envs.get(env_id, {}).get("Data", envs.get(env_id, {}).get("data", {}))
        if env_data.get("IsDefault") or str(env_data.get("EnvironmentSku", "")).lower() == "default":
            in_default.append({
                "Type": "CopilotStudioBot", "Name": data.get("DisplayName", ""),
                "ResourceId": data.get("BotId", ""),
                "EnvironmentName": data.get("EnvironmentName", ""),
            })
    if in_default:
        return [_as_finding(
            "cs_environment_governance", "cs_env_bots_in_default",
            f"{len(in_default)} agents running in the default environment",
            "The default environment gives all licensed users the Environment Maker role, "
            "has limited governance controls, and no backup guarantees. Move production "
            "agents to dedicated production environments.",
            "high", "copilot_studio", in_default,
            {"Description": "Migrate agents from the default environment to a production environment.",
             "PortalSteps": ["Create a dedicated production environment",
                             "Export agents via solution export",
                             "Import into the production environment",
                             "Configure security groups on the new environment"]},
        )]
    return []


def _check_cs_bots_in_dev_env(idx: dict) -> list[dict]:
    """Flag published agents in developer environments."""
    bots = idx.get("copilot-studio-bot", [])
    envs = {ev.get("Data", ev.get("data", {})).get("EnvironmentId", ""): ev
            for ev in idx.get("pp-environment", [])}
    in_dev: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("IsPublished"):
            continue
        env_id = data.get("EnvironmentId", "")
        env_data = envs.get(env_id, {}).get("Data", envs.get(env_id, {}).get("data", {}))
        if str(env_data.get("EnvironmentSku", "")).lower() == "developer":
            in_dev.append({
                "Type": "CopilotStudioBot", "Name": data.get("DisplayName", ""),
                "ResourceId": data.get("BotId", ""),
                "EnvironmentName": data.get("EnvironmentName", ""),
            })
    if in_dev:
        return [_as_finding(
            "cs_environment_governance", "cs_env_bots_in_dev_env",
            f"{len(in_dev)} published agents in developer environments",
            "Developer environments cannot have security groups assigned and are intended "
            "for single-developer use only. Published agents should be in production environments.",
            "medium", "copilot_studio", in_dev,
            {"Description": "Move published agents to production environments.",
             "PortalSteps": ["Export agent as solution from developer environment",
                             "Import into a production or sandbox environment"]},
        )]
    return []


def _check_cs_sandbox_for_production(idx: dict) -> list[dict]:
    """Flag published agents in sandbox environments."""
    bots = idx.get("copilot-studio-bot", [])
    envs = {ev.get("Data", ev.get("data", {})).get("EnvironmentId", ""): ev
            for ev in idx.get("pp-environment", [])}
    in_sandbox: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("IsPublished"):
            continue
        env_id = data.get("EnvironmentId", "")
        env_data = envs.get(env_id, {}).get("Data", envs.get(env_id, {}).get("data", {}))
        if str(env_data.get("EnvironmentSku", "")).lower() == "sandbox":
            in_sandbox.append({
                "Type": "CopilotStudioBot", "Name": data.get("DisplayName", ""),
                "ResourceId": data.get("BotId", ""),
                "EnvironmentName": data.get("EnvironmentName", ""),
            })
    if in_sandbox:
        return [_as_finding(
            "cs_environment_governance", "cs_env_sandbox_for_production",
            f"{len(in_sandbox)} published agents in sandbox (non-production) environments",
            "Sandbox environments can be reset or copied, which may disrupt agent "
            "availability. Published agents serving users should be in production environments.",
            "medium", "copilot_studio", in_sandbox,
            {"Description": "Promote agents from sandbox to production environments.",
             "PortalSteps": ["Export agent from sandbox via solution",
                             "Import into production environment",
                             "Test and publish in production"]},
        )]
    return []


def _check_cs_env_no_tenant_isolation(idx: dict) -> list[dict]:
    """Check if Power Platform tenant isolation is enabled."""
    envs = idx.get("pp-environment", [])
    if not envs:
        return []
    for ev in envs:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("CrossTenantIsolation"):
            return []
    return [_as_finding(
        "cs_environment_governance", "cs_env_no_tenant_isolation",
        "Power Platform tenant isolation is not enabled",
        "Without tenant isolation, connectors can establish cross-tenant connections "
        "using Entra ID credentials. This allows data exfiltration to external tenants "
        "via Power Platform apps, flows, and Copilot Studio agents.",
        "critical", "copilot_studio",
        [{"Type": "TenantSetting", "Name": "CrossTenantIsolation",
          "ResourceId": "pp-tenant-isolation"}],
        {"Description": "Enable tenant isolation in Power Platform admin center.",
         "PortalSteps": ["Go to Power Platform admin center > Security > Identity and access",
                         "Select 'Tenant isolation'",
                         "Turn on 'Restrict cross-tenant connections'",
                         "Add trusted tenants to the allow list as needed"]},
    )]


def _check_cs_env_gen_ai_unrestricted(idx: dict) -> list[dict]:
    """Check if generative AI agent publishing is restricted at tenant level."""
    envs = idx.get("pp-environment", [])
    summary = idx.get("copilot-studio-summary", [])
    if not envs and not summary:
        return []
    # If we have bots with generative AI and no DLP blocking the trigger connector
    blocked = _cs_dlp_blocked_connectors(idx)
    trigger_connector = "microsoft copilot studio"
    if trigger_connector not in blocked:
        bots = idx.get("copilot-studio-bot", [])
        gen_ai_bots = [b for b in bots
                       if b.get("Data", b.get("data", {})).get("GenerativeAnswersEnabled")]
        if gen_ai_bots:
            return [_as_finding(
                "cs_environment_governance", "cs_env_gen_ai_unrestricted",
                f"{len(gen_ai_bots)} agents use generative AI without tenant-level governance",
                "Generative AI features are not restricted at the tenant level. "
                "The 'Microsoft Copilot Studio' event trigger connector is not blocked, "
                "allowing autonomous agent behaviors without admin oversight.",
                "medium", "copilot_studio",
                [{"Type": "CopilotStudioBot", "Name": b.get("Data", b.get("data", {})).get("DisplayName", ""),
                  "ResourceId": b.get("Data", b.get("data", {})).get("BotId", "")}
                 for b in gen_ai_bots[:5]],
                {"Description": "Restrict generative AI publishing at the tenant level.",
                 "PortalSteps": ["Go to Power Platform admin center > Settings",
                                 "Under Copilot, disable generative AI agent publishing if needed",
                                 "Or block the 'Microsoft Copilot Studio' connector in DLP"]},
            )]
    return []


# ── Phase N: Copilot Studio Agent Advanced Security ──────────────────

def analyze_cs_agent_security_advanced(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Advanced agent-level security assessment for Copilot Studio."""
    findings: list[dict] = []
    findings.extend(_check_cs_auth_no_sign_in_required(evidence_index))
    findings.extend(_check_cs_auth_generic_oauth(evidence_index))
    findings.extend(_check_cs_auth_dlp_not_enforcing(evidence_index))
    findings.extend(_check_cs_agent_shared_to_everyone(evidence_index))
    findings.extend(_check_cs_agent_event_triggers_ungoverned(evidence_index))
    findings.extend(_check_cs_agent_http_unrestricted(evidence_index))
    return findings


def _check_cs_auth_no_sign_in_required(idx: dict) -> list[dict]:
    """Flag agents with manual auth but 'Require sign-in' not enforced."""
    bots = idx.get("copilot-studio-bot", [])
    no_signin: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        auth = str(data.get("AuthMode", "")).lower()
        if auth in ("manual", "oauth", "generic") and not data.get("RequiresAuthentication"):
            no_signin.append({
                "Type": "CopilotStudioBot", "Name": data.get("DisplayName", ""),
                "ResourceId": data.get("BotId", ""),
                "AuthMode": data.get("AuthMode", ""),
            })
    if no_signin:
        return [_as_finding(
            "cs_agent_security_advanced", "cs_auth_no_sign_in_required",
            f"{len(no_signin)} agents with manual auth do not require user sign-in",
            "When 'Require users to sign in' is not enabled, the agent only prompts "
            "for authentication when it encounters a topic that needs it, potentially "
            "exposing non-protected topics to unauthenticated users.",
            "high", "copilot_studio", no_signin,
            {"Description": "Enable 'Require users to sign in' in agent authentication settings.",
             "PortalSteps": ["Go to Copilot Studio > select agent > Settings > Security",
                             "Under Authentication, enable 'Require users to sign in'",
                             "Save and publish"]},
        )]
    return []


def _check_cs_auth_generic_oauth(idx: dict) -> list[dict]:
    """Flag agents using Generic OAuth2 instead of Entra ID."""
    bots = idx.get("copilot-studio-bot", [])
    generic: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        providers = data.get("AllowedAuthProviders", [])
        if isinstance(providers, list):
            for p in providers:
                p_lower = str(p).lower()
                if "generic" in p_lower or "oauth2" in p_lower:
                    generic.append({
                        "Type": "CopilotStudioBot", "Name": data.get("DisplayName", ""),
                        "ResourceId": data.get("BotId", ""),
                        "AuthProvider": str(p),
                    })
                    break
    if generic:
        return [_as_finding(
            "cs_agent_security_advanced", "cs_auth_generic_oauth",
            f"{len(generic)} agents use Generic OAuth2 instead of Entra ID",
            "Generic OAuth2 providers bypass Entra ID Conditional Access policies, "
            "MFA enforcement, and organizational identity governance. Use Microsoft "
            "Entra ID authentication where possible.",
            "medium", "copilot_studio", generic,
            {"Description": "Switch from Generic OAuth2 to Entra ID authentication.",
             "PortalSteps": ["Go to Copilot Studio > select agent > Authentication",
                             "Change service provider to 'Microsoft Entra ID V2'",
                             "Configure required app registration",
                             "Save and publish"]},
        )]
    return []


def _check_cs_auth_dlp_not_enforcing(idx: dict) -> list[dict]:
    """Cross-check: DLP should block unauthenticated agents if bots exist without auth."""
    bots = idx.get("copilot-studio-bot", [])
    no_auth_bots = [b for b in bots
                    if not b.get("Data", b.get("data", {})).get("RequiresAuthentication")]
    if not no_auth_bots:
        return []
    blocked = _cs_dlp_blocked_connectors(idx)
    target = "chat without microsoft entra id authentication in copilot studio"
    if target not in blocked and "chat without entra" not in " ".join(blocked):
        return [_as_finding(
            "cs_agent_security_advanced", "cs_auth_dlp_not_enforcing",
            "DLP not enforcing authentication — unauthenticated agents exist",
            "There are agents without authentication, AND the DLP does not block "
            "the 'Chat without Entra ID authentication' connector. This is a "
            "defense-in-depth failure: both agent-level and policy-level controls are missing.",
            "critical", "copilot_studio",
            [{"Type": "CopilotStudioBot",
              "Name": b.get("Data", b.get("data", {})).get("DisplayName", ""),
              "ResourceId": b.get("Data", b.get("data", {})).get("BotId", "")}
             for b in no_auth_bots[:5]],
            {"Description": "Block the 'Chat without Entra ID authentication' connector in DLP.",
             "PortalSteps": ["Go to Power Platform admin center > Data policies",
                             "Block 'Chat without Microsoft Entra ID authentication in Copilot Studio'",
                             "Apply policy to all environments"]},
        )]
    return []


def _check_cs_agent_shared_to_everyone(idx: dict) -> list[dict]:
    """Flag agents that appear to be shared organization-wide."""
    bots = idx.get("copilot-studio-bot", [])
    org_wide: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsPublished") and not data.get("RequiresAuthentication") and data.get("WebChannel"):
            org_wide.append({
                "Type": "CopilotStudioBot", "Name": data.get("DisplayName", ""),
                "ResourceId": data.get("BotId", ""),
            })
    if org_wide:
        return [_as_finding(
            "cs_agent_security_advanced", "cs_agent_shared_to_everyone",
            f"{len(org_wide)} published agents accessible to everyone (no auth + web channel)",
            "These agents are published, have no authentication, and have web channel "
            "enabled — anyone with the link can interact with them and potentially "
            "extract organizational data.",
            "critical", "copilot_studio", org_wide,
            {"Description": "Restrict agent access by enabling authentication and scoping sharing.",
             "PortalSteps": ["Enable authentication on the agent",
                             "Restrict sharing to specific security groups",
                             "Disable web channel if not needed"]},
        )]
    return []


def _check_cs_agent_event_triggers_ungoverned(idx: dict) -> list[dict]:
    """Flag when the Microsoft Copilot Studio connector (event triggers) is not governed."""
    blocked = _cs_dlp_blocked_connectors(idx)
    bots = idx.get("copilot-studio-bot", [])
    if not bots:
        return []
    gen_ai_count = sum(1 for b in bots
                       if b.get("Data", b.get("data", {})).get("OrchestratorEnabled"))
    if gen_ai_count > 0 and "microsoft copilot studio" not in blocked:
        return [_as_finding(
            "cs_agent_security_advanced", "cs_agent_event_triggers_ungoverned",
            f"{gen_ai_count} agents with orchestration enabled and event triggers ungoverned",
            "The 'Microsoft Copilot Studio' connector controls event triggers and automated "
            "evaluations. Without DLP governance, agents can be triggered autonomously, "
            "increasing risk of uncontrolled data processing and quota consumption.",
            "medium", "copilot_studio",
            [{"Type": "DLPGovernance", "Name": "EventTriggers",
              "ResourceId": "copilot-studio-trigger", "AffectedBotCount": gen_ai_count}],
            {"Description": "Block the 'Microsoft Copilot Studio' connector in DLP for regulated envs.",
             "PortalSteps": ["Edit DLP policy",
                             "Block 'Microsoft Copilot Studio' connector",
                             "This prevents event triggers and autonomous evaluations"]},
        )]
    return []


def _check_cs_agent_http_unrestricted(idx: dict) -> list[dict]:
    """Flag agents in environments where HTTP requests are not endpoint-filtered."""
    bots = idx.get("copilot-studio-bot", [])
    blocked = _cs_dlp_blocked_connectors(idx)
    http_terms = {"http", "http connector", "http webhook"}
    if http_terms.intersection(blocked):
        return []
    published_count = sum(1 for b in bots if b.get("Data", b.get("data", {})).get("IsPublished"))
    if published_count > 0:
        return [_as_finding(
            "cs_agent_security_advanced", "cs_agent_http_unrestricted",
            f"{published_count} published agents can make unrestricted HTTP requests",
            "The HTTP connector is not blocked and no endpoint filtering is configured. "
            "Published agents can make arbitrary HTTP calls to any URL, enabling "
            "data exfiltration to external services.",
            "high", "copilot_studio",
            [{"Type": "HTTPGovernance", "Name": "UnrestrictedHTTP",
              "ResourceId": "http-agent-risk", "PublishedBotCount": published_count}],
            {"Description": "Block HTTP connector or configure endpoint filtering.",
             "PortalSteps": ["Edit DLP policy",
                             "Block HTTP connector entirely, OR",
                             "Configure endpoint filtering to allow only approved URLs"]},
        )]
    return []


# ── Phase O: Audit, Compliance & Observability ───────────────────────

def analyze_cs_audit_compliance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess audit logging, compliance, and observability for Copilot Studio."""
    findings: list[dict] = []
    findings.extend(_check_cs_audit_purview(evidence_index))
    findings.extend(_check_cs_audit_dspm(evidence_index))
    findings.extend(_check_cs_compliance_cross_geo(evidence_index))
    findings.extend(_check_cs_compliance_region_mismatch(evidence_index))
    return findings


def _check_cs_audit_purview(idx: dict) -> list[dict]:
    """Check if unified audit logging is enabled for Copilot Studio events."""
    audit = idx.get("m365-audit-config", [])
    if not audit:
        summary = idx.get("copilot-studio-summary", [])
        if not summary:
            return []
        return [_as_finding(
            "cs_audit_compliance", "cs_audit_no_purview_integration",
            "Unable to verify Copilot Studio audit logging in Microsoft Purview",
            "Audit log configuration could not be retrieved. Copilot Studio logs both "
            "authoring events (agent create, delete, publish) and usage events "
            "(CopilotInteraction) to Microsoft Purview. Without verification, "
            "compliance gaps may exist.",
            "high", "copilot_studio",
            [{"Type": "AuditConfig", "Name": "PurviewAuditLog",
              "ResourceId": "m365-audit-config"}],
            {"Description": "Ensure unified audit logging is enabled in Microsoft Purview.",
             "PortalSteps": ["Go to Microsoft Purview portal > Audit",
                             "Click 'Start recording user and admin activity'",
                             "Verify Copilot Studio events appear in the audit log"]},
        )]
    for ev in audit:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("UnifiedAuditLogEnabled") is False:
            return [_as_finding(
                "cs_audit_compliance", "cs_audit_no_purview_integration",
                "Unified audit logging is disabled — Copilot Studio events not captured",
                "With audit logging disabled, Copilot Studio authoring events "
                "(BotCreate, BotDelete, BotPublish) and CopilotInteraction usage "
                "events are NOT being recorded. This is a compliance requirement "
                "for most regulated industries.",
                "critical", "copilot_studio",
                [{"Type": "AuditConfig", "Name": "UnifiedAuditLog",
                  "ResourceId": "m365-audit-config", "Status": "Disabled"}],
                {"Description": "Enable unified audit logging immediately.",
                 "PortalSteps": ["Go to Microsoft Purview portal > Audit",
                                 "Enable auditing",
                                 "Verify events flow within 24 hours"]},
            )]
    return []


def _check_cs_audit_dspm(idx: dict) -> list[dict]:
    """Check if DSPM for AI is configured for agent transcript review."""
    dspm = idx.get("m365-dspm-for-ai", [])
    summary = idx.get("copilot-studio-summary", [])
    if not summary:
        return []
    if not dspm:
        return [_as_finding(
            "cs_audit_compliance", "cs_audit_no_dspm_for_ai",
            "DSPM for AI not configured — no visibility into agent chat transcripts",
            "Data Security Posture Management (DSPM) for AI enables compliance teams "
            "to view chat transcripts for CopilotInteraction events. Without it, "
            "sensitive data in agent conversations goes unmonitored.",
            "high", "copilot_studio",
            [{"Type": "DSPMConfig", "Name": "DSPMForAI",
              "ResourceId": "m365-dspm-for-ai"}],
            {"Description": "Configure DSPM for AI in Microsoft Purview.",
             "PortalSteps": ["Go to Microsoft Purview portal > DSPM for AI",
                             "Enable the solution",
                             "Configure policies to monitor agent interactions"]},
        )]
    return []


def _check_cs_compliance_cross_geo(idx: dict) -> list[dict]:
    """Check if cross-geo data movement is enabled for generative AI."""
    bots = idx.get("copilot-studio-bot", [])
    gen_ai_bots = [b for b in bots
                   if b.get("Data", b.get("data", {})).get("GenerativeAnswersEnabled")]
    if not gen_ai_bots:
        return []
    envs = idx.get("pp-environment", [])
    regions = set()
    for ev in envs:
        data = ev.get("Data", ev.get("data", {}))
        region = data.get("Region", "")
        if region:
            regions.add(region.lower())
    if len(regions) > 1:
        return [_as_finding(
            "cs_audit_compliance", "cs_compliance_cross_geo_data_movement",
            f"Generative AI agents span {len(regions)} regions — cross-geo data movement risk",
            "Copilot Studio generative AI may process data outside the environment's "
            "geographic region. For regulated industries, disable data movement outside "
            "the organization's approved geography.",
            "medium", "copilot_studio",
            [{"Type": "DataResidency", "Name": "CrossGeoRisk",
              "ResourceId": "cross-geo", "Regions": sorted(regions)}],
            {"Description": "Disable cross-geo data movement for generative AI features.",
             "PortalSteps": ["Go to Power Platform admin center > Settings > Generative AI",
                             "Disable 'Move data across regions'",
                             "Consolidate agents to a single approved region"]},
        )]
    return []


def _check_cs_compliance_region_mismatch(idx: dict) -> list[dict]:
    """Flag environments in different regions from each other."""
    envs = idx.get("pp-environment", [])
    if len(envs) < 2:
        return []
    region_envs: dict[str, list[str]] = {}
    for ev in envs:
        data = ev.get("Data", ev.get("data", {}))
        region = data.get("Region", "unknown")
        name = data.get("DisplayName", data.get("EnvironmentId", ""))
        region_envs.setdefault(region, []).append(name)
    if len(region_envs) > 1:
        affected = [{"Type": "PPEnvironment", "Name": region, "ResourceId": region,
                     "EnvironmentCount": len(names)}
                    for region, names in region_envs.items()]
        return [_as_finding(
            "cs_audit_compliance", "cs_compliance_env_region_mismatch",
            f"Environments span {len(region_envs)} regions — data residency alignment needed",
            "Power Platform environments are distributed across multiple regions. "
            "Ensure this aligns with your data residency and regulatory requirements.",
            "low", "copilot_studio", affected,
            {"Description": "Review environment regions against compliance requirements.",
             "PortalSteps": ["Go to Power Platform admin center > Environments",
                             "Review the region for each environment",
                             "Migrate environments to approved regions if needed"]},
        )]
    return []


# ── Phase P: Dataverse Security & Power Platform Admin ───────────────

def analyze_cs_dataverse_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Dataverse security roles and Power Platform admin governance."""
    findings: list[dict] = []
    findings.extend(_check_cs_dv_env_maker_in_prod(evidence_index))
    findings.extend(_check_cs_dv_no_lockbox(evidence_index))
    findings.extend(_check_cs_dv_no_cmk(evidence_index))
    return findings


def _check_cs_dv_env_maker_in_prod(idx: dict) -> list[dict]:
    """Flag production environments where unrestricted maker access may exist."""
    envs = idx.get("pp-environment", [])
    prod_no_sg: list[dict] = []
    for ev in envs:
        data = ev.get("Data", ev.get("data", {}))
        sku = str(data.get("EnvironmentSku", "")).lower()
        if sku in ("production", "default"):
            if not data.get("HasSecurityGroup"):
                prod_no_sg.append({
                    "Type": "PPEnvironment", "Name": data.get("DisplayName", ""),
                    "ResourceId": data.get("EnvironmentId", ""),
                    "EnvironmentSku": data.get("EnvironmentSku", ""),
                })
    if prod_no_sg:
        return [_as_finding(
            "cs_dataverse_security", "cs_dv_env_maker_in_prod",
            f"{len(prod_no_sg)} production environments lack security group restrictions",
            "Without security groups, all licensed users in the tenant can access "
            "the environment and receive the Environment Maker role, allowing them "
            "to create apps, flows, and agents in production.",
            "high", "copilot_studio", prod_no_sg,
            {"Description": "Assign security groups to production environments.",
             "PortalSteps": ["Go to Power Platform admin center > Environments",
                             "Select the production environment > Edit",
                             "Assign a security group to restrict access",
                             "Save"]},
        )]
    return []


def _check_cs_dv_no_lockbox(idx: dict) -> list[dict]:
    """Check if Customer Lockbox is available for managed environments."""
    envs = idx.get("pp-environment", [])
    managed = [ev for ev in envs
               if ev.get("Data", ev.get("data", {})).get("IsManagedEnvironment")]
    if not managed:
        return []
    lockbox_data = idx.get("pp-tenant-settings", [])
    if lockbox_data:
        return []
    return [_as_finding(
        "cs_dataverse_security", "cs_dv_no_lockbox",
        "Customer Lockbox not verified for managed environments",
        "Customer Lockbox allows admins to approve or reject Microsoft support "
        "access to your data. For managed environments with sensitive Copilot Studio "
        "data, Lockbox provides an essential control.",
        "low", "copilot_studio",
        [{"Type": "ManagedEnv", "Name": ev.get("Data", ev.get("data", {})).get("DisplayName", ""),
          "ResourceId": ev.get("Data", ev.get("data", {})).get("EnvironmentId", "")}
         for ev in managed[:3]],
        {"Description": "Enable Customer Lockbox for managed environments.",
         "PortalSteps": ["Go to Power Platform admin center > Environments",
                         "Select managed environment > Settings",
                         "Enable Customer Lockbox"]},
    )]


def _check_cs_dv_no_cmk(idx: dict) -> list[dict]:
    """Check if Customer-Managed Keys are configured for managed environments."""
    envs = idx.get("pp-environment", [])
    managed = [ev for ev in envs
               if ev.get("Data", ev.get("data", {})).get("IsManagedEnvironment")]
    if not managed:
        return []
    return [_as_finding(
        "cs_dataverse_security", "cs_dv_no_cmk",
        "Customer-managed encryption keys (CMK) not verified",
        "Managed Environments support customer-managed encryption keys for data "
        "at rest. CMK provides an additional layer of data protection for "
        "Copilot Studio agent data stored in Dataverse.",
        "low", "copilot_studio",
        [{"Type": "ManagedEnv", "Name": ev.get("Data", ev.get("data", {})).get("DisplayName", ""),
          "ResourceId": ev.get("Data", ev.get("data", {})).get("EnvironmentId", "")}
         for ev in managed[:3]],
        {"Description": "Configure customer-managed encryption keys.",
         "PortalSteps": ["Go to Power Platform admin center > Environments",
                         "Select managed environment > Settings > Encryption",
                         "Configure customer-managed key from Azure Key Vault"]},
    )]


# ── Phase Q: Copilot Readiness Cross-Pollination ────────────────────

def analyze_cs_readiness_crosscheck(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Cross-pollinate Power Platform evidence into readiness assessment."""
    findings: list[dict] = []
    findings.extend(_check_pp_env_governance_for_readiness(evidence_index))
    findings.extend(_check_pp_dlp_coverage_for_copilot(evidence_index))
    findings.extend(_check_pp_cross_tenant_for_readiness(evidence_index))
    return findings


def _check_pp_env_governance_for_readiness(idx: dict) -> list[dict]:
    """Assess PP environment governance posture for Copilot readiness."""
    envs = idx.get("pp-environment", [])
    if not envs:
        return []
    managed_count = sum(1 for ev in envs
                        if ev.get("Data", ev.get("data", {})).get("IsManagedEnvironment"))
    total = len(envs)
    if managed_count < total:
        return [_as_finding(
            "cs_readiness_crosscheck", "pp_env_governance_for_readiness",
            f"Only {managed_count}/{total} Power Platform environments are managed",
            "Managed Environments are required for enterprise governance features "
            "including DLP enforcement, usage insights, solution checker, IP firewall, "
            "and extended backup. Unmanaged environments lack these controls.",
            "high", "copilot_studio",
            [{"Type": "PPGovernance", "Name": "ManagedEnvironments",
              "ResourceId": "pp-env-governance",
              "ManagedCount": managed_count, "TotalCount": total}],
            {"Description": "Convert all environments to Managed Environments.",
             "PortalSteps": ["Go to Power Platform admin center > Environments",
                             "Select each unmanaged environment > Edit",
                             "Enable 'Managed Environment' toggle",
                             "Configure governance settings"]},
        )]
    return []


def _check_pp_dlp_coverage_for_copilot(idx: dict) -> list[dict]:
    """Assess PP DLP policy coverage for Copilot Studio agents."""
    summary = idx.get("copilot-studio-summary", [])
    if not summary:
        return []
    s_data = summary[0].get("Data", summary[0].get("data", {}))
    dlp_count = s_data.get("DLPPolicies", 0)
    bot_count = s_data.get("TotalBots", 0)
    if bot_count > 0 and dlp_count == 0:
        return [_as_finding(
            "cs_readiness_crosscheck", "pp_dlp_coverage_for_copilot",
            f"{bot_count} Copilot Studio agents with zero DLP policies",
            "No DLP policies govern Copilot Studio agent connector usage. "
            "This is a critical governance gap for Copilot readiness.",
            "critical", "copilot_studio",
            [{"Type": "PPGovernance", "Name": "DLPCoverage",
              "ResourceId": "pp-dlp-coverage",
              "DLPCount": dlp_count, "BotCount": bot_count}],
            {"Description": "Create DLP policies governing Copilot Studio connectors.",
             "PortalSteps": ["Go to Power Platform admin center > Data policies",
                             "Create tenant-wide baseline DLP policy",
                             "Classify Copilot Studio virtual connectors"]},
        )]
    return []


def _check_pp_cross_tenant_for_readiness(idx: dict) -> list[dict]:
    """Flag cross-tenant isolation gap for Copilot readiness."""
    envs = idx.get("pp-environment", [])
    if not envs:
        return []
    any_isolated = any(ev.get("Data", ev.get("data", {})).get("CrossTenantIsolation")
                       for ev in envs)
    if any_isolated:
        return []
    bots = idx.get("copilot-studio-bot", [])
    if bots:
        return [_as_finding(
            "cs_readiness_crosscheck", "pp_cross_tenant_for_readiness",
            "Cross-tenant isolation not enabled with active Copilot Studio agents",
            "Power Platform connectors can establish cross-tenant connections. "
            "With Copilot Studio agents active, this creates a data exfiltration "
            "risk that affects Copilot deployment readiness.",
            "high", "copilot_studio",
            [{"Type": "PPGovernance", "Name": "CrossTenantIsolation",
              "ResourceId": "pp-cross-tenant", "BotCount": len(bots)}],
            {"Description": "Enable tenant isolation before Copilot deployment.",
             "PortalSteps": ["Go to Power Platform admin center > Security",
                             "Enable tenant isolation",
                             "Add partner tenants to the allow list as needed"]},
        )]
    return []

