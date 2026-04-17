"""Copilot Studio extended evaluators — knowledge sources, generative AI, governance, connector security."""

from __future__ import annotations

from .finding import _as_finding


def analyze_cs_knowledge_sources(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess knowledge source security for Copilot Studio agents."""
    findings: list[dict] = []
    findings.extend(_check_cs_overshared_knowledge(evidence_index))
    findings.extend(_check_cs_external_knowledge(evidence_index))
    findings.extend(_check_cs_public_website_source(evidence_index))
    return findings


def _check_cs_overshared_knowledge(idx: dict) -> list[dict]:
    """Flag Copilot Studio bots with overshared knowledge sources."""
    bots = idx.get("copilot-studio-bot", [])
    overshared: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        sources = data.get("KnowledgeSources", [])
        for src in sources:
            src_type = str(src.get("Type", "")).lower()
            if src_type in ("sharepoint", "dataverse") and src.get("IsOrgWide"):
                overshared.append({
                    "Type": "CopilotStudioBot",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("BotId", ""),
                    "KnowledgeSourceType": src_type,
                    "KnowledgeSourceName": src.get("Name", ""),
                })
    if overshared:
        return [_as_finding(
            "cs_knowledge_sources", "overshared_knowledge_source",
            f"{len(overshared)} agents connect to org-wide knowledge sources",
            "Agents with SharePoint or Dataverse knowledge sources scoped to the "
            "entire organization may expose sensitive documents to all agent users.",
            "high", "copilot_studio", overshared,
            {"Description": "Restrict knowledge sources to specific sites or tables with appropriate permissions.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Go to Knowledge > Manage sources",
                             "Replace org-wide SharePoint with scoped site collections",
                             "Apply row-level security for Dataverse sources"]},
        )]
    return []


def _check_cs_external_knowledge(idx: dict) -> list[dict]:
    """Flag Copilot Studio bots using external (non-Microsoft) knowledge sources."""
    bots = idx.get("copilot-studio-bot", [])
    external: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        sources = data.get("KnowledgeSources", [])
        for src in sources:
            src_type = str(src.get("Type", "")).lower()
            if src_type in ("http", "api", "external", "website", "custom"):
                external.append({
                    "Type": "CopilotStudioBot",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("BotId", ""),
                    "KnowledgeSourceType": src_type,
                    "Endpoint": src.get("Endpoint", ""),
                })
    if external:
        return [_as_finding(
            "cs_knowledge_sources", "external_knowledge_source",
            f"{len(external)} agents use external (non-Microsoft) knowledge sources",
            "External HTTP or API knowledge sources may introduce data exfiltration risks "
            "and bypass organizational DLP controls.",
            "medium", "copilot_studio", external,
            {"Description": "Review and restrict external knowledge source endpoints.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Go to Knowledge > Review external sources",
                             "Validate endpoints against approved URLs",
                             "Consider migrating to managed SharePoint or Dataverse sources"]},
        )]
    return []


def _check_cs_public_website_source(idx: dict) -> list[dict]:
    """Flag bots with knowledge sources pointing to public website URLs."""
    bots = idx.get("copilot-studio-bot", [])
    public_urls: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        sources = data.get("KnowledgeSources", [])
        for src in sources:
            src_type = str(src.get("Type", "")).lower()
            endpoint = str(src.get("Endpoint", ""))
            if src_type in ("website", "public_website", "url") or (
                endpoint.startswith("http") and "sharepoint" not in endpoint.lower()
                and "dataverse" not in endpoint.lower()
            ):
                public_urls.append({
                    "Type": "CopilotStudioBot",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("BotId", ""),
                    "SourceType": src_type,
                    "Endpoint": endpoint,
                })
    if public_urls:
        return [_as_finding(
            "cs_knowledge_sources", "public_website_source",
            f"{len(public_urls)} agents use public website URLs as knowledge sources",
            "Public websites as knowledge sources can be manipulated by third parties "
            "(content poisoning), may contain outdated information, and bypass DLP controls.",
            "medium", "copilot_studio", public_urls,
            {"Description": "Replace public website knowledge sources with controlled internal sources.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Go to Knowledge > Review sources",
                             "Replace public URLs with curated SharePoint sites",
                             "If a public URL is required, restrict to specific pages"]},
        )]
    return []


# ── 4c. Generative AI Controls ──────────────────────────────────────

def analyze_cs_generative_ai(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess generative AI controls for Copilot Studio agents."""
    findings: list[dict] = []
    findings.extend(_check_cs_generative_answers_guardrails(evidence_index))
    findings.extend(_check_cs_generative_orchestration(evidence_index))
    return findings


def _check_cs_generative_answers_guardrails(idx: dict) -> list[dict]:
    """Flag bots with generative answers but no content moderation."""
    bots = idx.get("copilot-studio-bot", [])
    no_guardrails: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("GenerativeAnswersEnabled") and not data.get("ContentModerationEnabled"):
            no_guardrails.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
            })
    if no_guardrails:
        return [_as_finding(
            "cs_generative_ai", "generative_answers_no_guardrails",
            f"{len(no_guardrails)} agents have generative answers without content moderation",
            "Generative answers without content moderation can produce harmful, "
            "inaccurate, or policy-violating responses.",
            "high", "copilot_studio", no_guardrails,
            {"Description": "Enable content moderation for generative AI features.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Go to Settings > Generative AI",
                             "Enable content moderation and set moderation level",
                             "Configure topic-level fallback behavior"]},
        )]
    return []


def _check_cs_generative_orchestration(idx: dict) -> list[dict]:
    """Flag bots with unrestricted generative orchestration."""
    bots = idx.get("copilot-studio-bot", [])
    unrestricted: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("OrchestratorEnabled") and not data.get("TopicRestrictionEnabled"):
            unrestricted.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
            })
    if unrestricted:
        return [_as_finding(
            "cs_generative_ai", "generative_orchestration_unrestricted",
            f"{len(unrestricted)} agents have unrestricted generative orchestration",
            "Generative orchestration without topic-level restrictions allows the agent "
            "to respond to any prompt, increasing risk of off-topic or harmful responses.",
            "medium", "copilot_studio", unrestricted,
            {"Description": "Enable topic restrictions for generative orchestration.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Go to Topics > Configure orchestration",
                             "Enable topic-level restrictions",
                             "Define allowed/blocked topics for generative responses"]},
        )]
    return []


# ── 4d. Governance Controls ─────────────────────────────────────────

def analyze_cs_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess governance controls for Copilot Studio agents."""
    findings: list[dict] = []
    findings.extend(_check_cs_unpublished_bot_secrets(evidence_index))
    findings.extend(_check_cs_solution_awareness(evidence_index))
    findings.extend(_check_cs_draft_bot_stale(evidence_index))
    return findings


def _check_cs_unpublished_bot_secrets(idx: dict) -> list[dict]:
    """Flag unpublished bots that have configured credentials."""
    bots = idx.get("copilot-studio-bot", [])
    risky: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("IsPublished") and data.get("HasConfiguredConnectors"):
            risky.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
                "EnvironmentName": data.get("EnvironmentName", ""),
            })
    if risky:
        return [_as_finding(
            "cs_governance", "unpublished_bot_with_secrets",
            f"{len(risky)} unpublished agents have configured connectors with credentials",
            "Draft agents with active connector credentials pose a risk if the "
            "environment is compromised — credentials may be extracted before the agent is published.",
            "medium", "copilot_studio", risky,
            {"Description": "Remove connector credentials from unpublished agents or publish them.",
             "PortalSteps": ["Go to Copilot Studio > Select the agent",
                             "Review configured connectors",
                             "Remove credentials from draft agents or publish the agent",
                             "Use managed connections where possible"]},
        )]
    return []


def _check_cs_solution_awareness(idx: dict) -> list[dict]:
    """Flag bots not deployed via managed solutions."""
    bots = idx.get("copilot-studio-bot", [])
    unmanaged: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsPublished") and not data.get("IsSolutionAware"):
            unmanaged.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
            })
    if unmanaged:
        return [_as_finding(
            "cs_governance", "bot_not_solution_aware",
            f"{len(unmanaged)} published agents are not solution-aware (ungoverned ALM)",
            "Agents not deployed via managed solutions bypass ALM controls, "
            "making version tracking, export, and environment promotion difficult.",
            "low", "copilot_studio", unmanaged,
            {"Description": "Add agents to managed solutions for proper ALM governance.",
             "PortalSteps": ["Go to Power Apps > Solutions",
                             "Create or select a solution",
                             "Add existing > Chatbot > Select the agent",
                             "Use solution export/import for environment promotion"]},
            compliance_status="partial",
        )]
    return []


def _check_cs_draft_bot_stale(idx: dict) -> list[dict]:
    """Flag unpublished bots that have been idle for >90 days."""
    from datetime import datetime, timezone, timedelta
    bots = idx.get("copilot-studio-bot", [])
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    stale: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsPublished"):
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
                    "EnvironmentName": data.get("EnvironmentName", ""),
                })
        except (ValueError, TypeError):
            continue
    if stale:
        return [_as_finding(
            "cs_governance", "draft_bot_stale",
            f"{len(stale)} unpublished agents have been idle for >90 days",
            "Stale draft agents may contain outdated configurations, test credentials, "
            "or unused connector associations. They increase the attack surface without "
            "providing value.",
            "low", "copilot_studio", stale,
            {"Description": "Delete or archive stale draft agents.",
             "PortalSteps": ["Go to Copilot Studio > View all agents",
                             "Identify agents last modified >90 days ago",
                             "Delete draft agents that are no longer needed",
                             "For agents worth keeping, publish or migrate to a solution"]},
        )]
    return []


# ── 4e. Connector Security ──────────────────────────────────────────

def analyze_cs_connector_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess connector security for Copilot Studio agents."""
    findings: list[dict] = []
    findings.extend(_check_cs_custom_connector_auth(evidence_index))
    findings.extend(_check_cs_premium_connector_dlp(evidence_index))
    findings.extend(_check_cs_connector_no_dlp_coverage(evidence_index))
    return findings


def _check_cs_custom_connector_auth(idx: dict) -> list[dict]:
    """Flag custom connectors without authentication (from bot data + environment connectors)."""
    no_auth: list[dict] = []
    # Check bot-level connector associations
    bots = idx.get("copilot-studio-bot", [])
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        connectors = data.get("CustomConnectors", [])
        for conn in connectors:
            if not conn.get("HasAuthentication"):
                no_auth.append({
                    "Type": "CopilotStudioBot",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("BotId", ""),
                    "ConnectorName": conn.get("Name", ""),
                })
    # Check environment-level custom connectors
    env_connectors = idx.get("pp-custom-connector", [])
    seen_ids: set[str] = set()
    for ev in env_connectors:
        data = ev.get("Data", ev.get("data", {}))
        cid = data.get("ConnectorId", "")
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        if not data.get("HasAuthentication"):
            no_auth.append({
                "Type": "PPCustomConnector",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": cid,
                "EnvironmentName": data.get("EnvironmentName", ""),
            })
    if no_auth:
        return [_as_finding(
            "cs_connector_security", "custom_connector_no_auth",
            f"{len(no_auth)} custom connectors lack authentication configuration",
            "Custom connectors without authentication allow unauthenticated access to "
            "backend APIs, creating a potential data exposure vector.",
            "high", "copilot_studio", no_auth,
            {"Description": "Configure authentication on all custom connectors.",
             "PortalSteps": ["Go to Power Apps > Custom connectors",
                             "Select the connector > Edit",
                             "Go to Security tab > Configure authentication (OAuth 2.0 or API key)",
                             "Update and test the connector"]},
        )]
    return []


def _check_cs_premium_connector_dlp(idx: dict) -> list[dict]:
    """Flag premium connectors in use without DLP coverage."""
    bots = idx.get("copilot-studio-bot", [])
    summary = idx.get("copilot-studio-summary", [])
    dlp_count = 0
    for ev in summary:
        dlp_count = ev.get("Data", ev.get("data", {})).get("DLPPolicies", 0)

    if dlp_count > 0:
        return []

    uncontrolled: list[dict] = []
    for ev in bots:
        data = ev.get("Data", ev.get("data", {}))
        premium = data.get("PremiumConnectors", [])
        if premium:
            uncontrolled.append({
                "Type": "CopilotStudioBot",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("BotId", ""),
                "PremiumConnectors": str(premium),
            })
    if uncontrolled:
        return [_as_finding(
            "cs_connector_security", "premium_connector_uncontrolled",
            f"{len(uncontrolled)} agents use premium connectors without DLP coverage",
            "Premium connectors (e.g., SQL, HTTP, custom) access external/sensitive data. "
            "Without DLP policies, their usage is ungoverned.",
            "medium", "copilot_studio", uncontrolled,
            {"Description": "Create DLP policies to govern premium connector usage.",
             "PortalSteps": ["Go to Power Platform admin center > Policies > Data policies",
                             "Create a policy blocking non-business premium connectors",
                             "Apply to environments used by Copilot Studio agents"]},
        )]
    return []


def _check_cs_connector_no_dlp_coverage(idx: dict) -> list[dict]:
    """Flag environments with custom connectors but no DLP policy covering them."""
    summary = idx.get("copilot-studio-summary", [])
    dlp_count = 0
    for ev in summary:
        dlp_count = ev.get("Data", ev.get("data", {})).get("DLPPolicies", 0)
    if dlp_count > 0:
        return []
    env_connectors = idx.get("pp-custom-connector", [])
    if not env_connectors:
        return []
    # Group by environment
    envs: dict[str, list[str]] = {}
    for ev in env_connectors:
        data = ev.get("Data", ev.get("data", {}))
        env_name = data.get("EnvironmentName", data.get("EnvironmentId", ""))
        envs.setdefault(env_name, []).append(data.get("DisplayName", ""))
    affected = [
        {"Type": "PowerPlatformEnvironment", "Name": env,
         "ResourceId": env, "ConnectorCount": len(conns)}
        for env, conns in envs.items()
    ]
    if affected:
        return [_as_finding(
            "cs_connector_security", "connector_no_dlp_coverage",
            f"{len(affected)} environments have custom connectors without DLP policies",
            "Custom connectors in environments without DLP policies can transfer data "
            "between business and non-business categories without restriction.",
            "medium", "copilot_studio", affected,
            {"Description": "Create DLP policies that classify custom connectors appropriately.",
             "PortalSteps": ["Go to Power Platform admin center > Policies > Data policies",
                             "Create a new policy or edit an existing one",
                             "Move custom connectors to the Business or Blocked category",
                             "Apply the policy to all affected environments"]},
        )]
    return []

