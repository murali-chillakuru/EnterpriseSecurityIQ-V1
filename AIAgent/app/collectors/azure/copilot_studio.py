"""
Copilot Studio & Power Platform Security Collector
Collects: Copilot Studio bot/agent configurations, DLP policies on Power Platform,
connector restrictions, authentication settings, conversation logging,
Power Platform environment settings.

Uses Power Platform admin REST APIs and Microsoft Graph beta endpoints.
"""

from __future__ import annotations
import asyncio
import aiohttp
from app.models import Source
from app.collectors.base import run_collector, make_evidence, AccessDeniedError
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

# Power Platform admin base URIs
_PP_ADMIN_API = "https://api.bap.microsoft.com"
_PP_API_VERSION = "2021-04-01"

_CONCURRENCY = asyncio.Semaphore(4)


async def _get_pp_token(creds: ComplianceCredentials) -> str:
    """Get access token for Power Platform admin API."""
    token = await creds.credential.get_token("https://api.bap.microsoft.com/.default")
    return token.token


async def _pp_get(session: aiohttp.ClientSession, url: str, token: str) -> dict | list | None:
    """Make an authenticated GET request to Power Platform admin API."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    async with session.get(url, headers=headers) as resp:
        if resp.status in (401, 403):
            raise AccessDeniedError(api=url, status=resp.status)
        if resp.status == 404:
            return None
        resp.raise_for_status()
        return await resp.json()


@register_collector(name="copilot_studio", plane="control", source="azure", priority=185)
async def collect_copilot_studio(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:  # noqa: ARG001
    """Collect Copilot Studio and Power Platform security configuration."""

    async def _collect():
        evidence: list[dict] = []
        beta = creds.get_graph_beta_client()

        # ── 1. Power Platform environments ───────────────────────────
        try:
            token = await _get_pp_token(creds)
            async with aiohttp.ClientSession() as session:
                env_url = f"{_PP_ADMIN_API}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version={_PP_API_VERSION}"
                env_data = await _pp_get(session, env_url, token)
                environments = (env_data or {}).get("value", []) if isinstance(env_data, dict) else []

                for env in environments:
                    props = env.get("properties", {})
                    env_name = env.get("name", "")
                    display = props.get("displayName", env_name)
                    env_type = props.get("environmentSku", "")
                    state = props.get("states", {}).get("runtime", {}).get("id", "")
                    governance = props.get("governanceConfiguration", {})
                    security = props.get("securityConfiguration", {})

                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="CopilotStudio",
                        evidence_type="pp-environment",
                        description=f"Power Platform environment: {display}",
                        data={
                            "EnvironmentId": env_name,
                            "DisplayName": display,
                            "EnvironmentSku": env_type,
                            "State": state,
                            "Region": props.get("azureRegion", ""),
                            "IsDefault": props.get("isDefault", False),
                            "SecurityGroupId": props.get("securityGroupId", ""),
                            "HasSecurityGroup": bool(props.get("securityGroupId")),
                            "GovernanceMode": governance.get("protectionLevel", ""),
                            "IsManagedEnvironment": governance.get("protectionLevel", "").lower() == "managed",
                            "DLPEnforcement": security.get("dlpEnforcement", ""),
                            "CrossTenantIsolation": security.get("crossTenantIsolation", ""),
                        },
                        resource_id=env_name, resource_type="PowerPlatformEnvironment",
                    ))

                log.info("  [CopilotStudio] Discovered %d Power Platform environments", len(environments))

                # ── 2. DLP policies on Power Platform ────────────────
                dlp_url = f"{_PP_ADMIN_API}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version={_PP_API_VERSION}"
                dlp_data = await _pp_get(session, dlp_url, token)
                dlp_policies = (dlp_data or {}).get("value", []) if isinstance(dlp_data, dict) else []

                for pol in dlp_policies:
                    pol_props = pol.get("properties", {})
                    pol_name = pol.get("name", "")
                    display = pol_props.get("displayName", pol_name)
                    env_type_filter = pol_props.get("environmentType", "")
                    created = pol_props.get("createdTime", "")

                    connector_groups = pol_props.get("connectorGroups", [])
                    business_data_count = 0
                    non_business_count = 0
                    blocked_count = 0
                    blocked_names: list[str] = []
                    for group in connector_groups:
                        classification = group.get("classification", "").lower()
                        connectors = group.get("connectors", [])
                        connector_count = len(connectors)
                        if classification == "confidential":
                            business_data_count = connector_count
                        elif classification == "general":
                            non_business_count = connector_count
                        elif classification == "blocked":
                            blocked_count = connector_count
                            for conn in connectors:
                                cname = conn.get("name", conn.get("id", ""))
                                if cname:
                                    blocked_names.append(cname)

                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="CopilotStudio",
                        evidence_type="pp-dlp-policy",
                        description=f"Power Platform DLP policy: {display}",
                        data={
                            "PolicyId": pol_name,
                            "DisplayName": display,
                            "EnvironmentType": env_type_filter,
                            "CreatedTime": created,
                            "BusinessDataConnectors": business_data_count,
                            "NonBusinessConnectors": non_business_count,
                            "BlockedConnectors": blocked_count,
                            "BlockedConnectorNames": blocked_names,
                            "HasBlockedConnectors": blocked_count > 0,
                        },
                        resource_id=pol_name, resource_type="PPDLPPolicy",
                    ))

                log.info("  [CopilotStudio] Collected %d DLP policies", len(dlp_policies))

                # ── 3. Copilot Studio bots per environment ───────────
                total_bots = 0
                for env in environments[:10]:  # Sample up to 10 environments
                    env_name = env.get("name", "")
                    env_display = env.get("properties", {}).get("displayName", env_name)
                    async with _CONCURRENCY:
                        try:
                            bots_url = (
                                f"{_PP_ADMIN_API}/providers/Microsoft.BusinessAppPlatform"
                                f"/scopes/admin/environments/{env_name}/bots"
                                f"?api-version={_PP_API_VERSION}"
                            )
                            bots_data = await _pp_get(session, bots_url, token)
                            bots = (bots_data or {}).get("value", []) if isinstance(bots_data, dict) else []

                            for bot in bots:
                                bot_props = bot.get("properties", {})
                                bot_name = bot.get("name", "")
                                bot_display = bot_props.get("displayName", bot_name)
                                auth_config = bot_props.get("authenticationConfiguration", {})

                                # Generative AI settings
                                gen_ai = bot_props.get("generativeAiSettings", bot_props.get("generativeSettings", {})) or {}
                                # Knowledge sources
                                raw_ks = bot_props.get("knowledgeSources", bot_props.get("knowledgeConfiguration", {}).get("sources", [])) or []
                                knowledge_sources = []
                                for ks in raw_ks:
                                    knowledge_sources.append({
                                        "Type": ks.get("type", ks.get("sourceType", "unknown")),
                                        "Name": ks.get("displayName", ks.get("name", "")),
                                        "IsOrgWide": ks.get("isOrgWide", ks.get("scope", "").lower() == "organization"),
                                        "Endpoint": ks.get("endpoint", ks.get("url", "")),
                                    })
                                # Connector associations
                                raw_connectors = bot_props.get("connectorAssociations", bot_props.get("connectors", [])) or []
                                custom_connectors = []
                                premium_connectors = []
                                for conn in raw_connectors:
                                    tier = str(conn.get("tier", conn.get("connectorTier", ""))).lower()
                                    conn_entry = {
                                        "Name": conn.get("displayName", conn.get("name", "")),
                                        "HasAuthentication": bool(conn.get("authenticationConfiguration") or conn.get("hasAuth")),
                                    }
                                    if tier == "premium" or conn.get("isPremium"):
                                        premium_connectors.append(conn_entry["Name"])
                                    if conn.get("isCustom") or tier == "custom":
                                        custom_connectors.append(conn_entry)
                                # Publication / solution governance
                                bot_state = bot_props.get("state", "").lower()
                                is_published = bot_state in ("published", "active") or bot_props.get("isPublished", False)
                                solution_id = bot_props.get("solutionId", bot_props.get("solutionComponentId", ""))
                                teams_cfg = bot_props.get("teamsChannel", {}) or {}

                                evidence.append(make_evidence(
                                    source=Source.ENTRA, collector="CopilotStudio",
                                    evidence_type="copilot-studio-bot",
                                    description=f"Copilot Studio bot: {bot_display}",
                                    data={
                                        "BotId": bot_name,
                                        "DisplayName": bot_display,
                                        "EnvironmentId": env_name,
                                        "EnvironmentName": env_display,
                                        "State": bot_props.get("state", ""),
                                        "AuthMode": auth_config.get("authenticationTrigger", ""),
                                        "RequiresAuthentication": auth_config.get("isAuthenticationRequired", False),
                                        "AllowedAuthProviders": auth_config.get("allowedAuthenticationProviders", []),
                                        "HasConversationLogging": bot_props.get("isConversationLoggingEnabled", False),
                                        "WebChannel": bot_props.get("webChannel", {}).get("isEnabled", False),
                                        "TeamsChannel": teams_cfg.get("isEnabled", False),
                                        "TeamsSSOEnabled": teams_cfg.get("isSsoEnabled", teams_cfg.get("ssoEnabled", False)),
                                        "ModifiedTime": bot_props.get("modifiedTime", ""),
                                        # Knowledge sources
                                        "KnowledgeSources": knowledge_sources,
                                        # Generative AI settings
                                        "GenerativeAnswersEnabled": gen_ai.get("isGenerativeAnswersEnabled", gen_ai.get("isEnabled", False)),
                                        "ContentModerationEnabled": gen_ai.get("isContentModerationEnabled", gen_ai.get("contentModeration", False)),
                                        "OrchestratorEnabled": gen_ai.get("isOrchestratorEnabled", gen_ai.get("orchestratorEnabled", False)),
                                        "TopicRestrictionEnabled": gen_ai.get("isTopicRestrictionEnabled", gen_ai.get("topicRestriction", False)),
                                        # Governance
                                        "IsPublished": is_published,
                                        "IsSolutionAware": bool(solution_id),
                                        "SolutionId": solution_id,
                                        "HasConfiguredConnectors": bool(raw_connectors),
                                        # Connectors
                                        "CustomConnectors": custom_connectors,
                                        "PremiumConnectors": premium_connectors,
                                    },
                                    resource_id=bot_name, resource_type="CopilotStudioBot",
                                ))
                                total_bots += 1

                        except AccessDeniedError:
                            log.debug("  [CopilotStudio] Bots access denied for env: %s", env_display)
                        except Exception as exc:
                            log.debug("  [CopilotStudio] Bots for env '%s' failed: %s", env_display, exc)

                log.info("  [CopilotStudio] Collected %d Copilot Studio bots", total_bots)

                # ── 3b. Custom connectors per environment ────────────
                total_connectors = 0
                for env in environments[:10]:
                    env_name = env.get("name", "")
                    env_display = env.get("properties", {}).get("displayName", env_name)
                    async with _CONCURRENCY:
                        try:
                            conn_url = (
                                f"{_PP_ADMIN_API}/providers/Microsoft.BusinessAppPlatform"
                                f"/scopes/admin/environments/{env_name}/connectors"
                                f"?api-version={_PP_API_VERSION}"
                            )
                            conn_data = await _pp_get(session, conn_url, token)
                            connectors = (conn_data or {}).get("value", []) if isinstance(conn_data, dict) else []
                            for conn in connectors:
                                conn_props = conn.get("properties", {})
                                conn_name = conn.get("name", "")
                                conn_display = conn_props.get("displayName", conn_name)
                                auth_def = conn_props.get("connectionParameters", {})
                                has_auth = bool(auth_def.get("token") or auth_def.get("oauthSettings")
                                                or conn_props.get("authType", "").lower() not in ("", "anonymous", "none"))
                                evidence.append(make_evidence(
                                    source=Source.ENTRA, collector="CopilotStudio",
                                    evidence_type="pp-custom-connector",
                                    description=f"Custom connector: {conn_display}",
                                    data={
                                        "ConnectorId": conn_name,
                                        "DisplayName": conn_display,
                                        "EnvironmentId": env_name,
                                        "EnvironmentName": env_display,
                                        "HasAuthentication": has_auth,
                                        "AuthType": conn_props.get("authType", ""),
                                        "IsPremium": conn_props.get("tier", "").lower() == "premium",
                                        "IsCustom": True,
                                    },
                                    resource_id=conn_name, resource_type="PPCustomConnector",
                                ))
                                total_connectors += 1
                        except AccessDeniedError:
                            log.debug("  [CopilotStudio] Connectors access denied for env: %s", env_display)
                        except Exception as exc:
                            log.debug("  [CopilotStudio] Connectors for env '%s' failed: %s", env_display, exc)

                log.info("  [CopilotStudio] Collected %d custom connectors", total_connectors)

        except AccessDeniedError:
            log.warning("  [CopilotStudio] Power Platform admin API access denied")
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="CopilotStudio",
                evidence_type="pp-access-denied",
                description="Power Platform admin API access denied",
                data={"AccessDenied": True, "API": "PowerPlatformAdmin"},
                resource_id="pp-access-denied", resource_type="AccessDenied",
            ))
        except Exception as exc:
            log.warning("  [CopilotStudio] Power Platform collection failed: %s", exc)

        # ── 4. M365 Copilot settings (Graph beta) ───────────────────
        # Requires OrgSettings.Read.All delegated scope (not in Azure CLI's
        # pre-consented scope set).
        try:
            # admin/microsoft365Apps/installationOptions for Copilot settings
            apps_settings = await beta.admin.microsoft365_apps.installation_options.get()
            if apps_settings:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="CopilotStudio",
                    evidence_type="m365-copilot-settings",
                    description="M365 Copilot installation/deployment settings",
                    data={
                        "UpdateChannel": getattr(apps_settings, "update_channel", "") or "",
                        "AppsForWindows": str(getattr(apps_settings, "apps_for_windows", None)),
                        "AppsForMac": str(getattr(apps_settings, "apps_for_mac", None)),
                    },
                    resource_id="m365-copilot-settings", resource_type="M365CopilotSettings",
                ))
        except Exception as exc:
            exc_str = str(exc).lower()
            if "403" in exc_str or "forbidden" in exc_str or "denied" in exc_str:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="CopilotStudio",
                    evidence_type="m365-copilot-settings-warning",
                    description="M365 Copilot settings inaccessible — missing OrgSettings.Read.All scope",
                    data={
                        "Error": "403 Forbidden",
                        "RequiredScope": "OrgSettings.Read.All",
                        "Reason": "The Graph API endpoint admin/microsoft365Apps/installationOptions "
                                  "requires the OrgSettings.Read.All delegated permission. The Azure CLI "
                                  "first-party app does not include this scope in its pre-consented set.",
                        "Workaround": "Use a custom app registration with OrgSettings.Read.All granted, "
                                      "or verify deployment configuration manually in M365 admin center.",
                    },
                    resource_id="m365-copilot-settings-warning", resource_type="CollectionWarning",
                ))
                log.warning("  [CopilotStudio] M365 Copilot settings 403 — OrgSettings.Read.All scope missing")
            else:
                log.debug("  [CopilotStudio] M365 Copilot settings check failed: %s", exc)

        # ── 5. Audit log configuration check ─────────────────────────
        try:
            # Probe the unified audit log endpoint — a successful response
            # (even if empty) confirms unified audit logging is enabled.
            audit_queries = await beta.security.audit_log.queries.get()
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="CopilotStudio",
                evidence_type="m365-audit-config",
                description="M365 audit log configuration",
                data={
                    "UnifiedAuditLogEnabled": True,
                    "AuditQueryCount": len(getattr(audit_queries, "value", []) or []) if audit_queries else 0,
                },
                resource_id="m365-audit-config", resource_type="AuditConfig",
            ))
        except Exception as exc:
            exc_str = str(exc).lower()
            if "403" in exc_str or "access" in exc_str or "denied" in exc_str or "forbidden" in exc_str:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="CopilotStudio",
                    evidence_type="m365-audit-config",
                    description="M365 audit log configuration (access denied)",
                    data={
                        "UnifiedAuditLogEnabled": "unknown",
                        "Note": "Security Reader role is required to probe the audit log endpoint. "
                                "Assign the role and re-run the assessment.",
                    },
                    resource_id="m365-audit-config", resource_type="AuditConfig",
                ))
                log.warning("  [CopilotStudio] Audit log probe 403 — need Security Reader role")
            else:
                log.debug("  [CopilotStudio] Audit config check failed: %s", exc)

        # Summary
        env_count = sum(1 for e in evidence if e.get("EvidenceType") == "pp-environment")
        dlp_count = sum(1 for e in evidence if e.get("EvidenceType") == "pp-dlp-policy")
        bot_count = sum(1 for e in evidence if e.get("EvidenceType") == "copilot-studio-bot")
        connector_count = sum(1 for e in evidence if e.get("EvidenceType") == "pp-custom-connector")
        managed_envs = sum(
            1 for e in evidence
            if e.get("EvidenceType") == "pp-environment"
            and (e.get("Data", e.get("data", {})).get("IsManagedEnvironment"))
        )

        evidence.append(make_evidence(
            source=Source.ENTRA, collector="CopilotStudio",
            evidence_type="copilot-studio-summary",
            description="Copilot Studio & Power Platform summary",
            data={
                "TotalEnvironments": env_count,
                "ManagedEnvironments": managed_envs,
                "UnmanagedEnvironments": env_count - managed_envs,
                "DLPPolicies": dlp_count,
                "TotalBots": bot_count,
                "TotalCustomConnectors": connector_count,
                "HasDLPPolicies": dlp_count > 0,
            },
            resource_id="copilot-studio-summary", resource_type="CopilotStudioSummary",
        ))

        log.info(
            "  [CopilotStudio] Collection complete: %d total evidence records",
            len(evidence),
        )
        return evidence

    return (await run_collector("CopilotStudio", Source.ENTRA, _collect)).data
