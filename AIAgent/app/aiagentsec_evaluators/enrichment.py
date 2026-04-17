"""
AI Agent Security — Compliance mapping enrichment.

Maps AI agent security findings to 13 compliance frameworks:
  11 standard (CIS, NIST-800-53, NIST-CSF, ISO-27001, PCI-DSS, HIPAA,
               SOC2, GDPR, FedRAMP, MCSB, CSA-CCM)
  2 AI-specific (NIST-AI-RMF, OWASP-LLM)
"""
from __future__ import annotations

# ── subcategory → { framework → [control_ids] } ──────────────────────────

_AUTH_FW = {"CIS": ["1.1.1", "1.2.1"], "NIST-800-53": ["IA-2", "IA-8"], "NIST-CSF": ["PR.AC-1", "PR.AC-7"], "ISO-27001": ["A.5.17", "A.8.5"], "PCI-DSS": ["8.3.1", "8.4.2"], "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1"], "GDPR": ["Art.32(1)"], "FedRAMP": ["IA-2", "IA-8"], "MCSB": ["IM-1", "IM-3"], "CSA-CCM": ["IAM-02", "IAM-08"], "NIST-AI-RMF": ["GOVERN 1.4", "MAP 1.1"], "OWASP-LLM": ["LLM06"]}
_AUTH_STRONG = {"CIS": ["1.1.1"], "NIST-800-53": ["IA-2(1)", "IA-2(2)"], "NIST-CSF": ["PR.AC-7"], "ISO-27001": ["A.8.5"], "PCI-DSS": ["8.4.2"], "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1"], "GDPR": ["Art.32(1)"], "FedRAMP": ["IA-2(1)"], "MCSB": ["IM-1"], "CSA-CCM": ["IAM-02"], "NIST-AI-RMF": ["GOVERN 1.4"], "OWASP-LLM": ["LLM06"]}
_DLP_FW = {"CIS": ["3.1", "3.12"], "NIST-800-53": ["SC-28", "MP-4"], "NIST-CSF": ["PR.DS-1", "PR.DS-5"], "ISO-27001": ["A.8.10", "A.8.12"], "PCI-DSS": ["3.4", "3.5.1"], "HIPAA": ["164.312(a)(1)", "164.312(e)(1)"], "SOC2": ["CC6.7"], "GDPR": ["Art.25(1)", "Art.32(1)"], "FedRAMP": ["SC-28", "MP-4"], "MCSB": ["DP-2", "DP-3"], "CSA-CCM": ["DSP-05", "DSP-10"], "NIST-AI-RMF": ["MANAGE 2.2", "GOVERN 1.5"], "OWASP-LLM": ["LLM06"]}
_ENCRYPT_FW = {"CIS": ["3.9", "3.10"], "NIST-800-53": ["SC-28(1)", "SC-12"], "NIST-CSF": ["PR.DS-1"], "ISO-27001": ["A.8.24"], "PCI-DSS": ["3.5.1"], "HIPAA": ["164.312(a)(2)(iv)"], "SOC2": ["CC6.1"], "GDPR": ["Art.32(1)"], "FedRAMP": ["SC-28(1)"], "MCSB": ["DP-4"], "CSA-CCM": ["DSP-10", "CEK-03"], "NIST-AI-RMF": ["MANAGE 2.2"], "OWASP-LLM": ["LLM06"]}
_NET_FW = {"CIS": ["6.1", "6.4"], "NIST-800-53": ["SC-7", "SC-7(5)"], "NIST-CSF": ["PR.AC-5", "PR.PT-4"], "ISO-27001": ["A.8.20", "A.8.21"], "PCI-DSS": ["1.3.1", "1.3.2"], "HIPAA": ["164.312(e)(1)"], "SOC2": ["CC6.6"], "GDPR": ["Art.32(1)"], "FedRAMP": ["SC-7"], "MCSB": ["NS-1", "NS-2"], "CSA-CCM": ["IVS-03", "IVS-09"], "NIST-AI-RMF": ["MAP 1.5", "MANAGE 2.2"], "OWASP-LLM": ["LLM06"]}
_CONTENT_FW = {"CIS": ["9.2"], "NIST-800-53": ["SI-3", "SI-10"], "NIST-CSF": ["DE.CM-4", "PR.IP-1"], "ISO-27001": ["A.8.23"], "PCI-DSS": ["6.5.1"], "HIPAA": ["164.312(c)(1)"], "SOC2": ["CC7.1"], "GDPR": ["Art.25(1)"], "FedRAMP": ["SI-3", "SI-10"], "MCSB": ["DP-7"], "CSA-CCM": ["AIS-04", "TVM-09"], "NIST-AI-RMF": ["MEASURE 2.6", "MANAGE 2.3"], "OWASP-LLM": ["LLM01", "LLM02"]}
_PROMPT_FW = {"CIS": ["9.2"], "NIST-800-53": ["SI-10", "SI-3"], "NIST-CSF": ["DE.CM-4", "PR.IP-1"], "ISO-27001": ["A.8.23", "A.8.26"], "PCI-DSS": ["6.5.1"], "HIPAA": ["164.312(c)(1)"], "SOC2": ["CC7.1"], "GDPR": ["Art.25(1)"], "FedRAMP": ["SI-10"], "MCSB": ["DP-7"], "CSA-CCM": ["AIS-04"], "NIST-AI-RMF": ["MEASURE 2.6", "MAP 1.5", "MANAGE 2.3"], "OWASP-LLM": ["LLM01"]}
_LOG_FW = {"CIS": ["5.1.1", "5.2.1"], "NIST-800-53": ["AU-2", "AU-3", "AU-6"], "NIST-CSF": ["DE.AE-3", "PR.PT-1"], "ISO-27001": ["A.8.15", "A.8.17"], "PCI-DSS": ["10.2", "10.3"], "HIPAA": ["164.312(b)"], "SOC2": ["CC7.2"], "GDPR": ["Art.30"], "FedRAMP": ["AU-2", "AU-3"], "MCSB": ["LT-1", "LT-3"], "CSA-CCM": ["LOG-01", "LOG-03"], "NIST-AI-RMF": ["GOVERN 1.5", "MEASURE 2.5"], "OWASP-LLM": ["LLM09"]}
_GOV_FW = {"CIS": ["1.24", "2.1"], "NIST-800-53": ["PL-2", "CM-2", "CM-3"], "NIST-CSF": ["ID.GV-1", "PR.IP-1"], "ISO-27001": ["A.5.1", "A.5.37"], "PCI-DSS": ["12.1"], "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC1.1"], "GDPR": ["Art.24", "Art.25(1)"], "FedRAMP": ["PL-2", "CM-2"], "MCSB": ["GS-1", "GS-2"], "CSA-CCM": ["GRC-01", "GRC-02"], "NIST-AI-RMF": ["GOVERN 1.1", "GOVERN 1.2"], "OWASP-LLM": ["LLM08"]}
_AC_FW = {"CIS": ["1.22", "1.23"], "NIST-800-53": ["AC-2", "AC-6"], "NIST-CSF": ["PR.AC-4"], "ISO-27001": ["A.5.15", "A.5.18"], "PCI-DSS": ["7.1", "7.2.1"], "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"], "GDPR": ["Art.25(1)"], "FedRAMP": ["AC-2", "AC-6"], "MCSB": ["PA-1", "PA-7"], "CSA-CCM": ["IAM-05", "IAM-09"], "NIST-AI-RMF": ["GOVERN 1.4", "MANAGE 2.4"], "OWASP-LLM": ["LLM08"]}
_AGENCY_FW = {"CIS": ["1.22"], "NIST-800-53": ["AC-6(10)", "CM-7"], "NIST-CSF": ["PR.AC-4", "PR.PT-3"], "ISO-27001": ["A.5.15", "A.8.19"], "PCI-DSS": ["7.1"], "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1"], "GDPR": ["Art.25(1)"], "FedRAMP": ["AC-6(10)"], "MCSB": ["PA-7"], "CSA-CCM": ["IAM-09"], "NIST-AI-RMF": ["GOVERN 1.7", "MANAGE 3.1", "MAP 1.5"], "OWASP-LLM": ["LLM08", "LLM07"]}
_SUPPLY_FW = {"CIS": ["2.15"], "NIST-800-53": ["SA-12", "SR-3"], "NIST-CSF": ["ID.SC-2"], "ISO-27001": ["A.5.21", "A.5.22"], "PCI-DSS": ["6.3"], "HIPAA": ["164.308(b)(1)"], "SOC2": ["CC9.2"], "GDPR": ["Art.28"], "FedRAMP": ["SA-12"], "MCSB": ["DP-6"], "CSA-CCM": ["STA-03"], "NIST-AI-RMF": ["MAP 1.1", "GOVERN 1.6"], "OWASP-LLM": ["LLM05"]}
_DATA_RES_FW = {"CIS": ["4.1"], "NIST-800-53": ["SA-9(5)", "SC-7"], "NIST-CSF": ["PR.DS-5"], "ISO-27001": ["A.5.23"], "PCI-DSS": ["12.8.2"], "HIPAA": ["164.308(b)(1)"], "SOC2": ["CC6.7"], "GDPR": ["Art.44", "Art.46"], "FedRAMP": ["SA-9(5)"], "MCSB": ["DP-9"], "CSA-CCM": ["DSP-19"], "NIST-AI-RMF": ["GOVERN 1.5"], "OWASP-LLM": ["LLM06"]}
_CRED_FW = {"CIS": ["1.11", "1.14"], "NIST-800-53": ["IA-5", "IA-5(1)"], "NIST-CSF": ["PR.AC-1"], "ISO-27001": ["A.5.17"], "PCI-DSS": ["8.3.9", "8.6"], "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1"], "GDPR": ["Art.32(1)"], "FedRAMP": ["IA-5"], "MCSB": ["IM-3"], "CSA-CCM": ["IAM-10"], "NIST-AI-RMF": ["GOVERN 1.4"], "OWASP-LLM": ["LLM06"]}
_CA_FW = {"CIS": ["1.2.4", "1.2.5"], "NIST-800-53": ["AC-2(5)", "AC-12"], "NIST-CSF": ["PR.AC-7"], "ISO-27001": ["A.8.5"], "PCI-DSS": ["8.6.1"], "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1"], "GDPR": ["Art.32(1)"], "FedRAMP": ["AC-2(5)"], "MCSB": ["IM-7"], "CSA-CCM": ["IAM-04"], "NIST-AI-RMF": ["GOVERN 1.4"], "OWASP-LLM": ["LLM06"]}
_PIM_FW = {"CIS": ["1.23"], "NIST-800-53": ["AC-2(7)", "AC-6(2)"], "NIST-CSF": ["PR.AC-4"], "ISO-27001": ["A.8.2"], "PCI-DSS": ["7.2.1"], "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.3"], "GDPR": ["Art.25(1)"], "FedRAMP": ["AC-2(7)"], "MCSB": ["PA-1", "PA-2"], "CSA-CCM": ["IAM-05"], "NIST-AI-RMF": ["GOVERN 1.4", "MANAGE 2.4"], "OWASP-LLM": ["LLM08"]}

_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    # ── Copilot Studio: Authentication ──
    "no_auth_required": _AUTH_FW,
    "non_aad_auth": _AUTH_STRONG,
    "stale_auth_config": _CRED_FW,
    "cs_auth_no_sign_in_required": _AUTH_FW,
    "cs_auth_generic_oauth": _AUTH_STRONG,
    "unauthenticated_web_channel": _AUTH_FW,
    "teams_channel_no_sso": _AUTH_STRONG,
    # ── Copilot Studio: DLP ──
    "no_pp_dlp_policies": _DLP_FW,
    "cs_dlp_no_auth_connector_allowed": _DLP_FW,
    "cs_dlp_knowledge_source_unrestricted": _DLP_FW,
    "cs_dlp_channel_unrestricted": _DLP_FW,
    "cs_dlp_skills_unrestricted": _DLP_FW,
    "cs_dlp_default_group_not_blocked": _DLP_FW,
    "cs_dlp_no_tenant_policy": _DLP_FW,
    "cs_dlp_http_unrestricted": _NET_FW,
    "cs_auth_dlp_not_enforcing": _DLP_FW,
    "connector_no_dlp_coverage": _DLP_FW,
    # ── Copilot Studio: Environment Governance ──
    "unmanaged_environments": _GOV_FW,
    "no_security_group": _AC_FW,
    "cs_env_bots_in_default": _GOV_FW,
    "cs_env_bots_in_dev_env": _GOV_FW,
    "cs_env_sandbox_for_production": _GOV_FW,
    "cs_env_no_tenant_isolation": _NET_FW,
    "cs_env_gen_ai_unrestricted": _CONTENT_FW,
    # ── Copilot Studio: Logging ──
    "no_conversation_logging": _LOG_FW,
    "environment_audit_disabled": _LOG_FW,
    "cs_audit_no_purview_integration": _LOG_FW,
    "cs_audit_no_dspm_for_ai": _LOG_FW,
    # ── Copilot Studio: Agent Security ──
    "cs_agent_shared_to_everyone": _AC_FW,
    "cs_agent_event_triggers_ungoverned": _GOV_FW,
    "cs_agent_http_unrestricted": _NET_FW,
    # ── Copilot Studio: Data Residency ──
    "cs_compliance_cross_geo_data_movement": _DATA_RES_FW,
    "cs_compliance_env_region_mismatch": _DATA_RES_FW,
    # ── Copilot Studio: Dataverse Security ──
    "cs_dv_env_maker_in_prod": _AC_FW,
    "cs_dv_no_lockbox": _ENCRYPT_FW,
    "cs_dv_no_cmk": _ENCRYPT_FW,
    # ── Copilot Studio: Readiness Crosscheck ──
    "pp_env_governance_for_readiness": _GOV_FW,
    "pp_dlp_coverage_for_copilot": _DLP_FW,
    "pp_cross_tenant_for_readiness": _DATA_RES_FW,
    # ── Copilot Studio: Knowledge & Gen AI ──
    "overshared_knowledge_source": _DLP_FW,
    "external_knowledge_source": _SUPPLY_FW,
    "public_website_source": _NET_FW,
    "generative_answers_no_guardrails": _CONTENT_FW,
    "generative_orchestration_unrestricted": _AGENCY_FW,
    # ── Copilot Studio: Bot Governance ──
    "unpublished_bot_with_secrets": _CRED_FW,
    "bot_not_solution_aware": _GOV_FW,
    "draft_bot_stale": _GOV_FW,
    # ── Copilot Studio: Connector Security ──
    "custom_connector_no_auth": _AUTH_FW,
    "premium_connector_uncontrolled": _GOV_FW,
    # ── Foundry: Network ──
    "public_access_enabled": _NET_FW,
    "no_private_endpoints": _NET_FW,
    "workspace_no_isolation": _NET_FW,
    "workspace_no_managed_network": _NET_FW,
    "managed_network_no_outbound_rules": _NET_FW,
    "outbound_fqdn_unrestricted": _NET_FW,
    # ── Foundry: Identity ──
    "local_auth_enabled": _AUTH_FW,
    "workspace_no_managed_identity": _AUTH_STRONG,
    "project_no_managed_identity": _AUTH_STRONG,
    "shared_project_identity": _AC_FW,
    "agent_permission_drift": _AC_FW,
    # ── Foundry: Content Safety ──
    "no_content_filter": _CONTENT_FW,
    "weak_content_filters": _CONTENT_FW,
    "content_filter_gaps": _CONTENT_FW,
    "no_prompt_shield": _PROMPT_FW,
    "jailbreak_filter_disabled": _PROMPT_FW,
    "blocklist_not_configured": _CONTENT_FW,
    "no_prompt_injection_mitigation": _PROMPT_FW,
    "no_groundedness_detection": _CONTENT_FW,
    "no_pii_filter": _DLP_FW,
    "agent_no_custom_guardrail": _CONTENT_FW,
    "agent_account_no_content_safety": _CONTENT_FW,
    "permissive_content_filters": _CONTENT_FW,
    "serverless_no_content_safety": _CONTENT_FW,
    "deployment_no_rai_policy": _CONTENT_FW,
    # ── Foundry: Deployments & Models ──
    "high_capacity_allocation": _GOV_FW,
    "deployment_deprecated_model": _SUPPLY_FW,
    "unapproved_model_deployed": _SUPPLY_FW,
    "model_version_outdated": _SUPPLY_FW,
    "outdated_model_version": _SUPPLY_FW,
    "no_token_rate_limit": {"CIS": ["9.2"], "NIST-800-53": ["SC-5"], "NIST-CSF": ["PR.DS-4"], "ISO-27001": ["A.8.6"], "PCI-DSS": ["6.5.1"], "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.8"], "GDPR": ["Art.32(1)"], "FedRAMP": ["SC-5"], "MCSB": ["NS-6"], "CSA-CCM": ["IVS-09"], "NIST-AI-RMF": ["MANAGE 2.3"], "OWASP-LLM": ["LLM04"]},
    "excessive_rate_limit": {"CIS": ["9.2"], "NIST-800-53": ["SC-5"], "NIST-CSF": ["PR.DS-4"], "ISO-27001": ["A.8.6"], "PCI-DSS": ["6.5.1"], "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.8"], "GDPR": ["Art.32(1)"], "FedRAMP": ["SC-5"], "MCSB": ["NS-6"], "CSA-CCM": ["IVS-09"], "NIST-AI-RMF": ["MANAGE 2.3"], "OWASP-LLM": ["LLM04"]},
    # ── Foundry: Governance ──
    "no_hub_structure": _GOV_FW,
    "workspace_no_cmk": _ENCRYPT_FW,
    "hub_no_project_isolation": _NET_FW,
    # ── Foundry: Compute ──
    "compute_public_ip": _NET_FW,
    "compute_ssh_enabled": _NET_FW,
    "compute_idle_no_shutdown": _GOV_FW,
    "compute_no_managed_identity": _AUTH_STRONG,
    # ── Foundry: Datastores ──
    "datastore_credential_in_config": _CRED_FW,
    "datastore_no_encryption": _ENCRYPT_FW,
    # ── Foundry: Endpoints ──
    "online_endpoint_public": _NET_FW,
    "endpoint_no_auth": _AUTH_FW,
    "endpoint_key_auth_only": _AUTH_STRONG,
    "endpoint_no_logging": _LOG_FW,
    "public_endpoint_exposure": _NET_FW,
    "no_auth_policy": _AUTH_FW,
    "deployment_unhealthy": _GOV_FW,
    # ── Foundry: Registry ──
    "registry_public_access": _NET_FW,
    "registry_no_rbac": _AC_FW,
    # ── Foundry: Connections ──
    "connection_static_credentials": _CRED_FW,
    "connection_shared_to_all": _AC_FW,
    "connection_expired_credentials": _CRED_FW,
    "connection_no_expiry": _CRED_FW,
    # ── Foundry: Serverless ──
    "serverless_key_auth": _AUTH_STRONG,
    "serverless_key_not_rotated": _CRED_FW,
    # ── Foundry: Diagnostics ──
    "ws_no_diagnostic_settings": _LOG_FW,
    "ws_no_log_analytics": _LOG_FW,
    # ── Foundry: MCP / Tools ──
    "mcp_no_secure_auth": _AUTH_FW,
    "mcp_public_endpoint": _NET_FW,
    "mcp_shared_to_all": _AC_FW,
    "a2a_no_identity_auth": _AUTH_FW,
    "non_microsoft_tool_connection": _SUPPLY_FW,
    "tool_credential_based_auth": _CRED_FW,
    # ── Foundry: Guardrails ──
    # (mapped above under Content Safety)
    # ── Foundry: Hosted Agents ──
    "hosted_no_vnet": _NET_FW,
    "hosted_no_acr": _GOV_FW,
    "hosted_unhealthy": _GOV_FW,
    # ── Foundry: Data Resources ──
    "data_connection_no_managed_identity": _AUTH_STRONG,
    "no_customer_managed_key": _ENCRYPT_FW,
    "data_connection_shared_to_all": _AC_FW,
    # ── Foundry: Observability ──
    "workspace_no_diagnostics": _LOG_FW,
    "project_no_tracing": _LOG_FW,
    "workspace_limited_log_coverage": _LOG_FW,
    # ── Foundry: Lifecycle ──
    "shadow_agents_unpublished": _GOV_FW,
    "excess_unpublished_agents": _GOV_FW,
    "agent_no_rbac": _AC_FW,
    # ── Entra AI: Service Principals ──
    "sp_excessive_permissions": _AC_FW,
    "sp_credential_expiry": _CRED_FW,
    "sp_no_credential_rotation": _CRED_FW,
    "sp_multi_tenant_exposure": _DATA_RES_FW,
    "sp_no_managed_identity": _AUTH_STRONG,
    "sp_ai_api_over_scoped": _AC_FW,
    "sp_risky_identity_protection": _AC_FW,
    "sp_privileged_directory_roles": _PIM_FW,
    "sp_owner_governance_weak": _AC_FW,
    "sp_stale_disabled": _GOV_FW,
    # ── Entra AI: Conditional Access ──
    "no_ca_for_ai_apps": _CA_FW,
    "no_token_lifetime_restriction": _CA_FW,
    "ca_weak_policy_quality": _CA_FW,
    "ca_no_session_controls": _CA_FW,
    # ── Entra AI: Consent ──
    "broad_user_consent_to_ai_apps": _AC_FW,
    "admin_consent_ai_high_privilege": _AC_FW,
    "ai_specific_consent_scopes": _AC_FW,
    # ── Entra AI: Workload Identity ──
    "wif_missing_federation": _AUTH_STRONG,
    # ── Entra AI: Cross-Tenant ──
    "cross_tenant_ai_exposure": _DATA_RES_FW,
    # ── Entra AI: PIM ──
    "pim_missing_for_ai_roles": _PIM_FW,
    # ── AI Defense ──
    "no_defender_for_ai": {"CIS": ["2.1.15"], "NIST-800-53": ["SI-3", "SI-4"], "NIST-CSF": ["DE.CM-4", "DE.CM-8"], "ISO-27001": ["A.8.7"], "PCI-DSS": ["5.2", "11.4"], "HIPAA": ["164.308(a)(5)"], "SOC2": ["CC7.1"], "GDPR": ["Art.32(1)"], "FedRAMP": ["SI-3", "SI-4"], "MCSB": ["LT-1"], "CSA-CCM": ["TVM-01"], "NIST-AI-RMF": ["MEASURE 2.6", "MANAGE 1.3"], "OWASP-LLM": ["LLM01", "LLM09"]},
    "defender_ai_alerts_suppressed": _LOG_FW,
    "no_ai_azure_policies": _GOV_FW,
    "ai_policy_non_compliant": _GOV_FW,
    # ── AI Agent Communication ──
    "agent_no_auth_between_agents": _AUTH_FW,
    "agent_unrestricted_tool_access": _AGENCY_FW,
    "agent_memory_no_encryption": _ENCRYPT_FW,
    # ── AI Agent Governance ──
    "no_agent_inventory": _GOV_FW,
    "agent_no_human_in_loop": _AGENCY_FW,
    "shadow_ai_agents": _GOV_FW,
    # ── AI Infrastructure ──
    "no_diagnostic_settings": _LOG_FW,
    "no_audit_logging": _LOG_FW,
    "training_data_no_classification": {"CIS": ["3.1"], "NIST-800-53": ["RA-5", "SC-28"], "NIST-CSF": ["ID.AM-5", "PR.DS-1"], "ISO-27001": ["A.5.12", "A.5.13"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.7"], "GDPR": ["Art.5(1)(e)", "Art.25(1)"], "FedRAMP": ["RA-5"], "MCSB": ["DP-1"], "CSA-CCM": ["DSP-01"], "NIST-AI-RMF": ["MAP 1.1", "GOVERN 1.5"], "OWASP-LLM": ["LLM03"]},
    "output_data_no_retention_policy": {"CIS": ["3.1"], "NIST-800-53": ["SI-12", "AU-11"], "NIST-CSF": ["PR.IP-6"], "ISO-27001": ["A.5.33", "A.8.10"], "PCI-DSS": ["3.1"], "HIPAA": ["164.530(j)"], "SOC2": ["CC6.5"], "GDPR": ["Art.5(1)(e)", "Art.17"], "FedRAMP": ["SI-12"], "MCSB": ["DP-8"], "CSA-CCM": ["DSP-16"], "NIST-AI-RMF": ["GOVERN 1.5", "MANAGE 2.2"], "OWASP-LLM": ["LLM06"]},
    # ── Custom AI ──
    "key_without_network_restriction": _NET_FW,
    "multi_region_sprawl": _DATA_RES_FW,
    "no_cmk_encryption": _ENCRYPT_FW,
}


# ── "FRAMEWORK:control_id" → {title, rationale, recommendation} ──────────

_CONTROL_DETAILS: dict[str, dict[str, str]] = {
    # ── OWASP LLM ──
    "OWASP-LLM:LLM01": {"title": "Prompt Injection", "rationale": "Attackers can manipulate LLM behaviour through crafted inputs, bypassing safety controls and exfiltrating data.", "recommendation": "Enable prompt shields, input validation, and content filtering on all AI endpoints."},
    "OWASP-LLM:LLM02": {"title": "Insecure Output Handling", "rationale": "Unvalidated LLM outputs can lead to XSS, SSRF, or downstream injection attacks.", "recommendation": "Validate and sanitise all LLM outputs before rendering or using in downstream systems."},
    "OWASP-LLM:LLM03": {"title": "Training Data Poisoning", "rationale": "Compromised training data can introduce biases or backdoors into model behaviour.", "recommendation": "Classify and protect training data; implement provenance tracking and integrity verification."},
    "OWASP-LLM:LLM04": {"title": "Model Denial of Service", "rationale": "Adversarial inputs can cause excessive resource consumption or model degradation.", "recommendation": "Configure rate limits and token caps on all model deployments."},
    "OWASP-LLM:LLM05": {"title": "Supply Chain Vulnerabilities", "rationale": "Third-party models, plugins, or data sources may introduce vulnerabilities.", "recommendation": "Use approved model catalogs, verify model provenance, and restrict third-party integrations."},
    "OWASP-LLM:LLM06": {"title": "Sensitive Information Disclosure", "rationale": "LLMs may reveal sensitive data from training sets or connected knowledge sources.", "recommendation": "Implement DLP policies, PII filters, and knowledge source access controls."},
    "OWASP-LLM:LLM07": {"title": "Insecure Plugin Design", "rationale": "Plugins may operate with excessive permissions or accept unvalidated inputs from LLMs.", "recommendation": "Apply least-privilege permissions to all tools and connectors; validate tool inputs."},
    "OWASP-LLM:LLM08": {"title": "Excessive Agency", "rationale": "Granting LLMs too much autonomy or access can lead to unintended actions with real-world consequences.", "recommendation": "Implement human-in-the-loop controls, restrict tool access, and enforce RBAC on agent actions."},
    "OWASP-LLM:LLM09": {"title": "Overreliance", "rationale": "Excessive trust in LLM outputs without human oversight can lead to incorrect decisions.", "recommendation": "Implement monitoring, alerting, and human review workflows for critical AI decisions."},
    "OWASP-LLM:LLM10": {"title": "Model Theft", "rationale": "Attackers may extract or replicate models through repeated API queries.", "recommendation": "Restrict public API access, enforce authentication, and monitor for extraction patterns."},
    # ── NIST AI RMF ──
    "NIST-AI-RMF:GOVERN 1.1": {"title": "Legal and regulatory requirements", "rationale": "AI systems must operate within applicable legal and regulatory frameworks.", "recommendation": "Document and verify compliance with AI-relevant regulations for all deployed models."},
    "NIST-AI-RMF:GOVERN 1.2": {"title": "Trustworthy AI characteristics", "rationale": "AI governance must incorporate trustworthiness principles including fairness, accountability, and transparency.", "recommendation": "Establish AI governance policies covering responsible AI principles."},
    "NIST-AI-RMF:GOVERN 1.4": {"title": "Risk management integration", "rationale": "AI risk management should be integrated into organisational risk management.", "recommendation": "Include AI-specific controls in enterprise security and compliance frameworks."},
    "NIST-AI-RMF:GOVERN 1.5": {"title": "Ongoing monitoring", "rationale": "AI systems require continuous monitoring for performance degradation and emerging risks.", "recommendation": "Enable diagnostic logging, tracing, and alerting for all AI deployments."},
    "NIST-AI-RMF:GOVERN 1.6": {"title": "Supply chain risk management", "rationale": "Third-party AI components introduce supply chain risks.", "recommendation": "Maintain an approved model catalog and verify model provenance."},
    "NIST-AI-RMF:GOVERN 1.7": {"title": "Human oversight", "rationale": "Critical AI decisions require human oversight to prevent unintended consequences.", "recommendation": "Implement human-in-the-loop controls for high-risk AI operations."},
    "NIST-AI-RMF:MAP 1.1": {"title": "Context and intended use", "rationale": "Understanding the AI system's context is essential for risk assessment.", "recommendation": "Document intended use, users, and operational context for all AI agents."},
    "NIST-AI-RMF:MAP 1.5": {"title": "Risk identification", "rationale": "Potential risks must be identified across the AI lifecycle.", "recommendation": "Conduct threat modelling for AI agents including prompt injection, data exfiltration, and excessive agency."},
    "NIST-AI-RMF:MEASURE 2.5": {"title": "Safety and security testing", "rationale": "AI systems must be tested for safety and security vulnerabilities.", "recommendation": "Run red-team exercises and adversarial testing against AI agent deployments."},
    "NIST-AI-RMF:MEASURE 2.6": {"title": "Content safety evaluation", "rationale": "AI-generated content must be evaluated for harmful, biased, or inappropriate material.", "recommendation": "Enable content safety filters and groundedness detection on all AI endpoints."},
    "NIST-AI-RMF:MANAGE 2.2": {"title": "Data protection", "rationale": "AI systems must protect the confidentiality and integrity of data they process.", "recommendation": "Encrypt data at rest and in transit; implement CMK for sensitive AI workloads."},
    "NIST-AI-RMF:MANAGE 2.3": {"title": "Harmful output mitigation", "rationale": "Harmful AI outputs must be detected and mitigated in real time.", "recommendation": "Deploy content filters, jailbreak protection, and responsible AI policies."},
    "NIST-AI-RMF:MANAGE 2.4": {"title": "Access management", "rationale": "AI system access must be governed by least-privilege principles.", "recommendation": "Use RBAC with PIM for AI resource access; avoid shared identities."},
    "NIST-AI-RMF:MANAGE 3.1": {"title": "Incident response", "rationale": "Organisations must plan for AI-specific security incidents.", "recommendation": "Include AI agent compromise scenarios in incident response plans."},
    # ── Standard Frameworks (key controls) ──
    "NIST-800-53:IA-2": {"title": "Identification and Authentication", "rationale": "Users and services must be uniquely identified and authenticated.", "recommendation": "Enforce Entra ID authentication with MFA for all AI service access."},
    "NIST-800-53:SC-7": {"title": "Boundary Protection", "rationale": "Network perimeters must be protected to prevent unauthorised access.", "recommendation": "Deploy private endpoints and restrict public access on AI services."},
    "NIST-800-53:AC-6": {"title": "Least Privilege", "rationale": "Users and services should operate with minimum necessary permissions.", "recommendation": "Apply least-privilege RBAC to all AI resources and agent identities."},
    "NIST-800-53:AU-2": {"title": "Audit Events", "rationale": "Security-relevant events must be logged for accountability and forensics.", "recommendation": "Enable diagnostic settings and audit logging on all AI workspaces."},
    "NIST-800-53:SI-10": {"title": "Information Input Validation", "rationale": "System inputs must be validated to prevent injection attacks.", "recommendation": "Enable prompt shields and input validation on all AI endpoints."},
    "CIS:1.1.1": {"title": "Ensure MFA is enabled for all users", "rationale": "MFA significantly reduces the risk of credential compromise.", "recommendation": "Enforce MFA via conditional access policies for all AI service access."},
    "CIS:6.1": {"title": "Ensure RDP/SSH access is restricted", "rationale": "Open management ports expose services to brute-force and remote exploitation.", "recommendation": "Disable public IP and SSH on AI compute instances; use bastion or private endpoints."},
    "ISO-27001:A.8.24": {"title": "Use of cryptography", "rationale": "Cryptographic controls protect data confidentiality and integrity.", "recommendation": "Enforce customer-managed keys for AI workspaces and data stores."},
    "MCSB:NS-2": {"title": "Secure cloud services with network controls", "rationale": "Network segmentation limits lateral movement in case of compromise.", "recommendation": "Deploy AI services in managed VNets with private endpoints and outbound rules."},
    "MCSB:DP-4": {"title": "Enable data-at-rest encryption", "rationale": "Encryption at rest protects data from unauthorised physical access.", "recommendation": "Enable CMK encryption on AI workspace storage and data connections."},
}


def enrich_compliance_mapping(findings: list[dict]) -> list[dict]:
    """Add ComplianceMapping and ComplianceDetails to each finding."""
    for f in findings:
        subcat = f.get("Subcategory", "")
        mapping = _COMPLIANCE_MAP.get(subcat)
        if mapping:
            f["ComplianceMapping"] = mapping
            details: dict[str, dict[str, str]] = {}
            for fw, ctrls in mapping.items():
                for ctrl in ctrls:
                    key = f"{fw}:{ctrl}"
                    if key in _CONTROL_DETAILS:
                        details[key] = _CONTROL_DETAILS[key]
            if details:
                f["ComplianceDetails"] = details
    return findings
