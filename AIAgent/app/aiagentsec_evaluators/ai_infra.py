"""AI infrastructure security evaluators — diagnostics, model governance, threat protection, data governance."""

from __future__ import annotations

from .finding import _as_finding


def analyze_ai_diagnostics(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess diagnostic settings for AI services."""
    findings: list[dict] = []
    findings.extend(_check_ai_no_diagnostic_settings(evidence_index))
    findings.extend(_check_ai_no_audit_logging(evidence_index))
    return findings


def _check_ai_no_diagnostic_settings(idx: dict) -> list[dict]:
    """Flag AI services with no diagnostic settings enabled."""
    services = idx.get("azure-ai-service", [])
    no_diag: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasDiagnosticSettings"):
            no_diag.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
                "Kind": data.get("Kind", ""),
            })
    if no_diag:
        return [_as_finding(
            "ai_diagnostics", "no_diagnostic_settings",
            f"{len(no_diag)} AI services have no diagnostic settings configured",
            "Without diagnostic settings, API calls, errors, and performance metrics "
            "are not logged — making incident investigation and compliance auditing impossible.",
            "high", "ai_infra", no_diag,
            {"Description": "Enable diagnostic settings on AI services.",
             "AzureCLI": "az monitor diagnostic-settings create --resource <resource-id> "
                         "--name ai-diagnostics --logs '[{\"category\":\"RequestResponse\",\"enabled\":true},"
                         "{\"category\":\"Audit\",\"enabled\":true}]' "
                         "--workspace <log-analytics-workspace-id>",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the resource",
                             "Go to Diagnostic settings > Add diagnostic setting",
                             "Enable RequestResponse and Audit logs",
                             "Select Log Analytics workspace as destination"]},
        )]
    return []


def _check_ai_no_audit_logging(idx: dict) -> list[dict]:
    """Flag AI services missing audit log categories."""
    services = idx.get("azure-ai-service", [])
    no_audit: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasDiagnosticSettings"):
            categories = [c.lower() for c in data.get("DiagnosticCategories", [])]
            if "audit" not in categories and "requestresponse" not in categories:
                no_audit.append({
                    "Type": "AzureAIService",
                    "Name": data.get("Name", "Unknown"),
                    "ResourceId": data.get("AccountId", ""),
                    "EnabledCategories": str(data.get("DiagnosticCategories", [])),
                })
    if no_audit:
        return [_as_finding(
            "ai_diagnostics", "no_audit_logging",
            f"{len(no_audit)} AI services have diagnostic settings but missing audit logs",
            "Diagnostic settings exist but RequestResponse or Audit log categories "
            "are not enabled, creating blind spots for security monitoring.",
            "medium", "ai_infra", no_audit,
            {"Description": "Enable Audit and RequestResponse log categories.",
             "PortalSteps": ["Go to Azure portal > AI Services > Diagnostic settings",
                             "Edit the diagnostic setting",
                             "Enable 'Audit' and 'RequestResponse' categories",
                             "Save"]},
        )]
    return []


# ── 17. AI Model Governance ─────────────────────────────────────────

def analyze_ai_model_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess AI model governance and rate limiting."""
    findings: list[dict] = []
    findings.extend(_check_outdated_model_version(evidence_index))
    findings.extend(_check_no_rate_limit(evidence_index))
    findings.extend(_check_excessive_rate_limit(evidence_index))
    return findings


def _check_outdated_model_version(idx: dict) -> list[dict]:
    """Flag deployments using deprecated model versions."""
    deployments = idx.get("azure-openai-deployment", [])
    outdated: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsDeprecated") or data.get("IsEndOfLife"):
            outdated.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "ModelName": data.get("ModelName", ""),
                "ModelVersion": data.get("ModelVersion", ""),
                "DeprecationDate": data.get("DeprecationDate", ""),
            })
    if outdated:
        return [_as_finding(
            "ai_model_governance", "outdated_model_version",
            f"{len(outdated)} deployments use deprecated or end-of-life model versions",
            "Deprecated models may have known vulnerabilities, reduced safety guardrails, "
            "or imminent retirement dates causing service disruption.",
            "medium", "ai_infra", outdated,
            {"Description": "Upgrade to supported model versions.",
             "PortalSteps": ["Go to Microsoft Foundry > Deployments",
                             "Select the deployment > Update model version",
                             "Choose the latest GA version",
                             "Test and validate before switching production traffic"]},
        )]
    return []


def _check_no_rate_limit(idx: dict) -> list[dict]:
    """Flag deployments with no TPM rate limit configured."""
    deployments = idx.get("azure-openai-deployment", [])
    no_limit: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        tpm = data.get("RateLimitTPM")
        if tpm is None or tpm == 0:
            no_limit.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
            })
    if no_limit:
        return [_as_finding(
            "ai_model_governance", "no_token_rate_limit",
            f"{len(no_limit)} deployments have no TPM rate limit configured",
            "Deployments without token-per-minute limits are vulnerable to abuse "
            "and cost spikes from uncontrolled consumption.",
            "medium", "ai_infra", no_limit,
            {"Description": "Configure appropriate TPM rate limits for each deployment.",
             "PortalSteps": ["Go to Microsoft Foundry > Model deployments",
                             "Select the deployment > Edit",
                             "Set tokens-per-minute rate limit",
                             "Save"]},
        )]
    return []


def _check_excessive_rate_limit(idx: dict) -> list[dict]:
    """Flag deployments with TPM over 250K."""
    deployments = idx.get("azure-openai-deployment", [])
    excessive: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        tpm = data.get("RateLimitTPM", 0)
        if isinstance(tpm, (int, float)) and tpm > 250000:
            excessive.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "RateLimitTPM": tpm,
            })
    if excessive:
        return [_as_finding(
            "ai_model_governance", "excessive_rate_limit",
            f"{len(excessive)} deployments have very high TPM limits (>250K)",
            "Extremely high TPM limits increase cost exposure and potential for "
            "AI service abuse if compromised.",
            "low", "ai_infra", excessive,
            {"Description": "Review and reduce TPM limits to actual usage levels.",
             "PortalSteps": ["Go to Microsoft Foundry > Model deployments",
                             "Review actual TPM usage metrics",
                             "Reduce limits to 1.5× peak observed usage"]},
            compliance_status="partial",
        )]
    return []


# ── 18. AI Threat Protection ────────────────────────────────────────

def analyze_ai_threat_protection(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess AI-specific threat protections (prompt injection, PII, groundedness)."""
    findings: list[dict] = []
    findings.extend(_check_no_prompt_injection_mitigation(evidence_index))
    findings.extend(_check_no_groundedness_detection(evidence_index))
    findings.extend(_check_no_pii_filter(evidence_index))
    findings.extend(_check_jailbreak_filter_disabled(evidence_index))
    return findings


def _check_no_prompt_injection_mitigation(idx: dict) -> list[dict]:
    """Flag deployments without prompt injection / Prompt Shields mitigation."""
    filters = idx.get("azure-openai-content-filter", [])
    services = idx.get("azure-ai-service", [])
    openai_accounts = {
        ev.get("Data", ev.get("data", {})).get("AccountId", "")
        for ev in services
        if ev.get("Data", ev.get("data", {})).get("IsOpenAI")
    }

    if not openai_accounts:
        return []

    covered_accounts = set()
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasPromptShields"):
            covered_accounts.add(data.get("AccountId", ""))

    uncovered = openai_accounts - covered_accounts
    if uncovered:
        resources = [{"Type": "AzureAIService", "Name": aid, "ResourceId": aid}
                     for aid in sorted(uncovered)]
        return [_as_finding(
            "ai_threat_protection", "no_prompt_injection_mitigation",
            f"{len(uncovered)} OpenAI accounts lack Prompt Shields (prompt injection protection)",
            "Prompt Shields detect and block prompt injection attacks where adversarial "
            "inputs manipulate the AI model into ignoring instructions or revealing data.",
            "critical", "ai_infra", resources,
            {"Description": "Enable Prompt Shields in content filter policies.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Content filters",
                             "Edit or create a content filter",
                             "Enable 'Prompt Shields' for both user and document attacks",
                             "Apply to all deployments"]},
        )]
    return []


def _check_no_groundedness_detection(idx: dict) -> list[dict]:
    """Flag deployments without groundedness detection."""
    filters = idx.get("azure-openai-content-filter", [])
    no_groundedness: list[dict] = []
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasGroundednessDetection") and data.get("TotalFilters", 0) > 0:
            no_groundedness.append({
                "Type": "ContentFilter",
                "Name": data.get("PolicyName", "Unknown"),
                "ResourceId": data.get("PolicyId", ""),
                "AccountId": data.get("AccountId", ""),
            })
    if no_groundedness:
        return [_as_finding(
            "ai_threat_protection", "no_groundedness_detection",
            f"{len(no_groundedness)} content filter policies lack groundedness detection",
            "Groundedness detection identifies hallucinated or ungrounded content — "
            "without it, AI agents may generate fabricated information presented as factual.",
            "high", "ai_infra", no_groundedness,
            {"Description": "Enable groundedness detection in content filter policies.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Content filters",
                             "Edit the content filter policy",
                             "Enable groundedness detection",
                             "Save and reapply to deployments"]},
        )]
    return []


def _check_no_pii_filter(idx: dict) -> list[dict]:
    """Flag deployments without PII detection/redaction."""
    filters = idx.get("azure-openai-content-filter", [])
    no_pii: list[dict] = []
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasPIIDetection") and data.get("TotalFilters", 0) > 0:
            no_pii.append({
                "Type": "ContentFilter",
                "Name": data.get("PolicyName", "Unknown"),
                "ResourceId": data.get("PolicyId", ""),
            })
    if no_pii:
        return [_as_finding(
            "ai_threat_protection", "no_pii_filter",
            f"{len(no_pii)} content filter policies lack PII detection/redaction",
            "Without PII detection, AI agents may output personal data (names, emails, "
            "SSNs) from their training or grounding data in responses.",
            "high", "ai_infra", no_pii,
            {"Description": "Enable PII detection and redaction in content filters.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Content filters",
                             "Edit the content filter policy",
                             "Enable PII detection (block or redact mode)",
                             "Save and reapply to deployments"]},
        )]
    return []


def _check_jailbreak_filter_disabled(idx: dict) -> list[dict]:
    """Flag content filter policies with jailbreak category set to allow."""
    filters = idx.get("azure-openai-content-filter", [])
    jailbreak_off: list[dict] = []
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("JailbreakFilterDisabled"):
            jailbreak_off.append({
                "Type": "ContentFilter",
                "Name": data.get("PolicyName", "Unknown"),
                "ResourceId": data.get("PolicyId", ""),
            })
    if jailbreak_off:
        return [_as_finding(
            "ai_threat_protection", "jailbreak_filter_disabled",
            f"{len(jailbreak_off)} content filter policies have jailbreak detection disabled",
            "Jailbreak detection prevents adversarial prompts from bypassing the model's "
            "safety training. Disabling it leaves the agent vulnerable to manipulation.",
            "critical", "ai_infra", jailbreak_off,
            {"Description": "Enable jailbreak detection in all content filter policies.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Content filters",
                             "Edit the content filter policy",
                             "Enable 'Jailbreak risk detection' in blocking mode",
                             "Save and reapply to deployments"]},
        )]
    return []


# ── 19. AI Data Governance ──────────────────────────────────────────

def analyze_ai_data_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data governance for AI workloads."""
    findings: list[dict] = []
    findings.extend(_check_training_data_classification(evidence_index))
    findings.extend(_check_output_data_retention(evidence_index))
    return findings


def _check_training_data_classification(idx: dict) -> list[dict]:
    """Flag AI datastores without sensitivity labels."""
    datastores = idx.get("azure-ai-datastore", [])
    unclassified: list[dict] = []
    for ev in datastores:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasSensitivityLabel"):
            unclassified.append({
                "Type": "AIDatastore",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("DatastoreId", ""),
            })
    if unclassified:
        return [_as_finding(
            "ai_data_governance", "training_data_no_classification",
            f"{len(unclassified)} AI datastores lack sensitivity classification",
            "Training and grounding data without sensitivity labels may contain "
            "confidential information that is inadvertently used for model training.",
            "medium", "ai_infra", unclassified,
            {"Description": "Apply sensitivity labels to AI training data stores.",
             "PortalSteps": ["Go to Microsoft Purview > Sensitivity labels",
                             "Create labels for AI training data classification",
                             "Apply to storage accounts used by AI datastores",
                             "Configure auto-labeling policies"]},
        )]
    return []


def _check_output_data_retention(idx: dict) -> list[dict]:
    """Flag AI services without data retention configuration."""
    services = idx.get("azure-ai-service", [])
    no_retention: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsOpenAI") and not data.get("HasDataRetentionPolicy"):
            no_retention.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
            })
    if no_retention:
        return [_as_finding(
            "ai_data_governance", "output_data_no_retention_policy",
            f"{len(no_retention)} AI services lack data retention configuration",
            "Without explicit data retention policies, prompts and completions may be "
            "stored indefinitely, increasing compliance and privacy risks.",
            "medium", "ai_infra", no_retention,
            {"Description": "Configure data retention policies for AI services.",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the resource",
                             "Review data, privacy, and security settings",
                             "Configure data retention period",
                             "Opt out of abuse monitoring data storage if compliant"]},
        )]
    return []

