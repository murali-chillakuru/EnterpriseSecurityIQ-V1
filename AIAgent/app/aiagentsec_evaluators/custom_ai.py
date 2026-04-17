"""Custom AI application security evaluators — API keys, data residency, content leakage."""

from __future__ import annotations

from .finding import _as_finding


def analyze_custom_api_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess API key management for custom AI agents."""
    findings: list[dict] = []
    findings.extend(_check_api_key_exposure(evidence_index))
    return findings


def _check_api_key_exposure(idx: dict) -> list[dict]:
    """Flag AI services that rely on API keys without managed identity."""
    services = idx.get("azure-ai-service", [])
    key_only: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("DisableLocalAuth") and not data.get("HasPrivateEndpoints"):
            key_only.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
                "Kind": data.get("Kind", ""),
                "PublicAccess": data.get("PublicNetworkAccess", ""),
            })
    if key_only:
        return [_as_finding(
            "custom_api_security", "key_without_network_restriction",
            f"{len(key_only)} AI services use API keys with no network restrictions",
            "AI services using API keys without private endpoints or network rules are "
            "vulnerable to key theft and unauthorized access from any network location.",
            "critical", "cross-cutting", key_only,
            {"Description": "Disable API keys and use managed identity, or add network restrictions.",
             "AzureCLI": "az cognitiveservices account update -n <name> -g <rg> "
                         "--disable-local-auth true",
             "PowerShell": "Set-AzCognitiveServicesAccount -ResourceGroupName <rg> -Name <name> "
                           "-DisableLocalAuth $true",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the resource", "Go to Networking > set public access to Disabled or Selected Networks", "Go to Identity > Enable system-assigned managed identity", "Assign RBAC roles (Cognitive Services User) to the managed identity"]},
        )]
    return []


# ── 11. Data Residency & Compliance ──────────────────────────────────

def analyze_custom_data_residency(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data residency compliance for AI agents."""
    findings: list[dict] = []
    findings.extend(_check_ai_data_residency(evidence_index))
    return findings


def _check_ai_data_residency(idx: dict) -> list[dict]:
    """Check if AI services are deployed in approved regions."""
    services = idx.get("azure-ai-service", [])
    if not services:
        return []

    regions: dict[str, int] = {}
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        loc = data.get("Location", "unknown")
        regions[loc] = regions.get(loc, 0) + 1

    if len(regions) > 3:
        return [_as_finding(
            "custom_data_residency", "multi_region_sprawl",
            f"AI services spread across {len(regions)} regions — data residency review needed",
            "AI services in multiple regions may violate data residency requirements. "
            "Review deployment locations against compliance requirements.",
            "medium", "cross-cutting",
            [{"Type": "RegionSprawl", "Name": f"{region} ({count} services)",
              "ResourceId": "ai-data-residency"}
             for region, count in sorted(regions.items(), key=lambda x: -x[1])],
            {"Description": "Consolidate AI services to approved regions based on data residency requirements.",
             "PortalSteps": ["Review your organization's data residency policy", "Go to Azure portal > AI Services > check Location of each resource", "Plan migration of services in non-compliant regions", "Recreate services in approved regions and migrate deployments"]},
            compliance_status="partial",
        )]
    return []


# ── 12. Sensitive Content Leakage ────────────────────────────────────

def analyze_custom_content_leakage(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess content leakage risks from AI agents."""
    findings: list[dict] = []
    findings.extend(_check_overall_content_filter_gaps(evidence_index))
    findings.extend(_check_cmk_for_ai_services(evidence_index))
    return findings


def _check_overall_content_filter_gaps(idx: dict) -> list[dict]:
    """Summarize content filter coverage across all AI deployments."""
    deployments = idx.get("azure-openai-deployment", [])
    if not deployments:
        return []

    filtered = sum(
        1 for ev in deployments
        if ev.get("Data", ev.get("data", {})).get("HasContentFilter")
    )
    unfiltered = len(deployments) - filtered

    if unfiltered > 0:
        pct = round(filtered / len(deployments) * 100, 1)
        return [_as_finding(
            "custom_content_leakage", "content_filter_gaps",
            f"{pct}% content filter coverage — {unfiltered} deployments unprotected",
            "Deployments without content safety filters can generate or surface "
            "harmful, toxic, or sensitive content. This is a direct leakage vector.",
            "high" if pct < 50 else "medium", "cross-cutting",
            [{"Type": "FilterCoverage", "Name": "Overall Coverage",
              "ResourceId": "ai-content-safety",
              "FilteredDeployments": filtered, "UnfilteredDeployments": unfiltered,
              "Coverage": f"{pct}%"}],
            {"Description": "Apply content filter policies to all AI deployments.",
             "PortalSteps": ["Go to Microsoft Foundry portal > Select the project", "Go to Safety + Security > Content filters", "Create or select a content filter configuration", "Apply to all unprotected deployments"]},
        )]
    return []


def _check_cmk_for_ai_services(idx: dict) -> list[dict]:
    """Check if AI services use customer-managed keys for encryption."""
    services = idx.get("azure-ai-service", [])
    no_cmk: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasCMK") and data.get("IsOpenAI"):
            no_cmk.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
            })
    if no_cmk:
        return [_as_finding(
            "custom_content_leakage", "no_cmk_encryption",
            f"{len(no_cmk)} OpenAI services use Microsoft-managed keys (no CMK)",
            "Customer-managed keys (CMK) provide additional control over data encryption. "
            "For highly sensitive agent workloads, CMK is recommended.",
            "low", "cross-cutting", no_cmk,
            {"Description": "Configure customer-managed keys for OpenAI services storing sensitive data.",
             "AzureCLI": "az cognitiveservices account update -n <name> -g <rg> "
                         "--encryption-key-source Microsoft.KeyVault "
                         "--encryption-key-name <key-name> --encryption-key-vault <vault-uri>",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the OpenAI resource", "Go to Encryption", "Select 'Customer-managed keys'", "Choose a Key Vault and key", "Save"]},
            compliance_status="partial",
        )]
    return []

