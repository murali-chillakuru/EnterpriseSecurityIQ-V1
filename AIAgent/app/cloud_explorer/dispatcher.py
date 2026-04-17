"""Cloud Explorer NL dispatcher.

v54 — Fully self-contained Cloud Explorer module. Routes natural-language
questions to ARG templates, Entra queries, composite queries, or findings
search. No assessment engine depends on this code.
"""

from __future__ import annotations
import difflib
import os
from typing import Any

from app.auth import ComplianceCredentials
from app.logger import log
from app.query_evaluators.arg_queries import query_resource_graph
from app.query_evaluators.cross_reference import cross_reference_findings
from app.query_evaluators.evidence_search import search_evidence
from app.query_evaluators.entra_dispatcher import _run_entra_query
from .arg_templates import ARG_TEMPLATES
from .keyword_map import NL_ARG_MAP, NL_ENTRA_MAP
from .orchestrator import run_composite_query, COMPOSITE_NAMES


# ---------------------------------------------------------------------------
# Fuzzy keyword vocabulary — built once at import time
# ---------------------------------------------------------------------------
def _build_keyword_vocab() -> set[str]:
    """Collect every unique keyword *word* used in ARG + Entra maps."""
    words: set[str] = set()
    for keywords, _ in NL_ARG_MAP:
        for phrase in keywords:
            words.update(phrase.lower().split())
    for keywords, _ in NL_ENTRA_MAP:
        for phrase in keywords:
            words.update(phrase.lower().split())
    return words


_KEYWORD_VOCAB: set[str] = _build_keyword_vocab()


def _fuzzy_correct_query(query: str, *, cutoff: float = 0.75) -> str:
    """Replace misspelled words in *query* with close matches from the keyword vocabulary.

    Uses difflib.get_close_matches with edit-distance-based similarity.
    Only single-word tokens that do NOT already appear in the vocab are
    candidates for correction.  Short words (≤ 2 chars) are left alone
    to avoid false positives on abbreviations like 'vm', 'lb', 'rg'.
    Common English stop words / verbs are also skipped so "get", "show",
    "list" etc. don't fuzzy-match to keywords like "guest" or "lock".
    """
    tokens = query.lower().split()
    corrected = []
    changed = False
    for token in tokens:
        # Already a known keyword word — keep as-is
        if token in _KEYWORD_VOCAB or len(token) <= 2:
            corrected.append(token)
            continue
        # Skip common English words that aren't cloud keywords
        if token in _STOP_WORDS:
            corrected.append(token)
            continue
        # Skip simple plurals whose singular is already in the vocab
        # e.g. "groups" → "group" ∈ vocab, "vms" → "vm" ∈ vocab
        if token.endswith("s") and token[:-1] in _KEYWORD_VOCAB:
            corrected.append(token)
            continue
        matches = difflib.get_close_matches(token, _KEYWORD_VOCAB, n=1, cutoff=cutoff)
        if matches:
            corrected.append(matches[0])
            changed = True
        else:
            corrected.append(token)
    result = " ".join(corrected)
    if changed:
        log.info("[fuzzy_correct] %r → %r", query.lower(), result)
    return result


# Common verbs / stop words that should never be fuzzy-corrected to keywords
_STOP_WORDS = frozenset({
    "get", "show", "list", "find", "display", "give", "tell", "check",
    "run", "see", "view", "fetch", "pull", "scan", "search", "look",
    "what", "which", "where", "who", "how", "when", "why",
    "is", "are", "was", "were", "be", "been", "being",
    "the", "a", "an", "this", "that", "these", "those",
    "my", "our", "your", "their", "its",
    "all", "any", "each", "every", "some", "many", "few",
    "and", "or", "but", "not", "no", "yes",
    "in", "on", "at", "to", "for", "of", "from", "with", "by", "about",
    "do", "does", "did", "can", "could", "has", "have", "had",
    "will", "would", "shall", "should", "may", "might", "must",
    "me", "us", "them", "it", "he", "she", "we", "they",
    "there", "here", "please", "now", "also", "just", "only",
})


# ---------------------------------------------------------------------------
# Entra query types recognized by _run_entra_query
# ---------------------------------------------------------------------------
_ENTRA_QUERY_TYPES = {
    "disabled_users", "guest_users", "stale_users", "directory_roles",
    "admin_users", "conditional_access", "apps", "service_principals",
    "groups", "users", "risky_users", "named_locations", "auth_methods",
    "pim_eligible", "organization_info", "security_defaults",
    "risk_detections", "risky_service_principals", "access_reviews",
    "consent_grants", "federated_credentials", "cross_tenant_access",
    "sharepoint_sites", "sensitivity_labels", "dlp_policies",
}

# ---------------------------------------------------------------------------
# Template catalog for LLM intent classifier (built once at import time)
# ---------------------------------------------------------------------------
_ARG_CATALOG_LINES = [
    "public_ips — Public IP addresses",
    "vms_without_disk_encryption — VMs lacking disk encryption",
    "all_vms — All virtual machines",
    "storage_public_access — Storage accounts with public access settings",
    "nsg_open_rules — Network security group rules (inbound open ports)",
    "sql_servers — SQL servers",
    "sql_databases_detailed — SQL databases with auditing and TDE status",
    "sql_firewall_rules — SQL server firewall rules",
    "keyvault_detailed — Key Vaults with access policies and network config",
    "aks_clusters — Azure Kubernetes Service clusters",
    "unattached_disks — Unattached/orphaned managed disks",
    "resource_counts_by_type — Count of resources grouped by type",
    "resources_by_location — Resources grouped by Azure region",
    "all_resources — All resources (name, type, location, resource group)",
    "webapp_detailed — Web apps / App Service with HTTPS and TLS info",
    "function_apps — Azure Function apps",
    "cosmosdb — Cosmos DB accounts",
    "postgres_mysql — PostgreSQL and MySQL flexible servers",
    "container_registries — Azure Container Registries",
    "vnets_subnets — Virtual networks and subnets",
    "private_endpoints — Private endpoints",
    "diagnostic_settings — Diagnostic settings on resources",
    "managed_identities — Managed identities (user and system assigned)",
    "ai_services — Azure AI, Cognitive Services, OpenAI, ML workspaces",
    "apim — API Management instances",
    "firewalls — Azure Firewalls",
    "load_balancers — Load balancers",
    "redis — Azure Cache for Redis",
    "app_gateways — Application Gateways / WAF",
    "policy_compliance — Policy compliance states (non-compliant resources)",
    "defender_plans — Microsoft Defender for Cloud pricing/plans",
    "tags_search — Resources with their tags",
    "untagged_resources — Resources missing tags",
    "subscriptions — All accessible subscriptions",
    "resource_groups — Resource groups",
    "resource_counts_by_subscription — Resource counts per subscription",
    "management_groups — Management group hierarchy",
    "role_assignments — Azure RBAC role assignments",
    "security_recommendations — Defender security recommendations",
    "secure_score — Microsoft Defender secure score",
    "log_analytics_workspaces — Log Analytics workspaces",
    "alert_rules — Metric and activity alert rules",
    "container_apps — Azure Container Apps",
    "event_hubs — Event Hubs namespaces",
    "service_bus — Service Bus namespaces",
    "backup_vaults — Backup and Recovery Services vaults",
    "openai_deployments — Azure OpenAI model deployments",
    "ml_workspaces — ML workspaces, AI Hubs, AI Projects, Foundry",
    "policy_assignments — Azure Policy assignments",
    "resource_locks — Resource locks (delete/read-only)",
    "network_interfaces — Network interfaces (NICs)",
    "route_tables — Route tables / UDRs",
    "sentinel_workspaces — Microsoft Sentinel workspaces",
    "purview_accounts — Microsoft Purview accounts",
    "web_apps — Web apps (basic view)",
    "keyvaults — Key Vaults (basic view)",
    "resources_by_subscription — Resources per subscription",
    # v54 — Compute & VM Scale Sets
    "vmss — Virtual machine scale sets",
    "dedicated_hosts — Dedicated host groups and hosts",
    "availability_sets — Availability sets",
    "disk_overview — All managed disks with state and encryption",
    "vm_extensions — VM extensions",
    "images_snapshots — VM images and disk snapshots",
    # v54 — Networking (Advanced)
    "front_door — Azure Front Door / CDN profiles",
    "expressroute — ExpressRoute circuits",
    "vpn_gateways — VPN / Virtual Network Gateways",
    "bastion_hosts — Azure Bastion hosts",
    "ddos_protection — DDoS protection plans",
    "virtual_wan — Virtual WANs and Virtual Hubs",
    "dns_zones — DNS zones and private DNS zones",
    "traffic_manager — Traffic Manager profiles",
    "nat_gateways — NAT Gateways",
    "network_watchers — Network Watchers",
    "nsg_flow_logs — NSG flow logs",
    "ip_groups — IP Groups",
    "peerings — VNet peerings",
    # v54 — Integration & Messaging
    "logic_apps — Logic Apps (Consumption and Standard)",
    "event_grid — Event Grid topics, domains, system topics, namespaces",
    "relay_namespaces — Azure Relay namespaces",
    "notification_hubs — Notification Hubs namespaces",
    "signalr — Azure SignalR and Web PubSub",
    # v54 — Containers
    "container_instances — Azure Container Instances (ACI)",
    "aro_clusters — Azure Red Hat OpenShift (ARO) clusters",
    # v54 — Databases (Extended)
    "sql_managed_instances — SQL Managed Instances",
    "mariadb — Azure Database for MariaDB",
    "elastic_pools — SQL elastic pools",
    "sql_virtual_machines — SQL Server on Azure VMs",
    # v54 — Big Data & Analytics
    "synapse — Synapse Analytics workspaces",
    "data_factory — Azure Data Factory instances",
    "databricks — Azure Databricks workspaces",
    "data_explorer — Azure Data Explorer (Kusto) clusters",
    "stream_analytics — Stream Analytics jobs",
    "hdinsight — HDInsight clusters",
    "analysis_services — Azure Analysis Services",
    "power_bi_embedded — Power BI Embedded capacities",
    # v54 — IoT
    "iot_hubs — IoT Hubs",
    "iot_central — IoT Central applications",
    "iot_dps — IoT Hub Device Provisioning Services",
    "digital_twins — Azure Digital Twins instances",
    # v54 — Hybrid & Migration
    "arc_servers — Azure Arc-enabled servers",
    "arc_kubernetes — Azure Arc-enabled Kubernetes clusters",
    "site_recovery — Recovery Services vaults (ASR / backup)",
    "migrate_projects — Azure Migrate and assessment projects",
    "stack_hci — Azure Stack HCI clusters",
    # v54 — Developer & DevOps
    "devtest_labs — Azure DevTest Labs",
    "devops_pipelines — Azure DevOps Pipelines (resource type)",
    "dev_center — Dev Centers and Dev Box projects",
    "load_testing — Azure Load Testing resources",
    "managed_grafana — Azure Managed Grafana",
    "managed_prometheus — Azure Monitor (Prometheus) accounts",
    # v54 — Security (Advanced)
    "defender_auto_provisioning — Defender auto-provisioning settings",
    "defender_assessments — Unhealthy Defender security assessments",
    "defender_alerts — Active Defender security alerts",
    "regulatory_compliance — Regulatory compliance standards status",
    "jit_policies — Just-in-Time VM access policies",
    "adaptive_app_controls — Adaptive application controls (whitelisting)",
    # v54 — Storage (Extended)
    "storage_accounts — All storage accounts with security config",
    "data_lake_stores — Data Lake Store and Analytics accounts",
    "file_shares — Storage accounts with Azure Files endpoints",
    "managed_disks_encryption — Managed disk encryption details",
    "netapp_accounts — Azure NetApp Files accounts and pools",
    # v54 — Identity & Governance
    "custom_roles — Custom RBAC role definitions",
    "deny_assignments — Deny assignments",
    "blueprint_assignments — Blueprint assignments",
    "policy_exemptions — Policy exemptions",
    "policy_definitions_custom — Custom policy definitions",
    # v54 — App Platform (Extended)
    "static_web_apps — Azure Static Web Apps",
    "app_service_plans — App Service plans (server farms)",
    "app_service_environments — App Service Environments (ASE)",
    "spring_apps — Azure Spring Apps",
    "app_configuration — Azure App Configuration stores",
    # v54 — Media & CDN
    "cdn_profiles — CDN profiles",
    "media_services — Azure Media Services",
    "communication_services — Azure Communication Services",
    # v54 — Search & Maps
    "search_services — Azure AI Search / Cognitive Search",
    "maps_accounts — Azure Maps accounts",
    # v54 — Blockchain & Confidential
    "confidential_ledger — Azure Confidential Ledger instances",
    "managed_hsm — Managed HSM pools",
    # v54 — Automation & Management
    "automation_accounts — Azure Automation accounts",
    "maintenance_configs — Maintenance configurations",
    "update_manager — VM patch assessment results",
    "action_groups — Azure Monitor action groups",
    "service_health — Active service health events",
    # v54 — Cost & Advisor
    "advisor_recommendations — Azure Advisor recommendations (all categories)",
    "advisor_cost_recommendations — Advisor cost-saving recommendations",
    # v54 — Compliance & Guest Config
    "guest_configuration — Guest configuration (policy) assignments",
    # v54 — Batch & HPC
    "batch_accounts — Azure Batch accounts",
    # v54 — Miscellaneous
    "managed_environments — Container App managed environments",
    "chaos_experiments — Chaos engineering experiments",
    "health_models — Workload health monitors",
    "cost_exports — Cost Management exports",
    "budgets — Cost Management budgets",
]

_COMPOSITE_CATALOG_LINES = [
    "hierarchy_tree — Full tenant tree: management groups → subscriptions → resource groups → resource counts (nested view)",
    "security_snapshot — Combined security posture: open NSGs, public IPs, unencrypted VMs, public storage, secure score, risky users",
    "resource_drill_down — Deep resource inventory: subscriptions → resource groups → all resources with details",
]

_ENTRA_CATALOG_LINES = [
    "users — All Entra ID users",
    "disabled_users — Disabled/blocked user accounts",
    "guest_users — External/guest (B2B) users",
    "stale_users — Users who haven't signed in for 90+ days",
    "admin_users — Users with administrative directory roles",
    "directory_roles — Directory roles with their members",
    "conditional_access — Conditional access policies",
    "apps — App registrations",
    "service_principals — Enterprise apps / service principals",
    "groups — Security groups and M365 groups",
    "risky_users — Users flagged by Identity Protection",
    "named_locations — Named/trusted network locations",
    "auth_methods — Authentication methods policy",
    "pim_eligible — PIM eligible role assignments",
    "organization_info — Tenant/organization info, domains, licenses",
    "security_defaults — Security defaults status",
    "risk_detections — Recent risk detection events",
    "risky_service_principals — Risky service principals",
    "access_reviews — Access review definitions",
    "consent_grants — OAuth/delegated permission grants",
    "federated_credentials — Federated identity credentials",
    "cross_tenant_access — Cross-tenant access policies",
    "sharepoint_sites — SharePoint Online sites",
    "sensitivity_labels — Sensitivity/classification labels",
    "dlp_policies — Data loss prevention policies",
]

_TEMPLATE_CATALOG = (
    "ARG (Azure Resource Graph) templates:\n"
    + "\n".join(f"  {line}" for line in _ARG_CATALOG_LINES)
    + "\n\nEntra ID / Microsoft Graph templates:\n"
    + "\n".join(f"  {line}" for line in _ENTRA_CATALOG_LINES)
    + "\n\nComposite (multi-step) queries:\n"
    + "\n".join(f"  {line}" for line in _COMPOSITE_CATALOG_LINES)
)

# All valid template names for validation
_ALL_TEMPLATE_NAMES = set(ARG_TEMPLATES.keys()) | _ENTRA_QUERY_TYPES | COMPOSITE_NAMES


# ---------------------------------------------------------------------------
# Lazy Azure OpenAI client for intent classification
# ---------------------------------------------------------------------------
_llm_client = None
_llm_deployment: str = ""


async def _get_llm_client():
    """Lazy-init an Azure OpenAI client for intent classification."""
    global _llm_client, _llm_deployment
    if _llm_client is not None:
        return _llm_client, _llm_deployment

    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    _llm_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1")
    if not endpoint:
        return None, ""

    from azure.identity.aio import DefaultAzureCredential
    from openai import AsyncAzureOpenAI
    import httpx

    cred = DefaultAzureCredential()
    from azure.identity.aio import get_bearer_token_provider
    token_provider = get_bearer_token_provider(
        cred, "https://cognitiveservices.azure.com/.default"
    )
    _llm_client = AsyncAzureOpenAI(
        azure_endpoint=endpoint,
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview"),
        azure_ad_token_provider=token_provider,
        timeout=httpx.Timeout(30, connect=10),
    )
    return _llm_client, _llm_deployment


async def _llm_classify_intent(question: str) -> list[str]:
    """Ask LLM to pick template(s) from the fixed catalog.

    Returns a list of valid template names (may be empty).
    The LLM never generates KQL — it only selects from the menu.
    """
    client, deployment = await _get_llm_client()
    if client is None:
        log.warning("[llm_classify] No OpenAI endpoint configured — skipping")
        return []

    system_prompt = (
        "You are a query router for a Microsoft cloud security tool. "
        "The user asked a question about their cloud environment. "
        "Your ONLY job is to pick 1-3 template names from the catalog below "
        "that would best answer the question. "
        "IMPORTANT: The user query may contain typos, misspellings, or abbreviations. "
        "Infer the intended meaning from context even if words are misspelled "
        "(e.g. 'mnagement' means 'management', 'subscripton' means 'subscription'). "
        "Reply with ONLY the template names separated by commas (e.g. 'all_vms, private_endpoints'). "
        "If no template matches, reply exactly: NONE\n\n"
        f"{_TEMPLATE_CATALOG}"
    )

    try:
        response = await client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": question},
            ],
            max_tokens=100,
            temperature=0,
        )
        reply = (response.choices[0].message.content or "").strip()
        log.info("[llm_classify] question=%r → reply=%r", question[:80], reply)

        if reply.upper() == "NONE":
            return []

        # Parse comma-separated template names and validate each
        candidates = [name.strip().lower().replace("-", "_") for name in reply.split(",")]
        valid = [name for name in candidates if name in _ALL_TEMPLATE_NAMES]

        if not valid and candidates:
            log.warning("[llm_classify] LLM returned names not in catalog: %s", candidates)

        return valid[:3]  # Cap at 3 templates

    except Exception as exc:
        log.warning("[llm_classify] LLM call failed: %s", exc)
        return []

async def dispatch_natural_language(
    creds: ComplianceCredentials,
    question: str,
    findings: list[dict] | None = None,
    evidence: list[dict] | None = None,
    top: int = 50,
) -> dict[str, Any]:
    """Route a natural language question to the appropriate query function.

    Supports multi-match: if the query matches multiple ARG templates,
    all are executed and results are merged.

    Returns:
        {"source": "arg"|"entra"|"findings"|"evidence"|"multi"|"none",
         "query_used": str,
         "results": list[dict],
         "count": int}
    """
    q = question.lower().strip()

    # 0. Fuzzy-correct misspelled words against the keyword vocabulary
    #    before any keyword matching. This lets "mnagement" → "management",
    #    "subscripton" → "subscription", etc.
    q = _fuzzy_correct_query(q)

    # 1. Check if it's a compliance/finding query
    compliance_keywords = [
        "non-compliant", "finding", "compliance", "fail", "gap",
        "control", "cis-", "iso-", "nist-", "pci-", "fedramp-",
        "mcsb-", "soc2-", "hipaa-", "gdpr-", "csa-",
    ]
    if findings and any(kw in q for kw in compliance_keywords):
        matched = cross_reference_findings(findings, question)
        return {
            "source": "findings",
            "query_used": f"cross_reference_findings('{question}')",
            "results": matched[:top],
            "count": len(matched),
        }

    # 1b. Check if it's an evidence search query
    evidence_keywords = ["evidence", "collected data", "raw data", "evidence record"]
    if evidence and any(kw in q for kw in evidence_keywords):
        matched = search_evidence(evidence, question, max_results=top)
        return {
            "source": "evidence",
            "query_used": f"search_evidence('{question}')",
            "results": matched[:top],
            "count": len(matched),
        }

    # 2. Check ARG queries FIRST — collect ALL matching templates (multi-match)
    #    ARG runs before Entra so that queries about "management group",
    #    "resource group", etc. are not hijacked by broad Entra keywords
    #    like "group".
    matched_templates: list[str] = []
    for keywords, template_name in NL_ARG_MAP:
        if any(kw in q for kw in keywords):
            matched_templates.append(template_name)

    if matched_templates:
        # Route any composite matches through the cloud_explorer orchestrator
        composite_matches = [t for t in matched_templates if t in COMPOSITE_NAMES]
        if composite_matches:
            return await run_composite_query(creds, composite_matches[0])

        all_rows: list[dict] = []
        for tpl in matched_templates:
            kql = ARG_TEMPLATES[tpl]
            try:
                # Use MG-scoped query for management_groups template
                if tpl == "management_groups" and creds.tenant_id:
                    rows = await query_resource_graph(
                        creds, kql, top=top,
                        management_group_ids=[creds.tenant_id],
                    )
                else:
                    rows = await query_resource_graph(creds, kql, top=top)
                # Tag each row with its source template for clarity
                for r in rows:
                    r["_queryTemplate"] = tpl
                all_rows.extend(rows)
            except Exception as exc:
                log.warning("ARG template %s failed: %s", tpl, exc)
                all_rows.append({"_queryTemplate": tpl, "_error": str(exc)})

        source = "arg" if len(matched_templates) == 1 else "multi"
        return {
            "source": source,
            "query_used": ", ".join(matched_templates),
            "results": all_rows[:top * len(matched_templates)],
            "count": len(all_rows),
        }

    # 3. Check Entra queries (after ARG so "management group" / "resource group"
    #    don't get caught by the broad Entra "group" keyword)
    for keywords, query_type in NL_ENTRA_MAP:
        if any(kw in q for kw in keywords):
            return await _run_entra_query(creds, query_type, q, top)

    # 4. LLM intent classifier — pick from the fixed template catalog
    llm_picks = await _llm_classify_intent(question)

    if llm_picks:
        # Check for composite queries first — they run their own orchestration
        composite_picks = [n for n in llm_picks if n in COMPOSITE_NAMES]
        if composite_picks:
            return await run_composite_query(creds, composite_picks[0], top=top)

        all_rows: list[dict] = []
        arg_picks = [n for n in llm_picks if n in ARG_TEMPLATES]
        entra_picks = [n for n in llm_picks if n in _ENTRA_QUERY_TYPES]

        # Execute ARG templates — with MG-scope for management_groups
        for tpl in arg_picks:
            kql = ARG_TEMPLATES[tpl]
            try:
                if tpl == "management_groups" and creds.tenant_id:
                    rows = await query_resource_graph(
                        creds, kql, top=top,
                        management_group_ids=[creds.tenant_id],
                    )
                else:
                    rows = await query_resource_graph(creds, kql, top=top)
                for r in rows:
                    r["_queryTemplate"] = tpl
                all_rows.extend(rows)
            except Exception as exc:
                log.warning("ARG template %s failed: %s", tpl, exc)
                all_rows.append({"_queryTemplate": tpl, "_error": str(exc)})

        # Execute Entra queries
        for qt in entra_picks:
            try:
                result = await _run_entra_query(creds, qt, q, top)
                for r in result.get("results", []):
                    r["_queryTemplate"] = qt
                all_rows.extend(result.get("results", []))
            except Exception as exc:
                log.warning("Entra query %s failed: %s", qt, exc)
                all_rows.append({"_queryTemplate": qt, "_error": str(exc)})

        source = "multi" if len(llm_picks) > 1 else ("arg" if arg_picks else "entra")
        return {
            "source": source,
            "query_used": ", ".join(llm_picks),
            "results": all_rows[:top * len(llm_picks)],
            "count": len(all_rows),
        }

    # 5. Nothing matched — return honest "no match" with guidance
    return {
        "source": "none",
        "query_used": "",
        "results": [],
        "count": 0,
        "message": "Could not match your query to any available data source. "
                   "Try asking about specific resource types (VMs, storage, NSGs, web apps, SQL, Key Vaults, "
                   "VNets, private endpoints, AKS, container apps, AI services, subscriptions), "
                   "Entra objects (users, groups, apps, service principals, risky users, PIM, "
                   "conditional access, named locations, access reviews, consent grants), "
                   "or compliance findings.",
    }
