# PostureIQ — File Reference

**Author: Murali Chillakuru**

> Complete documentation of every file in the Python AI-Agent engine — 64 collectors,
> modular assessment engines (PostureIQ, Risk, RBAC, Copilot, AI Agent Security, Data Security, Query),
> 11 compliance frameworks, 24 report generators, 14 agent tools, 15 test suites, and 11 web dashboard SPAs.
> Each major engine follows a `{prefix}_orchestrator.py` + `{prefix}_evaluators/` + `{prefix}_reports/` modular pattern.
> All metrics verified against source code.

> **Executive Summary** — Complete file-by-file inventory of the PostureIQ codebase.
> Every Python module, JSON schema, test file, and configuration file with its purpose, line count,
> and key exports. Use this as a navigation map when exploring or extending the codebase.
>
> | | |
> |---|---|
> | **Audience** | Developers, contributors, code reviewers |
> | **Prerequisites** | [Architecture](architecture.md) for structural overview |
> | **Companion docs** | [Agent Capabilities](agent-capabilities.md) for collector details · [Extending Frameworks](extending-frameworks.md) for development guide |

---

## Table of Contents

- [Pipeline Overview](#pipeline-overview)
- [CLI Entry Points (10 scripts)](#cli-entry-points)
- [Foundry Agent Entry Points](#foundry-agent-entry-points)
- [Core Modules (`AIAgent/app/`)](#core-modules-aiagentapp)
- [Collector Infrastructure (`AIAgent/app/collectors/`)](#collector-infrastructure)
- [Azure Collectors — Control Plane (39 modules)](#azure-collectors--control-plane)
- [Azure Collectors — Data Plane (8 modules)](#azure-collectors--data-plane)
- [M365 / Hybrid Collectors (2 modules, 5+ functions)](#m365--hybrid-collectors)
- [Standalone Azure Collectors (1 module)](#standalone-azure-collectors)
- [Entra Collectors — Directory (12 modules)](#entra-collectors--directory)
- [Entra Collectors — Standalone (1 module)](#entra-collectors--standalone)
- [Query Evaluators (`AIAgent/app/query_evaluators/`)](#query-evaluators)
- [Standalone Engines](#standalone-engines)
- [PostureIQ Standalone Engine](#postureiq-standalone-engine)
- [Agent Tools (`AIAgent/app/tools/`)](#agent-tools)
- [Report Generators (24 modules)](#report-generators)
- [Web Dashboard SPAs (`webapp/`)](#web-dashboard-spas)
- [Configuration (`config/`)](#configuration-config)
- [Framework Mappings](#framework-mappings)
- [JSON Schemas (`schemas/`)](#json-schemas-schemas)
- [Examples (`examples/`)](#examples-examples)
- [Tests (15 suites, ~1,357 functions)](#tests)
- [Documentation (`docs/`)](#documentation-docs)
- [Internals & Build (`_apply_phase_*.py`)](#internals--build)

---

## Pipeline Overview

```
                             ┌─────────────────────────────┐
                             │   CLI / Agent / API entry    │
                             │   (10 scripts + 14 tools)    │
                             └──────────────┬──────────────┘
                                            │
             ┌──────────────────────────────┼──────────────────────────────┐
             ▼                              ▼                              ▼
   ┌─────────────────┐          ┌─────────────────────┐        ┌─────────────────┐
   │  Phase 1: AUTH   │          │  Phase 1: AUTH      │        │  Phase 1: AUTH   │
   │  4 auth modes    │          │  DefaultAzureCredential      │  preflight_check │
   └────────┬────────┘          └──────────┬──────────┘        └────────┬────────┘
            │                              │                            │
            ▼                              ▼                            ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │  Phase 2: COLLECT  (concurrent async batches, checkpoint/resume)            │
   │                                                                             │
   │  Azure Control-Plane (39) ──→ batch by azure_batch_size (default 6)        │
   │  Azure Data-Plane (8)     ──→ same batching, requires data-plane tokens    │
   │  M365 / Hybrid (2 modules, 5+ functions) ──→ Graph beta endpoints          │
   │  Entra Directory (12)     ──→ batch by entra_batch_size (default 4)        │
   │  Standalone (2)           ──→ rbac_collector + ai_identity                  │
   │                                                                             │
   │  Total: 64 collector functions → 218 evidence types                        │
   └───────────────────────────────────┬─────────────────────────────────────────┘
                                       │
                                       ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │  Phase 3: EVALUATE                                                          │
   │                                                                             │
   │  PostureIQ evaluators (18 files) — risk-weighted scoring, attack paths      │
   │  Per-engine modular evaluators: risk (7), copilot (13), AI agent (13),      │
   │  RBAC (6), data security (11) — suppression rules, plugin hooks             │
   └───────────────────────────────────┬─────────────────────────────────────────┘
                                       │
                                       ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │  Phase 4: REPORT  (per-framework sub-folders + root-level cross-framework)  │
   │                                                                             │
   │  24 report generators (+ per-engine reports) → HTML, Markdown, Excel,       │
   │  PDF, JSON, CSV, OSCAL, SARIF, delta/drift/trending, remediation,          │
   │  executive dashboard, master report, methodology report,                    │
   │  RBAC report, risk report, data security report,                            │
   │  Copilot readiness report, AI agent security report                         │
   └─────────────────────────────────────────────────────────────────────────────┘
```

---

## CLI Entry Points

### Primary Assessment Scripts

| File | Purpose | Key Arguments | Engine / Delegate |
|------|---------|---------------|-------------------|
| `run_rbac_report.py` | Interactive RBAC hierarchy tree report | `--tenant`, `--output-dir`, `--subscriptions` | `rbac_collector.collect_rbac_data()` → `rbac_report.generate_rbac_report()` |
| `run_query.py` | Interactive REPL for Azure Resource Graph (KQL) and MS Graph queries | `--tenant` | `query_engine.py` |
| `run_risk_analysis.py` | Security risk gap analysis across 5 categories | `--tenant` | `risk_engine.py` |
| `run_data_security.py` | Data security posture assessment (7 categories, 50+ checks) | `--tenant` | `data_security_engine.py` |
| `run_copilot_readiness.py` | M365 Copilot readiness assessment (7 categories) | `--tenant`, `--evidence`, `--category`, `--previous-run`, `--fail-on-severity` | `copilot_readiness_engine.py` |
| `run_ai_agent_security.py` | AI agent security assessment (Copilot Studio, Foundry, custom agents) | `--tenant`, `--evidence`, `--category`, `--previous-run`, `--fail-on-severity` | `ai_agent_security_engine.py` |

### Determinism Validation Scripts

| File | Purpose | Pattern |
|------|---------|---------|
| `run_cr_determinism_check.py` | Copilot Readiness determinism: run 3× with identical evidence, compare outputs | Run × 3 → diff |
| `run_rbac_determinism_check.py` | RBAC Report determinism: collect once, re-run stats/risks/score 3×, compare | Collect → score × 3 → hash |

---

## Foundry Agent Entry Points

### `AIAgent/main.py`

| Property | Detail |
|----------|--------|
| **Type** | Foundry agent HTTP server |
| **Purpose** | Starts the agent on port 8088 using `responses` protocol v1 via `AzureAIClient.as_agent()` |
| **Tool Registration** | Loads 14 tools from `app/agent.py` |
| **Protocol** | Microsoft Agent Framework SDK (`agent-framework-azure-ai==1.0.0rc3`) |

### `AIAgent/agent.yaml`

| Property | Detail |
|----------|--------|
| **Purpose** | Azure Foundry agent definition — model, instructions, tool references, safety system messages |
| **Deployment** | Azure Container Apps / ACI via `azd up` |

### `AIAgent/Dockerfile`

| Property | Detail |
|----------|--------|
| **Purpose** | Multi-stage container image — Python 3.10+, installs Playwright for PDF export, exposes port 8088 |

### `AIAgent/requirements.txt`

| Property | Detail |
|----------|--------|
| **Purpose** | 40+ azure-mgmt-* SDKs, msgraph-sdk 1.12.0, openpyxl, playwright, agent-framework-azure-ai, aiohttp |

---

## Core Modules (`AIAgent/app/`)

### `AIAgent/app/agent.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Agent Framework integration: system prompt + 14 tool functions for the Foundry hosted agent |
| **Session State** | Thread-safe `_session_state` dict protected by `asyncio.Lock` — stores assessment results for cross-tool queries |
| **Tools (14)** | See [Agent Tool Functions](#agent-tool-functions-14) below |
| **Used by** | `main.py` |

### `AIAgent/app/auth.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Unified authentication with 4 modes |
| **Class** | `ComplianceCredentials` — wraps ARM + Graph credentials |
| **Auth Modes** | `auto` (DefaultAzureCredential), `azurecli` (AzureCliCredential), `serviceprincipal` (ClientSecretCredential), `appregistration` (ClientSecretCredential with app-only scopes) |
| **Key Functions** | `credential` → ARM credential, `get_graph_client()` → `GraphServiceClient`, `list_subscriptions()`, `preflight_check()` → ARM/Graph/role verification |
| **Used by** | `postureiq_orchestrator.py` at startup, all engines |

### `AIAgent/app/config.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Configuration dataclasses: `AssessmentConfig`, `AuthConfig`, `CollectorConfig` |
| **Key Class** | `AssessmentConfig.from_file(path)` — loads JSON config, merges env-var overrides |
| **Fields** | `name`, `frameworks`, `log_level`, `output_formats`, `output_dir`, `checkpoint_enabled`, `auth{}`, `collectors{}` (with `azure_batch_size`, `entra_batch_size`, `collector_timeout`, `user_sample_limit`) |
| **Thresholds** | 17 configurable thresholds: `owner_limit`, `privileged_user_limit`, `stale_days`, `mfa_minimum_pct`, `nsg_coverage_pct`, `encryption_pct`, `tls_minimum`, `log_coverage_pct`, `policy_coverage_pct`, and more |
| **Used by** | `postureiq_orchestrator.py`, all engine orchestrators |

### `AIAgent/app/models.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Core data model dataclasses |
| **Key Classes** | `ResourceContext`, `EvidenceRecord`, `FindingRecord`, `ComplianceControlResult`, `MissingEvidenceRecord`, `CollectorResult`, `AssessmentSummary`, `CheckpointState`, `Source` (enum) |
| **Serialization** | Python fields use snake_case, serialized to PascalCase via `to_dict()` |
| **Used by** | All collectors, evaluators, report generators |

### `AIAgent/app/logger.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Python `logging` configuration with console + file handlers, configurable log level |
| **Used by** | Every module |

### `AIAgent/app/api.py`

| Property | Detail |
|----------|--------|
| **Purpose** | FastAPI REST API + SSE chat streaming + report serving (local + blob fallback) |
| **Imports** | `app.postureiq_orchestrator` (replaced former `app.orchestrator`) |
| **Used by** | Web dashboard SPA, Foundry agent hosting, REST/webhook integration |

### `AIAgent/app/blob_store.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Azure Blob Storage persistence for reports — upload, download, and list blobs using `DefaultAzureCredential` |
| **Used by** | `agent.py` (upload after report generation), `api.py` (download on demand, merge listings) |
| **Dependencies** | `azure-storage-blob`, `azure-identity` |
| **Config** | `REPORT_STORAGE_ACCOUNT` (default: `esiqnewstorage`), `REPORT_STORAGE_CONTAINER` (default: `reports`) |

### `AIAgent/app/evidence_history.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Blob-backed assessment history — stores, queries, and compares past assessment runs |
| **Key Functions** | `save_run()` — persist assessment results to blob; `list_runs()` — enumerate past runs; `load_run()` — retrieve specific run; `query_history()` — filter/search history; `get_score_trend()` — score time-series |
| **Used by** | `agent.py` → `query_assessment_history` tool |
| **Dependencies** | `azure-storage-blob`, `azure-identity` |

### `AIAgent/app/i18n.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Internationalization — loads locale JSON files (`locales/en.json`) for report labels |
| **Used by** | Report generators |

### `AIAgent/app/locales/en.json`

| Property | Detail |
|----------|--------|
| **Purpose** | English locale strings for report section titles, status labels, and UI text |

---

## Collector Infrastructure

### `AIAgent/app/collectors/registry.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Plugin registry with `@register_collector` decorator for auto-discovery |
| **Decorator** | `@register_collector(name, plane, source, priority)` — registers function in global `_REGISTRY` |
| **Discovery** | `discover_collectors()` — imports all modules under `collectors/azure/` and `collectors/entra/` |
| **Helpers** | `get_collector_functions(source, plane)` — returns sorted list by priority |
| **Used by** | `orchestrator.py`, all collector modules |

### `AIAgent/app/collectors/base.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Base collector utilities: retry logic, pagination, permission-error detection |
| **Key Functions** | `_v(obj, default)` — safe Azure enum value extractor; `AccessDeniedError` — raised on 403/401; retry with exponential backoff (MAX_RETRIES=3, RETRY_BACKOFF=2s) |
| **Constants** | `ACCESS_DENIED_CODES = {401, 403}` |
| **Used by** | All collector modules |

### `AIAgent/app/collectors/inventory.py`

| Property | Detail |
|----------|--------|
| **Purpose** | `ResourceInventory` singleton — caches ARM resource list across collectors |
| **Pattern** | Thread-safe singleton via `asyncio.Lock`; `ensure_loaded()` populates once, then `by_type()` / `by_sub()` / `all()` for fast lookups |
| **Used by** | Collectors that need resource enumeration (storage, compute, network, etc.) |

### `AIAgent/app/collectors/__init__.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Package init — re-exports registry functions |

---

## Azure Collectors — Control Plane

39 registered control-plane collectors (`plane="control"`, `source="azure"`), organized by priority. All are async functions accepting `(creds, subscriptions)` and returning `list[dict]`.

| Priority | File | Function | Purpose | SDK |
|----------|------|----------|---------|-----|
| P10 | `resources.py` | `collect_azure_resources` | Subscriptions, resource groups, total resource inventory | `azure-mgmt-resource` |
| P20 | `rbac.py` | `collect_azure_rbac` | Role assignments, custom roles, privileged role analysis | `azure-mgmt-authorization` |
| P30 | `policy.py` | `collect_azure_policy` | Policy assignments, definitions, enforcement modes | `azure-mgmt-policyinsights` |
| P30 | `policy_compliance.py` | `collect_azure_policy_compliance` | Per-resource policy compliance states | `azure-mgmt-policyinsights` |
| P40 | `diagnostics.py` | `collect_azure_diagnostics` | Diagnostic settings coverage per resource | `azure-mgmt-monitor` |
| P40 | `activity_logs.py` | `collect_azure_activity_logs` | Activity logs (90-day lookback), resource locks | `azure-mgmt-monitor`, `azure-mgmt-resource.locks` |
| P50 | `monitoring.py` | `collect_azure_monitoring` | Alert rules, Log Analytics workspaces, action groups | `azure-mgmt-monitor` |
| P60 | `security.py` | `collect_azure_security` | Key Vaults (secrets/keys/certs), Defender assessments | `azure-mgmt-keyvault`, `azure-mgmt-security` |
| P60 | `defender_plans.py` | `collect_azure_defender_plans` | Defender for Cloud pricing tiers per subscription | `azure-mgmt-security` |
| P60 | `defender_advanced.py` | `collect_azure_defender_advanced` | Secure scores, regulatory compliance, JIT, alerts | `azure-mgmt-security` |
| P70 | `compute.py` | `collect_azure_compute` | VMs, managed disks (encryption, extensions) | `azure-mgmt-compute` |
| P70 | `managed_disks.py` | `collect_azure_disks_snapshots` | Managed disks, snapshots, disk encryption sets | `azure-mgmt-compute` |
| P80 | `network.py` | `collect_azure_network` | NSGs, VNets, subnets, private endpoints | `azure-mgmt-network` |
| P80 | `network_expanded.py` | `collect_azure_network_expanded` | Storage account network-layer security (TLS, HTTPS, public access) | `azure-mgmt-storage` |
| P80 | `app_gateway.py` | `collect_azure_app_gateway` | Application Gateways, WAF policies, backend health | `azure-mgmt-network` |
| P90 | `additional_services.py` | `collect_azure_additional_services` | Web Apps, SQL Servers (TLS, HTTPS, auditing) | `azure-mgmt-web`, `azure-mgmt-sql` |
| P90 | `webapp_detailed.py` | `collect_azure_webapp_detailed` | Web app auth settings, IP restrictions, CORS, diagnostic logging | `azure-mgmt-web` |
| P100 | `functions.py` | `collect_azure_functions` | Function apps, function details, deployment slots | `azure-mgmt-web` |
| P100 | `containers.py` | `collect_azure_containers` | Container Registry (ACR), Container Apps config | `azure-mgmt-containerregistry`, `azure-mgmt-appcontainers` |
| P100 | `aks_in_cluster.py` | `collect_azure_aks_config` | AKS deep config: RBAC, network policies, node pools, addons | `azure-mgmt-containerservice` |
| P110 | `databases.py` | `collect_azure_databases` | Cosmos DB, PostgreSQL & MySQL Flexible Server security | `azure-mgmt-cosmosdb`, `azure-mgmt-rdbms` |
| P110 | `sql_detailed.py` | `collect_azure_sql_detailed` | Per-database auditing, TDE, ATP, vulnerability assessment, LTR | `azure-mgmt-sql` |
| P110 | `rdbms_detailed.py` | `collect_azure_rdbms_detailed` | PostgreSQL & MySQL parameters, firewall rules, SSL enforcement | `azure-mgmt-rdbms` |
| P120 | `storage.py` | `collect_azure_storage` | Storage account encryption, soft delete, lifecycle, network rules | `azure-mgmt-storage` |
| P120 | `ai_services.py` | `collect_azure_ai_services` | Cognitive Services, OpenAI model deployments, ML Workspaces | `azure-mgmt-cognitiveservices`, `azure-mgmt-machinelearningservices` |
| P120 | `ml_cognitive.py` | `collect_azure_ml_cognitive` | ML workspaces, ML compute, Cognitive Services extended | `azure-mgmt-machinelearningservices`, `azure-mgmt-cognitiveservices` |
| P130 | `dns.py` | `collect_azure_dns` | DNS Zones, Private DNS Zones, Traffic Manager | `azure-mgmt-dns`, `azure-mgmt-privatedns`, `azure-mgmt-trafficmanager` |
| P130 | `frontdoor_cdn.py` | `collect_azure_frontdoor_cdn` | Front Door, WAF policies, CDN profiles/endpoints | `azure-mgmt-frontdoor`, `azure-mgmt-cdn` |
| P140 | `messaging.py` | `collect_azure_messaging` | Service Bus namespaces/queues, Event Hubs | `azure-mgmt-servicebus`, `azure-mgmt-eventhub` |
| P140 | `sentinel.py` | `collect_azure_sentinel` | Sentinel workspaces, data connectors, analytics rules, incidents, watchlists | `azure-mgmt-securityinsight`, `azure-mgmt-loganalytics` |
| P150 | `ai_content_safety.py` | `collect_azure_ai_content_safety` | OpenAI content safety, AI governance, blocklists | `azure-mgmt-cognitiveservices` |
| P150 | `data_analytics.py` | `collect_azure_data_analytics` | Synapse workspaces/pools, Data Factory, Databricks | `azure-mgmt-synapse`, `azure-mgmt-datafactory`, `azure-mgmt-databricks` |
| P160 | `redis_iot_logic.py` | `collect_azure_redis_iot_logic` | Redis Cache, IoT Hub, Logic Apps | `azure-mgmt-redis`, `azure-mgmt-iothub`, `azure-mgmt-logic` |
| P160 | `api_management.py` | `collect_azure_api_management` | APIM instances: TLS, VNet, identity, private endpoints | `azure-mgmt-apimanagement` |
| P170 | `batch_aci.py` | `collect_azure_batch_aci` | Batch accounts, Container Instance groups | `azure-mgmt-batch`, `azure-mgmt-containerinstance` |
| P170 | `arc_hybrid.py` | `collect_azure_arc` | Arc-enabled servers, extensions, Arc Kubernetes clusters | `azure-mgmt-hybridcompute`, `azure-mgmt-resource` |
| P180 | `copilot_studio.py` | `collect_copilot_studio` | Copilot Studio bots, Power Platform DLP, connector restrictions | `aiohttp` (Power Platform admin + Graph beta) |
| P180 | `cost_billing.py` | `collect_azure_cost_billing` | Budgets, Advisor cost recommendations | `azure-mgmt-costmanagement`, `azure-mgmt-advisor` |
| P190 | `backup_dr.py` | `collect_azure_backup_dr` | Recovery Services vaults, backup policies, backup items | `azure-mgmt-recoveryservices`, `azure-mgmt-recoveryservicesbackup` |

---

## Azure Collectors — Data Plane

8 registered data-plane collectors (`plane="data"`, `source="azure"`). Require additional data-plane tokens beyond ARM.

| Priority | File | Function | Purpose | SDK |
|----------|------|----------|---------|-----|
| P200 | `cosmosdb_data_plane.py` | `collect_azure_cosmosdb_data_plane` | CosmosDB databases, containers, RBAC role assignments | `azure-mgmt-cosmosdb` |
| P200 | `storage_data_plane.py` | `collect_azure_storage_data_plane` | Per-container public access, immutability policies, lifecycle | `azure-mgmt-storage`, `azure.storage.blob.aio` |
| P210 | `apim_data_plane.py` | `collect_azure_apim_data_plane` | APIM APIs, products, subscriptions, certificates, named values | `azure-mgmt-apimanagement` |
| P210 | `acr_data_plane.py` | `collect_azure_acr_data_plane` | ACR repository enumeration, tag mutability, image manifests | `azure.containerregistry.aio`, `azure.mgmt.containerregistry.aio` |
| P220 | `purview_dlp.py` | `collect_azure_purview_dlp` | Purview accounts, sensitivity labels, DLP labels | `azure-mgmt-purview`, `msgraph-sdk` |
| P220 | `sharepoint_onedrive.py` | `collect_sharepoint_onedrive` | SharePoint sites, permissions, sharing links, oversharing analysis | `msgraph` (Graph v1.0 + beta) |
| P230 | `foundry_config.py` | `collect_foundry_config` | Microsoft Foundry, Azure OpenAI, AI Services security config (16 evidence types) | `aiohttp` (ARM REST) |
| P240 | `m365_sensitivity_labels.py` | `collect_m365_sensitivity_labels` | Sensitivity label definitions, auto-labeling rules, usage summary | `msgraph` (Graph v1.0 + beta) |

---

## M365 / Hybrid Collectors

2 modules with 5+ functions registered as `source="entra"` in the registry despite living in `collectors/azure/`. These use Graph beta APIs for M365 compliance features.

| File | Functions | Purpose | SDK |
|------|-----------|---------|-----|
| `m365_compliance.py` | `collect_m365_retention`, `collect_m365_insider_risk`, `collect_m365_ediscovery`, `collect_m365_dlp`, `collect_m365_label_usage` | M365 Purview: retention policies/labels, Insider Risk settings, eDiscovery cases, DLP alerts, sensitivity label usage | `msgraph` (Graph beta) |

---

## Standalone Azure Collectors

Not registered in the plugin registry — invoked directly by dedicated CLI scripts and engines.

| File | Function | Lines | Purpose | SDK |
|------|----------|-------|---------|-----|
| `rbac_collector.py` | `collect_rbac_data` | 983 | Full management-group → subscription → RG → resource hierarchy with role assignments, PIM eligibility, group expansion, risk scoring | `azure-mgmt-authorization`, `azure-mgmt-managementgroups`, `azure-mgmt-resource`, `msgraph-sdk` |

> All registered collectors accept `(creds, subscriptions)` and return `list[dict]` of evidence records.
> Entra collectors accept `(graph_client)`. `user_details` also accepts `user_sample_limit`.

---

## Entra Collectors — Directory

12 registered Entra directory collectors (`source="entra"`). All are async functions using the Microsoft Graph Python SDK (read-only).

| File | Function | Purpose | Graph Permissions |
|------|----------|---------|-------------------|
| `tenant.py` | `collect_entra_tenant` | Tenant info, authentication methods policy | `Directory.Read.All`, `Policy.Read.All` |
| `roles.py` | `collect_entra_roles` | Directory roles, privileged role assignments, admin units | `RoleManagement.Read.All` |
| `conditional_access.py` | `collect_entra_conditional_access` | CA policies (MFA, block, device compliance) | `Policy.Read.All` |
| `applications.py` | `collect_entra_applications` | App registrations, service principals, credential expiry | `Application.Read.All` |
| `users.py` | `collect_entra_users` | User/group aggregate summaries (no PII) | `User.Read.All`, `Group.Read.All` |
| `user_details.py` | `collect_entra_user_details` | Per-user lifecycle (last sign-in, stale, disabled), OAuth2 grants | `User.Read.All`, `AuditLog.Read.All` |
| `audit_logs.py` | `collect_entra_audit_logs` | Sign-in logs, directory audit logs, named locations | `AuditLog.Read.All` |
| `identity_protection.py` | `collect_entra_identity_protection` | Risk detections, risky users | `IdentityRiskEvent.Read.All` |
| `governance.py` | `collect_entra_governance` | Access reviews, entitlement management | `AccessReview.Read.All` |
| `security_policies.py` | `collect_entra_security_policies` | Security defaults, cross-tenant access policies | `Policy.Read.All` |
| `workload_identity.py` | `collect_entra_workload_identity` | Federated credentials, managed identity SPs, credential review | `Application.Read.All` |
| `risk_policies.py` | `collect_entra_risk_policies` | Risky users, risk detections, named locations, auth methods/strength | `IdentityRiskEvent.Read.All`, `Policy.Read.All` |

---

## Entra Collectors — Standalone

| File | Function | Lines | Purpose | SDK |
|------|----------|-------|---------|-----|
| `ai_identity.py` | AI identity analysis | 419 | Enriches Entra data into AI-focused evidence: AI service principals, OAuth consent grants for AI services, cross-tenant policies for AI workloads | `msgraph` (Graph beta) |

---

## Query Evaluators

The query engine (`query_engine.py`) was refactored in v50a into a ~45-line backward-compatible shim that re-exports all public symbols from 8 new modules in `AIAgent/app/query_evaluators/`.

| File | Lines | Key Exports | Purpose |
|------|-------|-------------|---------|
| `arg_queries.py` | ~516 | `query_resource_graph()`, `ARG_TEMPLATES` | Azure Resource Graph (KQL) query execution and pre-built query templates |
| `entra_queries.py` | 379 | 12 `query_entra_*` functions | Entra ID directory queries (users, groups, roles, apps, policies, etc.) |
| `resource_detail.py` | 97 | `get_resource_detail()`, `get_entra_user_detail()` | Single-resource and single-user detail lookups |
| `cross_reference.py` | 130 | `cross_reference_findings()` | Cross-reference findings across evidence types and controls |
| `dispatcher.py` | 147 | `dispatch_natural_language()`, NL keyword maps | Natural language query routing to appropriate query functions |
| `entra_extended.py` | 270 | 11 `_query_*` helpers | Extended Entra queries for advanced directory analysis |
| `entra_dispatcher.py` | 100 | `_run_entra_query()` | Typed dispatcher for Entra query routing |
| `evidence_search.py` | 149 | `search_evidence()`, `search_evidence_advanced()` | Full-text and advanced search across collected evidence |
| `__init__.py` | — | Re-exports all public symbols | Package init — maintains backward compatibility with `query_engine` imports |

---

## Standalone Engines

Modular engines in `AIAgent/app/` providing specialized analysis. Each major engine follows a `{prefix}_orchestrator.py` + `{prefix}_evaluators/` + `{prefix}_reports/` pattern (v49+).

| Engine | Orchestrator | Evaluators | Reports | Entry Function | Purpose |
|--------|-------------|------------|---------|----------------|---------|
| **PostureIQ** | `postureiq_orchestrator.py` | `postureiq_evaluators/` (18 files) | `postureiq_reports/` (28 files) | `run_postureiq_assessment()` | Risk-weighted compliance posture with attack paths, priority ranking, AI-powered remediation |
| **Risk** | `risk_orchestrator.py` | `risk_evaluators/` (7 files) | `risk_reports/` | `run_risk_analysis()` | Security risk gap analysis across 5 categories: Identity, Network, Defender, Config, Data |
| **RBAC** | `rbac_orchestrator.py` | `rbac_evaluators/` (6 files) | `rbac_reports/` | `generate_rbac_report()` | Interactive RBAC hierarchy tree with role assignments and PIM |
| **Copilot Readiness** | `copilot_orchestrator.py` | `copilot_evaluators/` (13 files) | `copilot_reports/` | `run_copilot_readiness_assessment()` | M365 Copilot readiness across 7 categories |
| **AI Agent Security** | `aiagentsec_orchestrator.py` | `aiagentsec_evaluators/` (13 files) | `aiagentsec_reports/` | `run_ai_agent_security_assessment()` | AI agent security: Copilot Studio, Foundry, custom agents, Entra AI identity |
| **Data Security** | `data_security_engine.py` | `datasec_evaluators/` (11 files) | `datasec_reports/` | `run_data_security_assessment()` | Data security: Storage, Database, Key/Secret, Encryption, Classification, Lifecycle, DLP |
| **Query** | `query_engine.py` (shim) | `query_evaluators/` (8 modules) | — | `query_resource_graph()`, `dispatch_natural_language()` | Interactive query engine for ARG (KQL) and MS Graph with NL support |

### Non-Modular Engines

| File | Lines | Key Function/Class | Purpose |
|------|-------|--------------------|---------|
| `data_residency_engine.py` | 296 | `assess_data_residency()` | Data residency validation: region compliance, storage/DB replication, cross-region dependencies |
| `remediation_engine.py` | 299 | `generate_remediation()`, `generate_remediation_report()` | Auto-generates az CLI, PowerShell, ARM template remediation snippets for non-compliant findings |
| `continuous_monitor.py` | 196 | `ContinuousMonitor`, `TrendTracker`, `MonitoringSchedule` | Continuous monitoring — delegates to `postureiq_orchestrator.run_postureiq_assessment()` |
| `evidence_history.py` | — | `save_run()`, `list_runs()`, `load_run()`, `query_history()`, `get_score_trend()` | Blob-backed assessment history — stores and queries past assessment runs |

### Supporting Modules

| File | Lines | Purpose |
|------|-------|---------|
| `siem_integration.py` | 156 | SIEM/SOAR export: Azure Sentinel (DCR API), Splunk (HEC), or generic webhook. `SIEMExporter` with async batch sending. |
| `operational_integrations.py` | 443 | Webhook/email alerts (`WebhookConfig`, `EmailConfig`), ServiceNow/Jira ticket creation, Azure DevOps work items for findings |

---

## Agent Tools

### `AIAgent/app/tools/query.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Agent-tool wrapper for querying assessment results by control ID, domain, severity, or keyword |
| **Used by** | `agent.py` → `query_results` tool |

### Agent Tool Functions (14)

| # | Tool | Purpose | Backing Engine |
|---|------|---------|----------------|
| 1 | `query_results` | Query assessment results by control ID, domain, severity, keyword | `tools/query.py` |
| 2 | `search_tenant` | Natural language / KQL search of Azure resources and Entra objects | `query_engine.py` |
| 3 | `analyze_risk` | Security risk gap analysis across 5 categories with composite scoring | `risk_engine.py` |
| 4 | `assess_data_security` | Data-layer posture: storage, DB, KV, encryption, classification, lifecycle, DLP | `data_security_engine.py` |
| 5 | `generate_rbac_report` | Interactive RBAC hierarchy tree with role assignments and PIM | `rbac_collector.py` → `rbac_report.py` |
| 6 | `generate_report` | Generate HTML and/or JSON compliance reports from session state | `reports/*.py` |
| 7 | `assess_copilot_readiness` | M365 Copilot readiness across 7 categories | `copilot_readiness_engine.py` |
| 8 | `assess_ai_agent_security` | AI agent security: Copilot Studio, Foundry, custom agents, Entra AI identity | `ai_agent_security_engine.py` |
| 9 | `check_permissions` | Probe ARM, Graph, and Entra permissions before assessment | `auth.py` |
| 10 | `compare_runs` | Delta comparison: new findings, resolved, status changes, score drift | Session state comparison |
| 11 | `search_exposure` | Quick exposure scan: public storage, open NSGs, unencrypted VMs, unattached disks, public IPs | Inline evidence scan |
| 12 | `generate_custom_report` | Generate custom-scoped reports with user-selected frameworks and format options | `reports/*.py` |
| 13 | `run_postureiq_assessment` | PostureIQ risk-weighted posture assessment with attack paths, priority ranking, and AI fix recommendations | `postureiq_orchestrator.py` |
| 14 | `query_assessment_history` | Browse and trend-analyze past assessment runs (actions: list, trend, detail, compare) | `evidence_history.py` |

The `TOOLS` list in `agent.py`: `TOOLS = [query_results, search_tenant, analyze_risk, assess_data_security, generate_rbac_report, generate_report, assess_copilot_readiness, assess_ai_agent_security, check_permissions, compare_runs, search_exposure, generate_custom_report, run_postureiq_assessment, query_assessment_history]`

---

## Report Generators

24 modules in `AIAgent/app/reports/`. All accept assessment results and produce formatted output. Compliance-specific generators (`compliance_report_html.py`, `compliance_report_md.py`, `html_report.py`, `json_report.py`) were removed in v50b — their equivalents now live in `postureiq_reports/`.

### Compliance Reports (per-framework)

| File | Function | Output | Description |
|------|----------|--------|-------------|
| `markdown_report.py` | `generate_markdown_report()` | Markdown report | Human-readable Markdown compliance report |
| `gaps_report.py` | `generate_gaps_report()` | `gaps-report.html`, `gaps-report.md` | Non-compliant findings with phased remediation roadmap (~473 lines) |
| `excel_export.py` | `generate_excel_report()` | `{framework}-report.xlsx` | 3-sheet workbook: Compliance Report, Gap Analysis, Executive Summary. Color-coded. (~236 lines) |

### Specialized Reports

| File | Function | Output | Description |
|------|----------|--------|-------------|
| `data_security_report.py` | `generate_data_security_report()` | Data security HTML + Excel | Interactive data security posture report with 7-category breakdown (~3,348 lines) |
| `copilot_readiness_report.py` | `generate_copilot_readiness_report()` | Copilot readiness HTML + Excel | M365 Copilot readiness with executive summary and 7-category breakdown (~3,409 lines) |
| `ai_agent_security_report.py` | `generate_ai_agent_security_report()` | AI agent security HTML + Excel | AI agent security posture: Copilot Studio, Foundry, custom agents (~1,518 lines) |
| `rbac_report.py` | `generate_rbac_report()` | RBAC hierarchy HTML | Interactive RBAC tree: mgmt-group → subscription → RG with assignments, PIM, risk badges (~1,913 lines) |
| `risk_report.py` | `generate_risk_report()` | Risk analysis HTML + Excel | Security risk gap analysis with remediation roadmap (~917 lines) |

### Cross-Framework & Executive Reports

| File | Function | Output | Description |
|------|----------|--------|-------------|
| `master_report.py` | `generate_master_report()` | `master-report.html`, `master-report.md` | Combined master report across all frameworks (~594 lines) |
| `executive_dashboard.py` | `generate_executive_dashboard()` | `executive-dashboard.html` | Executive dashboard with compliance metrics (~222 lines) |
| `executive_summary.py` | — | `executive-summary.html/md` | One-page executive summary with compliance ring |
| `methodology_report.py` | `generate_methodology_html()` | `methodology-report.html` | 11-section auditor-facing report: pipeline, data sources, transparency, permission gaps |
| `remediation.py` | `generate_remediation_playbooks()` | Remediation playbooks | Step-by-step remediation guidance with az CLI, PowerShell, ARM snippets (~547 lines) |

### Data Exports

| File | Function | Output | Description |
|------|----------|--------|-------------|
| `data_exports.py` | `export_data_files()`, `save_raw_evidence()` | `findings.json/csv`, `control-results.json/csv`, `evidence.json`, `all-evidence.json` | Structured data for SIEM and programmatic use |
| `oscal_export.py` | `export_oscal()` | `oscal-results.json` | NIST OSCAL assessment results format (~102 lines) |
| `sarif_export.py` | `export_sarif()` | `results.sarif` | SARIF format for security tool integration (~119 lines) |
| `pdf_export.py` | `html_to_pdf()` | PDF files | Converts HTML reports to PDF via headless Chromium (Playwright) (~85 lines) |

### Trend & Drift Analysis

| File | Function | Output | Description |
|------|----------|--------|-------------|
| `delta_report.py` | `compute_delta()`, `generate_delta_section()` | Embedded in HTML | Trend analysis vs previous run — new/resolved findings, score changes |
| `drift_report_html.py` | `generate_drift_report_html()` | `drift-report.html` | Compliance drift visualization over time |
| `trending.py` | — | Trend data | Historical trending analysis with time-series data |

### Infrastructure & Utilities

| File | Purpose |
|------|---------|
| `shared_theme.py` | Dark/light Fluent Design CSS theme shared across all HTML reports — CSS variables, responsive layout, compliance ring SVG, theme toggle (~294 lines) |
| `evidence_catalog.py` | Evidence type catalog — lists all evidence types collected |
| `inventory.py` | Resource inventory report generation |
| `notifications.py` | Alert/notification dispatch for report delivery |
| `__init__.py` | Package init |

---

## PostureIQ Standalone Engine

PostureIQ is an **independent**, risk-weighted compliance posture assessment engine — a full parallel pipeline to the traditional compliance assessment. It has its own evaluators, framework mappings, report generators, and orchestrator.

### `AIAgent/app/postureiq_orchestrator.py`

| Property | Detail |
|----------|--------|
| **Purpose** | Multi-phase PostureIQ pipeline coordinator — collect → evaluate → risk scoring → attack paths → priority ranking → exception tracking → AI fixes → delta → report |
| **Key Function** | `async run_postureiq_assessment(creds, config)` |
| **Phases** | 1: Collect (reuses main collectors) → 2: Evaluate (postureiq_evaluators) → 2.1: Risk-weighted scoring → 2.2: Attack path analysis → 2.3: Priority ranking → 2.4: Exception tracking → 2.5: AI fix recommendations → 3: Delta comparison → 4: Report generation |
| **Used by** | `agent.py` → `run_postureiq_assessment` tool |

### PostureIQ Evaluators (`AIAgent/app/postureiq_evaluators/`)

18 files — 10 domain evaluators (mirroring the main engine) plus infrastructure modules and 3 new advanced analysis modules.

| File | Domain / Purpose | Function Count | Key Checks |
|------|-----------------|----------------|------------|
| `access.py` | `access` | 8 | RBAC Owner count, privileged access separation, least privilege, JIT access |
| `identity.py` | `identity` | 22 | MFA coverage, credential lifecycle, user lifecycle, OAuth2 consent, workload identity |
| `data_protection.py` | `data_protection` | 22 | Encryption at rest/transit, Key Vault, CMK, SQL/CosmosDB/AKS hardening |
| `logging_eval.py` | `logging` | 13 | Diagnostic coverage, threat detection, flow logs, activity analysis |
| `network.py` | `network` | 17 | NSG analysis, segmentation, storage firewalls, **private endpoint adoption** (10 PaaS types) |
| `governance.py` | `governance` | 21 | Policy compliance, Defender posture, resource locks, PIM, access reviews |
| `incident_response.py` | `incident_response` | 6 | Sentinel analytics, alert coverage, security playbook automation |
| `change_management.py` | `change_management` | 4 | Resource lock verification, policy enforcement, change audit trails |
| `business_continuity.py` | `business_continuity` | 4 | Backup vault coverage, disaster recovery, geo-redundancy |
| `asset_management.py` | `asset_management` | 4 | Resource inventory, tagging compliance, orphan detection |
| `engine.py` | Evaluation engine | — | Risk-weighted scoring (severity × exploitability × blast radius), RiskScore 0–100, RiskTier labels, cross-domain fallback |
| `plugins.py` | Plugin hooks | — | Custom evaluator plugin loader |
| `suppressions.py` | Suppression rules | — | Enhanced suppression with **audit trail** fields: `owner`, `ticket`, `risk_accepted`, `created` |
| `remediation.py` | Remediation hints | — | Maps findings to remediation recommendations |
| `attack_paths.py` | **Attack path analysis** (NEW) | — | Privilege escalation chains, lateral movement via managed identities, exposed high-value targets, permanent GA detection |
| `priority_ranking.py` | **Priority ranking** (NEW) | — | ROI-based ranking (risk/√effort), PriorityRank, EffortHours, PriorityLabel, quick wins identification |
| `ai_fix_recommendations.py` | **AI fix recommendations** (NEW) | — | GPT-powered tenant-specific remediation scripts (Azure CLI + PowerShell) for top-15 priority findings |
| `__init__.py` | Package init | — | — |

### PostureIQ Frameworks (`AIAgent/app/postureiq_frameworks/`)

11 JSON framework mapping files — independent copies ensuring PostureIQ can evolve framework mappings separately.

| File | Framework | Controls |
|------|-----------|----------|
| `nist-800-53-mappings.json` | NIST 800-53 Rev 5 | 83 |
| `fedramp-mappings.json` | FedRAMP High Baseline | 69 |
| `cis-mappings.json` | CIS Azure Benchmarks | 53 |
| `mcsb-mappings.json` | Microsoft Cloud Security Benchmark | 53 |
| `pci-dss-mappings.json` | PCI DSS v4.0 | 51 |
| `iso-27001-mappings.json` | ISO 27001:2022 | 51 |
| `soc2-mappings.json` | SOC 2 Type II | 47 |
| `hipaa-mappings.json` | HIPAA Security Rule | 43 |
| `nist-csf-mappings.json` | NIST Cybersecurity Framework | 29 |
| `csa-ccm-mappings.json` | CSA Cloud Controls Matrix | 24 |
| `gdpr-mappings.json` | GDPR | 22 |

### PostureIQ Reports (`AIAgent/app/postureiq_reports/`)

20 report generator files — full report suite with 2 PostureIQ-specific report generators.

| File | Purpose |
|------|---------|
| `postureiq_report_html.py` | PostureIQ-specific HTML report with risk scoring, attack paths, priority ranking, AI fixes |
| `postureiq_report_md.py` | PostureIQ-specific Markdown report |
| `compliance_report_html.py` | Compliance report (HTML) |
| `compliance_report_md.py` | Compliance report (Markdown) |
| `data_security_report.py` | Data security posture report |
| `copilot_readiness_report.py` | Copilot readiness report |
| `ai_agent_security_report.py` | AI agent security report |
| `rbac_report.py` | RBAC hierarchy report |
| `risk_report.py` | Risk analysis report |
| `executive_dashboard.py` | Executive dashboard |
| `gaps_report.py` | Gaps analysis report |
| `master_report.py` | Master cross-framework report |
| `excel_export.py` | Excel export |
| `oscal_export.py` | OSCAL export |
| `sarif_export.py` | SARIF export |
| `pdf_export.py` | PDF export via Playwright |
| `html_report.py` | Standard HTML report |
| `json_report.py` | JSON report |
| `markdown_report.py` | Markdown report |
| `evidence_catalog.py` | Evidence type catalog |
| `data_exports.py` | JSON/CSV data exports |
| `delta_report.py` | Delta/drift comparison |
| `drift_report_html.py` | Drift visualization |
| `inventory.py` | Resource inventory report |
| `methodology_report.py` | Methodology report |
| `remediation.py` | Remediation playbooks |
| `shared_theme.py` | Dark/light Fluent Design CSS |
| `__init__.py` | Package init |

---

## Web Dashboard SPAs (`webapp/`)

11 self-contained HTML single-page applications with MSAL.js authentication and SSE streaming. Each SPA communicates with the agent's `/chat` SSE endpoint.

| File | Purpose |
|------|---------|
| `index.html` | **Portal** — card-grid launcher linking to all assessment SPAs |
| `EnterpriseSecurityIQ.html` | Full dashboard (copy of original monolithic SPA) |
| `esiq.html` | Full dashboard (alias) |
| `enterpriseIQ.html` | Full dashboard (alias) |
| `ComplianceAssessment.html` | Focused SPA for compliance assessments |
| `RiskAnalysis.html` | Focused SPA for security risk gap analysis |
| `DataSecurity.html` | Focused SPA for data security assessments |
| `RBACReport.html` | Focused SPA for RBAC hierarchy reports |
| `CopilotReadiness.html` | Focused SPA for M365 Copilot readiness |
| `AIAgentSecurity.html` | Focused SPA for AI agent security assessments |
| `PostureIQ.html` | Focused SPA for PostureIQ posture assessments with framework picker |

---

## Configuration (`config/`)

### `config/enterprisesecurityiq.config.json`

| Property | Detail |
|----------|--------|
| **Purpose** | Master configuration for the Python assessment engine |
| **Top-level keys** | `name`, `frameworks[]`, `logLevel`, `outputFormats[]`, `outputDir`, `checkpointEnabled`, `auth{}`, `collectors{}`, `thresholds{}` |
| **auth** | `tenantId`, `authMode` (`auto` / `serviceprincipal` / `azurecli` / `appregistration`), `subscriptionFilter[]` |
| **collectors** | `azureEnabled`, `entraEnabled`, `azureBatchSize` (default 6), `entraBatchSize` (default 4), `collectorTimeout` (default 600s), `userSampleLimit` |
| **thresholds** | 17 configurable thresholds controlling evaluator sensitivity |
| **Used by** | `config.py → AssessmentConfig.from_file()` |

### `config/config.schema.json`

| Property | Detail |
|----------|--------|
| **Purpose** | JSON Schema validating `enterprisesecurityiq.config.json` against the Python dataclass structure |

### `config/data-security-relevance.json`

| Property | Detail |
|----------|--------|
| **Purpose** | Prose rationale descriptions for each data-security category (storage, database, cosmosdb, keyvault, encryption, etc.) — used as contextual descriptions in Data Security reports |

---

## Framework Mappings

Framework mapping JSON files are maintained per engine. The original `AIAgent/app/frameworks/` directory was removed in v50b. Active framework mapping directories:

### PostureIQ Frameworks (`AIAgent/app/postureiq_frameworks/`)

11 JSON framework mapping files — 525 controls. PostureIQ is now the primary posture assessment engine. See [PostureIQ Standalone Engine](#postureiq-standalone-engine) for the full framework table.

### Data Security Frameworks (`AIAgent/app/datasec_frameworks/`)

Data security-specific framework mappings used by the data security engine.

**Structure per control**: `control_id`, `title`, `domain`, `severity`, `evidence_types[]`, `evaluation_logic`, `rationale`, `recommendation`, `compensating_evidence` (optional)

---

## JSON Schemas (`schemas/`)

| File | Defines | Key Fields |
|------|---------|------------|
| `evidence-record.schema.json` | Evidence record structure | Source, Collector, EvidenceType, Description, Data, ResourceId, ResourceType, Timestamp, Id |
| `finding-record.schema.json` | Finding record structure | ControlId, Framework, ControlTitle, Status (`compliant` / `non_compliant` / `partial` / `missing_evidence` / `not_assessed`), Severity, Domain |
| `compliance-control.schema.json` | Control definition structure | control_id, title, domain, severity, evidence_types, evaluation_logic |
| `report-summary.schema.json` | Report summary output | TotalControls, Compliant, NonCompliant, Partial, MissingEvidence, NotAssessed, ComplianceScore, DomainScores |

---

## Examples (`examples/`)

| File | Purpose |
|------|---------|
| `sample-config.json` | Example configuration matching `AssessmentConfig.from_file()` format |
| `sample-evidence.json` | Example evidence records with Python field names |
| `sample-mappings.json` | Example framework mapping with control definitions |
| `sample-report.md` | Example Markdown report output |

---

## Tests

15 test suites in `AIAgent/tests/` using `pytest`. Total: ~1,357 test functions, ~16,834 lines.

| File | Lines | Purpose |
|------|-------|---------|
| `test_ai_agent_security_engine.py` | 4,450 | AI Agent Security engine: Copilot Studio, Foundry, custom agent, Entra AI identity checks |
| `test_copilot_readiness_engine.py` | 2,324 | Copilot Readiness engine: oversharing, labels, DLP, retention, access governance, lifecycle, audit |
| `test_data_security_engine.py` | 4,230 | Data Security engine: storage, database, KV, encryption, classification, lifecycle, DLP |
| `test_ai_agent_security_determinism.py` | 1,005 | Determinism: AI Agent Security produces identical output for identical input |
| `test_copilot_readiness_determinism.py` | 708 | Determinism: Copilot Readiness produces identical output for identical input |
| `test_rbac_determinism.py` | 809 | Determinism: RBAC report stats/risks/scores stable under re-evaluation |
| `test_assessment_determinism.py` | 737 | Determinism: full assessment produces identical findings for shuffled evidence |
| `test_report_determinism.py` | 598 | Determinism: report generation produces identical HTML/MD for same input |
| `test_determinism.py` | 295 | Core determinism utilities: hash comparison, evidence shuffle, output diff |
| `test_risk_engine.py` | 538 | Risk engine: identity, network, defender, config, data risk analysis |
| `test_evaluators.py` | 460 | Evaluator logic: all 10 domains with sample evidence |
| `test_query_engine.py` | 304 | Query engine: ARG, Graph, compliance cross-reference |
| `test_enhancements.py` | 442 | Enhancement features: delta, drift, trending, notifications |
| `test_reports.py` | 270 | Report generation: HTML, Markdown, Excel, data exports |
| `test_dry_run_ds.py` | 264 | Dry-run mode for Data Security engine |

### Running Tests

```bash
cd AIAgent
python -m pytest tests/ -v
python -m pytest tests/ -v --tb=short    # concise tracebacks
python -m pytest tests/test_evaluators.py -v    # single file
```

---

## Documentation (`docs/`)

📖 For the complete documentation index (21 documents with HTML + Markdown links), see the **[Knowledge Hub (index.html)](index.html)**.

---

## Internals & Build

| File | Purpose |
|------|---------|
| `_apply_phase_g.py` | Internal build phase G — incremental feature application |
| `_apply_phase_h.py` | Internal build phase H — incremental feature application |
| `_apply_phase_i.py` | Internal build phase I — incremental feature application |
| `_apply_phase_j.py` | Internal build phase J — incremental feature application |
| `_apply_phase_k.py` | Internal build phase K — incremental feature application |
| `_run_azure_only.py` | One-shot Azure-only assessment across 5 frameworks (FedRAMP, PCI-DSS, NIST-800-53, MCSB, CIS) with hardcoded tenant |
| `.env.template` | Environment variable template for local development |
| `.gitignore` | Git ignore rules |
