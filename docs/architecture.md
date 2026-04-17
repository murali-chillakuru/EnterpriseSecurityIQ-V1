# PostureIQ Architecture

**Author:** Murali Chillakuru

> **Executive Summary** — Bird's-eye view of the PostureIQ platform architecture:
> the PostureIQ pipeline (collect → evaluate → risk-score → report) as the sole posture assessment engine,
> all 64 collectors, 11 compliance frameworks (525 controls) via PostureIQ, 28 report generators,
> 10 modular engines (Risk, RBAC, Copilot, AI Agent Security each with `{prefix}_orchestrator / _evaluators / _reports`),
> 14 agent tools, and 11 web dashboard SPAs. Start here to understand how the pieces fit together.
>
> | | |
> |---|---|
> | **Audience** | Architects, senior engineers, new contributors |
> | **Prerequisites** | [README](../README.md) for project overview |
> | **Companion docs** | [Agent Capabilities](agent-capabilities.md) for per-collector SDK details · [Evaluation Rules](evaluation-rules.md) for check function reference · [FILE-REFERENCE](FILE-REFERENCE.md) for per-file inventory |

## Overview

PostureIQ is a **Python 3.10+ async** security intelligence platform that assesses Azure subscriptions, Microsoft Entra ID, M365 services, and AI platforms. PostureIQ is the sole posture assessment engine, evaluating against 11 compliance frameworks (525 controls) with risk-weighted scoring. It operates in strict **read-only** mode, collecting evidence via 64 collectors, evaluating via PostureIQ's domain evaluators (10 domains, 113 check functions), and generating reports in 8+ formats.

The assessment engine runs as an AI Agent built on the [Microsoft Agent Framework SDK](https://github.com/microsoft/agents) (`agent-framework-azure-ai==1.0.0rc3`). It uses a single `DefaultAzureCredential` for both Azure ARM operations and Microsoft Graph operations — no browser popup or separate consent flow required.

## Pipeline Architecture

The PostureIQ orchestrator (`app/postureiq_orchestrator.py`) is the **sole posture assessment pipeline**, coordinating a multi-phase pipeline: **collect → evaluate → risk-score → attack-path → prioritize → report**. Azure and Entra collector groups run concurrently via `asyncio.gather()`, with configurable batch sizes to avoid API throttling. The old `orchestrator.py` and its `evaluators/` + `frameworks/` directories have been removed.

```
┌────────────────────────────────────────────────────────────────────────┐
│  PostureIQ Pipeline (postureiq_orchestrator.py) — sole posture engine   │
│                                                                        │
│  Phase 1: Collect (64 collectors, 218 evidence types, concurrent)       │
│      │                                                                  │
│      ├─▶ Phase 2: Evaluate (postureiq_evaluators, 10 domains, 113 fns) │
│      │   11 frameworks (postureiq_frameworks), 525 controls              │
│      ├─▶ Phase 2.1: Risk-Weighted Scoring                                │
│      │   severity × exploitability × blast radius → RiskScore 0–100      │
│      ├─▶ Phase 2.2: Attack Path Analysis                                 │
│      │   privilege escalation chains, lateral movement, exposed HV       │
│      ├─▶ Phase 2.3: Priority Ranking                                     │
│      │   ROI = risk/√effort, quick wins, effort hours                    │
│      ├─▶ Phase 2.4: Exception Tracking                                   │
│      │   audit trail: owner, ticket, risk_accepted                       │
│      ├─▶ Phase 2.5: AI Fix Recommendations                               │
│      │   GPT-powered Azure CLI + PowerShell scripts for top-15           │
│      └─▶ Phase 3: Delta & Report (postureiq_reports, 28 generators)       │
└────────────────────────────────────────────────────────────────────────┘
```

### Phase 1: Evidence Collection

All collectors are async coroutines discovered via `@register_collector` decorators. The orchestrator calls `discover_collectors()` to import all modules from `collectors/azure/` and `collectors/entra/`, sorted by priority (lower = runs earlier). Collectors run in batches: **8 Azure concurrent** and **6 Entra concurrent** by default.

**Azure Control-Plane Collectors** (39 registered, via `azure-mgmt-*` async SDKs):

| # | Collector | Module | Priority | Evidence Types |
|---|-----------|--------|----------|----------------|
| 1 | Resources & MG | `azure/resources.py` | 10 | `azure-resource`, `azure-resource-group` |
| 2 | RBAC | `azure/rbac.py` | 20 | `azure-role-assignment` (19 privileged roles tracked) |
| 3 | Azure Policy | `azure/policy.py` | 30 | `azure-policy-assignment`, `azure-policy-definition` |
| 4 | Diagnostic Settings | `azure/diagnostics.py` | 40 | `azure-diagnostic-setting` (17 resource types) |
| 5 | Activity Logs & Locks | `azure/activity_logs.py` | 50 | `azure-activity-log`, `azure-activity-event`, `azure-resource-lock` |
| 6 | Security & Key Vault | `azure/security.py` | 60 | `azure-keyvault`, `azure-keyvault-secret-expiry`, `azure-keyvault-cert-expiry`, `azure-keyvault-key-expiry`, `azure-managed-identity` |
| 7 | Network Security | `azure/network.py` | 70 | `azure-nsg-rule`, `azure-virtual-network`, `azure-storage-security` |
| 8 | Network Expanded | `azure/network_expanded.py` | 71 | `azure-firewall`, `azure-route-table`, `azure-nsg-flow-log` |
| 9 | Policy Compliance | `azure/policy_compliance.py` | 80 | `azure-policy-compliance` |
| 10 | Defender Plans | `azure/defender_plans.py` | 90 | `azure-defender-pricing`, `azure-auto-provisioning`, `azure-security-contact` |
| 11 | Defender Advanced | `azure/defender_advanced.py` | 91 | `azure-secure-score`, `azure-security-assessment`, `azure-regulatory-compliance`, `azure-jit-policy`, `azure-security-alert` |
| 12 | Sentinel | `azure/sentinel.py` | 92 | `azure-sentinel-workspace`, `-connector`, `-rule`, `-incident`, `-automation`, `-watchlist` |
| 13 | Compute | `azure/compute.py` | 100 | `azure-vm-config`, `azure-webapp-config`, `azure-sql-server`, `azure-aks-cluster` |
| 14 | Monitoring | `azure/monitoring.py` | 110 | `azure-log-analytics`, `azure-alert-rule`, `azure-action-group` |
| 15 | Additional Services | `azure/additional_services.py` | 120 | `azure-private-endpoint`, `azure-recovery-vault`, `azure-disk-encryption-set` |
| 16 | AI Services | `azure/ai_services.py` | 130 | `azure-cognitive-account`, `azure-ai-deployment`, `azure-ml-workspace` |
| 17 | Functions | `azure/functions.py` | 135 | `azure-function-app`, `azure-function-detail`, `azure-function-slot` |
| 18 | Storage | `azure/storage.py` | 140 | `azure-storage-account` |
| 19 | DNS & Traffic Manager | `azure/dns.py` | 140 | `azure-dns-zone`, `azure-private-dns-zone`, `azure-traffic-manager` |
| 20 | Front Door & CDN | `azure/frontdoor_cdn.py` | 142 | `azure-front-door`, `azure-waf-policy`, `azure-cdn-profile`, `azure-cdn-endpoint` |
| 21 | Messaging | `azure/messaging.py` | 145 | `azure-servicebus-namespace`, `-queue`, `-topic`, `azure-eventhub-namespace`, `-hub` |
| 22 | Containers (ACR & CA) | `azure/containers.py` | 150 | `azure-container-registry`, `azure-container-app` |
| 23 | Data Analytics | `azure/data_analytics.py` | 150 | `azure-synapse-workspace`, `-sql-pool`, `-spark-pool`, `azure-data-factory`, `azure-databricks-workspace` |
| 24 | Redis, IoT, Logic Apps | `azure/redis_iot_logic.py` | 155 | `azure-redis-cache`, `azure-iot-hub`, `azure-logic-app` |
| 25 | Databases | `azure/databases.py` | 160 | `azure-cosmosdb-account`, `azure-database-server` |
| 26 | AKS Deep Config | `azure/aks_in_cluster.py` | 160 | `azure-aks-cluster-config`, `azure-aks-addon`, `azure-aks-node-pool` |
| 27 | Batch & ACI | `azure/batch_aci.py` | 165 | `azure-batch-account`, `azure-container-instance` |
| 28 | Managed Disks | `azure/managed_disks.py` | 170 | `azure-managed-disk`, `azure-snapshot`, `azure-disk-encryption-set` |
| 29 | Purview & DLP | `azure/purview_dlp.py` | 170 | `azure-purview-account`, `m365-sensitivity-label`, `m365-dlp-sensitivity-label` |
| 30 | App Gateway | `azure/app_gateway.py` | 170 | `azure-app-gateway`, `azure-waf-policy` |
| 31 | ML & Cognitive Extended | `azure/ml_cognitive.py` | 175 | `azure-ml-workspace`, `azure-ml-compute`, `azure-cognitive-account` |
| 32 | API Management | `azure/api_management.py` | 180 | `azure-apim-instance` |
| 33 | Arc & Hybrid | `azure/arc_hybrid.py` | 180 | `azure-arc-server`, `azure-arc-extension`, `azure-arc-kubernetes` |
| 34 | SharePoint & OneDrive | `azure/sharepoint_onedrive.py` | 180 | `spo-site-inventory`, `spo-site-permissions`, `spo-sharing-links`, `spo-tenant-sharing-config`, `spo-label-summary` |
| 35 | M365 Sensitivity Labels | `azure/m365_sensitivity_labels.py` | 182 | `m365-sensitivity-label-definition`, `m365-label-summary`, `m365-label-policy-summary`, `m365-dlp-label-integration` |
| 36 | Copilot Studio | `azure/copilot_studio.py` | 185 | `pp-environment`, `pp-dlp-policy`, `copilot-studio-bot`, `pp-custom-connector`, `m365-copilot-settings`, `m365-audit-config`, `copilot-studio-summary` |
| 37 | Backup & DR | `azure/backup_dr.py` | 185 | `azure-recovery-vault`, `azure-backup-policy`, `azure-backup-item` |
| 38 | Foundry Configuration | `azure/foundry_config.py` | 188 | 16 evidence types (largest collector — 1,081 lines) |
| 39 | Cost & Billing | `azure/cost_billing.py` | 190 | `azure-budget`, `azure-advisor-cost-recommendation` |

> **📖 Deep reference:** For per-collector SDK methods, data-plane operations, and evidence schemas, see [Agent Capabilities](agent-capabilities.md).

**Azure Data-Plane Collectors** (8 registered):

| # | Collector | Module | Priority | Evidence Types |
|---|-----------|--------|----------|----------------|
| 40 | Storage Data Plane | `azure/storage_data_plane.py` | 200 | `azure-storage-container` |
| 41 | SQL Detailed | `azure/sql_detailed.py` | 210 | `azure-sql-detailed` |
| 42 | AI Content Safety | `azure/ai_content_safety.py` | 210 | `azure-ai-deployment-safety`, `azure-ai-governance`, `azure-content-safety-blocklist` |
| 43 | CosmosDB Data Plane | `azure/cosmosdb_data_plane.py` | 215 | `azure-cosmosdb-account`, `-database`, `-container`, `-role-assignment` |
| 44 | WebApp Detailed | `azure/webapp_detailed.py` | 220 | `azure-webapp-detailed` |
| 45 | APIM Data Plane | `azure/apim_data_plane.py` | 220 | `azure-apim-service`, `-api`, `-product`, `-subscription`, `-certificate`, `-named-value`, `-backend` |
| 46 | RDBMS Detailed | `azure/rdbms_detailed.py` | 230 | `azure-database-config` |
| 47 | ACR Data Plane | `azure/acr_data_plane.py` | 240 | `azure-acr-repository` |

**M365 Compliance Collectors** (5, registered with `source="entra"`):

| Module | Evidence Types |
|--------|----------------|
| `azure/m365_compliance.py` | `m365-label-analytics`, `m365-dlp-alert-metrics`, `m365-retention-label`, `m365-retention-summary`, `m365-irm-status`, `m365-irm-settings`, `m365-ediscovery-case`, `m365-ediscovery-summary` |

**Entra ID Collectors** (12 registered, via `msgraph-sdk`):

| # | Collector | Module | Priority | Evidence Types |
|---|-----------|--------|----------|----------------|
| 1 | Tenant & Org | `entra/tenant.py` | 10 | `entra-tenant-info` |
| 2 | Users & Groups | `entra/users.py` | 20 | `entra-user-summary`, `entra-group-summary` |
| 3 | User Details & MFA | `entra/user_details.py` | 30 | `entra-user-detail`, `entra-user-lifecycle-summary`, `entra-mfa-registration`, `entra-mfa-summary`, `entra-oauth2-grant` |
| 4 | Conditional Access | `entra/conditional_access.py` | 40 | `entra-conditional-access-policy` |
| 5 | Directory Roles & PIM | `entra/roles.py` | 50 | `entra-role-definition`, `entra-role-assignment`, `entra-pim-eligible-assignment`, `entra-directory-role-member` |
| 6 | Applications | `entra/applications.py` | 60 | `entra-application`, `entra-service-principal` |
| 7 | Workload Identity | `entra/workload_identity.py` | 65 | `entra-federated-credential`, `entra-managed-identity-sp`, `entra-workload-credential-review` |
| 8 | Risk Policies | `entra/risk_policies.py` | 66 | `entra-named-location`, `entra-auth-methods-policy`, `entra-auth-strength-policy` |
| 9 | Security Policies | `entra/security_policies.py` | 70 | `entra-security-defaults`, `entra-authorization-policy`, `entra-cross-tenant-policy`, `entra-cross-tenant-partner`, `entra-auth-method-config` |
| 10 | Governance | `entra/governance.py` | 80 | `entra-pim-policy`, `entra-pim-policy-rule`, `entra-access-review`, `entra-access-package`, `entra-terms-of-use` |
| 11 | Identity Protection | `entra/identity_protection.py` | 90 | `entra-risky-user`, `entra-risky-service-principal`, `entra-risk-detection`, `entra-risk-summary` |
| 12 | Audit & Sign-In Logs | `entra/audit_logs.py` | 100 | `entra-signin-summary`, `entra-directory-audit-summary`, `entra-named-location` |

**Standalone Collectors** (2, not auto-registered):

| Collector | Module | Lines | Called By |
|-----------|--------|-------|-----------|
| RBAC Hierarchy | `collectors/rbac_collector.py` | 983 | `run_rbac_report.py`, `generate_rbac_report` tool |
| AI Identity | `collectors/ai_identity.py` | 419 | AI Agent Security engine |

### Phase 2: PostureIQ Evaluation

The PostureIQ evaluation engine (`postureiq_evaluators/engine.py`) processes evidence against framework control mappings in `postureiq_frameworks/`:

1. **Evidence indexing** — All evidence records indexed by `EvidenceType` into a dict for O(1) lookup
2. **Framework loading** — 11 JSON mapping files in `postureiq_frameworks/` define controls with `domain`, `evidence_types`, `handler`, and `compensating_evidence`
3. **Domain dispatch** — `DOMAIN_EVALUATORS` maps each domain string to its evaluator module (10 domains → 113 check functions)
4. **Cross-domain fallback** — If primary evaluator returns `not_assessed`, `_CROSS_DOMAIN_MAP` re-dispatches (e.g., `storage_security` → `network`)
5. **Scoring** — Severity-weighted with partial credit (50%); `missing_evidence` excluded from compliance percentage. Weights: critical=4, high=3, medium=2, low=1

**Domain Evaluators** (all in `AIAgent/app/postureiq_evaluators/`):

| Module | Domain | Functions | Key Checks |
|--------|--------|-----------|------------|
| `access.py` | access | 8 | RBAC separation, least privilege, CA, custom owners, managed identity hygiene |
| `identity.py` | identity | 22 | MFA coverage, app credentials, user lifecycle, risky users, OAuth2, workload identity, managed identity, cross-tenant |
| `data_protection.py` | data_protection | 22 | Encryption in transit/at rest, Key Vault, VM/SQL/AKS/CosmosDB/Functions/messaging/Redis/analytics/Purview |
| `logging_eval.py` | logging | 13 | Diagnostic coverage ≥80%, threat detection, flow logs, activity analysis, sign-in monitoring, retention |
| `network.py` | network | 16 | Segmentation, NSGs, storage firewalls, Azure Firewall, routes, DNS, AKS, APIM, Front Door/CDN |
| `governance.py` | governance | 21 | Policy compliance ≥80%, Defender plans, locks, PIM, access reviews, AI governance, regulatory compliance |
| `incident_response.py` | incident_response | 6 | Security contacts, detection, alerting, Sentinel, investigation readiness |
| `change_management.py` | change_management | 4 | Change control, resource lock governance, policy enforcement |
| `business_continuity.py` | business_continuity | 4 | Backup configuration, geo-redundancy, VM availability, database resilience |
| `asset_management.py` | asset_management | 4 | Asset inventory, classification/tagging, authorized software, application inventory |

Additional PostureIQ-specific evaluators: `attack_paths.py`, `priority_ranking.py`, `ai_fix_recommendations.py`, `exception_tracking.py`.

> **📖 Deep reference:** For all 113 check functions with parameters, thresholds, evidence types, and cross-domain fallback routes, see [Evaluation Rules](evaluation-rules.md).

Supporting engine modules: `plugins.py` (custom evaluator plugin loader), `suppressions.py` (finding suppression by control ID or pattern), `remediation.py` (automated remediation plan generation).

> **Note:** The old `orchestrator.py`, `evaluators/` (14 files), and `frameworks/` (11 JSON) have been removed. PostureIQ is now the sole posture assessment engine. `api.py` imports from `postureiq_orchestrator`, and `continuous_monitor.py` uses `postureiq_orchestrator.run_postureiq_assessment`.

### Phase 3: Report Generation

Reports are generated per framework into sub-folders when multiple frameworks are selected. 28 report generators produce 8+ output formats.

Reports are written to the local filesystem (`/agent/output`) and then automatically
uploaded to **Azure Blob Storage** (`app/blob_store.py`) for persistence across container
restarts and redeployments. When a report is requested but missing locally, the API
downloads it from blob storage on demand.

```
Report generation flow:

  Engine → Report generator → /agent/output/{timestamp}/{type}/
       │                                │
       │                                ├── report.html
       │                                ├── report.pdf  (Playwright Chromium)
       │                                ├── report.xlsx
       │                                └── report.json
       │
       └── blob_store.upload_directory() → Azure Blob Storage
                                            (esiqnewstorage/reports)

  Report serving:

  GET /reports/{path}
       ├── local filesystem hit? → FileResponse
       └── blob download → cache locally → FileResponse
```

| Report | Module | Lines | Format |
|--------|--------|-------|--------|
| Compliance Report | `compliance_report_html.py` | 1,680 | HTML |
| Compliance Report MD | `compliance_report_md.py` | — | Markdown |
| Data Security Report | `data_security_report.py` | 3,348 | HTML |
| Copilot Readiness Report | `copilot_readiness_report.py` | 3,409 | HTML |
| AI Agent Security Report | `ai_agent_security_report.py` | 1,518 | HTML |
| RBAC Report | `rbac_report.py` | 1,913 | HTML |
| Risk Report | `risk_report.py` | 917 | HTML |
| Executive Dashboard | `executive_dashboard.py` | 222 | HTML |
| Gaps Report | `gaps_report.py` | 473 | HTML, Markdown |
| Master Report | `master_report.py` | 594 | HTML, Markdown |
| Excel Export | `excel_export.py` | 236 | XLSX (3 sheets) |
| OSCAL Export | `oscal_export.py` | 102 | JSON (NIST OSCAL) |
| SARIF Export | `sarif_export.py` | 119 | SARIF |
| PDF Export | `pdf_export.py` | 85 | PDF (via Playwright) |
| Remediation Playbooks | `remediation.py` | 547 | HTML |
| Delta Report | `delta_report.py` | — | HTML (run comparison) |
| Drift Report | `drift_report_html.py` | — | HTML (compliance drift) |
| Trending | `trending.py` | — | JSON (historical analysis) |
| Data Exports | `data_exports.py` | — | JSON/CSV |
| Notifications | `notifications.py` | — | Email/webhook |
| Evidence Catalog | `evidence_catalog.py` | — | Reference HTML |
| Shared Theme | `shared_theme.py` | 294 | CSS/JS (dark/light Fluent) |

## Standalone Engines

10 standalone engines provide dedicated assessment capabilities. In v49, Risk, RBAC, Copilot, and AI Agent Security were refactored into the **modular engine pattern**: each has a `{prefix}_orchestrator.py`, `{prefix}_evaluators/`, and `{prefix}_reports/` directory. The Query Engine was also modularized into `query_evaluators/` with a backward-compatible shim.

| Engine | Module(s) | Pattern | Purpose |
|--------|-----------|---------|---------|
| **PostureIQ Engine** | `postureiq_orchestrator.py` + `postureiq_evaluators/` + `postureiq_reports/` | Modular | **Sole posture assessment engine** — risk-weighted scoring, attack path analysis, priority ranking, AI fix recommendations, exception tracking |
| Query Engine | `query_engine.py` (shim) + `query_evaluators/` (8 modules) | Modular | Interactive Azure Resource Graph (KQL) + MS Graph queries with natural-language support |
| Risk Engine | `risk_orchestrator.py` + `risk_evaluators/` + `risk_reports/` | Modular | Security risk gap analysis across identity, network, Defender, and config categories |
| RBAC Engine | `rbac_orchestrator.py` + `rbac_evaluators/` + `rbac_reports/` | Modular | RBAC hierarchy tree with PIM, risk analysis, excessive permissions detection |
| Data Security Engine | `data_security_engine.py` | Standalone | Data security assessment: 12 categories (storage, DB, encryption, keys, classification, and more) |
| Copilot Readiness Engine | `copilot_orchestrator.py` + `copilot_evaluators/` + `copilot_reports/` | Modular | M365 Copilot readiness: oversharing, sensitivity labels, DLP, restricted search, access governance (9+ categories) |
| AI Agent Security Engine | `ai_agent_security_orchestrator.py` + `ai_agent_security_evaluators/` + `ai_agent_security_reports/` | Modular | AI agent security across 6 platforms (Copilot Studio, Foundry, Azure OpenAI, custom agents) and 23+ security areas |
| Data Residency Engine | `data_residency_engine.py` | Standalone | Data residency compliance — 5 checks |
| Remediation Engine | `remediation_engine.py` | Standalone | Automated remediation plans — 7 rules |
| Continuous Monitor | `continuous_monitor.py` | Standalone | Scheduled re-assessments via `postureiq_orchestrator.run_postureiq_assessment` with drift detection |

Integrations: `siem_integration.py` (156 lines — Sentinel, Splunk, generic webhook), `operational_integrations.py` (443 lines — ServiceNow, Jira, Azure DevOps).

## Directory Structure

```
EnterpriseSecurityIQ/
├── AIAgent/                       # Python assessment engine
│   ├── main.py                    # Foundry agent HTTP server (port 8088, responses v1)
│   ├── agent.yaml                 # Agent Framework manifest
│   ├── Dockerfile                 # Container build (linux/amd64)
│   ├── requirements.txt           # 40+ azure-mgmt-* + msgraph-sdk + Agent Framework SDK
│   ├── run_rbac_report.py         # CLI: RBAC hierarchy tree report
│   ├── run_query.py               # CLI: interactive ARG / Graph query REPL
│   ├── run_risk_analysis.py       # CLI: security risk gap analysis
│   ├── run_data_security.py       # CLI: data security assessment
│   ├── run_copilot_readiness.py   # CLI: M365 Copilot readiness
│   ├── run_ai_agent_security.py   # CLI: AI agent security
│   ├── run_assessment_determinism_check.py   # Determinism verification
│   ├── run_rbac_determinism_check.py         # RBAC determinism verification
│   ├── run_cr_determinism_check.py           # Copilot readiness determinism verification
│   └── app/
│       ├── agent.py               # Agent Framework integration (14 tools)
│       ├── auth.py                # Unified DefaultAzureCredential (ARM + Graph) with preflight
│       ├── config.py              # AssessmentConfig with 17 configurable thresholds
│       ├── models.py              # Typed dataclasses with deterministic UUID5 IDs
│       ├── query_engine.py        # Backward-compat shim → query_evaluators/
│       ├── data_security_engine.py # Data security — 12 categories (9,085 lines)
│       ├── data_residency_engine.py     # Data residency compliance (296 lines)
│       ├── remediation_engine.py        # Automated remediation plans (299 lines)
│       ├── continuous_monitor.py        # Scheduled re-assessments via postureiq_orchestrator
│       ├── evidence_history.py          # Blob-backed assessment history
│       ├── siem_integration.py          # Sentinel, Splunk, webhook export (156 lines)
│       ├── operational_integrations.py  # ServiceNow, Jira, Azure DevOps (443 lines)
│       ├── api.py                       # FastAPI REST API + SSE chat (imports postureiq_orchestrator)
│       ├── blob_store.py                # Azure Blob Storage persistence for reports
│       ├── i18n.py                      # Locale-based string localization
│       ├── logger.py                    # Structured logging
│       ├── collectors/
│       │   ├── registry.py              # @register_collector + discover_collectors()
│       │   ├── base.py                  # run_collector, paginate_arm, make_evidence
│       │   ├── inventory.py             # Shared resource inventory cache
│       │   ├── rbac_collector.py        # Standalone RBAC hierarchy (983 lines)
│       │   ├── ai_identity.py           # Standalone AI identity collector (419 lines)
│       │   ├── azure/  (50 collectors, 29 resource categories)
│       │   └── entra/  (18 collectors incl. 5 M365 compliance)
│       ├── query_evaluators/            # Query engine modules (8 files, modularized from query_engine.py)
│       ├── reports/                     # 28 report generators
│       ├── postureiq_orchestrator.py    # PostureIQ — sole posture assessment pipeline coordinator
│       ├── postureiq_evaluators/        # PostureIQ evaluators (18 files, incl. attack_paths, priority_ranking, ai_fix_recommendations)
│       ├── postureiq_frameworks/        # PostureIQ framework mappings (11 JSON, 525 controls)
│       ├── postureiq_reports/           # PostureIQ report generators (20 files, incl. postureiq_report_html/md)
│       ├── risk_orchestrator.py         # Risk engine orchestrator
│       ├── risk_evaluators/             # Risk engine evaluators
│       ├── risk_reports/                # Risk engine report generators
│       ├── rbac_orchestrator.py         # RBAC engine orchestrator
│       ├── rbac_evaluators/             # RBAC engine evaluators
│       ├── rbac_reports/                # RBAC engine report generators
│       ├── copilot_orchestrator.py      # Copilot readiness orchestrator
│       ├── copilot_evaluators/          # Copilot readiness evaluators
│       ├── copilot_reports/             # Copilot readiness report generators
│       ├── ai_agent_security_orchestrator.py  # AI Agent Security orchestrator
│       ├── ai_agent_security_evaluators/      # AI Agent Security evaluators
│       └── ai_agent_security_reports/         # AI Agent Security report generators
├── webapp/                              # 11 self-contained HTML SPAs with MSAL auth + SSE streaming
│   ├── index.html                       # Portal — card-grid launcher
│   ├── EnterpriseSecurityIQ.html        # Full dashboard
│   ├── ComplianceAssessment.html        # Focused: compliance assessment
│   ├── RiskAnalysis.html                # Focused: risk analysis
│   ├── DataSecurity.html                # Focused: data security
│   ├── RBACReport.html                  # Focused: RBAC report
│   ├── CopilotReadiness.html            # Focused: Copilot readiness
│   ├── AIAgentSecurity.html             # Focused: AI agent security
│   └── PostureIQ.html                   # Focused: PostureIQ posture assessment
├── config/
│   ├── enterprisesecurityiq.config.json # Assessment configuration
│   ├── config.schema.json               # Config JSON Schema
│   └── data-security-relevance.json     # Data security scoring weights
├── schemas/                             # JSON Schemas for data models
├── examples/                            # Sample config, evidence, mappings
├── docs/                                # Documentation
├── tests/  (15 files, 1,357 tests, 14,915 lines)
└── output/                              # Assessment output (gitignored)
```

## Entry Points

PostureIQ can be invoked via 9 CLI scripts or the Foundry agent. Each CLI tool runs a dedicated engine; the Foundry agent wraps all of them as tool functions.

### CLI Scripts

| Script | Purpose | Engine |
|--------|---------|--------|
| `run_rbac_report.py` | RBAC hierarchy tree (MG → Sub → RG) with PIM and risk analysis | `rbac_orchestrator.py` |
| `run_query.py` | Interactive query REPL for Azure Resource Graph and MS Graph | `query_engine.py` → `query_evaluators/` |
| `run_risk_analysis.py` | Security risk gap analysis (identity, network, Defender, config) | `risk_orchestrator.py` |
| `run_data_security.py` | Data security assessment (12 categories) | `data_security_engine.py` |
| `run_copilot_readiness.py` | M365 Copilot readiness assessment (9+ categories) | `copilot_orchestrator.py` |
| `run_ai_agent_security.py` | AI agent security across 6 platforms and 23+ areas | `ai_agent_security_orchestrator.py` |
| `run_assessment_determinism_check.py` | Verify assessment pipeline produces deterministic results | PostureIQ pipeline |
| `run_rbac_determinism_check.py` | Verify RBAC report produces deterministic results | RBAC pipeline |
| `run_cr_determinism_check.py` | Verify Copilot readiness produces deterministic results | Copilot pipeline |

### Foundry Agent Tools

The hosted agent (`main.py` → `agent.py`) exposes **14 tools** that an LLM can invoke:

| Tool Function | Description | Maps to CLI |
|---------------|-------------|-------------|
| `query_results` | Query cached findings by control, domain, severity, or natural language | — (in-memory session) |
| `search_tenant` | Live ARG / Graph queries with natural-language support | `run_query.py` |
| `analyze_risk` | Security risk gap analysis across 4 categories | `run_risk_analysis.py` |
| `assess_data_security` | Data security assessment across 12 categories | `run_data_security.py` |
| `generate_rbac_report` | RBAC hierarchy tree with PIM and risk analysis | `run_rbac_report.py` |
| `generate_report` | Regenerate reports from cached results | — (report generators) |
| `assess_copilot_readiness` | M365 Copilot readiness (oversharing, labels, DLP) | `run_copilot_readiness.py` |
| `assess_ai_agent_security` | AI agent security across 6 platforms | `run_ai_agent_security.py` |
| `check_permissions` | Preflight probe for ARM access, Graph scopes, Entra roles | — (auth.py) |
| `compare_runs` | Diff current vs. previous run: new, resolved, changed, score drift | — (delta_report.py) |
| `search_exposure` | Surface exposure: public storage, open NSGs, unencrypted VMs | — (query_engine.py ARG templates) |
| `generate_custom_report` | Generate custom-scoped reports with user-selected frameworks | — (report generators) |
| `run_postureiq_assessment` | PostureIQ risk-weighted posture assessment with attack paths, priority ranking, and AI fix recommendations | — (`postureiq_orchestrator.py`) |
| `query_assessment_history` | Query blob-backed assessment history for past runs, trends, and comparisons | — (`evidence_history.py`) |

## Data Models

All models are Python dataclasses defined in `AIAgent/app/models.py` with deterministic UUID5 IDs and PascalCase JSON serialization:

| Class | Purpose | Key Fields |
|-------|---------|------------|
| `EvidenceRecord` | Normalized evidence from any collector | `evidence_type`, `resource_id`, `data`, `source`, `collected_at` |
| `FindingRecord` | Single control evaluation finding | `control_id`, `status`, `severity`, `domain`, `evidence_refs` |
| `ComplianceControlResult` | Per-control aggregated result | `control_id`, `title`, `status`, `findings[]`, `score` |
| `MissingEvidenceRecord` | Tracks controls lacking evidence | `control_id`, `missing_types[]`, `compensating_available` |
| `CollectorResult` | Collector execution metadata | `collector_name`, `duration_ms`, `evidence_count`, `errors[]` |
| `AssessmentSummary` | Overall assessment metrics | `total_controls`, `passed`, `failed`, `not_assessed`, `overall_score` |

## Framework Mapping Structure

Each of the 11 framework JSON files in `AIAgent/app/postureiq_frameworks/` contains:

```json
{
  "framework": "FedRAMP",
  "version": "1.0",
  "controls": [
    {
      "control_id": "AC-2",
      "title": "Account Management",
      "domain": "access",
      "severity": "high",
      "evidence_types": ["azure-role-assignment", "entra-role-assignment"],
      "evaluation_logic": "check_account_management",
      "compensating_evidence": ["entra-conditional-access-policy"],
      "rationale": "...",
      "recommendation": "..."
    }
  ]
}
```

| Framework | Controls |
|-----------|----------|
| NIST 800-53 | 83 |
| FedRAMP | 69 |
| CIS Benchmarks | 53 |
| MCSB | 53 |
| PCI DSS | 51 |
| ISO 27001 | 51 |
| SOC 2 | 47 |
| HIPAA | 43 |
| NIST CSF | 29 |
| CSA CCM | 24 |
| GDPR | 22 |

The `evaluation_logic` field maps to a Python function in the corresponding PostureIQ domain evaluator module (`postureiq_evaluators/`). The `compensating_evidence` field defines fallback evidence types when primary evidence is unavailable.

## Authentication

`ComplianceCredentials` in `app/auth.py` supports 4 authentication modes:

| Mode | Credential Source | Use Case |
|------|-------------------|----------|
| `auto` (default) | `DefaultAzureCredential` | Picks up `az login`, managed identity, or env vars |
| `azurecli` | `AzureCliCredential` | Explicit CLI session |
| `serviceprincipal` | `ClientSecretCredential` | CI/CD pipelines |
| `appregistration` | `ClientSecretCredential` | App registration with Graph consent |

A single credential is used for both ARM (`https://management.azure.com/.default`) and Graph (`https://graph.microsoft.com/.default`). The `preflight_check()` method probes both APIs before running any assessment.

## Safety Guarantees

1. **Read-Only**: All API calls are `GET` / `list()` / `get()` operations via Azure Management SDKs and MS Graph
2. **No PII Export**: User data is aggregated to counts and rates; no names, emails, or UPNs in reports
3. **No Modifications**: Zero `PUT`, `POST`, `PATCH`, or `DELETE` operations on tenant resources
4. **Mostly Control-Plane**: Data-plane reads limited to Key Vault metadata, CosmosDB config, APIM config, ACR repositories, SQL security config, and webapp auth settings
5. **Unified Credential**: Both ARM and Graph use `DefaultAzureCredential` (`exclude_shared_token_cache=True`) with `.default` scope
6. **Checkpoint Resume**: Collection progress saved after each batch; interrupted runs resume automatically
7. **Deterministic Output**: UUID5-based IDs ensure reproducible results across identical inputs
8. **Error Isolation**: Each collector catches exceptions independently; failures produce access-denied markers, not pipeline failures
