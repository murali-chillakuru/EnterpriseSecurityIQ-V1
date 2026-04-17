# Changelog — PostureIQ

All notable enhancements, fixes, and deployment changes from v1 through v50.

**Author:** Murali Chillakuru

---

## v50 — Query Engine Modularization + Compliance Removal + PostureIQ History (2026-04-16)

**Goal:** Modularize query engine for maintainability, remove deprecated compliance assessment (superseded by PostureIQ), and add blob-backed assessment history tracking for auditing and change tracking.

### v50a — Query Engine Modularization

Split `query_engine.py` (1,798 lines, 31 functions) into 8 focused modules under `query_evaluators/`:

| Module | Lines | Purpose |
|--------|-------|---------|
| `arg_queries.py` | ~516 | `query_resource_graph()`, `ARG_TEMPLATES` (50+ templates) |
| `entra_queries.py` | 379 | 12 `query_entra_*` functions (users, groups, apps, roles, etc.) |
| `resource_detail.py` | 97 | `get_resource_detail()`, `get_entra_user_detail()` |
| `cross_reference.py` | 130 | `cross_reference_findings()` |
| `dispatcher.py` | 147 | `dispatch_natural_language()` + NL keyword maps |
| `entra_extended.py` | 270 | 11 `_query_*` helpers (org info, security defaults, risk detections, etc.) |
| `entra_dispatcher.py` | 100 | `_run_entra_query()` typed dispatcher |
| `evidence_search.py` | 149 | `search_evidence()`, `search_evidence_advanced()` |

- `query_engine.py` replaced with backward-compatible shim (~45 lines) re-exporting all public symbols
- All imports in `agent.py` unchanged — zero-breakage refactor

### v50b — Compliance Assessment Removal

Removed the deprecated compliance assessment engine (fully superseded by PostureIQ):

**Deleted Files (30+ files):**

| Category | Files Removed |
|----------|---------------|
| Orchestrator | `orchestrator.py` (618 lines) |
| Evaluators | `evaluators/` directory (14 files: access.py, identity.py, governance.py, data_protection.py, logging_eval.py, network.py, incident_response.py, change_management.py, business_continuity.py, asset_management.py, engine.py, plugins.py, remediation.py, suppressions.py, \_\_init\_\_.py) |
| Frameworks | `frameworks/` directory (11 JSON mapping files) |
| Reports | `compliance_report_html.py`, `compliance_report_md.py`, `html_report.py`, `json_report.py` |
| CLI Scripts | `run_assessment.py`, `run_assessment_determinism_check.py` |
| Tool Wrapper | `tools/assessment.py` |

**Agent Changes:**
- Removed `run_assessment` from TOOLS list (14 → 14 tools, replaced by `query_assessment_history`)
- Removed `run_assessment` from TOOL_SCHEMAS in `api.py`
- Updated SYSTEM_PROMPT: "compliance assessment" → "security posture assessment"
- Updated `generate_report`: removed compliance fallback, now dispatches to specific assessment report generators
- Updated `compare_runs`: searches for `assessment-results*.json` instead of `compliance-data.json`
- Updated `continuous_monitor.py`: rewired from `orchestrator.run_full_assessment` → `postureiq_orchestrator.run_postureiq_assessment`

**Preserved Shared Infrastructure:**
- `ComplianceCredentials` (used by ALL engines)
- `cross_reference_findings()` (generic utility)
- `ComplianceScore` field (used by PostureIQ)
- `policy_compliance` ARG template

### v50c — PostureIQ Historic Evidence Tracking

New blob-backed assessment history system for auditing and change tracking:

| Component | Description |
|-----------|-------------|
| `evidence_history.py` | `save_run()`, `list_runs()`, `load_run()`, `query_history()`, `get_score_trend()` |
| Blob Layout | `history/{tenant_id}/{timestamp}/postureiq-results.json` |
| Index File | `history/{tenant_id}/_index.json` (500-entry rolling window) |
| Agent Tool | `query_assessment_history` (actions: list, trend, detail, compare) |
| Auto-Save | Every PostureIQ assessment automatically persisted at completion |

**Integration:**
- `postureiq_orchestrator.py`: calls `save_run()` at end of assessment
- `agent.py`: new `query_assessment_history` tool added to TOOLS list
- `api.py`: schema added to TOOL_SCHEMAS

---

## v49 — Modular Engines + PostureIQ Rebranding (2026-04-15)

**Goal:** Modularize 4 standalone engines (Risk, RBAC, Copilot Readiness, AI Agent Security) into independent `{prefix}_evaluators/` + `{prefix}_orchestrator.py` + `{prefix}_reports/` packages. Complete PostureIQ rebranding across all touchpoints.

### Engine Modularization

Each engine now follows the PostureIQ modular pattern:

| Engine | Orchestrator | Evaluators | Reports |
|--------|-------------|------------|----------|
| Risk Analysis | `risk_orchestrator.py` | `risk_evaluators/` (7 files) | `risk_reports/` |
| RBAC | `rbac_orchestrator.py` | `rbac_evaluators/` (6 files) | `rbac_reports/` |
| Copilot Readiness | `copilot_orchestrator.py` | `copilot_evaluators/` (13 files) | `copilot_reports/` |
| AI Agent Security | `aiagentsec_orchestrator.py` | `aiagentsec_evaluators/` (13 files) | `aiagentsec_reports/` |

### PostureIQ Rebranding
- All SYSTEM_PROMPT references updated from "Full Security Assessment" to "PostureIQ"
- Tool descriptions, capability listings, and report headers updated

---

## v48 — Data Security Fix + Follow-Up Guard (2025-07-22)

**Goal:** Fix Data Security crashes from v46 modular restructure + prevent follow-up questions from re-running assessments.

### Bug Fixes — v46 Missing Cross-Module Imports (5 total)
During v46's modular restructure, 5 functions were placed in `data_factory.py` but called from other modules without imports:

| Module | Missing Function(s) | Defined In |
|--------|---------------------|------------|
| `data_access.py` | `_check_sensitive_data_tags` | `data_classification_tags.py` |
| `redis.py` | `_check_redis_no_patch_schedule`, `_check_redis_public_access` | `data_factory.py` |
| `messaging.py` | `_check_eventhub_local_auth`, `_check_servicebus_local_auth`, `_check_eventhub_capture_disabled` | `data_factory.py` |

### Session-Duplicate Guard — All 7 Assessment Tools
- Added `_session_duplicate_guard()` helper that checks if results already exist in the current session.
- When the LLM tries to re-run an assessment for a follow-up question, the tool now returns a redirect message: _"Results are already available. Use query_results instead."_
- Applied to: `run_assessment`, `analyze_risk`, `assess_data_security`, `generate_rbac_report`, `assess_copilot_readiness`, `assess_ai_agent_security`, `run_postureiq_assessment`.
- Users must start a **New Chat** to run a fresh assessment.

### Broadened Keyword Matching in `query_results`
- PostureIQ section now catches reversed phrasing ("10 top", "5 top"), natural variants ("address immediately", "top risk", "among all frameworks", "most important", "urgent", "worst"), and cross-framework queries ("across all", "all framework").

---

## v47 — Data Security 11-Framework Compliance Parity (2025-07-22)

**Goal:** Add CSA-CCM, FedRAMP, and GDPR framework mappings to Data Security — matching PostureIQ's full 11-framework coverage.

### New Framework Files

| File | Entries |
|------|---------|
| `datasec_frameworks/csa-ccm-mappings.json` | 108 subcategories → CSA CCM v4 controls |
| `datasec_frameworks/fedramp-mappings.json` | 108 subcategories → FedRAMP/NIST 800-53 controls |
| `datasec_frameworks/gdpr-mappings.json` | 108 subcategories → GDPR articles |

### Modified Files

| File | Change |
|------|--------|
| `datasec_evaluators/enrichment.py` | Added CSA-CCM, FedRAMP, GDPR to all 73+ `_COMPLIANCE_MAP` entries; added 93 new `_CONTROL_DETAILS` entries (31 CSA-CCM + 47 FedRAMP + 15 GDPR) |
| `datasec_frameworks/compliance-mappings.json` | All 108 subcategories now include all 11 frameworks |

### Framework Coverage (Before → After)

| Framework | Before | After |
|-----------|--------|-------|
| CIS | Yes | Yes |
| PCI-DSS | Yes | Yes |
| HIPAA | Yes | Yes |
| NIST-800-53 | Yes | Yes |
| ISO-27001 | Yes | Yes |
| SOC2 | Yes | Yes |
| NIST-CSF | Yes | Yes |
| MCSB | Yes | Yes |
| CSA-CCM | — | **Yes** |
| FedRAMP | — | **Yes** |
| GDPR | — | **Yes** |

---

## v46 — Data Security Modular Restructure (2025-07-22)

**Goal:** Refactor the 9,085-line `data_security_engine.py` monolith into a modular architecture matching the PostureIQ pattern — individual evaluator files, extracted framework mappings, dedicated orchestrator, and a thin backward-compatible facade.

### New Structure

| Directory / File | Content |
|-----------------|---------|
| **`datasec_evaluators/`** (30 modules) | Individual evaluator files: `storage.py`, `database.py`, `cosmosdb.py`, `keyvault.py`, `encryption.py`, `data_access.py`, `private_endpoints.py`, `purview.py`, `data_classification.py`, `backup_dr.py`, `containers.py`, `network_segmentation.py`, `threat_detection.py`, `sharepoint.py`, `m365_dlp.py`, `m365_lifecycle.py`, `dlp_alerts.py`, `redis.py`, `messaging.py`, `ai_services.py`, `data_factory.py`, `managed_identity.py`, `platform_services.py`, `identity_access.py`, `advanced_analytics.py`, `file_sync.py`, `postgres_mysql.py`, `data_residency.py`, `data_classification_tags.py` |
| **`datasec_evaluators/finding.py`** | Shared `ds_finding()` helper, `SEVERITY_WEIGHTS`, `DS_FINDING_NS` |
| **`datasec_evaluators/scoring.py`** | `compute_data_security_scores()`, `compute_trend_analysis()` |
| **`datasec_evaluators/enrichment.py`** | `enrich_compliance_mapping()`, `enrich_per_resource_details()`, `compute_remediation_impact()`, `consolidate_findings()` with full `_COMPLIANCE_MAP` and `_CONTROL_DETAILS` |
| **`datasec_frameworks/`** (9 JSON) | `compliance-mappings.json` + per-framework: CIS, PCI-DSS, HIPAA, NIST-800-53, ISO-27001, SOC2, NIST-CSF, MCSB |
| **`datasec_reports/`** | `data_security_report.py` (copied from `reports/`) |
| **`datasec_orchestrator.py`** | `run_data_security_assessment()`, `_ds_lightweight_collect()`, all ARM enrichment helpers |

### Modified Files

| File | Change |
|------|--------|
| `data_security_engine.py` | Replaced 9,085-line monolith with thin facade (~70 lines) — re-exports all symbols via `from app.datasec_evaluators.X import *` |

### Architecture

- **39 categories**, **~140 checks** distributed across 30 evaluator modules
- Each evaluator imports `ds_finding` from `finding.py` for consistent finding creation
- `datasec_orchestrator.py` imports all `analyze_*` functions and orchestrates collection + evaluation
- Facade in `data_security_engine.py` ensures zero breaking changes — `agent.py`, `run_data_security.py`, and all tests continue working unchanged

---

## v45 — Multi-Hop Deep Attack Path Analysis (2026-04-15)

**Goal:** Deepen PostureIQ attack path analysis with 5 new multi-hop detection categories using existing evidence. Zero new collectors required.

### New Detections in `attack_paths.py`

| # | Detection | Type | Risk Score | Severity |
|---|-----------|------|------------|----------|
| 5 | Key Vault → Identity → Resource chain | `credential_chain / keyvault_to_resource` | 88 | High |
| 6 | App/Function → MI → Privileged Resource | `lateral_movement / app_mi_to_resource` | 87 | High |
| 7 | Conditional Access bypass (no MFA on privileged role) | `ca_bypass / privileged_role_no_mfa` | 92 | Critical |
| 8 | Service Principal weak credentials + privileged role | `credential_chain / weak_credential_privileged_sp` | 75–82 | Medium–High |
| 9 | Network pivot — Internet-exposed VM with privileged MI | `network_pivot / internet_exposed_vm_privileged_mi` | 93 | Critical |

### Changes

| File | Change |
|------|--------|
| `attack_paths.py` | Added 5 new detection functions, deduplication, new summary fields (CredentialChain, CABypass, NetworkPivot, AppMIChain, MediumPaths) |
| `agent.py` | Extended query handler with new keyword triggers and category filters; updated session summary and assessment result text |
| `docs/enhancement-backlog.md` | New backlog document with Option B (standalone pathfinder) and Option C (cross-cloud AI) |
| `docs/enhancement-backlog.html` | HTML version with enterprise styling, architecture diagrams, detection cards |

---

## v44 — LLM BadRequestError Fallback (2026-04-15)

**Goal:** Catch `BadRequestError` (context_length_exceeded) in LLM fallback — auto-trims messages and switches to fallback model.

| File | Change |
|------|--------|
| `api.py` | Import `BadRequestError`, updated 2 except blocks with context_length detection + message trimming |

---

## v43 — PostureIQ Performance + RBAC Report Fix (2026-04-15)

| File | Change |
|------|--------|
| `postureiq_orchestrator.py` | Skip 3 overhead Entra collectors in PostureIQ |
| `api.py` | Set OpenAI timeout 900s, truncate tool result to 4000 chars |
| `config.py` | Default user_sample_limit=200 |
| `agent.py` | Add RBAC handler to generate_report() |

---

## v42 — Compliance Query Fix (2026-04-15)

| File | Change |
|------|--------|
| `agent.py` | Compliance storage → `compliance_results` unique key |

---

## v41 — PostureIQ Query Fix (2026-04-15)

| File | Change |
|------|--------|
| `agent.py` | PostureIQ storage → `postureiq_results` unique key + dedicated query handler |

---

## v27 — PostureIQ Tier 1 Enhancements: Risk-Weighted Scoring, Attack Paths, Priority Ranking, AI Fix Recommendations (2026-06-10)

**Goal:** Make PostureIQ a world-class security posture assessment engine with risk intelligence capabilities beyond traditional compliance scoring.

### New Modules

| File | Purpose |
|------|---------|
| **`postureiq_evaluators/attack_paths.py`** (new) | Identifies privilege escalation chains, lateral movement via managed identities, exposed high-value targets, and permanent Global Admin without PIM |
| **`postureiq_evaluators/priority_ranking.py`** (new) | ROI-based remediation ranking: `risk/√effort`, PriorityRank, EffortHours, PriorityLabel, quick wins (50+ checks mapped) |
| **`postureiq_evaluators/ai_fix_recommendations.py`** (new) | GPT-powered tenant-specific remediation scripts (Azure CLI + PowerShell) for top-15 priority findings with impact, downtime, and prerequisite details |

### Enhanced Modules

| File | Enhancement |
|------|-------------|
| **`postureiq_evaluators/engine.py`** | Risk-weighted scoring: severity × exploitability × blast radius = RiskScore 0–100. `_EXPLOITABILITY` dict (30+ checks), `_BLAST_RADIUS` dict (10 domains), RiskTier labels (Critical/High/Medium/Low), RiskSummary output, `EvaluationLogic` tag on findings |
| **`postureiq_evaluators/network.py`** | Private endpoint adoption tracking across 10 PaaS types (Storage, SQL, CosmosDB, Key Vault, ACR, App Service, Functions, AI Services, Event Hub, Service Bus) |
| **`postureiq_evaluators/suppressions.py`** | Exception audit trail: `owner`, `ticket`, `risk_accepted`, `created` fields; `generate_exception_report()` with expiry warnings and missing-approval detection |
| **`postureiq_orchestrator.py`** | New pipeline phases 2.1–2.5: risk scoring → attack paths → priority ranking → exception tracking → AI fixes |
| **`agent.py`** | PostureIQ result text now includes Risk Intelligence, Attack Paths, Priority Ranking, and AI Fix Scripts sections |
| **`api.py`** | PostureIQ tool schema description updated with new capabilities |
| **`webapp/PostureIQ.html`** | Updated sidebar, login, and welcome text with new capability descriptions |
| **`webapp/index.html`** | PostureIQ card description and tags updated |

### Deployment

- **Commit:** `0dc961c`
- **Image:** `esiqnewacr.azurecr.io/esiqnew-agent:v40-postureiq`
- **Container App:** `esiqnew-agent` (North Europe)

---

## v26 — SPA Decomposition & PostureIQ Independent Engine (2026-06-09)

**Goal:** Decompose the monolithic single-page dashboard into focused assessment SPAs and create PostureIQ as a fully independent compliance posture engine.

### Web Dashboard SPA Decomposition

| File | Purpose |
|------|---------|
| **`webapp/index.html`** (new) | Portal — card-grid launcher linking to all assessment SPAs |
| **`webapp/ComplianceAssessment.html`** (new) | Focused SPA for compliance assessments |
| **`webapp/RiskAnalysis.html`** (new) | Focused SPA for risk analysis |
| **`webapp/DataSecurity.html`** (new) | Focused SPA for data security |
| **`webapp/RBACReport.html`** (new) | Focused SPA for RBAC reports |
| **`webapp/CopilotReadiness.html`** (new) | Focused SPA for Copilot readiness |
| **`webapp/AIAgentSecurity.html`** (new) | Focused SPA for AI agent security |
| **`webapp/PostureIQ.html`** (new) | Focused SPA for PostureIQ posture assessments (with framework picker) |
| **`webapp/EnterpriseSecurityIQ.html`** | Full dashboard (copy of original) |
| **`webapp/esiq.html`**, **`webapp/enterpriseIQ.html`** | Full dashboard aliases |

Each focused SPA is self-contained (~1,550 lines) with inline CSS + JS, MSAL.js v5.6.3 auth, and SSE streaming. The portal provides a card-grid entry point.

### PostureIQ Independent Engine

A fully independent assessment engine — not a rebrand of the compliance assessment. PostureIQ has its own separate evaluators, framework mappings, report generators, and orchestrator.

| Component | Files |
|-----------|-------|
| **Orchestrator** | `postureiq_orchestrator.py` — multi-phase pipeline (collect → evaluate → report) |
| **Evaluators** | `postureiq_evaluators/` — 15 domain evaluators + engine + plugins + suppressions + remediation (18 files) |
| **Frameworks** | `postureiq_frameworks/` — 11 JSON framework mappings (independent copies, 525 controls) |
| **Reports** | `postureiq_reports/` — 20 report generators including PostureIQ-specific HTML and Markdown |
| **Agent Tool** | `run_postureiq_assessment` — 14th tool in the TOOLS list |

### Deployment

- **Commit:** `601149d`
- **Image:** `esiqnewacr.azurecr.io/esiqnew-agent:v39-spa`
- **Container App:** `esiqnew-agent` (North Europe)

---

## v25 — Persistent Report Storage via Azure Blob Storage (2026-04-13)

**Problem:** Reports were stored in ephemeral container storage (`/agent/output`).
Every container restart or redeployment wiped all generated reports, causing
`{"detail":"Report not found"}` 404 errors when users clicked previously generated
report links.

**Root cause:** Azure Files volume mounts require `allowSharedKeyAccess: true`, but
an Azure Policy at the management group level forces `allowSharedKeyAccess: false`
on every storage account in the subscription — this cannot be overridden.

**Solution:** Switched to Azure Blob Storage with managed identity authentication
(DefaultAzureCredential), which uses Entra ID OAuth2 and does not require shared keys.

### Changes

| File | Change |
|------|--------|
| **`app/blob_store.py`** (new) | Upload, download, and list report blobs via `azure-storage-blob` SDK with `DefaultAzureCredential` |
| **`app/agent.py`** | Added `_blob_upload_dir()` call after every report generation (risk, data security, copilot readiness, AI agent security, RBAC, compliance assessment, generate_report) |
| **`app/api.py`** | `GET /reports` now returns the union of local files and blob storage entries; `GET /reports/{path}` falls back to blob download when a file is missing locally |

### Infrastructure

| Resource | Detail |
|----------|--------|
| Storage account | `esiqnewstorage` (existing) |
| Blob container | `reports` (created) |
| RBAC | `Storage Blob Data Contributor` assigned to managed identity `ESIQNew-identity` (principal `d742617c-6f14-4215-be65-e1f7b68866de`) |
| Public network access | Enabled on storage account (was disabled) |
| Env vars added | `REPORT_STORAGE_ACCOUNT=esiqnewstorage`, `REPORT_STORAGE_CONTAINER=reports` |

### How it works

```
Report generated → written to /agent/output (local)
                 → uploaded to blob storage (persistent)

Report requested → check local filesystem first
                 → if missing, download from blob storage on demand
                 → serve to user

Report listing   → merge local files + blob storage entries
                 → deduplicate by path
```

---

## v24 — Multi-Tenant Authentication (2026-04-13)

**Problem:** Users from external tenants saw "Selected user account does not exist
in tenant 'Contoso'" when trying to sign in via the web dashboard.

**Root cause:** MSAL authority was hardcoded to the home tenant
(`https://login.microsoftonline.com/4a3eb5f4-...`) and the app registration's
`signInAudience` was set to `AzureADMyOrg` (single-tenant).

### Changes

| File | Change |
|------|--------|
| **`webapp/index.html`** | Changed MSAL authority from `/4a3eb5f4-...` to `/common` |
| **App Registration** | Changed `signInAudience` from `AzureADMyOrg` to `AzureADMultipleOrgs` via `az ad app update` |

---

## v23 — Dockerfile Cache Busting (2026-04-13)

**Problem:** After the v21 UX redesign, the deployed container still served the old
`index.html`. Docker layer caching in ACR reused the cached `COPY webapp/ webapp/`
layer because the Dockerfile lines above it hadn't changed.

### Changes

| File | Change |
|------|--------|
| **`Dockerfile`** | Added `ARG CACHEBUST=1` before `COPY webapp/ webapp/` |
| **Build command** | Now uses `--build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')` to bust cache on every build |

Also removed the Azure Files volume mount from the Container App configuration
(workaround for `VolumeMountFailure: Permission denied` caused by
`allowSharedKeyAccess: false`).

---

## v21 — UX Redesign: Sidebar Layout & Professional UI (2026-04-13)

**Scope:** Complete redesign of the single-page web dashboard (`webapp/index.html`).

### Changes

| Feature | Before | After |
|---------|--------|-------|
| **Navigation** | Dashboard grid of cards | Persistent left sidebar with categorized assessment tools |
| **Layout** | Fixed two-column | Draggable resizer between sidebar and chat area |
| **Tenant info** | Hidden | Always-visible tenant badge in sidebar header |
| **Progress** | Spinner text | Professional multi-phase progress indicator with tool-level status |
| **Session header** | Dynamic "New session" banner | Removed — cleaner interface |

SPA grew from ~817 to ~1,035 lines.

---

## v20 — Full PDF Support & Download Pipeline (2026-04-12)

### Changes

- Integrated **Playwright Chromium** into the Docker image for server-side HTML→PDF conversion
- Added `playwright install --with-deps chromium` to Dockerfile
- Added PDF generation to all 6 report pipelines:
  - Risk Analysis, Data Security, Copilot Readiness, AI Agent Security, RBAC, Compliance Assessment
- Added PDF and CSV MIME types to `_MIME_MAP` in `api.py`
- SPA download buttons now show PDF/CSV alongside HTML/Excel/JSON

---

## v19 — Framework Selection & Azure Files Storage (2026-04-12)

### Changes

- **Framework picker modal** in SPA — users can select which compliance frameworks
  to evaluate (FedRAMP, CIS, ISO-27001, NIST-800-53, PCI-DSS, MCSB, HIPAA, SOC2,
  GDPR, NIST-CSF, CSA-CCM) before running assessments
- **`run_assessment` tool** updated to accept a `frameworks` parameter
- **Azure Files persistent storage** — mounted `esiq-reports` share at `/agent/output`
  (later removed in v23 due to `allowSharedKeyAccess` policy; replaced by blob storage in v25)
- Container App scaled to **single replica** (`minReplicas: 1, maxReplicas: 1`)

---

## v18 — Report Pipeline Fixes (2026-04-12)

### Changes

Fixed 6 report pipeline gaps where assessments completed successfully but reports
were not generated or returned to the user:

1. Risk Analysis — `_generate_risk_reports()` not called after scoring
2. Data Security — report generation path missing from `assess_data_security()`
3. Copilot Readiness — `_generate_cr_reports()` not wired in
4. AI Agent Security — `_generate_as_reports()` missing from tool function
5. RBAC Report — PDF generation not invoked after HTML
6. Compliance Assessment — `run_assessment()` didn't scan output dir for fallback

---

## v13 — Entra Role Detection Fix (2026-04-11)

### Changes

- Fixed `check_permissions` tool: Entra directory role detection was failing because
  the Graph API call to `/me/memberOf` wasn't filtering by `#microsoft.graph.directoryRole`
- Improved error handling in `auth.py` preflight check

---

## v12 — Report Link Rendering Fix (2026-04-11)

### Changes

- Fixed report link extraction in SSE stream — the LLM was sometimes rewriting
  report URLs with a `sandbox:` prefix
- Added regex extraction `r'\[([^\]]+)\]\((/reports/[^)]+)\)'` in `api.py` to
  capture report URLs from tool results and emit them as dedicated `report` SSE events
- SPA now renders download buttons from SSE `report` events, not from LLM text

---

## v11 — SSE Streaming & Graph Connection Pooling (2026-04-11)

### Changes

- **Server-Sent Events (SSE)** for real-time chat — replaced polling with streaming
- **Shared httpx connection pool** for Microsoft Graph API calls — reduced connection
  overhead across concurrent collectors
- **Report download buttons** rendered directly in the web UI from SSE events
- Tool execution progress shown in real-time during assessments

---

## v6 — User-Delegated Authentication (2026-04-10)

### Changes

- **MSAL SPA login** — users authenticate via Entra ID in the browser
- **Token passthrough** — SPA sends the user's access token to the backend,
  which uses it for Azure ARM and Graph API calls (user-delegated permissions)
- Replaced managed-identity-only auth with hybrid:
  - Web users → user token (broader Entra ID access)
  - Foundry/CLI → managed identity (DefaultAzureCredential)

---

## v5 — Chat-First SPA Redesign (2026-04-10)

### Changes

- Redesigned the web dashboard from a form-based interface to a **chat-first** experience
- Agent chat with conversational AI interface
- Tool usage displayed inline during conversations
- Report links embedded in chat responses

---

## v4 — SPA Dashboard + Foundry Registration (2026-04-09)

### Changes

- **Single-page application (SPA)** dashboard served from the container at `/`
- **Foundry agent auto-registration** on startup via the Assistants API
- Agent appears in the Azure AI Foundry portal with tracing and evaluation support

---

## v3 — Deployment Infrastructure (2026-04-09)

### Changes

- `infra/deploy.ps1` — Fully parameterized PowerShell deployment script
- `infra/redeploy-image.ps1` — Quick rebuild and restart script
- `infra/main.bicep` — Bicep template for Container Apps + ACR + managed identity
- Dockerfile optimizations for ACR Tasks (removed `--platform` from `FROM`)
- Fixed `six` module dependency for Python 3.12-slim
- Fixed beta-only Azure SDK package versions

---

## v2 — New Foundry Deployment (2026-04-08)

### Changes

- Migrated from legacy Foundry to **New Foundry** (CognitiveServices/accounts/projects)
- Created `ESIQNew` prefix resources (ACR, Container App, managed identity)
- Region: North Europe

---

## v1 — Initial Release (2026-04-07)

### Capabilities

- 64 async collectors (50 Azure + 14 Entra ID)
- 10 evaluation domains with 113 check functions
- 11 compliance frameworks (525 total controls)
- 12 agent tools for Foundry
- 10 CLI scripts for standalone operation
- 28 report generators (HTML, JSON, Markdown, Excel, OSCAL, SARIF, PDF, Webhook)
- 8 standalone engines (query, risk, data security, Copilot readiness, AI agent security, data residency, remediation, continuous monitoring)
- Microsoft Agent Framework SDK integration
- DefaultAzureCredential for unified ARM + Graph authentication

---

## Current Production Environment

| Resource | Value |
|----------|-------|
| **Container App** | `esiqnew-agent` |
| **FQDN** | `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` |
| **Resource Group** | `ESIQNew-RG` |
| **Region** | North Europe |
| **ACR** | `esiqnewacr.azurecr.io` |
| **Current Image** | `esiqnew-agent:v25` |
| **Managed Identity** | `ESIQNew-identity` (client ID: `d5d10273-4a8b-4251-9b9d-00fe035df97a`) |
| **App Registration** | `EnterpriseSecurityIQ-SPA` (ID: `ffb6f10d-6991-430e-b3d6-23a0101a92b1`, multi-tenant) |
| **Storage Account** | `esiqnewstorage` (blob container: `reports`) |
| **Subscription** | `d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0` |
| **Container App Env** | `ESIQNew-env` |
| **Compute** | 1.0 vCPU, 2 Gi memory, 4 Gi ephemeral storage, min/max 1 replica |

### Build & Deploy Commands

```powershell
# Build (from repo root)
az acr build --registry esiqnewacr --image esiqnew-agent:v<N> `
  --file AIAgent/Dockerfile . --no-logs `
  --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')

# Deploy
az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG `
  --image esiqnewacr.azurecr.io/esiqnew-agent:v<N> -o table
```
