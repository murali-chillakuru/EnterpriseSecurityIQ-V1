# PostureIQ — Complete Knowledge Hub

> **Author:** Murali Chillakuru  
> AI-powered compliance assessment for Azure, Entra ID, Microsoft 365, and AI platforms.  
> 14 agent tools · 68 collectors · 11 frameworks · 525 controls · 120+ evaluators · 10 domains · 29 report generators · 9 engines

---

## What Is PostureIQ?

**PostureIQ** is an AI-powered compliance and security assessment tool that automatically audits your Azure subscriptions, Entra ID tenant, and Microsoft 365 environment against industry compliance frameworks. It collects evidence from 68 data sources, evaluates 525 controls across 11 frameworks (NIST 800-53, FedRAMP, CIS, PCI-DSS, ISO 27001, SOC 2, HIPAA, NIST CSF, CSA-CCM, MCSB, GDPR), and generates detailed reports with findings, scores, and remediation guidance.

It runs as a **Microsoft Foundry AI Agent** (conversational) or as **standalone CLI scripts** (headless for CI/CD). The agent understands natural language queries like *"How compliant are we with NIST 800-53?"* or *"What are our top 10 risks?"* and produces detailed, evidence-backed answers. PostureIQ is the sole posture assessment engine, providing risk-weighted scoring, attack path analysis, and AI fix recommendations.

### What Problems Does It Solve?

Manual compliance audits take weeks and go stale immediately. This tool automates the entire cycle — collect evidence, evaluate controls, generate reports — in minutes. Run it weekly in CI/CD to catch compliance drift before auditors do.

### Who Is It For?

- **Security engineers** who need continuous compliance monitoring
- **Compliance officers** who need audit-ready evidence
- **Platform teams** who want security gates in deployment pipelines
- **CISOs** who need risk dashboards

### How Does It Work?

Three-phase pipeline:

1. **Collect** — 68 collectors gather evidence from Azure ARM, Microsoft Graph, and Entra ID
2. **Evaluate** — 120+ check functions across 10 security domains assess 525 controls
3. **Report** — 29 generators produce HTML, JSON, Markdown, Excel, OSCAL, SARIF, PDF

### AI Agent vs CLI

The **AI Agent** runs on Microsoft Foundry with 14 registered tools (`query_results`, `search_tenant`, `analyze_risk`, `assess_data_security`, `generate_rbac_report`, `generate_report`, `assess_copilot_readiness`, `assess_ai_agent_security`, `check_permissions`, `compare_runs`, `search_exposure`, `generate_custom_report`, `run_postureiq_assessment`, `query_assessment_history`) — invoke via natural language. The **CLI scripts** (8 total) run headlessly for automation, CI/CD, and scheduled assessments with no human interaction.

---

## Knowledge Ladder

Documents are organized from foundational concepts (L100) to expert-level internals (L500). Start at your level and work up.

| Level | Focus | Audience |
|-------|-------|----------|
| 🟢 **L100** | Fundamentals — what it is, getting started | Newcomers, stakeholders |
| 🔵 **L200** | Architecture, frameworks, domains, scoring | Developers, architects |
| 🟣 **L300** | Configuration, CLI, reports, CI/CD, suppressions | Practitioners, operators |
| 🟠 **L400** | Extending frameworks, custom collectors/evaluators | Contributors, advanced users |
| 🔴 **L500** | Internals, dispatch mechanics, determinism, troubleshooting | Experts, maintainers |

---

## L100 — Fundamentals

> Start here if you're new to the tool, to compliance frameworks, or to Azure security.

### What Is Compliance?

Compliance means your IT systems meet specific security standards required by regulations (HIPAA for healthcare, PCI-DSS for payments) or best practices (NIST, CIS). Each standard defines **controls** — specific security requirements like "enforce MFA" or "encrypt data at rest." This tool checks your Azure/Entra environment against those controls automatically.

### What Is Azure + Entra ID?

**Azure** is Microsoft's cloud platform where your VMs, databases, storage, and services run. **Entra ID** (formerly Azure AD) is the identity platform that manages users, groups, app registrations, and access policies. This tool audits both — Azure resources via ARM APIs and Entra identity data via Microsoft Graph.

### What Are Frameworks?

A compliance framework is a structured set of security controls. Examples:

- **NIST 800-53** — 83 controls, US government standard
- **PCI-DSS** — 51 controls, payment card industry
- **HIPAA** — 43 controls, healthcare
- **ISO 27001** — 56 controls, international information security

This tool maps controls from 11 frameworks to Azure/Entra evidence and evaluates each one.

### How Do I Run It?

Two ways:

1. **AI Agent** — Deploy to Microsoft Foundry and ask questions in natural language (e.g., *"Run a PostureIQ assessment"*)
2. **CLI** — Run individual scripts like `python run_risk_analysis.py --tenant YOUR-TENANT-ID` for specific analyses

PostureIQ assessments are invoked via the agent's `run_postureiq_assessment` tool; use `query_assessment_history` to list, trend, compare, or drill into past results. Output goes to `output/YYYYMMDD_HHMMSS/` with HTML, JSON, and Markdown reports.

### L100 Documents

| # | Document | Link |
|---|----------|------|
| 1 | **Project README** — High-level overview, quick start, installation | [README.md](../README.md) |
| 2 | **AI Agent README** — Agent-specific setup, Foundry deployment, Docker build | [AIAgent/README.md](../AIAgent/README.md) |
| 3 | **Agent Capabilities** — All 14 agent tools, example prompts, response formats | [agent-capabilities.md](agent-capabilities.md) |

---

## L200 — Architecture & Concepts

> Understand the internal architecture, the three-phase pipeline, evidence types, evaluator domains, and compliance scoring.

### Three-Phase Pipeline

**Phase 1: Collect** — 68 collectors (47 Azure + 17 Entra + 2 standalone) gather evidence. Azure and Entra groups run concurrently via `asyncio.gather()`. Collectors are auto-discovered by the `@register_collector` decorator — no manual import needed.

**Phase 2: Evaluate** — 120+ check functions across 10 security domains evaluate 525 controls against gathered evidence. Each assessment engine (PostureIQ, Risk, RBAC, Copilot Readiness, AI Agent Security, Data Security) follows a modular `{prefix}_orchestrator.py` + `{prefix}_evaluators/` + `{prefix}_reports/` structure. PostureIQ reads each control's `domain` field and dispatches to the matching domain evaluator; cross-domain fallback (28 routes) handles controls whose evidence maps to a different domain.

**Phase 3: Report** — 29 generators produce output in 8+ formats (HTML, JSON, Markdown, Excel, OSCAL, SARIF, PDF, drift HTML). Per-framework subfolders with framework-specific reports.

### Evidence Types (121 Total)

Each collector produces evidence records keyed by type (e.g., `azure-keyvault`, `entra-conditional-access-policy`). The engine builds an O(1) lookup index via `_index_evidence()`. Controls reference evidence types in their `evidence_types` field. If primary evidence is missing, `compensating_evidence` provides fallback.

- **93 Azure evidence types** — from resources like Key Vault, NSG, Storage Account, SQL Server, etc.
- **28 Entra evidence types** — from users, groups, conditional access policies, app registrations, etc.

### Security Domains (10)

| Domain | Handlers | Example Checks |
|--------|----------|----------------|
| `access` | 8 | RBAC roles, JIT, PIM, least privilege |
| `identity` | 22 | MFA, conditional access, legacy auth, password policies |
| `data_protection` | 22 | Encryption at rest/transit, key rotation, DLP |
| `network` | 16 | NSG rules, private endpoints, WAF, DDoS |
| `logging` | 13 | Diagnostic settings, audit logs, retention |
| `governance` | 21 | Policies, tags, resource locks, naming |
| `incident_response` | 6 | Alert rules, playbooks, contacts |
| `change_management` | 4 | DevOps controls, deployment gates |
| `business_continuity` | 4 | Backup, geo-replication, availability |
| `asset_management` | 4 | Inventory, classification, lifecycle |

### Severity-Weighted Scoring

Each finding carries a severity weight: **critical=4**, **high=3**, **medium=2**, **low=1**, informational=0. The compliance score is a weighted percentage with 50% partial credit for `partially_compliant` status. Framework-level and domain-level breakdowns are provided.

### PostureIQ — Independent Risk-Weighted Engine

PostureIQ is a parallel assessment engine that goes beyond compliance scoring with risk intelligence:

| Capability | Description |
|------------|-------------|
| **Risk-Weighted Scoring** | severity × exploitability × blast radius = RiskScore 0–100 with RiskTier labels |
| **Attack Path Analysis** | Privilege escalation chains, lateral movement, exposed high-value targets |
| **Priority Ranking** | ROI-based ranking: risk/√effort with quick wins identification |
| **AI Fix Recommendations** | GPT-powered Azure CLI + PowerShell remediation scripts |
| **Exception Tracking** | Audit trail with owner, ticket, risk_accepted fields |

For full details, see [PostureIQ Deep Dive](postureiq-deep-dive.md).

### L200 Documents

| # | Document | Link |
|---|----------|------|
| 4 | **Architecture Deep Dive** — Full pipeline diagrams, collector registry, evaluator dispatch | [architecture.md](architecture.md) |
| 5 | **Evaluation Rules** — All 10 domains, 120+ check functions, cross-domain fallback, PostureIQ risk scoring | [evaluation-rules.md](evaluation-rules.md) |
| 6 | **File Reference** — Complete inventory of every file in the repo | [FILE-REFERENCE.md](FILE-REFERENCE.md) |
| 7 | **PostureIQ Deep Dive** — Risk-weighted scoring, attack paths, priority ranking, AI fix recommendations | [postureiq-deep-dive.md](postureiq-deep-dive.md) |

---

## L300 — Operations

> Day-to-day usage: configuration, CLI commands, report formats, CI/CD pipelines, suppression rules, and authentication modes.

### 4 Authentication Modes

| Mode | Description |
|------|-------------|
| `auto` | `DefaultAzureCredential` — tries managed identity, CLI, env vars in sequence |
| `serviceprincipal` | Client ID + secret via `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` |
| `appregistration` | Certificate-based app registration |
| `azurecli` | Uses existing `az login` session |

Set via `ENTERPRISESECURITYIQ_AUTH_MODE` env var. Preflight check probes ARM + Graph + Entra to detect permission boundaries before collection.

### 8 CLI Scripts

| Script | Purpose |
|--------|--------|
| `run_rbac_report.py` | RBAC role analysis with over-privilege detection |
| `run_query.py` | Query past assessment results |
| `run_risk_analysis.py` | Risk scoring and top-N risk dashboard |
| `run_data_security.py` | Data security posture evaluation. Supports `--fail-on-severity`. |
| `run_copilot_readiness.py` | M365 Copilot readiness assessment. Supports `--fail-on-severity`. |
| `run_ai_agent_security.py` | AI agent security posture. Supports `--fail-on-severity`. |
| `run_cr_determinism_check.py` | Verify Copilot readiness determinism |
| `run_rbac_determinism_check.py` | Verify RBAC report determinism |

> **Note:** `run_assessment.py` and `run_assessment_determinism_check.py` were removed in v49. PostureIQ is now the sole posture assessment engine, invoked via the agent's `run_postureiq_assessment` tool.

### Report Formats

29 report generators produce:

- **HTML** — Interactive dashboards with charts, drill-down, severity filters
- **JSON** — Machine-readable for downstream systems and SIEM integration
- **Markdown** — Human-readable for Git repos, wikis, PR comments
- **Excel** — Spreadsheet format for compliance officers
- **OSCAL** — NIST Open Security Controls Assessment Language
- **SARIF** — Static Analysis Results Interchange Format (IDE/GitHub integration)
- **PDF** — Via Playwright headless Chromium rendering
- **Drift HTML** — Delta comparison when delta mode is active

### Suppression Rules

Mute accepted risks via `suppressions.json` with regex-based `control_id` (uses `re.fullmatch()`, not `re.search()`) and `resource` matching (uses `re.search()` case-insensitive), ISO date expiry, and full audit trail. Suppressed findings stay in JSON exports for auditability. Expiry behavior: past date = suppression skipped, within 7 days = warning logged, missing = permanent.

### L300 Documents

| # | Document | Link |
|---|----------|------|
| 7 | **Configuration Guide** — Config file, env vars, auth, collector tuning | [configuration-guide.md](configuration-guide.md) |
| 8 | **Usage & Prompts Guide** — CLI scripts, agent prompts, operational workflows | [PROMPTS.md](PROMPTS.md) |
| 9 | **CI/CD Integration** — GitHub Actions, Azure DevOps, compliance gates | [ci-cd-integration.md](ci-cd-integration.md) |
| 10 | **Suppressions Guide** — Suppression rules, regex matching, audit trail | [suppressions-guide.md](suppressions-guide.md) |

---

## L400 — Advanced Extension

> Extend the tool: add custom compliance frameworks, write new collectors, create evaluator functions, and build plugins.

### Add a Custom Framework

1. Create a JSON mapping file in `AIAgent/app/postureiq_frameworks/`
2. Define controls with: `control_id`, `domain`, `severity`, `evidence_types`, `evaluation_logic`, `compensating_evidence` (optional), `custom_evaluator` (optional)
3. Register in the `AVAILABLE_FRAMEWORKS` dict in `postureiq_orchestrator.py`
4. All field names use **snake_case** (not camelCase)

### Add a Collector

1. Create a Python module in `AIAgent/app/collectors/azure/` or `AIAgent/app/collectors/entra/`
2. Use the `@register_collector(name, plane, source, priority)` decorator
3. Auto-discovered via `pkgutil.iter_modules()` — no manual import needed
4. Priority: P10-P190 (control Azure), P200-P240 (data Azure), P10-P170 (Entra)
5. Base collector provides: 3 retries, exponential backoff (2s → 4s → 8s), partial evidence preservation

### Add an Evaluator Function

1. Write a handler: `_check_xxx(control_id, control, evidence, evidence_index, thresholds) → list[dict]`
2. Add to the domain dispatch dict in the appropriate `postureiq_evaluators/eval_*.py` file (or the engine-specific `{prefix}_evaluators/` directory for Risk, RBAC, Copilot Readiness, AI Agent Security, Data Security, or Query evaluators)
3. Reference the function name in framework JSON's `evaluation_logic` field

### Plugin System

1. Drop a `.py` file in `plugins/` directory
2. Must export: `evaluate(control, evidence_index) → tuple[str, list[dict]]`
3. Set `custom_evaluator` field in framework JSON to the plugin filename (without `.py`)
4. Auto-discovered by `load_plugins()` at startup

### L400 Documents

| # | Document | Link |
|---|----------|------|
| 11 | **Extending Frameworks** — Full extension guide, 4 extension points, evidence types | [extending-frameworks.md](extending-frameworks.md) |

---

## L500 — Expert Internals

> Deep internals: evaluation dispatch mechanics, determinism guarantees, checkpoint/resume, error recovery, and troubleshooting.

### Modular Engine Architecture (v49+)

Each assessment engine follows a consistent modular pattern: `{prefix}_orchestrator.py` + `{prefix}_evaluators/` + `{prefix}_reports/`. Engines: PostureIQ, Risk, RBAC, Copilot Readiness, AI Agent Security, Data Security, and Query (8 modules in `query_evaluators/`). The query engine was modularized from a single `query_engine.py` into 8 focused modules.

### Two-Stage Evaluation Dispatch (PostureIQ)

PostureIQ reads a control's `domain` field and dispatches to the matching domain evaluator in `postureiq_evaluators/`. If all findings return `not_assessed`, the engine checks `_CROSS_DOMAIN_MAP` (28 routes) and redirects to an alternative domain. This ensures controls get evaluated even when primary evidence maps to a different domain.

### Determinism Guarantees

Two determinism check scripts verify evaluation reproducibility (PostureIQ determinism is validated via the agent's `query_assessment_history` compare mode):

1. **Phase A** — Collect evidence once
2. **Phase B** — Evaluate N times with identical evidence order
3. **Phase C** — Evaluate N times with shuffled evidence order (seed `i*42+7`)
4. **Phase D** — Compare SHA-256 hashes after stripping 12 volatile fields
5. **Phase E** — Report generation determinism check

Exit code: **0 = PASS**, **1 = FAIL**. 12 volatile fields stripped: timestamps, run IDs, durations, etc.

### Collector Error Recovery

| Error Type | Behavior |
|-----------|----------|
| Transient (500, 503) | 3 retries with exponential backoff: 2s → 4s → 8s |
| `AccessDeniedError` (403) | Creates permission marker, pipeline continues |
| Rate limited (429) | Reads `Retry-After` header, respects the delay |
| Timeout | Preserves partial evidence via `_partial_evidence` attribute |
| Network error | Retries, then creates connectivity marker |

### Checkpoint / Resume

- `.checkpoint.json` stores `{completed, failed, evidence}`
- On resume: completed collectors are skipped, failed collectors retry
- Corrupt checkpoint → fresh start (auto-deleted)
- Auto-deleted on successful completion
- `.last_run.json` enables delta/drift analysis between consecutive runs

### Thread-Safe Agent State

The AI Agent uses `_session_state` protected by `asyncio.Lock` for concurrent tool invocations. Each tool invocation reads/writes to session state atomically. The agent runs on port 8088 using the `responses` protocol v1 via `AzureAIClient.as_agent()`.

### L500 Documents

| # | Document | Link |
|---|----------|------|
| 12 | **Troubleshooting** — 15 diagnostic topics, error codes, checkpoint recovery | [troubleshooting.md](troubleshooting.md) |

---

## Complete Document Index

| # | Document | Level | Link |
|---|----------|-------|------|
| 1 | Project README | L100 | [README.md](../README.md) |
| 2 | AI Agent README | L100 | [AIAgent/README.md](../AIAgent/README.md) |
| 3 | Agent Capabilities | L100 | [agent-capabilities.md](agent-capabilities.md) |
| 4 | Architecture Deep Dive | L200 | [architecture.md](architecture.md) |
| 5 | Evaluation Rules | L200 | [evaluation-rules.md](evaluation-rules.md) |
| 6 | File Reference | L200 | [FILE-REFERENCE.md](FILE-REFERENCE.md) |
| 7 | Configuration Guide | L300 | [configuration-guide.md](configuration-guide.md) |
| 8 | Usage & Prompts Guide | L300 | [PROMPTS.md](PROMPTS.md) |
| 9 | CI/CD Integration | L300 | [ci-cd-integration.md](ci-cd-integration.md) |
| 10 | Suppressions Guide | L300 | [suppressions-guide.md](suppressions-guide.md) |
| 11 | Extending Frameworks | L400 | [extending-frameworks.md](extending-frameworks.md) |
| 12 | Troubleshooting | L500 | [troubleshooting.md](troubleshooting.md) |

---

*PostureIQ — Complete Knowledge Hub — Author: Murali Chillakuru*
