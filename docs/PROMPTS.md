# PostureIQ — Usage Guide

**Author: Murali Chillakuru**

> **Executive Summary** — Step-by-step usage guide for all 10 CLI scripts, 4 authentication
> workflows, selective assessment patterns, multi-tenant support, and the Foundry agent.
> This is the canonical "how to run it" reference — start here for practical operations.
>
> | | |
> |---|---|
> | **Audience** | Operators, security analysts, CI/CD engineers |
> | **Prerequisites** | Python 3.10+, `pip install -r requirements.txt`, Azure authentication |
> | **Companion docs** | [Configuration Guide](configuration-guide.md) for settings · [Troubleshooting](troubleshooting.md) for error resolution · [CI/CD Integration](ci-cd-integration.md) for pipeline setup |

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Full Compliance Assessment](#full-compliance-assessment)
- [RBAC Analysis](#rbac-analysis)
- [Security Risk Analysis](#security-risk-analysis)
- [Data Security Assessment](#data-security-assessment)
- [M365 Copilot Readiness](#m365-copilot-readiness)
- [AI Agent Security Assessment](#ai-agent-security-assessment)
- [Query Engine](#query-engine)
- [Selective Assessment Patterns](#selective-assessment-patterns)
- [Multi-Tenant Assessment](#multi-tenant-assessment)
- [Continuous Monitoring](#continuous-monitoring)
- [Remediation Plans](#remediation-plans)
- [SIEM Export](#siem-export)
- [Data Residency Validation](#data-residency-validation)
- [Determinism Checks](#determinism-checks)
- [Foundry Agent](#foundry-agent)
- [Reviewing Results](#reviewing-results)
- [Output Files Reference](#output-files-reference)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Install Python Dependencies

```bash
# Python 3.10+ required (3.12 recommended)
cd AIAgent
pip install -r requirements.txt
```

### Authenticate to Azure

The engine uses unified `DefaultAzureCredential` for both ARM and Graph — no separate consent flows or browser popups required:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
2. Azure CLI (`az login`)
3. Managed Identity (when running in Azure)

Before each assessment, a **preflight permissions check** verifies ARM access, Graph connectivity, and Entra directory roles. If permissions are insufficient, the assessment stops with actionable guidance.

**Interactive use:**

```bash
az login --tenant "4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67"
```

**Service principal automation (CI/CD):**

```bash
export AZURE_TENANT_ID="4a3eb5f4-..."
export AZURE_CLIENT_ID="<app-registration-client-id>"
export AZURE_CLIENT_SECRET="<client-secret>"
```

**App registration (dedicated):**

```bash
export ENTERPRISESECURITYIQ_APP_CLIENT_ID="<app-id>"
export ENTERPRISESECURITYIQ_APP_CLIENT_SECRET="<app-secret>"
export ENTERPRISESECURITYIQ_AUTH_MODE="appregistration"
```

### Required Permissions

**Azure RBAC:** `Reader` role on target subscriptions.

**Microsoft Graph** (application or delegated):

| Permission | Purpose |
|------------|---------|
| `User.Read.All` | User details, MFA status, stale account detection |
| `Directory.Read.All` | Tenant info, roles, groups, applications, service principals |
| `Policy.Read.All` | Conditional Access, auth methods, security policies |
| `RoleManagement.Read.All` | Directory role assignments, PIM eligibility |
| `Application.Read.All` | App registrations, OAuth grants |
| `AuditLog.Read.All` | Sign-in logs, directory audit logs |
| `SecurityEvents.Read.All` | Security alerts, risky users |
| `IdentityRiskyUser.Read.All` | Risky user details |
| `Group.Read.All` | Group membership and inventory |
| `IdentityRiskEvent.Read.All` | Risk detections |
| `AccessReview.Read.All` | Access review status |
| `EntitlementManagement.Read.All` | Governance data |
| `InformationProtection.Read` | Sensitivity labels (Purview) |

> **📖 Complete reference:** For all auth modes, env var overrides, and preflight validation details, see [Configuration Guide — Authentication](configuration-guide.md#authentication).

**Sufficient Entra Roles:** Global Administrator, Global Reader, Security Administrator, Security Reader, Compliance Administrator

---

## Quick Start

```bash
cd AIAgent

# Interactive — prompts for tenant ID and framework selection
python run_assessment.py

# Non-interactive — specify everything on command line
python run_assessment.py --tenant "4a3eb5f4-..." --framework FedRAMP
```

The assessment will:
1. Authenticate using `DefaultAzureCredential` (ARM + Graph, no popup)
2. Discover accessible subscriptions (with optional filter)
3. Run all 64 collectors in parallel batches (Azure + Entra concurrently)
4. Evaluate collected evidence against selected frameworks (113 check functions)
5. Generate HTML, Markdown, Excel, and JSON reports per framework
6. Print a summary with compliance score

---

## Authentication

Authentication is handled automatically via `ComplianceCredentials` (`app/auth.py`) which supports 4 modes.

### Azure CLI (Interactive)

```bash
az login --tenant "<tenant-id>"
python run_assessment.py --tenant "<tenant-id>" --framework FedRAMP
```

### Service Principal (CI/CD)

```bash
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<client-id>"
export AZURE_CLIENT_SECRET="<secret>"
python run_assessment.py --tenant "$AZURE_TENANT_ID" --framework FedRAMP NIST-800-53
```

### App Registration (Dedicated App)

```bash
export AZURE_TENANT_ID="<tenant-id>"
export ENTERPRISESECURITYIQ_APP_CLIENT_ID="<app-client-id>"
export ENTERPRISESECURITYIQ_APP_CLIENT_SECRET="<app-secret>"
export ENTERPRISESECURITYIQ_AUTH_MODE="appregistration"
python run_assessment.py --tenant "$AZURE_TENANT_ID" --framework FedRAMP
```

### Managed Identity (Azure-hosted)

When running in Azure (Container Apps, App Service, VM), managed identity is used automatically. No environment variables needed.

### Preflight Validation

Before collection starts, `preflight_check()` probes:
- **ARM:** subscription listing
- **Graph (Users):** `User.Read.All`
- **Graph (CA):** `Policy.Read.All`
- **Graph (Roles):** `RoleManagement.Read.All`

403 → warnings (collection continues with reduced scope). 401 → blocking errors.

---

## Full Compliance Assessment

### Single Framework

```bash
python run_assessment.py --tenant "..." --framework FedRAMP
```

### Multiple Frameworks

```bash
python run_assessment.py --tenant "..." --framework FedRAMP NIST-800-53 CIS
```

Each framework gets its own subfolder with dedicated reports.

### All 11 Frameworks

```bash
python run_assessment.py --tenant "..." --framework all
```

### With Config File

```bash
ENTERPRISESECURITYIQ_CONFIG=../config/enterprisesecurityiq.config.json \
  python run_assessment.py --tenant "..."
```

---

## RBAC Analysis

Generate a comprehensive RBAC report analyzing role assignments, privilege sprawl, and access patterns.

```bash
python run_rbac_report.py --tenant "..."
```

Produces:
- Role assignment analysis per subscription
- Privileged role inventory (Owner, Contributor, User Access Admin)
- Entra directory role assignments
- PIM eligibility status
- Custom role definitions with risk indicators
- Detailed HTML report with interactive tables

---

## Security Risk Analysis

Analyze attack-surface risk across 5 categories with severity-weighted scoring.

```bash
python run_risk_analysis.py --tenant "..."
```

**Categories:** Identity, Network, Defender, Config, Data

**Severity weights:** critical=10, high=7.5, medium=5, low=2.5, informational=1

Produces an interactive risk report with categorized findings, severity distribution, and prioritized remediation recommendations.

---

## Data Security Assessment

Deep assessment of data-layer security posture across 7 categories.

```bash
python run_data_security.py --tenant "..."
```

**Categories:** Storage Exposure, Database Security, Key/Secret Hygiene, Encryption Posture, Data Classification, Data Lifecycle, DLP Posture

Produces a detailed report with per-category scores, finding drill-downs, and contextual explanations (powered by 42 categories from `config/data-security-relevance.json`).

---

## M365 Copilot Readiness

Evaluate organizational readiness for M365 Copilot deployment.

```bash
python run_copilot_readiness.py --tenant "..."
```

**Categories:** Oversharing, Sensitivity Labels, DLP Policies, Retention/RSS, Access Governance, Lifecycle Management, Audit Readiness

Produces a readiness scorecard with category-level grades, specific findings, and a deployment readiness summary.

---

## AI Agent Security Assessment

Assess AI agent security posture across multiple platforms.

```bash
python run_ai_agent_security.py --tenant "..."
```

**Assessment areas:**
- **Copilot Studio** (5 checks): Bot auth, DLP, connectors, data loss prevention, channels
- **Microsoft Foundry** (20+ checks): Deployments, content safety, network isolation, identity, API keys, responsible AI
- **Custom Agents** (3 checks): SP security, API auth, data handling
- **Entra AI Identity** (3+ checks): AI SP hygiene, OAuth consent, cross-tenant policies

---

## Query Engine

Query results from past assessment runs.

```bash
python run_query.py --query "non-compliant controls in FedRAMP"
```

The query engine searches evidence, findings, and control results from the most recent assessment output, supporting natural language queries.

---

## Selective Assessment Patterns

### Azure-Only (No Entra)

```json
{
  "collectors": {
    "azureEnabled": true,
    "entraEnabled": false
  }
}
```

### Entra-Only (No Azure)

```json
{
  "collectors": {
    "azureEnabled": false,
    "entraEnabled": true
  }
}
```

### Filter to Specific Subscriptions

```json
{
  "auth": {
    "subscriptionFilter": [
      "d33fc1a7-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "0eb177bd-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ]
  }
}
```

Or via environment variable:

```bash
export AZURE_SUBSCRIPTION_FILTER="d33fc1a7-xxxx,0eb177bd-xxxx"
```

### Large Tenant Optimization (50K+ users)

```json
{
  "collectors": {
    "userSampleLimit": 5000,
    "azureBatchSize": 6,
    "entraBatchSize": 4,
    "collectorTimeout": 600
  }
}
```

---

## Multi-Tenant Assessment

Assess additional tenants alongside the primary tenant:

```json
{
  "additionalTenants": ["tenant-id-2", "tenant-id-3"]
}
```

Or via CLI:

```bash
python run_assessment.py --tenant "primary-tenant" \
  --additional-tenants "tenant-2" "tenant-3" --framework FedRAMP
```

Each tenant's evidence is collected separately, then combined for cross-tenant evaluation.

---

## Continuous Monitoring

Run periodic re-assessments and track compliance score trends:

```json
{
  "continuousMonitoring": {
    "enabled": true,
    "intervalMinutes": 1440,
    "collectors": ["defender", "policy", "rbac"],
    "frameworks": ["FedRAMP"],
    "alertOnRegression": true,
    "minScoreThreshold": 80
  }
}
```

The monitor stores historical scores to `.trends.json` and detects regressions between runs. Use selective collectors for faster cycles.

---

## Remediation Plans

Generate actionable fix scripts for non-compliant findings:

```json
{
  "remediation": {
    "enabled": true,
    "includeAzCli": true,
    "includePowerShell": true,
    "includeArmSnippets": false
  }
}
```

**Generated commands cover:** Encryption, TLS, network rules, MFA, diagnostics, database hardening, Key Vault, CMK, and private endpoints.

---

## SIEM Export

### Azure Sentinel

```json
{
  "siemIntegration": {
    "sentinel": {
      "enabled": true,
      "endpointUrl": "https://<dce>.ingest.monitor.azure.com",
      "workspaceId": "<workspace-id>",
      "dcrImmutableId": "<dcr-immutable-id>",
      "dcrStreamName": "Custom-EnterpriseSecurityIQ_CL",
      "batchSize": 100
    }
  }
}
```

### Splunk

```bash
export SPLUNK_HEC_TOKEN="<your-hec-token>"
```

```json
{
  "siemIntegration": {
    "splunk": {
      "enabled": true,
      "endpointUrl": "https://splunk-hec:8088/services/collector"
    }
  }
}
```

### Generic Webhook

```bash
export SIEM_WEBHOOK_TOKEN="<your-token>"
```

```json
{
  "siemIntegration": {
    "generic": {
      "enabled": true,
      "endpointUrl": "https://your-siem/api/events"
    }
  }
}
```

---

## Data Residency Validation

Validate Azure resources are deployed in approved geographic boundaries:

```json
{
  "dataResidency": {
    "enabled": true,
    "allowedRegions": ["eastus", "westus2"],
    "allowedRegionGroups": ["US"]
  }
}
```

Checks resource locations, storage replication targets, CosmosDB multi-region writes, backup vault regions, CDN endpoints, and cross-region data flows.

---

## Determinism Checks

Verify that assessment output is deterministic (same input → same output). Used for CI and regression testing.

```bash
# Full assessment determinism
python run_assessment_determinism_check.py --tenant "..."

# Copilot Readiness determinism
python run_cr_determinism_check.py --tenant "..."

# RBAC report determinism
python run_rbac_determinism_check.py --tenant "..."
```

Each script runs two assessments and compares output to verify no non-deterministic artifacts.

---

## Foundry Agent

PostureIQ runs as a **Microsoft Foundry hosted agent** with 12 registered tools.

### Local Development

```bash
cd AIAgent
pip install -r requirements.txt
python main.py
# Agent listens on http://localhost:8088
```

### Docker

```bash
cd AIAgent
docker build -t enterprisesecurityiq .
docker run -p 8088:8088 \
  -e AZURE_TENANT_ID="..." \
  -e AZURE_CLIENT_ID="..." \
  -e AZURE_CLIENT_SECRET="..." \
  enterprisesecurityiq
```

### Agent Tools (12)

| Tool | Purpose |
|------|---------|
| `run_assessment` | Full compliance assessment |
| `query_results` | Query past assessment results |
| `search_tenant` | Search tenant for specific resources |
| `analyze_risk` | Security risk analysis |
| `assess_data_security` | Data security posture assessment |
| `generate_rbac_report` | RBAC analysis report |
| `assess_copilot_readiness` | M365 Copilot readiness |
| `assess_ai_agent_security` | AI agent security assessment |
| `generate_report` | Generate specific report formats |
| `check_permissions` | Verify access permissions |
| `compare_runs` | Compare two assessment runs |
| `search_exposure` | Search for security exposure patterns |

The agent accepts requests via the Foundry `responses` protocol (v1) on port 8088.

---

## Reviewing Results

### Navigate Output Directory

```bash
# Assessment prints the output path. Open reports:
# Windows
start output\20260327_151401\FedRAMP\compliance-report.html

# macOS
open output/20260327_151401/FedRAMP/compliance-report.html

# Linux
xdg-open output/20260327_151401/FedRAMP/compliance-report.html
```

### Quick JSON Check

```bash
# Python
python -c "
import json
r = json.load(open('output/<timestamp>/control-results.json'))
for c in r: print(f\"{c['ControlId']:12} {c['Status']:18} {c['Domain']}\")
"

# jq
jq '.[] | {ControlId, Status, Domain}' output/<timestamp>/control-results.json
```

### Report Types

| Report | Best For |
|--------|---------|
| `compliance-report.html` | Full interactive audit — sidebar nav, search, filters |
| `executive-summary.html` | Management presentations — one-page with compliance ring |
| `gaps-report.html` | Remediation planning — non-compliant findings with roadmap |
| `{framework}-report.xlsx` | Data analysis — 3-sheet Excel workbook |
| `methodology-report.html` | Auditor handoff — explains assessment methodology |

---

## Output Files Reference

Each run creates a timestamped directory under `output/`.

```
output/20260327_151401/
├── FedRAMP/
│   ├── compliance-report.html / .md
│   ├── executive-summary.html / .md
│   ├── gaps-report.html / .md
│   ├── FedRAMP-report.xlsx
│   └── oscal-results.json         (if oscal format enabled)
├── NIST-800-53/
│   └── ... (same structure)
├── methodology-report.html
├── findings.json / .csv
├── control-results.json / .csv
├── evidence.json
├── all-evidence.json
├── access-denied.json
└── .checkpoint.json               (auto-removed on success)
```

| File | Description |
|------|-------------|
| `compliance-report.html/md` | Full interactive compliance report |
| `executive-summary.html/md` | One-page executive summary with compliance ring |
| `gaps-report.html/md` | Non-compliant findings with remediation roadmap |
| `{framework}-report.xlsx` | Excel: Compliance Report, Gap Analysis, Executive Summary |
| `methodology-report.html` | Assessment methodology (for auditors) |
| `oscal-results.json` | NIST OSCAL assessment results (if enabled) |
| `findings.json/csv` | All individual findings |
| `control-results.json/csv` | Per-control status summary |
| `evidence.json` | Normalized evidence records |
| `all-evidence.json` | Complete evidence dataset |
| `access-denied.json` | Collectors blocked by insufficient permissions |
| `.checkpoint.json` | Collection checkpoint (auto-removed on success) |

---

## Troubleshooting

### Check Authentication

```bash
# Verify Azure CLI login
az account show --query '{tenant:tenantId, subscription:name}'

# List accessible subscriptions
az account list --query '[].{name:name, id:id, state:state}' -o table
```

### Assessment Runs Slow

Large tenants may take 10+ minutes. To speed up:

```json
{
  "collectors": {
    "userSampleLimit": 5000,
    "azureBatchSize": 6,
    "entraBatchSize": 4,
    "collectorTimeout": 120
  }
}
```

### Sign-In Logs Return 0 Records

Expected if the tenant lacks Entra ID P1/P2 license. The assessment continues with `missing_evidence` status for sign-in log controls.

### Collector Timeout

If collectors timeout on large subscriptions:

```json
{
  "collectors": { "collectorTimeout": 600 }
}
```

### Permission Errors

Assessment continues despite permission failures. Check `access-denied.json` in the output for details. The methodology report also lists permission gaps.

### Resume After Failure

With `checkpointEnabled: true` (default), the assessment saves progress to `.checkpoint.json`. Re-run the same command and it resumes from the last checkpoint. The checkpoint is auto-removed on success.

### Missing Evidence Types

If controls show `missing_evidence`, check:
1. **Permissions** — verify `access-denied.json` for 403 errors
2. **Collector toggles** — ensure `azureEnabled`/`entraEnabled` are true
3. **Resource existence** — some evidence requires specific Azure resources (e.g., Sentinel, Purview)

> **📖 Full guide:** For comprehensive error resolution including error codes, see [Troubleshooting Guide](troubleshooting.md).
