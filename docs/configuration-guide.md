# PostureIQ — Configuration Guide

**Author: Murali Chillakuru**

> **Executive Summary** — Complete configuration reference: authentication modes, collector tuning,
> 17 evaluation thresholds, SIEM integration (Sentinel/Splunk/webhook), data residency, continuous
> monitoring, remediation engine, and all environment variable overrides. This is the canonical
> source for all configuration settings.
>
> | | |
> |---|---|
> | **Audience** | Administrators, DevOps engineers, CI/CD integrators |
> | **Prerequisites** | [Architecture](architecture.md) for what the settings control |
> | **Companion docs** | [Evaluation Rules](evaluation-rules.md) for threshold meanings · [CI/CD Integration](ci-cd-integration.md) for pipeline setup · [Usage Guide](PROMPTS.md) for running assessments |

---

## Table of Contents

- [Configuration Loading](#configuration-loading)
- [Top-Level Settings](#top-level-settings)
- [Authentication (auth)](#authentication)
- [Collector Configuration (collectors)](#collector-configuration)
- [Evaluation Thresholds (thresholds)](#evaluation-thresholds)
- [Continuous Monitoring](#continuous-monitoring)
- [Remediation Engine](#remediation-engine)
- [SIEM Integration](#siem-integration)
- [Data Residency Validation](#data-residency-validation)
- [Data Security Relevance](#data-security-relevance)
- [Environment Variable Overrides](#environment-variable-overrides)
- [Config File Precedence](#config-file-precedence)
- [Available Frameworks (11)](#available-frameworks)
- [Running an Assessment](#running-an-assessment)
- [Authentication Deep Dive](#authentication-deep-dive)
- [Output Files](#output-files)
- [Running Tests](#running-tests)
- [Quick Reference: Extending the System](#quick-reference-extending-the-system)

---

## Configuration Loading

The main configuration file is `config/enterprisesecurityiq.config.json`.

```
                      ENTERPRISESECURITYIQ_CONFIG env var
                                  │
                    ┌─────────────▼──────────────┐
                    │   AssessmentConfig.from_file()   │
                    │   (app/config.py)                │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │   AssessmentConfig.from_env()    │
                    │   (env vars override file)       │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │   Final AssessmentConfig         │
                    │   (dataclass with defaults)      │
                    └─────────────────────────────┘
```

**Load order:**
1. `from_env()` checks if `ENTERPRISESECURITYIQ_CONFIG` is set → if so, calls `from_file()` first
2. `from_file()` reads JSON, maps camelCase keys to snake_case dataclass fields
3. Environment variables override file-loaded values
4. Any unset fields use Python dataclass defaults

Copy `examples/sample-config.json` as a starting point.

---

## Top-Level Settings

```json
{
  "name": "Q1 2026 FedRAMP High Assessment",
  "frameworks": ["FedRAMP", "NIST-800-53"],
  "logLevel": "INFO",
  "outputFormats": ["json", "html", "md"],
  "outputDir": "./output",
  "checkpointEnabled": true,
  "additionalTenants": []
}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | `string` | `"EnterpriseSecurityIQ Assessment"` | Human-readable assessment name |
| `frameworks` | `string[]` | `["FedRAMP"]` | **Required.** Compliance frameworks to evaluate (see [Available Frameworks](#available-frameworks)) |
| `logLevel` | `string` | `"INFO"` | Minimum log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `outputFormats` | `string[]` | `["json", "html"]` | Report formats: `json`, `html`, `md`, `oscal`. Config JSON ships with `["json", "html", "md"]` |
| `outputDir` | `string` | `"output"` | Base directory; each run creates a timestamped subfolder |
| `checkpointEnabled` | `bool` | `true` | Save collection progress to `.checkpoint.json` for resume |
| `additionalTenants` | `string[]` | `[]` | Extra tenant IDs for multi-tenant assessments |

---

## Authentication

```json
"auth": {
  "tenantId": "4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67",
  "authMode": "auto",
  "subscriptionFilter": []
}
```

| Field | Values | Default | Description |
|-------|--------|---------|-------------|
| `tenantId` | UUID string | `""` | Target Azure / Entra tenant ID |
| `authMode` | `auto`, `serviceprincipal`, `appregistration`, `azurecli` | `auto` | Authentication method (see [Authentication Deep Dive](#authentication-deep-dive)) |
| `subscriptionFilter` | `string[]` | `[]` | Limit Azure collection to these subscription IDs (empty = all accessible) |

### Auth Modes Summary

| Mode | Credential | When to Use |
|------|-----------|-------------|
| `auto` | `DefaultAzureCredential` | Local dev (`az login`), managed identity, or env vars — most flexible |
| `serviceprincipal` | `ClientSecretCredential` | CI/CD pipelines with `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` |
| `appregistration` | `ClientSecretCredential` | Dedicated app registration with `ENTERPRISESECURITYIQ_APP_CLIENT_ID` (falls back to `AZURE_CLIENT_ID`) |
| `azurecli` | `AzureCliCredential` | Force Azure CLI credential only |

> **📖 Canonical reference:** For complete auth mode details including preflight validation, required Graph permissions, and troubleshooting, see [Authentication Deep Dive](#authentication-deep-dive) below or [Troubleshooting](troubleshooting.md).

---

## Collector Configuration

```json
"collectors": {
  "azureEnabled": true,
  "entraEnabled": true,
  "subscriptionFilter": [],
  "azureBatchSize": 4,
  "entraBatchSize": 3,
  "collectorTimeout": 300,
  "userSampleLimit": 0
}
```

| Field | Type | Config Default | Code Default | Description |
|-------|------|-------|---------|-------------|
| `azureEnabled` | `bool` | `true` | `True` | Master toggle for all 49 Azure ARM/data-plane collectors |
| `entraEnabled` | `bool` | `true` | `True` | Master toggle for all 17 Entra / MS-Graph collectors |
| `subscriptionFilter` | `string[]` | `[]` | `[]` | Alternate location for subscription filter (merged with `auth.subscriptionFilter`) |
| `azureBatchSize` | `int` | **4** | **8** | Max concurrent Azure collector coroutines |
| `entraBatchSize` | `int` | **3** | **6** | Max concurrent Entra collector coroutines |
| `collectorTimeout` | `int` | **300** | **600** | Per-collector timeout in seconds (0 = no timeout) |
| `userSampleLimit` | `int` | `0` | `0` | Max users for detail collection (0 = all). Set for large tenants (50K+ users) |

> **Note:** The shipped config JSON uses conservative batch sizes (4/3) and shorter timeout (300s). The Python dataclass defaults are more aggressive (8/6, 600s). When running from a config file, file values take effect.

---

## Evaluation Thresholds

All 17 numeric thresholds are configurable via the `thresholds` section. The evaluation engine reads these at runtime to determine pass/fail boundaries.

```json
"thresholds": {
  "max_subscription_owners": 3,
  "max_privileged_percent": 0.20,
  "max_global_admins": 5,
  "max_subscription_contributors": 10,
  "max_entra_privileged_roles": 10,
  "min_mfa_percent": 90.0,
  "max_no_default_mfa_percent": 30.0,
  "max_stale_percent": 20.0,
  "max_stale_guests": 10,
  "max_high_priv_oauth": 5,
  "max_admin_grants": 20,
  "max_not_mfa_registered": 10,
  "diagnostic_coverage_target": 80.0,
  "diagnostic_coverage_minimum": 50.0,
  "min_policies_for_baseline": 5,
  "min_tagging_percent": 80.0,
  "policy_compliance_target": 80.0,
  "max_open_incidents": 50
}
```

### Thresholds by Domain

| Domain | Key | Default | Rule |
|--------|-----|---------|------|
| **Access** | `max_subscription_owners` | 3 | Non-compliant if > N Owner assignments per subscription |
| | `max_privileged_percent` | 0.20 | Non-compliant if privileged ratio exceeds 20% |
| | `max_global_admins` | 5 | Non-compliant if > N Global Admin members |
| | `max_subscription_contributors` | 10 | Non-compliant if > N Contributor assignments |
| | `max_entra_privileged_roles` | 10 | Non-compliant if > N privileged Entra role assignments |
| **Identity** | `min_mfa_percent` | 90.0 | Non-compliant if MFA-registered < N% |
| | `max_no_default_mfa_percent` | 30.0 | Non-compliant if > N% without default MFA |
| | `max_stale_percent` | 20.0 | Non-compliant if stale accounts > N% |
| | `max_stale_guests` | 10 | Non-compliant if > N stale guest accounts |
| | `max_high_priv_oauth` | 5 | Non-compliant if > N high-privilege OAuth apps |
| | `max_admin_grants` | 20 | Non-compliant if > N admin-consented grants |
| | `max_not_mfa_registered` | 10 | Non-compliant if > N users not MFA-registered |
| **Logging** | `diagnostic_coverage_target` | 80.0 | Compliant if ≥ N% resources have diagnostic settings |
| | `diagnostic_coverage_minimum` | 50.0 | Partial if ≥ N% but below target |
| **Governance** | `min_policies_for_baseline` | 5 | Non-compliant if < N policy assignments |
| | `min_tagging_percent` | 80.0 | Non-compliant if < N% of resources tagged |
| | `policy_compliance_target` | 80.0 | Non-compliant if policy compliance < N% |
| **Incident Response** | `max_open_incidents` | 50 | Alert fatigue flag if > N open Sentinel incidents |

See [Evaluation Rules](evaluation-rules.md) for how thresholds interact with domain evaluators.

---

## Continuous Monitoring

```json
"continuousMonitoring": {
  "enabled": false,
  "intervalMinutes": 1440,
  "collectors": [],
  "frameworks": [],
  "alertOnRegression": true,
  "minScoreThreshold": 0
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable continuous monitoring mode |
| `intervalMinutes` | `int` | `1440` | Re-assessment interval (minimum 5 minutes) |
| `collectors` | `string[]` | `[]` | Subset of collectors to run (empty = all) |
| `frameworks` | `string[]` | `[]` | Subset of frameworks (empty = all from top-level) |
| `alertOnRegression` | `bool` | `true` | Flag compliance score drops between runs |
| `minScoreThreshold` | `number` | `0` | Minimum score threshold (0–100); scores below trigger alerts |

Continuous monitoring stores historical scores to `.trends.json` for regression detection.

---

## Remediation Engine

```json
"remediation": {
  "enabled": false,
  "includeAzCli": true,
  "includePowerShell": false,
  "includeArmSnippets": false
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Generate remediation plans for non-compliant findings |
| `includeAzCli` | `bool` | `true` | Include Azure CLI remediation commands |
| `includePowerShell` | `bool` | `false` | Include PowerShell remediation commands |
| `includeArmSnippets` | `bool` | `false` | Include ARM template snippets |

---

## SIEM Integration

Export findings to external SIEM/SOAR platforms.

```json
"siemIntegration": {
  "sentinel": {
    "enabled": false,
    "endpointUrl": "https://<dce>.ingest.monitor.azure.com",
    "workspaceId": "<workspace-id>",
    "dcrImmutableId": "<dcr-immutable-id>",
    "dcrStreamName": "Custom-EnterpriseSecurityIQ_CL",
    "batchSize": 100
  },
  "splunk": {
    "enabled": false,
    "endpointUrl": "https://splunk-hec:8088/services/collector",
    "batchSize": 100
  },
  "generic": {
    "enabled": false,
    "endpointUrl": "https://your-siem/api/events",
    "batchSize": 100
  }
}
```

| Target | Protocol | Authentication | Fields |
|--------|----------|----------------|--------|
| **Sentinel** | Data Collection Rules (DCR) | `DefaultAzureCredential` | `enabled`, `endpointUrl`, `workspaceId`, `dcrImmutableId`, `dcrStreamName`, `batchSize` |
| **Splunk** | HTTP Event Collector (HEC) | `SPLUNK_HEC_TOKEN` env var | `enabled`, `endpointUrl`, `batchSize` |
| **Generic** | HTTPS POST webhook | `SIEM_WEBHOOK_TOKEN` env var | `enabled`, `endpointUrl`, `batchSize` |

---

## Data Residency Validation

Validate that Azure resources are deployed in approved geographic boundaries.

```json
"dataResidency": {
  "enabled": false,
  "allowedRegions": ["eastus", "westus2"],
  "allowedRegionGroups": ["US"]
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable data residency validation |
| `allowedRegions` | `string[]` | `[]` | Specific Azure regions: `eastus`, `westus2`, `westeurope`, etc. |
| `allowedRegionGroups` | `string[]` | `[]` | Region groups: US, Europe, AsiaPacific, Canada, UK, Australia, Brazil, India, Japan, Korea, SouthAfrica, UAE, Switzerland, Germany, France, Norway, Sweden |

The data residency engine (`data_residency_engine.py`) validates resource locations, storage replication targets, CosmosDB multi-region writes, backup vault locations, CDN origins, and Front Door backends against these boundaries.

---

## Data Security Relevance

The file `config/data-security-relevance.json` provides contextual explanations for 42 data security categories. The data security engine uses these to annotate findings with business context. Categories include:

`storage`, `database`, `cosmosdb`, `pgmysql`, `keyvault`, `encryption`, `data_access`, `private_endpoints`, `purview`, `file_sync`, `m365_dlp`, `data_classification`, `backup_dr`, `container_security`, `network_segmentation`, `data_residency`, `threat_detection`, `redis`, `messaging`, `ai_services`, `data_pipeline`, `identity`, `sharepoint_governance`, `data_lifecycle`, `dlp_alert`, `app_config`, `databricks`, `apim`, `frontdoor`, `secret_sprawl`, `firewall`, `bastion`, `policy_compliance`, `defender_score`, `stale_permissions`, `data_exfiltration`, `conditional_access`, `config_drift`, `supply_chain`

This file is not typically modified by end users. It can be customized to add new categories or adjust explanations for organizational context.

---

## Environment Variable Overrides

Environment variables take precedence over the config file. They are applied in `AssessmentConfig.from_env()`.

| Variable | Maps To | Format |
|----------|---------|--------|
| `ENTERPRISESECURITYIQ_CONFIG` | Config file path | File path; if set and exists, file is loaded first |
| `AZURE_TENANT_ID` | `auth.tenantId` | UUID string |
| `AZURE_CLIENT_ID` | Service principal app ID | UUID (required for `serviceprincipal` auth mode) |
| `AZURE_CLIENT_SECRET` | Service principal secret | String (required for `serviceprincipal` auth mode) |
| `ENTERPRISESECURITYIQ_APP_CLIENT_ID` | App registration ID | UUID (for `appregistration` mode; falls back to `AZURE_CLIENT_ID`) |
| `ENTERPRISESECURITYIQ_APP_CLIENT_SECRET` | App registration secret | String (for `appregistration` mode; falls back to `AZURE_CLIENT_SECRET`) |
| `ENTERPRISESECURITYIQ_AUTH_MODE` | `auth.authMode` | `auto`, `serviceprincipal`, `appregistration`, `azurecli` |
| `AZURE_SUBSCRIPTION_FILTER` | `collectors.subscriptionFilter` | Comma-separated subscription IDs |
| `ENTERPRISESECURITYIQ_FRAMEWORKS` | `frameworks` | Comma-separated framework names |
| `ENTERPRISESECURITYIQ_LOG_LEVEL` | `logLevel` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `SPLUNK_HEC_TOKEN` | Splunk HEC auth | Token string (used by SIEM integration) |
| `SIEM_WEBHOOK_TOKEN` | Generic webhook auth | Token string (used by SIEM integration) |

---

## Config File Precedence

```
Priority (highest → lowest):
┌───────────────────────────────────┐
│ 1. Environment Variables          │  ← Override everything
│ 2. Config JSON File               │  ← from_file() values
│ 3. Python Dataclass Defaults      │  ← Code-level defaults
└───────────────────────────────────┘
```

**Key differences between code defaults and shipped config JSON:**

| Setting | Code Default | Config JSON |
|---------|-------------|-------------|
| `azureBatchSize` | 8 | 4 |
| `entraBatchSize` | 6 | 3 |
| `collectorTimeout` | 600 | 300 |
| `outputFormats` | `["json", "html"]` | `["json", "html", "md"]` |

---

## Available Frameworks

11 compliance frameworks with 525 total controls:

| Framework | Controls | Description |
|-----------|----------|-------------|
| `MCSB` | 53 | Microsoft Cloud Security Benchmark |
| `NIST-800-53` | 83 | NIST SP 800-53 Rev 5 |
| `CIS` | 53 | CIS Microsoft Azure Foundations Benchmark |
| `ISO-27001` | 51 | ISO/IEC 27001:2022 |
| `PCI-DSS` | 51 | PCI DSS v4.0 |
| `FedRAMP` | 69 | FedRAMP High Baseline |
| `SOC2` | 47 | SOC 2 Type II |
| `HIPAA` | 43 | HIPAA Security Rule |
| `GDPR` | 22 | General Data Protection Regulation |
| `NIST-CSF` | 29 | NIST Cybersecurity Framework |
| `CSA-CCM` | 24 | Cloud Security Alliance CCM |

Framework mappings are JSON files in `AIAgent/app/frameworks/`. See [Extending Frameworks](extending-frameworks.md) for how to add custom frameworks.

> **PostureIQ Note:** PostureIQ uses its own independent framework mappings in `AIAgent/app/postureiq_frameworks/`.
> These are identical initially but can evolve separately. PostureIQ risk-weighted scoring thresholds
> (exploitability weights, blast radius weights, RiskTier boundaries) are defined in
> `postureiq_evaluators/engine.py` and are not user-configurable in the config JSON — they are tuned
> based on industry-standard risk assessment methodologies.

---

## Running an Assessment

### Prerequisites

1. **Python 3.10+** (3.12 recommended)
2. Install dependencies:
   ```bash
   cd AIAgent
   pip install -r requirements.txt
   ```
3. Authenticate via one of:
   - `az login` — Azure CLI (used by DefaultAzureCredential for both ARM and Graph)
   - Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`) for service principal
   - Managed Identity (automatic when running in Azure)

### Execution

Compliance assessments are now run via the agent chat interface (`run_postureiq_assessment` tool) or the `/assessments` API endpoint. Specialized CLI scripts are available for individual assessment domains:

```bash
cd AIAgent

# Data security assessment
python run_data_security.py --tenant "4a3eb5f4-..."

# Risk analysis
python run_risk_analysis.py --tenant "4a3eb5f4-..."

# Copilot readiness
python run_copilot_readiness.py --tenant "4a3eb5f4-..."

# Using a config file (env var applies to all CLI scripts)
ENTERPRISESECURITYIQ_CONFIG=../config/enterprisesecurityiq.config.json python run_data_security.py --tenant "..."
```

### Other CLI Scripts

| Script | Purpose |
|--------|----------|
| `run_rbac_report.py` | RBAC analysis report |
| `run_query.py` | Query engine for past assessment results |
| `run_risk_analysis.py` | Security risk analysis across 5 categories |
| `run_data_security.py` | Data security posture assessment |
| `run_copilot_readiness.py` | M365 Copilot readiness evaluation |
| `run_ai_agent_security.py` | AI agent security assessment |
| `run_cr_determinism_check.py` | Verify Copilot Readiness determinism |
| `run_rbac_determinism_check.py` | Verify RBAC report determinism |

---

## Authentication Deep Dive

The `ComplianceCredentials` class (`app/auth.py`) manages all authentication. It provides unified credential creation for both ARM (Azure Resource Manager) and MS Graph APIs.

### Auth Mode Details

| Mode | Credential Class | Required Configuration |
|------|-----------------|----------------------|
| `auto` | `DefaultAzureCredential` | None — chains: env vars → managed identity → Azure CLI → Visual Studio, etc. |
| `serviceprincipal` | `ClientSecretCredential` | `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` + `AZURE_TENANT_ID` |
| `appregistration` | `ClientSecretCredential` | `ENTERPRISESECURITYIQ_APP_CLIENT_ID` (fallback: `AZURE_CLIENT_ID`) + `ENTERPRISESECURITYIQ_APP_CLIENT_SECRET` (fallback: `AZURE_CLIENT_SECRET`) |
| `azurecli` | `AzureCliCredential` | Active `az login` session |

### Required Permissions

**Azure RBAC:** `Reader` role on target subscriptions (for ARM collectors).

**Entra ID / MS Graph:** The following application permissions (or equivalent directory roles):

| Permission | Used By |
|------------|---------|
| `User.Read.All` | User listing, MFA status, stale account detection |
| `Directory.Read.All` | Roles, groups, applications, service principals |
| `Policy.Read.All` | Conditional Access, authentication methods, security policies |
| `RoleManagement.Read.All` | Directory role assignments, PIM eligibility |
| `AuditLog.Read.All` | Audit logs, sign-in logs |
| `SecurityEvents.Read.All` | Security alerts, risky users |
| `IdentityRiskyUser.Read.All` | Risky user details |
| `Application.Read.All` | App registrations, OAuth grants |

**Sufficient Entra Directory Roles:** `Global Administrator`, `Global Reader`, `Security Administrator`, `Security Reader`, `Compliance Administrator`

### Preflight Check

Before running collection, `ComplianceCredentials.preflight_check()` validates:
- ARM access (subscription listing)
- Graph access: `Users` (User.Read.All), `ConditionalAccess` (Policy.Read.All), `RoleManagement` (RoleManagement.Read.All)
- Returns: `ok`, `user`, `tenant`, `roles`, `arm_subs`, `graph_ok`, `warnings`, `errors`

Probes returning 403 are logged as **warnings** (collection continues with reduced scope). Probes returning 401 are logged as **blocking errors**.

### Graph API Clients

| Method | API Version | Purpose |
|--------|------------|---------|
| `get_graph_client()` | v1.0 | Standard queries: users, groups, apps, policies |
| `get_graph_beta_client()` | beta | PIM, risky service principals, advanced Entra features |

---

## Output Files

Each run creates a timestamped directory under `output/` (e.g., `output/20260327_151401/`).

```
output/20260327_151401/
├── FedRAMP/
│   ├── compliance-report.html
│   ├── compliance-report.md
│   ├── executive-summary.html
│   ├── executive-summary.md
│   ├── gaps-report.html
│   ├── gaps-report.md
│   ├── FedRAMP-report.xlsx
│   └── oscal-results.json        (if oscal format enabled)
├── NIST-800-53/
│   └── ... (same structure)
├── methodology-report.html        (root — explains how the assessment works)
├── findings.json / .csv
├── control-results.json / .csv
├── evidence.json
├── all-evidence.json
├── access-denied.json
└── .checkpoint.json               (removed on successful completion)
```

| File | Description |
|------|-------------|
| `compliance-report.html/md` | Full interactive compliance report with sidebar, search, filters |
| `executive-summary.html/md` | One-page executive summary with compliance ring, metrics, top risks |
| `gaps-report.html/md` | Non-compliant findings only, with remediation roadmap |
| `{framework}-report.xlsx` | Excel workbook: Compliance Report, Gap Analysis, Executive Summary sheets |
| `methodology-report.html` | Assessment methodology (for auditors) |
| `oscal-results.json` | NIST OSCAL assessment results format |
| `findings.json/csv` | All individual findings |
| `control-results.json/csv` | Per-control status summary |
| `evidence.json` | Normalized evidence records |
| `all-evidence.json` | Complete evidence dataset |
| `access-denied.json` | Collectors blocked by insufficient permissions |
| `.checkpoint.json` | Collection checkpoint (auto-removed on success) |

---

## Running Tests

```bash
cd AIAgent
python -m pytest tests/ -v
```

15 test suites with ~1,357 test functions across ~16,834 lines.

---

## Quick Reference: Extending the System

### Adding a New Framework

1. Create `AIAgent/app/frameworks/yourframework-mappings.json` following the existing structure
2. Add the framework name to your config's `frameworks` array
3. Map controls to existing `evaluation_logic` functions or create new ones

### Adding a New Evaluator Function

1. Add a function in the appropriate domain evaluator (e.g., `postureiq_evaluators/identity.py`)
2. Register it in `postureiq_evaluators/engine.py`'s `_CROSS_DOMAIN_MAP` or `EVALUATOR_DISPATCH`
3. Reference the function name in framework mapping's `evaluation_logic` field

### Adding a New Collector

1. Create `AIAgent/app/collectors/azure/your_source.py` or `collectors/entra/your_source.py`
2. Use the `@register_collector` decorator:
   ```python
   from app.collectors.registry import register_collector

   @register_collector(name="your_source", source="azure", priority=100)
   async def collect_azure_your_source(creds, subscriptions):
       ...
   ```
3. Auto-discovered at startup — no manual import needed

See [Extending Frameworks](extending-frameworks.md) for detailed guidance.

> **📖 Full guide:** For complete extension documentation including JSON schema, plugin system, and testing, see [Extending Frameworks](extending-frameworks.md).
