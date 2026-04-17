# PostureIQ — Troubleshooting Guide

**Author: Murali Chillakuru**

> **Executive Summary** — Diagnostic reference for all PostureIQ failure modes:
> authentication errors, collector failures, retry/rate-limiting, checkpoint recovery,
> evaluation issues, report generation, PDF export, SIEM export, and error codes.
> The canonical troubleshooting resource.
>
> | | |
> |---|---|
> | **Audience** | Operators, support engineers |
> | **Prerequisites** | [Configuration Guide](configuration-guide.md) for settings context |
> | **Companion docs** | [Usage Guide](PROMPTS.md) for correct invocation patterns · [CI/CD Integration](ci-cd-integration.md) for pipeline-specific issues |

---

## Table of Contents

- [Authentication Issues](#authentication-issues)
- [Preflight Check Failures](#preflight-check-failures)
- [Collector Failures](#collector-failures)
- [Retry Logic & Rate Limiting](#retry-logic--rate-limiting)
- [Checkpoint & Resume](#checkpoint--resume)
- [Evaluation Issues](#evaluation-issues)
- [Report Generation Issues](#report-generation-issues)
- [PDF Export (Playwright)](#pdf-export-playwright)
- [Logging & Diagnostics](#logging--diagnostics)
- [SIEM Export Issues](#siem-export-issues)
- [Data Residency Issues](#data-residency-issues)
- [Remediation Engine Issues](#remediation-engine-issues)
- [Continuous Monitoring Issues](#continuous-monitoring-issues)
- [Diagnostic Scripts](#diagnostic-scripts)
- [Error Code Reference](#error-code-reference)

---

## Authentication Issues

### "DefaultAzureCredential failed"

The engine uses `DefaultAzureCredential` which tries multiple credential sources in order:

1. **Environment variables** — `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`
2. **Managed Identity** — Azure-hosted environments (Container Apps, App Service, VM)
3. **Azure CLI** — `az login` session cache
4. **App Registration** — `ENTERPRISESECURITYIQ_APP_CLIENT_ID` + `_SECRET` with `AUTH_MODE=appregistration`

**Fix:** Run `az login --tenant <TENANT_ID>` before starting the assessment.

```bash
# Verify your session is active
az account show --query '{tenant:tenantId, subscription:name}'
```

### "Insufficient privileges to complete the operation"

Your account needs these minimum roles:

| Scope | Role | Purpose |
|-------|------|---------|
| Subscription | **Reader** | Azure resource collection |
| Subscription | **Security Reader** | Defender, security recommendations |
| Entra ID | **Global Reader** | Users, roles, CA policies, apps |
| Entra ID | **Security Reader** | Identity protection, sign-in logs |

**Sufficient Entra Roles (any one):** Global Administrator, Global Reader, Security Administrator, Security Reader, Compliance Administrator.

**Fix:** Ask your admin to assign these roles, or use a service principal with the required permissions.

### Graph API 403 Errors

Some Entra collectors require specific Graph API permissions. If you see `access_denied`
entries in the methodology report or `access-denied.json`:

| Collector | Required Permission |
|-----------|-------------------|
| `collect_entra_user_details` | `User.Read.All`, `AuditLog.Read.All` (for `signInActivity`) |
| `collect_entra_audit_logs` | `AuditLog.Read.All` |
| `collect_entra_identity_protection` | `IdentityRiskEvent.Read.All` |
| `collect_entra_governance` | `AccessReview.Read.All`, `EntitlementManagement.Read.All` |
| `collect_entra_workload_identity` | `Application.Read.All` |
| `collect_entra_risk_policies` | `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All` |
| `collect_entra_sensitivity_labels` | `InformationProtection.Read` |

**Risk Analysis Lightweight Collector** — when running `analyze_risk` standalone (without
a prior full assessment), the engine uses its own lightweight Graph collection. Each call
is isolated so a single 403 won't block other categories:

| Data Point | Required Permission |
|-----------|-------------------|
| User summary + dormant accounts | `User.Read.All`, `AuditLog.Read.All` |
| Directory role members | `RoleManagement.Read.Directory` or `Directory.Read.All` |
| Application credentials | `Application.Read.All` |
| MFA registration summary | `UserAuthenticationMethod.Read.All` |
| Risky users | `IdentityRiskyUser.Read.All` |

If a specific Graph call returns 403, that section is skipped and a warning is logged.
The `identity` category in the risk analysis output will be empty or partial.

The engine continues when collectors fail — affected controls show `missing_evidence` status.

### Sentinel & Defender Collector Permissions

The `sentinel` and `defender_advanced` collectors require:

- **Security Reader** role on the subscription containing the Sentinel workspace
- Reader access to `Microsoft.SecurityInsights` and `Microsoft.Security` resource providers

**Fix:** Assign Security Reader at the subscription level and ensure providers are registered:

```bash
az provider register --namespace Microsoft.SecurityInsights
az provider register --namespace Microsoft.Security
```

### Purview and Sensitivity Labels

The `purview_dlp` collector requires:

- **Reader** role on Purview accounts
- `InformationProtection.Read` Graph permission for sensitivity labels
- Purview must be provisioned and active in the tenant

### Arc Hybrid Collector Issues

The `arc_hybrid` collector queries Azure Arc connected machines:

- Machines must be registered in Azure Arc
- **Reader** role required on the subscription
- No on-premises agent connectivity required (reads ARM metadata only)

### Cost Management / Billing Collector

The `cost_billing` collector requires:

- **Reader** role (for budgets) or **Cost Management Reader** (for cost data)
- Budgets must exist at the subscription scope
- Advisor recommendations need **Advisor Reader** or equivalent

---

## Preflight Check Failures

Before collection starts, `ComplianceCredentials.preflight_check()` probes 3 Graph endpoints:

| Probe | Endpoint | Permission | On 403 | On 401 |
|-------|----------|-----------|--------|--------|
| Users | `/users?$top=1` | `User.Read.All` | Warning | Blocking |
| Conditional Access | `/identity/conditionalAccess/policies` | `Policy.Read.All` | Warning | Blocking |
| Role Management | `/roleManagement/directory/roleAssignments` | `RoleManagement.Read.All` | Warning | Blocking |

**403** = Assessment continues with reduced scope. Collectors requiring that permission will produce `access-denied` evidence markers.

**401** = Assessment stops with an actionable error. The credential is not valid for Graph access.

**Fix for 401:**

```bash
# Verify Graph access separately
az rest --method GET --url "https://graph.microsoft.com/v1.0/me" --headers "Content-Type=application/json"
```

If this fails, re-authenticate: `az login --tenant <TENANT_ID>`.

---

## Collector Failures

### How Collector Errors Are Handled

All 64 collectors inherit error handling from `app/collectors/base.py`. Three outcomes:

1. **Success** — Returns evidence records. Collector marked as completed.
2. **Access Denied (401/403)** — Creates an `access-denied` evidence marker with `Data.AccessDenied=True`, `Data.Api`, `Data.StatusCode`. Treated as `success=True` — the pipeline continues.
3. **Hard failure** (after 3 retries) — Returns `success=False` with error string. Collector marked as failed.

Access-denied markers are aggregated into `access-denied.json` in the output directory and listed in the methodology report.

### Timeout Errors

Collectors have a configurable timeout (code default: 600s, shipped config: 300s).

**Log pattern:** `WARNING: <collector> collector timed out after <N>s`

If a collector has a `_partial_evidence` attribute, partial results are preserved even after timeout.

**Fix:** Increase `collectorTimeout` in config:

```json
{
  "collectors": { "collectorTimeout": 900 }
}
```

### Module Import Failures

If a collector module fails to import during `discover_collectors()`, it logs a warning and continues — it does NOT crash the pipeline. Missing dependencies or syntax errors in individual collector files will reduce the collector count but won't block the assessment.

**Log pattern:** `WARNING: Failed to import collector module <module_name>`

### Large Tenants

For tenants with many subscriptions/resources:

- Use `subscriptionFilter` in config to target specific subscriptions
- Set `userSampleLimit` to cap user detail collection (e.g., 5000)
- Reduce batch sizes to decrease memory pressure
- Monitor memory — each evidence record adds ~1-2 KB

```json
{
  "collectors": {
    "subscriptionFilter": ["sub-id-1", "sub-id-2"],
    "userSampleLimit": 5000,
    "azureBatchSize": 4,
    "entraBatchSize": 3,
    "collectorTimeout": 600
  }
}
```

---

## Retry Logic & Rate Limiting

### Built-In Retry

`app/collectors/base.py` implements automatic retry with exponential backoff:

| Parameter | Value |
|-----------|-------|
| Max retries | 3 |
| Initial backoff | 2 seconds |
| Backoff multiplier | 2× (2s → 4s → 8s) |

On each retry, the collector re-attempts the full API call. After 3 failures, it records a hard failure.

### HTTP 429 — Rate Limiting

Azure and Graph APIs enforce rate limits. The collector base handles 429 responses specially:

- **Graph 429:** Reads the `Retry-After` header and waits the specified duration before retrying.
- **Log pattern:** `WARNING: Graph 429 throttled (attempt N/3), retrying in <N>s`

To reduce 429 frequency, lower the batch sizes:

```json
{
  "collectors": {
    "azureBatchSize": 2,
    "entraBatchSize": 2
  }
}
```

**Code default batch sizes:** `azureBatchSize=8`, `entraBatchSize=6`
**Shipped config batch sizes:** `azureBatchSize=4`, `entraBatchSize=3`

### Graph Pagination Errors

Graph API pagination failures are logged but don't crash the collector:

**Log pattern:** `WARNING: Graph pagination error: <detail>`

The collector returns whatever results were collected before the pagination failure.

---

## Checkpoint & Resume

### How Checkpoints Work

With `checkpointEnabled: true` (default), the orchestrator saves collection progress to `.checkpoint.json` in the output directory.

**Checkpoint contents:**
- `completed` — set of completed collector names
- `failed` — set of failed collector names
- `evidence` — all evidence records collected so far

### Resume After Failure

Re-run the same command. The orchestrator detects `.checkpoint.json`, loads completed evidence, and skips already-completed collectors:

```bash
# Original run (interrupted)
python run_assessment.py --tenant "..." --framework FedRAMP

# Resume — skips completed collectors
python run_assessment.py --tenant "..." --framework FedRAMP
```

### Corrupt Checkpoint

If `.checkpoint.json` is corrupt (malformed JSON, missing keys), the orchestrator logs a warning and starts a fresh run — it does NOT crash:

**Log pattern:** `WARNING: Checkpoint corrupt, starting fresh run`

### Checkpoint Cleanup

After successful collection, `.checkpoint.json` is automatically deleted. If you see it persisting in the output directory, the last run did not complete successfully.

### Delta / Incremental Mode

The orchestrator also supports delta mode via `.last_run.json`, which tracks resource IDs and timestamps for change detection between runs.

---

## Evaluation Issues

### All Controls Show "missing_evidence"

This means collectors didn't return the expected evidence types.

**Diagnostic steps:**

1. **Check permissions** — Look in `access-denied.json` for 403 errors
2. **Check collector toggles** — Ensure `azureEnabled`/`entraEnabled` are both true
3. **Check subscription filter** — An overly restrictive filter may exclude needed resources
4. **Check logs** — Search for `ERROR` entries indicating collector failures
5. **Check resource existence** — Some evidence requires specific Azure resources (e.g., Sentinel, Purview, Defender for Cloud)

### Unexpectedly Low Scores

Compliance scores use severity-weighted calculations: `critical=4, high=3, medium=2, low=1`.

Check evaluation thresholds in your config — the defaults may be stricter than expected:

| Domain | Threshold | Default | Impact |
|--------|-----------|---------|--------|
| Access | `max_subscription_owners` | 3 | More owners → non-compliant |
| Identity | `min_mfa_percent` | 90.0 | Below 90% → non-compliant |
| Identity | `max_stale_days` | 90 | Inactive > 90 days → flagged |
| Logging | `diagnostic_coverage_target` | 80.0 | Below 80% → partial |
| Governance | `policy_compliance_target` | 80.0 | Below 80% → non-compliant |
| Data Protection | `max_key_age_days` | 365 | Keys older → non-compliant |
| Network | `max_open_management_ports` | 0 | Any open → non-compliant |

**Fix:** Adjust thresholds to match your organizational policies:

```json
{
  "thresholds": {
    "max_subscription_owners": 5,
    "min_mfa_percent": 80.0,
    "diagnostic_coverage_target": 70.0
  }
}
```

### Cross-Domain Fallback

The evaluation engine has 28 cross-domain fallback routes. If a primary evaluator lacks evidence, the `_CROSS_DOMAIN_MAP` directs the evaluation to an alternative domain. This can cause unexpected status values if the fallback domain has different evidence quality.

**Diagnostic:** Enable `DEBUG` logging to see fallback paths:

```
DEBUG: Cross-domain fallback: governance → access (control AC-2)
```

### Suppressions Overriding Findings

If expected findings are missing, check for active suppressions. Suppression rules use control ID glob patterns and resource regex matching with optional expiry dates. See [Suppressions Guide](suppressions-guide.md) for details.

---

## Report Generation Issues

### Empty or Missing Reports

Report generation is wrapped in `_safe()` error handling — one failing report won't block others.

**Log pattern:** `ERROR: Report '<report_type>' failed for <framework>: <error>`

**Common causes:**
- Missing evidence data for the specific report type
- Framework mapping file not found
- Template rendering error

### Excel Report Errors

Ensure `openpyxl` is installed:

```bash
pip install openpyxl
```

### Multi-Tenant Report Failures

Multi-tenant assessments log per-tenant errors and continue to the next tenant:

**Log pattern:** `ERROR: Tenant <tenant_id> failed: <error>`

### SARIF Export Failures

SARIF export failures are non-blocking:

**Log pattern:** `ERROR: SARIF export failed: <error>`

---

## PDF Export (Playwright)

PDF generation uses **Playwright** with headless Chromium. It's always optional — failures are logged but never crash the assessment.

### Chromium Not Installed

**Log pattern:** `WARNING: [PDF] Chromium launch failed, falling back to per-file mode`

**Fix:**

```bash
pip install playwright
playwright install chromium
```

### Individual File Conversion Failure

**Log pattern:** `WARNING: [PDF] Failed to convert <file>: <error>`

The engine continues to convert remaining HTML files.

### HTML File Not Found

**Log pattern:** `WARNING: [PDF] HTML file not found: <file>`

This typically means the report generator failed silently for that specific report.

### Playwright Not Installed

If Playwright is not installed at all, the import fails, and PDF generation is skipped entirely. The assessment completes normally with HTML/MD/JSON outputs.

### PDF Batch Conversion

`convert_all_html_to_pdf()` reuses a single browser instance for efficiency. If the batch mode fails, it falls back to individual `html_to_pdf()` calls per file.

---

## Logging & Diagnostics

### Log Configuration

| Setting | Default | Options |
|---------|---------|---------|
| Logger name | `enterprisesecurityiq` | — |
| Default level | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| Output | `stdout` (StreamHandler) | No file logging by default |
| Format | Text mode | Set `ENTERPRISESECURITYIQ_LOG_FORMAT=json` for structured JSON |

### Enable Debug Logging

```json
{ "logLevel": "DEBUG" }
```

Or via environment variable:

```bash
export ENTERPRISESECURITYIQ_LOG_LEVEL=DEBUG
```

### Structured JSON Logging

Set `ENTERPRISESECURITYIQ_LOG_FORMAT=json` for machine-parseable log lines:

```json
{"timestamp": "2026-03-27T15:14:01Z", "level": "WARNING", "logger": "enterprisesecurityiq", "message": "Access Denied for 3 collectors: ..."}
```

Exception details are included in the `"exception"` field when present.

### What to Look For

| Log Level | Meaning |
|-----------|---------|
| `DEBUG` | Verbose trace — collector progress, evaluation dispatch, fallback paths |
| `INFO` | Normal operations — start/complete for each phase, summary counts |
| `WARNING` | Degraded — access denied, timeout with partial data, Graph 429 retries |
| `ERROR` | Failures — collector hard failure, report generation error, PDF error |
| `CRITICAL` | Fatal — preflight 401, invalid config, unrecoverable errors |

---

## SIEM Export Issues

### Sentinel Export Fails

| Check | Detail |
|-------|--------|
| Endpoint URL | Must be the **Data Collection Endpoint (DCE)**, not the workspace URL |
| DCR Immutable ID | Must match an existing Data Collection Rule |
| Stream Name | Must match the DCR stream (e.g., `Custom-EnterpriseSecurityIQ_CL`) |
| Identity Role | The credential needs **Monitoring Metrics Publisher** role on the DCR |

### Splunk HEC Errors

| Check | Detail |
|-------|--------|
| Token | Set `SPLUNK_HEC_TOKEN` environment variable |
| Endpoint | Verify the HEC endpoint URL is reachable from the agent's network |
| HEC Enabled | Ensure HEC is enabled in Splunk and the target index exists |

### Generic Webhook Errors

| Check | Detail |
|-------|--------|
| Token | Set `SIEM_WEBHOOK_TOKEN` environment variable |
| Endpoint | Verify the webhook URL is reachable |
| Response | Check for non-2xx response codes in the logs |

---

## Data Residency Issues

### All Resources Flagged as Non-Compliant

Check that `allowedRegions` uses **exact Azure region names** (lowercase, no spaces):

```
✅ eastus, westus2, northeurope
❌ East US, West US 2, North Europe
```

Alternatively use `allowedRegionGroups` for broader geographic matching.

### Region Groups Not Matching

Supported region groups (17):

US, Europe, AsiaPacific, Canada, UK, Australia, Brazil, India, Japan, Korea, SouthAfrica, UAE, Switzerland, Germany, France, Norway, Sweden.

### Cross-Region Data Flow Detection

The data residency engine checks: resource locations, storage replication targets, CosmosDB multi-region write regions, backup vault regions, CDN endpoint origins, and cross-region data flows. Findings indicate the specific data flow path.

---

## Remediation Engine Issues

### No Remediation Scripts Generated

Ensure `remediation.enabled` is `true`. Scripts are only generated for `non_compliant` findings — not `partial` or `missing_evidence`.

### Missing PowerShell or ARM Snippets

By default only Azure CLI commands are generated. Enable additional formats:

```json
{
  "remediation": {
    "enabled": true,
    "includeAzCli": true,
    "includePowerShell": true,
    "includeArmSnippets": true
  }
}
```

**Log pattern for remediation failures:** `ERROR: Remediation playbooks failed: <error>`

---

## Continuous Monitoring Issues

### Monitor Not Running

Ensure `continuousMonitoring.enabled` is `true` and `intervalMinutes` is ≥ 5.

### Regression Alerts Not Firing

Regression detection requires at least **two runs** to compare. The first run establishes the baseline. Scores are stored in `.trends.json`.

### Score Threshold Not Triggering

Set `minScoreThreshold` in the continuous monitoring config. Alerts fire when the score drops below this threshold.

---

## Diagnostic Scripts

### Azure-Only Assessment

`_run_azure_only.py` is a convenience script that runs Azure-only assessment (no Entra). Useful for isolating Azure-vs-Entra collection issues:

```bash
python _run_azure_only.py
```

It explicitly disables Entra, sets 600s timeout, and runs 5 frameworks (FedRAMP, PCI-DSS, NIST-800-53, MCSB, CIS). Includes a preflight check and prints user/tenant/subscription info before starting.

### Determinism Checks

Run determinism checks to verify assessment output is consistent:

```bash
python run_assessment_determinism_check.py --tenant "..."
python run_cr_determinism_check.py --tenant "..."
python run_rbac_determinism_check.py --tenant "..."
```

Each runs two back-to-back assessments and compares output. Non-deterministic artifacts (e.g., timestamps, UUIDs) are expected — the check verifies structural consistency.

---

## Error Code Reference

### Log Error Patterns

| Pattern | Source | Meaning |
|---------|--------|---------|
| `<collector> collector timed out after <N>s` | Orchestrator | Collector exceeded `collectorTimeout` |
| `<collector> collector error: <fn> — <msg>` | Orchestrator | Hard failure after 3 retries |
| `Access Denied for <N> collectors: [...]` | Orchestrator | Collectors returned 401/403 |
| `Report '<type>' failed for <framework>: <msg>` | Orchestrator | Report generator crashed |
| `PDF generation failed: <msg>` | Orchestrator | Playwright/Chromium error |
| `SARIF export failed: <msg>` | Orchestrator | SARIF format export error |
| `Remediation playbooks failed: <msg>` | Orchestrator | Remediation engine error |
| `Drift report HTML failed: <msg>` | Orchestrator | Drift comparison report error |
| `Tenant <id> failed: <msg>` | Orchestrator | Multi-tenant single-tenant failure |
| `Assessment failed: <msg>` | Agent | Top-level assessment error (returned to agent caller) |
| `Graph 429 throttled (attempt N/3), retrying in <N>s` | Base Collector | Graph API rate limit |
| `[<collector>] Access Denied (<code>): <api>` | Base Collector | Specific API permission failure |
| `[<collector>] Failed after <N> attempts: <msg>` | Base Collector | Final hard failure |
| `Graph pagination error: <msg>` | Base Collector | Pagination interrupted (partial data preserved) |
| `[PDF] Chromium launch failed` | PDF Export | Missing Chromium installation |
| `[PDF] Failed to convert <file>` | PDF Export | Single file conversion error |

### HTTP Status Codes

| Code | Meaning | Assessment Impact |
|------|---------|-------------------|
| 200 | OK | Normal operation |
| 401 | Unauthorized | Blocking — credential invalid |
| 403 | Forbidden | Non-blocking — `access-denied` marker created, pipeline continues |
| 404 | Not Found | Resource/API doesn't exist — skipped |
| 429 | Too Many Requests | Automatic retry with `Retry-After` backoff |
| 500+ | Server Error | Retry with exponential backoff (3 attempts) |
