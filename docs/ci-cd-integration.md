# CI/CD Integration Guide

> **Author:** Murali Chillakuru
> All metrics verified against source code.

> **Executive Summary** — How to run PostureIQ in CI/CD pipelines: GitHub Actions
> (OIDC), Azure DevOps, compliance gates with `--fail-on-severity`, determinism verification,
> delta tracking, checkpoint/resume, and config tuning for automated runs.
>
> | | |
> |---|---|
> | **Audience** | DevOps engineers, CI/CD pipeline authors |
> | **Prerequisites** | [Configuration Guide](configuration-guide.md) for auth + settings · [Usage Guide](PROMPTS.md) for CLI reference |
> | **Companion docs** | [Suppressions Guide](suppressions-guide.md) for managing accepted risks in CI/CD · [Troubleshooting](troubleshooting.md) for pipeline failures |

## Overview

PostureIQ runs headlessly in CI/CD pipelines to enforce compliance gates, track compliance drift, and generate audit artifacts. The tool supports 8 CLI scripts, 4 authentication modes, and integrates with both GitHub Actions and Azure DevOps. Determinism checks ensure evaluation repeatability.

---

## Prerequisites

| Requirement | Details |
|------------|---------|
| **Service Principal** | Reader + Security Reader on target subscriptions; Global Reader on Entra ID |
| **Python** | 3.10+ (3.12 recommended) |
| **Dependencies** | `pip install -r AIAgent/requirements.txt` |
| **RBAC roles** (any one) | Global Administrator, Global Reader, Security Administrator, Security Reader, Compliance Administrator |

---

## Authentication Modes

The tool reads `ENTERPRISESECURITYIQ_AUTH_MODE` (or `auth_mode` in config) to select a credential strategy. All modes use the same `ComplianceCredentials` class in `app/auth.py`.

| Mode | Credential Class | Required Env Vars | Best For |
|------|-----------------|-------------------|----------|
| `auto` (default) | `DefaultAzureCredential` | None (uses az CLI, managed identity, OIDC, etc.) | GitHub Actions OIDC, Azure Managed Identity |
| `serviceprincipal` | `ClientSecretCredential` | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` | Traditional CI/CD |
| `appregistration` | `ClientSecretCredential` | `ENTERPRISESECURITYIQ_APP_CLIENT_ID` (fallback: `AZURE_CLIENT_ID`), `ENTERPRISESECURITYIQ_APP_CLIENT_SECRET` (fallback: `AZURE_CLIENT_SECRET`) | Dedicated app registration |
| `azurecli` | `AzureCliCredential` | None (uses `az login` session) | Local dev, manual pipelines |

> **📖 Canonical reference:** For full auth mode details, env var overrides, and Graph permission lists, see [Configuration Guide — Authentication](configuration-guide.md#authentication).

### Preflight Permission Check

Before any collection begins, `preflight_check()` probes 4 endpoints:

1. **ARM** — list subscriptions
2. **Graph** — `/me` + `/organization`
3. **Entra roles** — `/me/memberOf` filtering for `directoryRole`
4. **Graph data** — Users (top=1), Conditional Access policies, Directory Roles

A 403 produces a **warning** (pipeline continues with reduced evidence). A 401 is **blocking** (pipeline fails).

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AZURE_TENANT_ID` | Target tenant | (required) |
| `ENTERPRISESECURITYIQ_AUTH_MODE` | Auth strategy | `auto` |
| `AZURE_CLIENT_ID` | Service principal / app client ID | — |
| `AZURE_CLIENT_SECRET` | Service principal / app secret | — |
| `ENTERPRISESECURITYIQ_APP_CLIENT_ID` | Override for `appregistration` mode | Falls back to `AZURE_CLIENT_ID` |
| `ENTERPRISESECURITYIQ_APP_CLIENT_SECRET` | Override for `appregistration` mode | Falls back to `AZURE_CLIENT_SECRET` |
| `ENTERPRISESECURITYIQ_CONFIG` | Path to config JSON | `config/enterprisesecurityiq.config.json` |
| `ENTERPRISESECURITYIQ_FRAMEWORKS` | Comma-separated framework list | All 11 |
| `AZURE_SUBSCRIPTION_FILTER` | Comma-separated subscription IDs to limit scope | All subscriptions |
| `ENTERPRISESECURITYIQ_LOG_LEVEL` | Logging verbosity | `INFO` |
| `ENTERPRISESECURITYIQ_LOG_FORMAT` | Set to `json` for structured logging | text |

---

## CLI Scripts Reference

| Script | Key Args | CI/CD Gate Available |
|--------|----------|---------------------|
| `run_copilot_readiness.py` | `--tenant`, `--category`, `--evidence`, `--suppressions`, `--previous-run` | `--fail-on-severity` |
| `run_data_security.py` | `--tenant`, `--category`, `--evidence`, `--suppressions`, `--previous-run`, `--output-dir`, `--format`, `--quiet`, `--verbose`, `--list-categories` | `--fail-on-severity` |
| `run_ai_agent_security.py` | `--tenant`, `--category`, `--evidence`, `--suppressions`, `--previous-run` | `--fail-on-severity` |
| `run_risk_analysis.py` | `--tenant`, `--category`, `--evidence` | No |
| `run_rbac_report.py` | `--tenant`, `--output-dir`, `--subscriptions` | No |
| `run_query.py` | `--query`, `--arg-kql`, `--findings` | No |

> **📖 Full reference:** For complete CLI usage with examples, flags, and output descriptions, see [Usage Guide](PROMPTS.md).

---

## Output Directory Convention

Assessment output is written to timestamped folders using 12-hour format:

```
output/YYYYMMDD_HHMMSS_AM|PM/
├── <Framework-Name>/         # Per-framework subfolder
│   ├── compliance_html/
│   ├── excel/
│   └── oscal/
├── data_exports/             # JSON data exports
├── raw_evidence/             # Raw collector output
├── sarif/                    # Static analysis format
├── remediation/              # Playbooks
└── drift_html/               # Only when delta mode active
```

Example: `output/20260411_021534_PM/`

---

## GitHub Actions Example (OIDC)

```yaml
name: Compliance Assessment
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am UTC
  workflow_dispatch:

permissions:
  id-token: write    # For OIDC federated auth
  contents: read

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r AIAgent/requirements.txt

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Run Data Security Assessment
        working-directory: AIAgent
        run: python run_data_security.py --tenant ${{ secrets.AZURE_TENANT_ID }}
        env:
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          ENTERPRISESECURITYIQ_AUTH_MODE: auto

      - name: Compliance Gate
        run: |
          OUTDIR=$(ls -td AIAgent/output/*/ | head -1)
          SCORE=$(python -c "
          import json, pathlib, glob
          files = glob.glob(str(pathlib.Path('${OUTDIR}') / 'data_exports' / '*.json'))
          if files:
              r = json.load(open(files[0]))
              print(r.get('CompliancePercentage', 0))
          else:
              print(0)
          ")
          echo "Compliance Score: $SCORE%"
          if (( $(echo "$SCORE < 70" | bc -l) )); then
            echo "::error::Compliance score $SCORE% below 70% threshold"
            exit 1
          fi

      - uses: actions/upload-artifact@v4
        with:
          name: compliance-report-${{ github.run_number }}
          path: AIAgent/output/
          retention-days: 90
```

---

## GitHub Actions — Specialized Assessments with `--fail-on-severity`

```yaml
      - name: Data Security Assessment
        working-directory: AIAgent
        run: |
          python run_data_security.py \
            --tenant ${{ secrets.AZURE_TENANT_ID }} \
            --fail-on-severity critical \
            --quiet
        # Exit code 1 if any critical-severity finding exists
```

---

## Azure DevOps Pipeline Example

```yaml
trigger: none
schedules:
  - cron: '0 6 * * 1'
    displayName: Weekly Compliance Check
    branches:
      include: [main]

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: EnterpriseSecurityIQ-Secrets

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: pip install -r AIAgent/requirements.txt
    displayName: Install Dependencies

  - task: AzureCLI@2
    displayName: Run Assessment
    inputs:
      azureSubscription: 'EnterpriseSecurityIQ-SPN'
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: |
        cd AIAgent
        export ENTERPRISESECURITYIQ_AUTH_MODE=auto
        python run_data_security.py --tenant $(AZURE_TENANT_ID)

  - task: AzureCLI@2
    displayName: Run Copilot Readiness
    inputs:
      azureSubscription: 'EnterpriseSecurityIQ-SPN'
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: |
        cd AIAgent
        python run_copilot_readiness.py \
          --tenant $(AZURE_TENANT_ID) \
          --fail-on-severity high

  - publish: $(System.DefaultWorkingDirectory)/AIAgent/output
    artifact: compliance-report
    displayName: Publish Reports
```

---

## Compliance Gate Strategy

| Score Range | Pipeline Action | Severity |
|------------|----------------|----------|
| 90–100% | **Pass** — no action | Info |
| 70–89% | **Warn** — create tracking ticket | Warning |
| < 70% | **Fail** — block deployment | Error |

For specialized assessments (`run_data_security.py`, `run_copilot_readiness.py`, `run_ai_agent_security.py`), use `--fail-on-severity <level>` which exits with code `1` if any finding meets or exceeds the specified severity.

---

## Determinism Checks

Determinism checks verify that evaluation is reproducible given identical evidence. Run them in CI/CD to catch non-deterministic regressions.

### How They Work

All three scripts share a pattern: **collect once → evaluate N times → compare**.

| Script | Default Runs | Configurable | Extra Args |
|--------|-------------|-------------|------------|
| `run_cr_determinism_check.py` | 3 | No | `--tenant`, `--evidence` |
| `run_rbac_determinism_check.py` | 3 | No | `--tenant`, `--data` |

### Assessment Determinism — 5 Phases

1. **Phase A** — Collect evidence once
2. **Phase B** — N evaluations in identical control order
3. **Phase C** — N evaluations with shuffled control order (seed: `i * 42 + 7`)
4. **Phase D** — Compare via SHA-256 hashes of volatile-stripped JSON across `summary`, `control_results`, `findings`, `missing_evidence` + per-framework
5. **Phase E** — Report-layer determinism (generate reports twice, strip timestamps via regex)

**Volatile fields stripped** before comparison: `FindingId`, `EvaluatedAt`, `RecordId`, `RecordedAt`, `EvidenceId`, `CollectedAt`, `AssessmentId`, `StartedAt`, `CompletedAt`, `DurationSeconds`, `OutputDirectory`, `Timestamp`

**Exit codes:** `0` = PASS, `1` = FAIL.

### CI/CD Integration

```yaml
      - name: Determinism Gate
        working-directory: AIAgent
        run: |
          python run_cr_determinism_check.py \
            --tenant ${{ secrets.AZURE_TENANT_ID }}
          python run_rbac_determinism_check.py \
            --tenant ${{ secrets.AZURE_TENANT_ID }}
          echo "Determinism checks passed"
```

---

## Delta Tracking

When `.last_run.json` exists in the output directory (saved after every run), the next run's delta report shows:

- New findings since last run
- Resolved findings
- Score change (+/− percentage)

Store output directories as pipeline artifacts to maintain history across runs.

---

## Checkpoint / Resume

Collection uses `.checkpoint.json` for fault tolerance:

- Stores `{completed, failed, evidence}` during collector execution
- On resume, already-completed collectors are skipped
- Corrupt checkpoint file → fresh start
- Automatically deleted after successful collection

In CI/CD, this means a timed-out pipeline can resume where it left off if the workspace is cached.

---

## Config Tuning for CI/CD

Key settings in `config/enterprisesecurityiq.config.json` (env var: `ENTERPRISESECURITYIQ_CONFIG`):

| Setting | JSON Default | Code Default | CI/CD Recommendation |
|---------|-------------|-------------|---------------------|
| `azureBatchSize` | 4 | 8 | 4–8 depending on rate limits |
| `entraBatchSize` | 3 | 6 | 3–6 depending on tenant size |
| `collectorTimeout` | 300s | 600s | 600s for large tenants |
| `checkpointEnabled` | true | true | Keep enabled |
| `outputFormats` | `["json","html","md"]` | `["json","html"]` | `["json"]` for minimal CI/CD |

---

## Suppression Management in CI/CD

Commit `suppressions.json` to your repo alongside the config. Pass it to specialized assessments via `--suppressions suppressions.json`.

- Suppressed findings: excluded from compliance score, still logged for audit
- Subject to expiry dates (see [suppressions-guide.md](suppressions-guide.md))
- Rules expiring within 7 days trigger warnings in pipeline logs
