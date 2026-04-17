# PostureIQ — Extending Frameworks

**Author: Murali Chillakuru**

> **Executive Summary** — Developer guide for extending PostureIQ: add custom compliance
> frameworks (JSON mappings), new collectors (`@register_collector`), evaluator functions (domain dispatch),
> and plugins. Includes the formal JSON schema, 218 evidence types inventory, cross-domain fallback map,
> and testing recipes. This is the canonical extension reference.
>
> | | |
> |---|---|
> | **Audience** | Developers extending the platform |
> | **Prerequisites** | [Architecture](architecture.md) for structural overview · [Evaluation Rules](evaluation-rules.md) for evaluation logic |
> | **Companion docs** | [FILE-REFERENCE](FILE-REFERENCE.md) for file inventory · [Configuration Guide](configuration-guide.md) for threshold configuration |

---

## Table of Contents

- [Extension Architecture](#extension-architecture)
- [Adding a New Framework](#adding-a-new-framework)
- [Framework JSON Reference](#framework-json-reference)
- [Evidence Types](#evidence-types)
- [Adding a New Collector](#adding-a-new-collector)
- [Adding a New Evaluator Function](#adding-a-new-evaluator-function)
- [Evaluation Dispatch & Fallback](#evaluation-dispatch--fallback)
- [Plugin System](#plugin-system)
- [Available Domains & Handlers](#available-domains--handlers)
- [The Formal JSON Schema](#the-formal-json-schema)
- [Testing](#testing)

---

## Extension Architecture

PostureIQ has four extension points, plus PostureIQ-specific extension points:

| Extension | Location | Registration |
|-----------|----------|-------------|
| **Framework mapping** | `AIAgent/app/frameworks/<name>-mappings.json` | Add to `AVAILABLE_FRAMEWORKS` in `engine.py` |
| **Collector** | `AIAgent/app/collectors/azure/` or `entra/` | `@register_collector` decorator (auto-discovered) |
| **Evaluator function** | `AIAgent/app/evaluators/<domain>.py` | Add to domain dispatch dict |
| **Plugin** | `plugins/<name>.py` | `load_plugins()` auto-discovers `.py` files |
| **PostureIQ framework** | `AIAgent/app/postureiq_frameworks/<name>-mappings.json` | Add to `AVAILABLE_FRAMEWORKS` in `postureiq_evaluators/engine.py` |
| **PostureIQ evaluator** | `AIAgent/app/postureiq_evaluators/<domain>.py` | Add to PostureIQ domain dispatch dict |
| **PostureIQ attack path rule** | `AIAgent/app/postureiq_evaluators/attack_paths.py` | Add detection function to `analyze_attack_paths()` |
| **PostureIQ priority mapping** | `AIAgent/app/postureiq_evaluators/priority_ranking.py` | Add effort estimate to `_EFFORT_HOURS` dict |

```
Extension Pipeline:

  Framework JSON ──→ Engine loads controls
                        ↓
  Collectors ────────→ Produce evidence records (keyed by EvidenceType)
                        ↓
  Evaluators ────────→ Match evidence_types → dispatch to handler functions
                        ↓
  Plugins ───────────→ Custom evaluators for controls with custom_evaluator field
```

---

## Adding a New Framework

### Step 1: Create the Mapping File

Create `AIAgent/app/frameworks/<name>-mappings.json`:

```json
{
  "framework": "MY-FRAMEWORK",
  "frameworkName": "My Custom Framework",
  "version": "1.0",
  "description": "Custom compliance framework for internal use",
  "controls": [
    {
      "control_id": "MF-1.1",
      "title": "Access Control Policy",
      "domain": "access",
      "severity": "high",
      "evidence_types": ["azure-role-assignment", "entra-directory-role"],
      "evaluation_logic": "check_privileged_access_separation",
      "rationale": "Organization shall establish access control policies",
      "recommendation": "Review and restrict privileged role assignments"
    },
    {
      "control_id": "MF-2.1",
      "title": "Encryption at Rest",
      "domain": "data_protection",
      "severity": "high",
      "evidence_types": ["azure-keyvault", "azure-storage-security"],
      "evaluation_logic": "check_encryption_at_rest",
      "compensating_evidence": ["azure-disk-encryption-set"]
    }
  ]
}
```

### Step 2: Register the Framework

Add the key → filename entry to `AVAILABLE_FRAMEWORKS` in `AIAgent/app/evaluators/engine.py`:

```python
AVAILABLE_FRAMEWORKS = {
    "FedRAMP":       "fedramp-mappings.json",
    "CIS":           "cis-mappings.json",
    # ... existing frameworks ...
    "MY-FRAMEWORK":  "my-framework-mappings.json",  # ← add here
}
```

### Step 3: Use It

```bash
python run_assessment.py --tenant "..." --framework MY-FRAMEWORK
```

Or in config:

```json
{ "frameworks": ["FedRAMP", "MY-FRAMEWORK"] }
```

---

## Framework JSON Reference

### Top-Level Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `framework` | Yes | string | Short identifier key (matches `AVAILABLE_FRAMEWORKS`) |
| `frameworkName` | Yes* | string | Human-readable name. Falls back to `framework` if missing |
| `version` | No | string | Semantic version |
| `description` | No | string | Framework description |
| `controls` | Yes | array | Array of control objects |

### Control Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `control_id` | Yes | string | Unique control identifier (e.g., `"MF-1.1"`) |
| `title` | Yes | string | Human-readable title |
| `domain` | Yes | string | Evaluator domain — one of the 10 supported domains |
| `severity` | Yes | string | `critical`, `high`, `medium`, `low`, `informational` |
| `evidence_types` | Yes | string[] | Evidence type keys required for evaluation |
| `evaluation_logic` | Yes | string | Handler function name in the domain evaluator's dispatch dict |
| `rationale` | No | string | Why this control matters |
| `recommendation` | No | string | Remediation guidance |
| `compensating_evidence` | No | string[] | Fallback evidence types when primary evidence is missing |
| `custom_evaluator` | No | string | Plugin name — if present, the plugin handles evaluation instead |

### Supported Domains (10)

| Domain | Evaluator File | Check Functions |
|--------|---------------|----------------|
| `access` | `evaluators/access.py` | 8 |
| `identity` | `evaluators/identity.py` | 22 |
| `data_protection` | `evaluators/data_protection.py` | 22 |
| `network` | `evaluators/network.py` | 16 |
| `logging` | `evaluators/logging_eval.py` | 13 |
| `governance` | `evaluators/governance.py` | 21 |
| `incident_response` | `evaluators/incident_response.py` | 6 |
| `change_management` | `evaluators/change_management.py` | 4 |
| `business_continuity` | `evaluators/business_continuity.py` | 4 |
| `asset_management` | `evaluators/asset_management.py` | 4 |

> **PostureIQ evaluators** mirror the same 10 domains in `postureiq_evaluators/` with additional capabilities (risk-weighted scoring, attack paths, priority ranking). New domain functions added to PostureIQ won't affect the traditional engine and vice versa.

### Severity Levels

| Severity | Weight | Score Impact |
|----------|--------|-------------|
| `critical` | 4 | Highest deduction |
| `high` | 3 | |
| `medium` | 2 | |
| `low` | 1 | |
| `informational` | 0 | No score impact |

---

## Evidence Types

The engine matches controls to evidence using an index built from collector output. Each evidence record has an `EvidenceType` field. The engine's `_index_evidence()` builds a `dict[str, list[dict]]` keyed by this field.

For each control:
1. Primary lookup: `evidence_types` keys are searched in the index
2. Fallback: if primary yields nothing, `compensating_evidence` keys are checked

### Evidence Type Inventory

**Azure (93 types):** `azure-acr-repository`, `azure-action-group`, `azure-activity-event`, `azure-activity-log`, `azure-ai-deployment`, `azure-ai-deployment-safety`, `azure-ai-governance`, `azure-aks-addon`, `azure-aks-cluster`, `azure-aks-cluster-config`, `azure-aks-node-pool`, `azure-alert-rule`, `azure-api-management`, `azure-apim-api`, `azure-apim-certificate`, `azure-apim-instance`, `azure-apim-named-value`, `azure-apim-service`, `azure-app-gateway`, `azure-app-service-network`, `azure-auto-provisioning`, `azure-cdn-endpoint`, `azure-cdn-profile`, `azure-cognitive-account`, `azure-container-app`, `azure-container-registry`, `azure-content-safety-blocklist`, `azure-cosmosdb-account`, `azure-cosmosdb-container`, `azure-cosmosdb-database`, `azure-cosmosdb-role-assignment`, `azure-data-factory`, `azure-database-config`, `azure-database-server`, `azure-databricks-workspace`, `azure-defender-pricing`, `azure-diagnostic-setting`, `azure-disk-encryption-set`, `azure-dns-zone`, `azure-eventhub-namespace`, `azure-firewall`, `azure-front-door`, `azure-function-app`, `azure-function-detail`, `azure-jit-policy`, `azure-keyvault`, `azure-log-analytics`, `azure-managed-identity`, `azure-ml-workspace`, `azure-nsg-flow-log`, `azure-nsg-rule`, `azure-policy-assignment`, `azure-policy-compliance`, `azure-policy-definition`, `azure-private-dns-zone`, `azure-private-endpoint`, `azure-purview-account`, `azure-recovery-vault`, `azure-redis-cache`, `azure-regulatory-compliance`, `azure-resource`, `azure-resource-group`, `azure-resource-lock`, `azure-role-assignment`, `azure-route-table`, `azure-secure-score`, `azure-security-alert`, `azure-security-assessment`, `azure-security-contact`, `azure-sentinel-automation`, `azure-sentinel-connector`, `azure-sentinel-incident`, `azure-sentinel-rule`, `azure-sentinel-workspace`, `azure-servicebus-namespace`, `azure-sql-advanced-threat`, `azure-sql-auditing`, `azure-sql-database`, `azure-sql-detailed`, `azure-sql-firewall`, `azure-sql-server`, `azure-sql-tde`, `azure-sql-vulnerability`, `azure-storage-account`, `azure-storage-container`, `azure-storage-queue`, `azure-storage-security`, `azure-synapse-workspace`, `azure-traffic-manager`, `azure-virtual-network`, `azure-vm-config`, `azure-waf-policy`, `azure-webapp-auth`, `azure-webapp-config`, `azure-webapp-detailed`, `azure-webapp-diagnostic`, `azure-webapp-tls`

**Entra (28 types):** `entra-access-review`, `entra-application`, `entra-auth-methods-policy`, `entra-auth-strength-policy`, `entra-conditional-access-policy`, `entra-cross-tenant-partner`, `entra-cross-tenant-policy`, `entra-directory-audit-summary`, `entra-federated-credential`, `entra-managed-identity-sp`, `entra-mfa-registration`, `entra-mfa-summary`, `entra-oauth2-grant`, `entra-pim-eligible-assignment`, `entra-pim-policy-rule`, `entra-risk-detection`, `entra-risk-summary`, `entra-risky-service-principal`, `entra-risky-user`, `entra-role-assignment`, `entra-security-defaults`, `entra-service-principal`, `entra-signin-summary`, `entra-tenant-info`, `entra-terms-of-use`, `entra-user-detail`, `entra-user-lifecycle-summary`, `entra-workload-credential-review`

---

## Adding a New Collector

### Step 1: Create the Collector File

Create `AIAgent/app/collectors/azure/my_source.py` or `collectors/entra/my_source.py`:

```python
from app.collectors.registry import register_collector

@register_collector(
    name="my_source",
    plane="control",      # "control" = ARM, "data" = data-plane
    source="azure",       # "azure" or "entra"
    priority=150          # lower = runs earlier
)
async def collect_azure_my_source(creds, subscriptions):
    """Collect evidence from my custom Azure source."""
    evidence = []
    for sub in subscriptions:
        # Your collection logic here
        evidence.append({
            "EvidenceType": "azure-my-source",
            "SubscriptionId": sub["subscriptionId"],
            "ResourceId": "/subscriptions/.../my-resource",
            "Data": {
                "propertyA": "value",
                "propertyB": True,
            }
        })
    return evidence
```

### Step 2: No Registration Needed

The `@register_collector` decorator registers the function in the global `_REGISTRY` dict. The orchestrator calls `discover_collectors()` at startup, which:

1. Uses `pkgutil.iter_modules()` to scan `app.collectors.azure/` and `app.collectors.entra/`
2. Imports each module — this triggers the decorators
3. All registered collectors are available for execution

**No manual import or list update required.** Just place the file in the right directory.

### Decorator Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `str` | (required) | Human-readable name for logging and checkpoints |
| `plane` | `"control"` or `"data"` | `"control"` | `control` = ARM management plane, `data` = per-resource data plane |
| `source` | `"azure"` or `"entra"` | `"azure"` | Evidence source system |
| `priority` | `int` | `100` | Execution order — lower runs first |

### Priority Ranges

| Range | Plane | Examples |
|-------|-------|---------|
| P10–P190 | Control (Azure) | rbac(10), networking(30), policy(50), storage(140) |
| P200–P240 | Data (Azure) | sql_detailed(200), webapp_detailed(220) |
| P10–P170 | Control (Entra) | users(10), mfa(20), applications(50) |

### Error Handling

Your collector doesn't need to handle errors — `base.py` wraps all collector calls with:
- 3 retries with exponential backoff
- Access-denied detection (401/403 → creates marker, pipeline continues)
- Timeout handling (respects `collectorTimeout` config)

---

## Adding a New Evaluator Function

### Step 1: Add the Handler

Add your function to the appropriate domain evaluator file (e.g., `evaluators/access.py`):

```python
def _check_my_custom_logic(control_id, control, evidence, evidence_index, thresholds):
    """Custom evaluation logic for my control."""
    findings = []
    relevant = evidence_index.get("azure-my-source", [])

    for record in relevant:
        data = record.get("Data", {})
        if data.get("propertyB") is not True:
            findings.append({
                "ControlId": control_id,
                "Status": "non_compliant",
                "Severity": control.get("severity", "medium"),
                "ResourceId": record.get("ResourceId", "N/A"),
                "Description": f"Property B is not enabled on {record.get('ResourceId')}",
                "Recommendation": control.get("recommendation", "Enable property B"),
            })

    if not relevant:
        findings.append({
            "ControlId": control_id,
            "Status": "missing_evidence",
            "Severity": control.get("severity", "medium"),
            "Description": "No azure-my-source evidence collected",
        })

    return findings
```

### Step 2: Register in the Dispatch Dict

Add the function to the dispatch dict in the domain's evaluate function:

```python
dispatch = {
    "check_privileged_access_separation": _check_privileged_access_separation,
    # ... existing handlers ...
    "check_my_custom_logic": _check_my_custom_logic,  # ← add here
}
```

### Step 3: Reference in Framework JSON

```json
{
  "control_id": "MF-3.1",
  "title": "My Custom Control",
  "domain": "access",
  "severity": "high",
  "evidence_types": ["azure-my-source"],
  "evaluation_logic": "check_my_custom_logic"
}
```

### Handler Signature

All handler functions must follow this signature:

```python
def _check_xxx(
    control_id: str,
    control: dict,
    evidence: list[dict],
    evidence_index: dict[str, list],
    thresholds: ThresholdConfig
) -> list[dict]:
```

Returns a list of finding dicts with `ControlId`, `Status`, `Severity`, `ResourceId`, `Description`, `Recommendation`.

---

## Evaluation Dispatch & Fallback

### Two-Stage Dispatch

1. **Primary dispatch** — The control's `domain` field selects the domain evaluator via `DOMAIN_EVALUATORS` dict in `engine.py`
2. **Cross-domain fallback** — If the primary evaluator returns `not_assessed` for all findings, `_CROSS_DOMAIN_MAP` (28 routes) redirects to an alternative domain

```
Control domain="governance", evaluation_logic="check_baseline_config"
    ↓
  Stage 1: governance.evaluate_governance(...)
    ↓ (if not_assessed)
  Stage 2: _CROSS_DOMAIN_MAP["check_baseline_config"] → "access"
    ↓
  access.evaluate_access(...) with same control
```

### Cross-Domain Fallback Map (28 Routes)

The `_CROSS_DOMAIN_MAP` in `engine.py` maps `evaluation_logic` strings to alternative domains. This ensures controls get evaluated even when the primary domain lacks the evidence.

---

## Plugin System

### Overview

Plugins provide a way to add evaluation logic without modifying evaluator source files. Plugins are discovered from a `plugins/` directory and matched to controls via the `custom_evaluator` field.

### Creating a Plugin

Create `plugins/my_custom_check.py`:

```python
def evaluate(control: dict, evidence_index: dict[str, list]) -> tuple[str, list[dict]]:
    """
    Custom evaluation plugin.

    Args:
        control: The control definition from the framework JSON
        evidence_index: Dict mapping EvidenceType → list of evidence records

    Returns:
        Tuple of (status_string, list_of_finding_dicts)
    """
    relevant = evidence_index.get("azure-my-source", [])

    if not relevant:
        return "missing_evidence", [{
            "ControlId": control["control_id"],
            "Status": "missing_evidence",
            "Description": "No evidence found",
        }]

    findings = []
    for record in relevant:
        # Your custom logic here
        findings.append({
            "ControlId": control["control_id"],
            "Status": "compliant",
            "ResourceId": record.get("ResourceId", "N/A"),
        })

    return "compliant", findings
```

### Referencing a Plugin

In your framework JSON control:

```json
{
  "control_id": "MF-4.1",
  "title": "Custom Plugin Control",
  "domain": "governance",
  "severity": "high",
  "evidence_types": ["azure-my-source"],
  "evaluation_logic": "check_fallback",
  "custom_evaluator": "my_custom_check"
}
```

### Plugin Loading

`load_plugins(plugin_dir="plugins")` scans for `.py` files (skips `_`-prefixed), imports them dynamically, and looks for a callable `evaluate` attribute. Returns `dict[str, PluginFn]` keyed by file stem.

`run_plugins(plugins, controls, evidence_index)` iterates controls, invoking the matching plugin for controls with `custom_evaluator` fields.

---

## Available Domains & Handlers

### access (evaluators/access.py) — 8 functions

| Handler | Description |
|---------|-------------|
| `check_privileged_access_separation` | RBAC role distribution |
| `check_least_privilege` | Owner/contributor counts |
| `check_access_enforcement` | Conditional access enforcement |
| `check_account_management` | Account lifecycle management |
| `check_custom_owner_roles` | Custom owner role definitions |
| `check_rbac_review` | RBAC assignment review |
| `check_service_account_access` | Service account access controls |
| `check_access_provisioning` | Access provisioning workflows |

### identity (evaluators/identity.py) — 22 functions

| Handler | Description |
|---------|-------------|
| `check_authenticator_management` | MFA enrollment/registration |
| `check_mfa_enforcement` | MFA percentage thresholds |
| `check_stale_accounts` | Stale/inactive user detection |
| `check_guest_access` | Guest user governance |
| `check_service_principal_hygiene` | OAuth grants, app credentials |
| `check_workload_identity_security` | Federated credentials, managed identity |
| `check_auth_methods_security` | Auth methods policy, strength policies |
| `check_managed_identity_hygiene` | Managed identity adoption/cleanup |

### data_protection (evaluators/data_protection.py) — 22 functions

| Handler | Description |
|---------|-------------|
| `check_encryption_at_rest` | Storage and disk encryption |
| `check_encryption_in_transit` | TLS enforcement |
| `check_key_management` | Key Vault usage and CMK |
| `check_storage_cmk` | Customer-managed key adoption |
| `check_function_app_security` | HTTPS, TLS, managed identity, CORS |
| `check_messaging_security` | Service Bus / Event Hubs |
| `check_redis_security` | SSL enforcement, TLS version |
| `check_cosmosdb_advanced_security` | Local auth, VNet, RBAC |
| `check_data_analytics_security` | Synapse / ADF / Databricks |
| `check_purview_classification` | Purview deployment, sensitivity labels |

### network (evaluators/network.py) — 16 functions

| Handler | Description |
|---------|-------------|
| `check_network_segmentation` | NSG rules, firewall presence |
| `check_boundary_protection` | Network boundary controls |
| `check_dns_security` | Private DNS, DNSSEC, zone transfers |
| `check_aks_advanced_security` | Network policy, private cluster, authorized IPs |
| `check_apim_advanced_security` | VNet, client certs, Key Vault named values |
| `check_frontdoor_cdn_security` | WAF prevention, managed rules, HTTPS |

### logging (evaluators/logging_eval.py) — 13 functions

| Handler | Description |
|---------|-------------|
| `check_diagnostic_settings` | Diagnostic coverage percentage |
| `check_retention` | Log retention policies |

### governance (evaluators/governance.py) — 21 functions

| Handler | Description |
|---------|-------------|
| `check_baseline_config` | Policy assignment count |
| `check_continuous_monitoring` | Tagging, compliance percentage |
| `check_flaw_remediation` | Vulnerability management |
| `check_defender_posture_advanced` | Secure score, assessments, JIT |
| `check_ai_content_safety` | Content filters per AI deployment |
| `check_regulatory_compliance` | Regulatory standard pass rates |

### incident_response — 6, change_management — 4, business_continuity — 4, asset_management — 4

Sentinel monitoring, alert response, incident investigation, backup coverage, disaster recovery, and asset inventory checks.

---

## The Formal JSON Schema

The schema is defined in `schemas/compliance-control.schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "EnterpriseSecurityIQ Compliance Control Mapping",
  "type": "object",
  "required": ["framework", "frameworkName", "controls"],
  "properties": {
    "framework":    { "type": "string" },
    "frameworkName": { "type": "string" },
    "version":      { "type": "string" },
    "description":  { "type": "string" },
    "controls": {
      "type": "array",
      "items": {
        "required": ["control_id", "title", "domain", "severity",
                     "evidence_types", "evaluation_logic"],
        "properties": {
          "control_id":       { "type": "string" },
          "title":            { "type": "string" },
          "domain":           { "type": "string" },
          "severity":         { "type": "string",
                                "enum": ["critical","high","medium","low","informational"] },
          "evidence_types":   { "type": "array", "items": { "type": "string" } },
          "evaluation_logic": { "type": "string" },
          "rationale":        { "type": "string" },
          "recommendation":   { "type": "string" }
        }
      }
    }
  }
}
```

**Schema vs. practice:** The schema's `domain` enum lists only 6 values. The engine supports all 10 domains. The schema also omits `compensating_evidence` and `custom_evaluator`. Use the documented control fields table above as the authoritative reference.

---

## Testing

### Validate Your Framework Mapping

```bash
cd AIAgent
python -m pytest tests/ -x -q
```

### Quick Spot Check

```python
import json
from pathlib import Path

mapping = json.loads(Path("app/frameworks/my-framework-mappings.json").read_text())
print(f"Framework: {mapping['framework']}")
print(f"Controls: {len(mapping['controls'])}")

domains = set(c["domain"] for c in mapping["controls"])
print(f"Domains used: {sorted(domains)}")

logics = set(c["evaluation_logic"] for c in mapping["controls"])
print(f"Unique handlers: {len(logics)}")
```

### Determinism Check

Run the assessment twice and compare output to verify your new framework produces deterministic results:

```bash
python run_assessment_determinism_check.py --tenant "..." --framework MY-FRAMEWORK
```
