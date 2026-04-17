# PostureIQ — Evaluation Rules Reference

**Author: Murali Chillakuru**

> **Executive Summary** — Complete reference for the evaluation engine: 10 domain evaluators
> with 113 check functions, severity-weighted scoring, cross-domain fallback dispatch (28 routes),
> suppressions, plugins, and 17 configurable thresholds. The authoritative source for all
> evaluation logic — no other document covers rules at this depth.
>
> | | |
> |---|---|
> | **Audience** | Security engineers, compliance analysts, evaluator developers |
> | **Prerequisites** | [Architecture](architecture.md) for pipeline overview |
> | **Companion docs** | [Extending Frameworks](extending-frameworks.md) for adding rules · [Configuration Guide](configuration-guide.md) for threshold tuning · [Suppressions Guide](suppressions-guide.md) for muting findings |

---

## Table of Contents

- [Evaluation Overview](#evaluation-overview)
- [Compliance Statuses](#compliance-statuses)
- [Scoring Algorithm](#scoring-algorithm)
- [Configurable Thresholds (17)](#configurable-thresholds)
- [Domain: Access (8 functions)](#domain-access)
- [Domain: Identity (22 functions)](#domain-identity)
- [Domain: Data Protection (22 functions)](#domain-data-protection)
- [Domain: Network (16 functions)](#domain-network)
- [Domain: Logging (13 functions)](#domain-logging)
- [Domain: Governance (21 functions)](#domain-governance)
- [Domain: Incident Response (6 functions)](#domain-incident-response)
- [Domain: Change Management (4 functions)](#domain-change-management)
- [Domain: Business Continuity (4 functions)](#domain-business-continuity)
- [Domain: Asset Management (4 functions)](#domain-asset-management)
- [Cross-Domain Fallback Dispatch](#cross-domain-fallback-dispatch)
- [Suppression Rules](#suppression-rules)
- [Plugin System](#plugin-system)
- [Standalone Analysis Engines](#standalone-analysis-engines)
- [Evidence Types](#evidence-types)
- [Severity Levels](#severity-levels)

---

## Evaluation Overview

The evaluation engine maps collected evidence to compliance framework controls and applies domain-specific rules to determine compliance status. For each of the 525 controls across 11 frameworks, the engine:

1. Reads the `evaluation_logic` field from the framework mapping JSON
2. Routes to the appropriate domain evaluator (10 domains)
3. Falls back to cross-domain dispatch if the primary domain doesn't handle it
4. Applies suppression rules to skip or downgrade findings
5. Runs any registered plugins for custom evaluation
6. Calculates a severity-weighted compliance score

```
Framework Control → evaluation_logic → Domain Evaluator → Finding  
                                          ↓ (fallback)               
                                    Cross-Domain Map (28 routes)     
                                          ↓                          
                                    Suppressions → Plugin Hooks      
                                          ↓                          
                                    Weighted Score Aggregation        
```

---

## Compliance Statuses

| Status | Meaning |
|--------|---------|
| `compliant` | Evidence meets all requirements |
| `non_compliant` | Evidence shows a clear violation |
| `partial` | Some requirements met, others not |
| `missing_evidence` | Required evidence types not collected (e.g., 403 permission denied) |
| `not_assessed` | Control not evaluated (no handler or no applicable resources) |

---

## Scoring Algorithm

The evaluation engine uses a **severity-weighted scoring** system:

| Severity | Weight |
|----------|--------|
| critical | 4 |
| high | 3 |
| medium | 2 |
| low | 1 |

**Compliance percentage** is calculated per domain and overall:

```
weighted_pass = SUM(weight[severity] for each compliant control)
weighted_total = SUM(weight[severity] for each assessed control)
compliance_pct = (weighted_pass / weighted_total) × 100
```

Controls with `missing_evidence` or `not_assessed` status are **excluded** from the denominator — they don't penalize the score but are reported separately. `partial` status contributes half the severity weight.

**Domain scores** are aggregated independently, then the overall score is a weighted average across all domains based on control count.

---

## Configurable Thresholds

All numeric thresholds are configurable via the `thresholds` section of `config/enterprisesecurityiq.config.json`. Defaults shown below.

```json
{
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
}
```

---

## Domain: Access

**Evaluator:** `evaluators/access.py` — 8 check functions

| Rule | Threshold | Logic |
|------|-----------|-------|
| Subscription owners | `max_subscription_owners` (3) | Non-compliant if > 3 Owner role assignments per subscription |
| Privileged ratio | `max_privileged_percent` (20%) | Non-compliant if privileged assignments exceed 20% of total |
| Global Admins | `max_global_admins` (5) | Non-compliant if > 5 Global Administrator role members |
| Contributors | `max_subscription_contributors` (10) | Non-compliant if > 10 Contributor assignments per subscription |
| Entra privileged roles | `max_entra_privileged_roles` (10) | Non-compliant if > 10 privileged Entra role assignments |
| Custom owner roles | N/A | Non-compliant if custom roles with Owner-equivalent permissions exist |
| Access enforcement | N/A | Evaluates Conditional Access policy presence and enforcement |
| JIT / PIM access | N/A | Checks for JIT access configuration and PIM eligibility |

---

## Domain: Identity

**Evaluator:** `evaluators/identity.py` — 22 check functions

| Rule | Threshold | Logic |
|------|-----------|-------|
| MFA enrollment | `min_mfa_percent` (90%) | Non-compliant if MFA-registered users < 90% |
| MFA not registered | `max_not_mfa_registered` (10) | Non-compliant if > 10 users not registered for MFA |
| No default MFA | `max_no_default_mfa_percent` (30%) | Non-compliant if > 30% of auth methods have no default MFA |
| Stale accounts | `max_stale_percent` (20%) | Non-compliant if stale/inactive accounts exceed 20% |
| Guest users | `max_stale_guests` (10) | Non-compliant if > 10 stale guest accounts |
| High-privilege OAuth | `max_high_priv_oauth` (5) | Non-compliant if > 5 OAuth apps with high-privilege grants |
| Admin consent grants | `max_admin_grants` (20) | Non-compliant if > 20 admin-consented OAuth grants |
| Centralized identity | N/A | Checks CA policies exist AND enforce MFA |
| Workload identity security | N/A | Evaluates federated credentials, managed identity usage, password-based vs. federation |
| Auth methods security | N/A | Checks authentication methods policy, strength policies, insecure methods disabled |
| Managed identity hygiene | N/A | Evaluates managed identity adoption rate and unused identity cleanup |
| Credential lifecycle | N/A | Checks app registration credential expiry, rotation policies |
| Service principal hygiene | N/A | Evaluates SP ownership, credential types, unused SPs |
| User lifecycle management | N/A | Checks user provisioning, deprovisioning, access reviews |
| Password policy | N/A | Evaluates password ban lists, complexity requirements, self-service reset |
| Risk-based access | N/A | Checks CA policies with risk conditions (sign-in risk, user risk) |
| Session management | N/A | Evaluates CA session controls (sign-in frequency, persistent browser) |
| B2B collaboration | N/A | Checks cross-tenant access settings, external collaboration policies |
| Emergency access | N/A | Verifies break-glass account configuration |
| Named locations | N/A | Evaluates location-based CA policies |
| Auth strength | N/A | Checks for phishing-resistant auth strength policies |
| Token protection | N/A | Evaluates token lifetime policies and token protection settings |

---

## Domain: Data Protection

**Evaluator:** `evaluators/data_protection.py` — 22 check functions

| Rule | Evidence | Logic |
|------|----------|-------|
| Encryption at rest | `azure-compute-disk`, `azure-keyvault` | Checks disk encryption and Key Vault presence |
| Encryption in transit | `azure-storage-security` | Verifies HTTPS-only and minimum TLS 1.2 |
| Key management (CMK) | `azure-keyvault`, `azure-storage-security` | Checks `EncryptionKeySource` for customer-managed keys |
| Data classification | `azure-resource` | Evaluates tagging and classification policies |
| Function app security | `azure-function-app` | HTTPS enforcement, TLS version, managed identity, CORS |
| Messaging security | `azure-servicebus-namespace`, `azure-eventhub-namespace` | TLS version, local auth disabled, public access |
| Redis security | `azure-redis-cache` | SSL enforcement, TLS version, public network access |
| CosmosDB advanced | `azure-cosmosdb-account` | Local auth, public network, VNet filtering, RBAC mode |
| Data analytics security | `azure-synapse-workspace`, `azure-data-factory`, `azure-databricks-workspace` | Managed VNet, CMK, public access |
| Purview classification | `azure-purview-account`, `m365-sensitivity-label` | Purview deployment, sensitivity label coverage |
| SQL detailed security | `azure-sql-detailed` | Per-database auditing, TDE, ATP, vulnerability assessment |
| Storage advanced | `azure-storage-account`, `azure-storage-container` | Soft delete, immutability, lifecycle policies, versioning |
| Key Vault security | `azure-keyvault` | Soft delete, purge protection, RBAC model, network ACLs, private endpoints |
| Web app advanced | `azure-webapp-detailed` | Auth settings, IP restrictions, CORS, diagnostic logging |
| Container security | `azure-container-registry`, `azure-container-app` | Image scanning, admin access, network isolation |
| AKS data protection | `azure-aks-cluster-config` | Secrets encryption, disk encryption, Azure Key Vault integration |
| RDBMS security | `azure-rdbms-detailed` | SSL enforcement, parameter configuration, firewall |
| ACR data protection | `azure-acr-repository` | Tag mutability, content trust, quarantine |
| APIM data protection | `azure-apim-service` | Backend certificates, named value encryption, subscription keys |
| Disk encryption sets | `azure-disk-encryption-set` | CMK rotation, platform vs. customer encryption |
| Backup encryption | `azure-backup-item` | Backup vault encryption, immutability |
| Storage data plane | `azure-storage-data-plane` | Per-container public access, immutability policies |

---

## Domain: Network

**Evaluator:** `evaluators/network.py` — 16 check functions

| Rule | Evidence | Logic |
|------|----------|-------|
| Network segmentation | `azure-nsg-rule`, `azure-virtual-network` | NSG presence, rule quality (detects allow-all-inbound) |
| Boundary protection | `azure-nsg-rule`, `azure-virtual-network` | Perimeter controls evaluation |
| TLS enforcement | `azure-storage-security` | Minimum TLS version checks |
| DNS security | `azure-dns-zone`, `azure-private-dns-zone` | Private DNS usage, DNSSEC, zone transfer restrictions |
| AKS network security | `azure-aks-cluster-config`, `azure-aks-node-pool` | Network policy, private cluster, authorized IPs, Defender for Containers |
| APIM network security | `azure-apim-service` | VNet integration, client certificates, Key Vault named values |
| Front Door / CDN security | `azure-front-door`, `azure-waf-policy`, `azure-cdn-profile` | WAF in Prevention mode, managed rule sets, HTTPS enforcement |
| App Gateway / WAF | `azure-application-gateway`, `azure-waf-policy` | WAF enabled and enforcing, backend health, HTTPS listeners |
| Private endpoint coverage | `azure-private-endpoint` | Private endpoint adoption for storage, SQL, Key Vault, Cosmos DB |
| Public IP exposure | `azure-public-ip` | Unused public IPs, public IPs without DDoS protection |
| NSG risky ports | `azure-nsg-rule` | Flags inbound allow rules for ports 22, 3389, 3306, 1433, 5432 |
| VNet peering | `azure-vnet-peering` | Peering topology, transit routing, cross-subscription peering |
| Network Watcher | `azure-network-watcher` | Network Watcher enabled per region, flow logs |
| DDoS protection | `azure-ddos-protection-plan` | DDoS Standard plan coverage for VNets |
| SSL/TLS posture | `azure-sql-server`, `azure-webapp-config` | TLS 1.2+ enforcement across services |
| Firewall rules | `azure-sql-firewall-rule`, `azure-rdbms-firewall-rule` | Overly permissive rules (0.0.0.0/0), allow Azure services |

**NSG Rule Quality:** The evaluator flags NSG rules with `Source: *`, `Destination: *`, `DestinationPort: *`, `Access: Allow` as weak rules that undermine segmentation.

---

## Domain: Logging

**Evaluator:** `evaluators/logging_eval.py` — 13 check functions

| Rule | Threshold | Logic |
|------|-----------|-------|
| Diagnostic coverage | `diagnostic_coverage_target` (80%) | Compliant if ≥ 80% of resources have diagnostic settings |
| Diagnostic minimum | `diagnostic_coverage_minimum` (50%) | Partial if ≥ 50% but < 80% |
| Log retention | N/A | Checks workspace retention policies |
| Activity logs | N/A | Verifies activity log collection and routing |
| Sign-in log monitoring | N/A | Checks Entra sign-in logs are collected and reviewed |
| Directory audit logs | N/A | Verifies Entra directory audit log collection |
| Log Analytics workspace | N/A | Workspace presence, retention configuration, data caps |
| Resource-specific logging | N/A | Checks per-service diagnostic categories (Storage, SQL, Key Vault) |
| Flow logs | N/A | NSG flow log enablement and storage configuration |
| Alert rule coverage | N/A | Evaluates alert rules for critical operations |
| Log export | N/A | Checks logs exported to external SIEM/storage |
| Sentinel integration | N/A | Sentinel data connector status for log ingestion |
| Audit log completeness | N/A | Cross-references collected log types against expected categories |

---

## Domain: Governance

**Evaluator:** `evaluators/governance.py` — 21 check functions

| Rule | Threshold | Logic |
|------|-----------|-------|
| Baseline policy count | `min_policies_for_baseline` (5) | Non-compliant if < 5 policy assignments |
| Tagging compliance | `min_tagging_percent` (80%) | Non-compliant if < 80% of resources are tagged |
| Policy compliance | `policy_compliance_target` (80%) | Non-compliant if overall policy compliance < 80% |
| Continuous monitoring | N/A | Evaluates monitoring and alerting configuration |
| Defender posture | `azure-secure-score`, `azure-security-assessment` | Secure score, unhealthy assessments, JIT access |
| AI content safety | `azure-ai-deployment-safety`, `azure-ai-governance` | Content filters per deployment, public access, local auth |
| Regulatory compliance | `azure-regulatory-compliance` | Regulatory standard pass rates, failed controls |
| Resource lock governance | N/A | Critical resource lock coverage |
| Budget management | N/A | Checks budget alerts and cost threshold configuration |
| Naming conventions | N/A | Evaluates resource naming compliance patterns |
| Lifecycle management | N/A | Checks resource lifecycle policies and automation |
| Configuration management | N/A | Azure Policy assignment enforcement modes |
| Risk assessment | N/A | Overall security posture evaluation |
| Access governance | N/A | Access review configuration and completion rates |
| Defender for Cloud plans | N/A | Defender plan enablement across resource types |
| Security recommendations | N/A | Outstanding security recommendations and remediation status |
| Compliance reporting | N/A | Automated compliance evidence generation |
| Architecture governance | N/A | Well-Architected Framework alignment checks |
| Cost governance | N/A | Cost optimization recommendations from Advisor |
| Operational excellence | N/A | Health probe, diagnostics, and operational readiness |
| Security awareness | N/A | Security training and awareness program indicators |

---

## Domain: Incident Response

**Evaluator:** `evaluators/incident_response.py` — 6 check functions

| Rule | Evidence | Logic |
|------|----------|-------|
| Security contact config | `azure-security-contact` | Security contacts have email and alert notifications enabled |
| Incident detection | `azure-defender-pricing`, `azure-alert-rule`, `entra-risk-summary` | Defender plans enabled for critical services (VMs, SQL, App Services, Storage, Key Vaults, ARM, Containers); identity risk signals monitored |
| Incident alerting | `azure-action-group`, `azure-alert-rule`, `azure-security-contact` | Action groups have receivers, alert rules linked |
| Investigation readiness | `azure-diagnostic-setting`, `azure-log-analytics`, `azure-activity-log` | Log Analytics present, diagnostic coverage ≥ 80%, activity logs collected |
| Sentinel monitoring | `azure-sentinel-workspace`, `azure-sentinel-connector`, `azure-sentinel-rule`, `azure-sentinel-automation` | Sentinel deployed, connectors active, analytics rules enabled, automation configured |
| Alert response coverage | `azure-security-alert`, `azure-sentinel-incident`, `azure-action-group` | High/critical alerts have action groups; flags > 50 open Sentinel incidents as alert fatigue |

---

## Domain: Change Management

**Evaluator:** `evaluators/change_management.py` — 4 check functions

| Rule | Evidence | Logic |
|------|----------|-------|
| Change control policies | `azure-policy-assignment`, `azure-policy-definition` | Azure policies with deny/audit effects enforce change governance; checks custom policy definitions |
| Resource lock governance | `azure-resource-lock`, `azure-resource-group` | Resource locks (CanNotDelete/ReadOnly) protect critical resources; locks ≥ resource group count |
| Change tracking | `azure-activity-log`, `azure-activity-event`, `azure-diagnostic-setting` | Activity logs track write/delete operations; diagnostics route to Log Analytics |
| Policy enforcement | `azure-policy-compliance`, `azure-policy-assignment` | Compliance ≥ 80% = pass, 50–79% = needs improvement, < 50% = weak enforcement |

---

## Domain: Business Continuity

**Evaluator:** `evaluators/business_continuity.py` — 4 check functions

| Rule | Evidence | Logic |
|------|----------|-------|
| Backup configuration | `azure-recovery-vault`, `azure-vm-config`, `azure-sql-server` | Recovery Services vaults exist with soft-delete enabled; immutability state checked |
| Geo-redundancy | `azure-storage-account`, `azure-cosmosdb-account` | Storage uses GRS/RAGRS/GZRS; Cosmos DB has multi-region writes. Accepted types: `Standard_GRS`, `Standard_RAGRS`, `Standard_GZRS`, `Standard_RAGZRS` |
| VM availability | `azure-vm-config` | VMs deployed in availability zones or availability sets |
| Database resilience | `azure-sql-server`, `azure-sql-detailed`, `azure-database-server` | SQL/PostgreSQL/MySQL have HA, geo-replication, proper network isolation; SQL version ≥ 12.0 for modern HA |

---

## Domain: Asset Management

**Evaluator:** `evaluators/asset_management.py` — 4 check functions

| Rule | Evidence | Logic |
|------|----------|-------|
| Asset inventory | `azure-resource`, `azure-resource-group`, `azure-managed-identity` | Resource inventory completeness; flags low type diversity (< 3 types when > 10 resources) |
| Classification tagging | `azure-resource`, `azure-resource-group` | Tags present; checks for classification keys (`data-classification`, `sensitivity`, etc.). ≥ 80% = pass, 50–79% = needs improvement, < 50% = inadequate |
| Authorized software | `azure-policy-assignment` | Policies restrict resource types/locations; checks for initiatives |
| Application inventory | `entra-application`, `entra-service-principal` | App registrations and SPs inventoried; flags SPs without owners |

---

## Cross-Domain Fallback Dispatch

When a control's `evaluation_logic` doesn't match the primary domain evaluator, `engine.py` uses `_CROSS_DOMAIN_MAP` to route 28 evaluation functions to the correct domain:

```
evaluation_logic function     →  Routed Domain
─────────────────────────────────────────────────
check_sentinel_monitoring     →  incident_response
check_alert_response          →  incident_response
check_security_contact        →  incident_response
check_nsg_rules               →  network
check_network_segmentation    →  network
check_aks_security            →  data_protection
check_backup_config           →  business_continuity
check_geo_redundancy          →  business_continuity
check_resource_locks          →  change_management
check_change_tracking         →  change_management
check_asset_inventory         →  asset_management
check_tagging_compliance      →  asset_management
... (28 total routes)
```

If no route matches and no domain handler exists, the engine applies a **generic fallback**: checks if the required `evidence_types` are present in the evidence index. If present → `partial`; if absent → `missing_evidence`.

---

## Suppression Rules

The suppression engine (`evaluators/suppressions.py`) allows administrators to skip or downgrade specific findings. Rules are loaded from a `suppressions.json` file.

### Rule Structure

| Field | Type | Description |
|-------|------|-------------|
| `control_id` | `str \| null` | Exact match or glob pattern on control ID (e.g., `"AC-*"`, `"NIST-AC-2"`) |
| `resource` | `str \| null` | Regex pattern matching resource name/ID |
| `reason` | `str` | Required justification for suppression |
| `expires` | `str \| null` | ISO date (YYYY-MM-DD); suppression ignored after expiry |

### Matching Logic

1. Rules are tested in order of definition
2. A rule matches when **both** `control_id` (exact/glob) AND `resource` (regex) match
3. Expired rules (past `expires` date) are skipped with a warning log
4. Rules expiring within 7 days trigger a warning log about upcoming expiration
5. A matched rule suppresses the finding from the final report but is tracked in metadata

### Example

```json
[
  {
    "control_id": "AC-6",
    "resource": ".*-dev-.*",
    "reason": "Dev subscription excluded from least-privilege audit",
    "expires": "2025-12-31"
  }
]
```

See [Suppressions Guide](suppressions-guide.md) for detailed configuration.

---

## Plugin System

The plugin engine (`evaluators/plugins.py`) allows custom evaluation functions to be injected at runtime.

### Registration

`load_plugins(plugin_dir)` scans a directory for `.py` files (skipping `_`-prefixed), dynamically imports each via `importlib.util`, and collects any module-level `evaluate()` callable.

### Plugin Signature

```python
def evaluate(control: dict, evidence_index: dict[str, list]) -> tuple[str, list[dict]]:
    """
    Args:
        control: Framework control definition dict
        evidence_index: Dict mapping evidence_type → list of evidence records
    Returns:
        (status, findings) — status is one of the 5 compliance statuses
    """
```

### Invocation

`run_plugins()` iterates all controls tagged with `custom_evaluator` matching a plugin name and calls the corresponding plugin function, collecting results into a flat list.

---

## Standalone Analysis Engines

Beyond framework-based compliance evaluation, PostureIQ includes 9 specialized engines. These run independently or are invoked by agent tools.

### Security Risk Analysis (`risk_engine.py` — 1,124 lines)

Analyses attack-surface risk across five categories using collected evidence:

| Category | Key Checks |
|----------|------------|
| **Identity** | Dormant accounts, over-permissioned SPs, credential hygiene, MFA gaps, admin proliferation, guest risks, risky users |
| **Network** | Open management ports (22, 3389), public storage, web-app transport, SQL firewall exposure |
| **Defender** | Disabled Defender plans, security recommendations, secure score |
| **Config** | Missing diagnostics, Azure Policy violations, tag governance |
| **Data** | Unencrypted storage, public blob access, missing Key Vault security features |

Each risk finding is scored using severity weights (critical=10, high=7.5, medium=5, low=2.5, informational=1). Run standalone: `python run_risk_analysis.py`

### Data Security Assessment (`data_security_engine.py` — 9,085 lines)

Analyses data-layer security posture across seven categories:

| Category | Key Checks |
|----------|------------|
| **Storage Exposure** | Blob public access, HTTPS enforcement, network rules, soft-delete |
| **Database Security** | SQL TDE, auditing, threat protection, firewall rules |
| **Key/Secret Hygiene** | Key Vault access policies, expiring items, purge protection |
| **Encryption Posture** | Disk encryption, storage encryption, CMK usage |
| **Data Classification** | Sensitive-data indicators from resource tags / Purview metadata |
| **Data Lifecycle** | Retention policies, soft delete, lifecycle management rules |
| **DLP Posture** | Sensitivity labels, DLP policies, auto-labeling rules |

Run standalone: `python run_data_security.py`

### Copilot Readiness Assessment (`copilot_readiness_engine.py` — 5,090 lines)

Evaluates M365 Copilot deployment readiness across seven categories:

| Category | Key Checks |
|----------|------------|
| **Oversharing** | SharePoint site permissions, sharing links, external access, anyone links |
| **Sensitivity Labels** | Label definitions, auto-labeling rules, label usage coverage |
| **DLP Policies** | DLP rule coverage, endpoint DLP, policy enforcement modes |
| **Retention / RSS** | Retention policies, labels, records management, information governance |
| **Access Governance** | Access reviews, entitlement management, conditional access for Copilot |
| **Lifecycle Management** | Site lifecycle, inactive site policies, guest expiration |
| **Audit Readiness** | Unified audit log, search enabled, retention period, export capabilities |

Run standalone: `python run_copilot_readiness.py`

### AI Agent Security Assessment (`ai_agent_security_engine.py` — 5,968 lines)

Evaluates AI agent security posture across four assessment areas:

| Area | Checks | Key Evaluations |
|------|--------|-----------------|
| **Copilot Studio** | 5 | Bot authentication, DLP policy, connector restrictions, data loss prevention, channel security |
| **Microsoft Foundry** | 20+ | Model deployments, content safety filters, network isolation, identity config, API key management, responsible AI settings, throughput limits |
| **Custom Agents** | 3 | Service principal security, API authentication, data handling practices |
| **Entra AI Identity** | 3+ | AI service principal hygiene, OAuth consent grants for AI services, cross-tenant policies for AI workloads |

Run standalone: `python run_ai_agent_security.py`

### PostureIQ Risk-Weighted Posture Assessment (`postureiq_orchestrator.py`)

PostureIQ is an **independent assessment engine** that provides a risk-weighted view of security posture, going beyond traditional compliance scoring. It uses its own evaluators, framework mappings, and report generators.

**Key differences from traditional compliance evaluation:**

| Aspect | Traditional (orchestrator.py) | PostureIQ (postureiq_orchestrator.py) |
|--------|-------------------------------|---------------------------------------|
| **Scoring** | Severity-weighted (critical=4, high=3, medium=2, low=1) | Risk-weighted (severity × exploitability × blast radius = RiskScore 0–100) |
| **Tiers** | Compliance percentage | RiskTier: Critical (≥80), High (≥60), Medium (≥40), Low (<40) |
| **Analysis** | Per-control pass/fail | Attack path analysis, priority ranking, AI-powered remediation |
| **Output** | Compliance score + findings | RiskScore + AttackPaths + PriorityRanking + AI Fix Scripts |

#### Risk-Weighted Scoring (`postureiq_evaluators/engine.py`)

Each finding is enriched with three risk dimensions:

| Dimension | Source | Values |
|-----------|--------|--------|
| **Severity** | Framework control definition | critical=4, high=3, medium=2, low=1 |
| **Exploitability** | `_EXPLOITABILITY` dict (30+ checks mapped) | 0.0–1.0 (ease of exploitation) |
| **Blast Radius** | `_BLAST_RADIUS` dict (10 domains) | 0.0–1.0 (scope of impact) |

**Formula:** `RiskScore = severity × exploitability × blast_radius × 100 / max_possible`

#### Attack Path Analysis (`postureiq_evaluators/attack_paths.py`)

Identifies exploitable attack chains in the environment:

| Analysis | Key Checks |
|----------|------------|
| **Privilege Escalation** | Users with IAM-write roles that can escalate to higher privileges (Owner, User Access Admin, Role Based Access Control Admin) |
| **Lateral Movement** | Managed identities with privileged roles that enable cross-resource movement |
| **Exposed High-Value Targets** | Public storage accounts, SQL servers without firewall rules, Key Vaults without private endpoints |
| **Permanent Global Admin** | Global Administrators without PIM (always-on privileged access) |

#### Priority Ranking (`postureiq_evaluators/priority_ranking.py`)

Ranks findings by remediation ROI to guide fix-first decisions:

| Field | Description |
|-------|-------------|
| **PriorityRank** | 1-based rank (lowest = fix first) |
| **PriorityScore** | `risk / √effort` — higher = better ROI |
| **EffortHours** | Estimated fix time from `_EFFORT_HOURS` dict (50+ checks mapped) |
| **PriorityLabel** | `Fix Immediately` / `Fix Soon` / `Plan` / `Backlog` |
| **QuickWins** | Findings with EffortHours ≤ 2 and high risk |

#### AI Fix Recommendations (`postureiq_evaluators/ai_fix_recommendations.py`)

GPT-powered tenant-specific remediation scripts for the top-15 priority findings:

| Output | Description |
|--------|-------------|
| **cli** | Azure CLI command(s) with exact resource names from the tenant |
| **powershell** | Equivalent PowerShell command(s) |
| **impact** | Expected security improvement |
| **downtime** | Whether the fix causes service disruption |
| **prerequisites** | Required permissions or pre-conditions |

Invoked by agent tool: `run_postureiq_assessment`

### Data Residency Validation (`data_residency_engine.py` — 296 lines)

| Analyzer | Key Checks |
|----------|------------|
| **Region Compliance** | Resource location vs. allowed regions/region groups |
| **Replication Analysis** | Storage replication targets, CosmosDB multi-region writes |
| **Data Transfer** | Cross-region data flows, peering, Traffic Manager endpoints |
| **Backup Location** | Recovery vault region, backup redundancy type |
| **Network Egress** | CDN endpoint origins, Front Door backends |

Configure via `dataResidency` section in config. See [Configuration Guide](configuration-guide.md#dataresidency).

### Continuous Monitoring (`continuous_monitor.py` — 196 lines)

| Feature | Description |
|---------|-------------|
| **Scheduled Runs** | Configurable interval (minimum 5 minutes) |
| **Trend Tracking** | Stores historical scores to `.trends.json` and detects regressions |
| **Selective Collection** | Run a subset of collectors/frameworks for faster cycles |
| **Regression Alerts** | Flags compliance score drops between runs via alert callbacks |

Configure via `continuousMonitoring` section in config. See [Configuration Guide](configuration-guide.md#continuousmonitoring).

### Remediation Engine (`remediation_engine.py` — 299 lines)

Generates actionable fix scripts for non-compliant findings.

| Rule Category | Generated Commands |
|---------------|-------------------|
| **Encryption** | Enable storage encryption, disk encryption, CMK |
| **TLS** | Set minimum TLS version on storage, SQL, App Service |
| **Network** | Configure NSG rules, private endpoints, firewall rules |
| **MFA** | Conditional Access policy configuration |
| **Diagnostics** | Enable diagnostic settings on resources |
| **Database** | Enable SQL TDE, auditing, threat detection |
| **Key Vault** | Enable purge protection, soft delete, RBAC model |

Outputs Azure CLI commands (default), with optional PowerShell and ARM template snippets.

### SIEM Integration (`siem_integration.py` — 156 lines)

| Target | Protocol | Authentication |
|--------|----------|----------------|
| **Azure Sentinel** | Data Collection Rules (DCR) | DefaultAzureCredential |
| **Splunk** | HTTP Event Collector (HEC) | `SPLUNK_HEC_TOKEN` env var |
| **Generic Webhook** | HTTPS POST | `SIEM_WEBHOOK_TOKEN` env var |

Configure via `siemIntegration` section in config. See [Configuration Guide](configuration-guide.md#siemintegration).

> **📖 Deep references:** Each engine has its own deep-dive document:
> [Data Security](data-security-deep-dive.md) · [AI Agent Security](ai-agent-security-deep-dive.md) · [Copilot Readiness](copilot-readiness-deep-dive.md) · [RBAC Reporting](rbac-reporting-deep-dive.md) · [Risk Analysis](risk-analysis-deep-dive.md) · [Query Engine](query-engine-deep-dive.md) · [Tenant Assessment](tenant-assessment-deep-dive.md)

---

## Evidence Types

Each control requires specific evidence types listed in its `evidence_types[]` array. Missing types result in `missing_evidence` status. Controls may also specify `compensating_evidence` — alternative evidence types that can satisfy the requirement if primary evidence is unavailable (e.g., due to 403 permissions).

See [Architecture](architecture.md) for the full collector → evidence type mapping covering 218 evidence types.

---

## Severity Levels

| Level | Weight | Description | Remediation Timeline |
|-------|--------|-------------|---------------------|
| `critical` | 4 | Direct security impact, immediate exploitation risk | 0–14 days |
| `high` | 3 | Significant security gap | 0–30 days |
| `medium` | 2 | Configuration gap, exploitable under conditions | 30–90 days |
| `low` | 1 | Best-practice deviation, minimal direct impact | 90–180 days |
