# PostureIQ — Deep Dive

**Author:** Murali Chillakuru

> **Executive Summary** — PostureIQ is an independent, risk-weighted security posture assessment engine
> that goes beyond traditional compliance scoring. It provides attack path analysis, ROI-based
> priority ranking, AI-powered remediation scripts, and enhanced exception tracking — all built
> on a separate evaluator pipeline with its own framework mappings and report generators.
>
> | | |
> |---|---|
> | **Audience** | Security engineers, risk analysts, CISOs |
> | **Prerequisites** | [Architecture](architecture.md) for pipeline overview · [Evaluation Rules](evaluation-rules.md) for scoring methodology |
> | **Companion docs** | [FILE-REFERENCE](FILE-REFERENCE.md) for PostureIQ file inventory · [Suppressions Guide](suppressions-guide.md) for exception tracking |

---

## Table of Contents

- [What Is PostureIQ?](#what-is-postureiq)
- [Architecture](#architecture)
- [PostureIQ vs Traditional Assessment](#postureiq-vs-traditional-assessment)
- [Pipeline Phases](#pipeline-phases)
- [Risk-Weighted Scoring](#risk-weighted-scoring)
- [Attack Path Analysis](#attack-path-analysis)
- [Priority Ranking](#priority-ranking)
- [AI Fix Recommendations](#ai-fix-recommendations)
- [Exception Tracking](#exception-tracking)
- [Private Endpoint Adoption](#private-endpoint-adoption)
- [File Inventory](#file-inventory)
- [Agent Integration](#agent-integration)
- [Web Dashboard](#web-dashboard)
- [Extending PostureIQ](#extending-postureiq)

---

## What Is PostureIQ?

PostureIQ is a **fully independent** assessment engine within PostureIQ. Unlike the traditional
compliance assessment (which maps findings to framework controls and produces pass/fail scores),
PostureIQ evaluates **risk posture** using a multi-dimensional scoring model that accounts for
exploitability, blast radius, and remediation effort.

**Key capabilities:**
- **Risk-weighted scoring** — severity × exploitability × blast radius = RiskScore 0–100
- **Attack path analysis** — identifies privilege escalation chains, lateral movement, and exposed high-value targets
- **Priority ranking** — ROI-based remediation ranking with effort estimates and quick wins
- **AI fix recommendations** — GPT-powered tenant-specific remediation scripts (Azure CLI + PowerShell)
- **Enhanced exception tracking** — audit trail with owner, ticket, risk acceptance, and expiry management

PostureIQ has its own evaluators, framework mappings, report generators, and orchestrator — it does not
share evaluation state with the traditional compliance engine.

---

## Architecture

```
PostureIQ Pipeline (postureiq_orchestrator.py)
═══════════════════════════════════════════════

Phase 1: COLLECT
    Reuses the shared collector infrastructure (64 collectors, 218 evidence types)
    Same @register_collector decorators, same concurrent batching

         │
         ▼

Phase 2: EVALUATE (postureiq_evaluators/engine.py)
    10 domain evaluators with 113+ check functions
    Uses postureiq_frameworks/ (11 JSON, 525 controls) — independent copies
    Severity-weighted scoring + EvaluationLogic tagging

         │
         ▼

Phase 2.1: RISK-WEIGHTED SCORING (postureiq_evaluators/engine.py)
    Enriches each finding with:
    • Exploitability score (0.0–1.0) from _EXPLOITABILITY dict
    • Blast radius score (0.0–1.0) from _BLAST_RADIUS dict
    • Composite RiskScore = severity × exploitability × blast_radius × 100 / max
    • RiskTier label (Critical ≥80, High ≥60, Medium ≥40, Low <40)

         │
         ▼

Phase 2.2: ATTACK PATH ANALYSIS (postureiq_evaluators/attack_paths.py)
    Identifies exploitable attack chains:
    • Privilege escalation (IAM-write role holders)
    • Lateral movement (managed identities with privileged roles)
    • Exposed high-value targets (public storage, SQL, Key Vault)
    • Permanent Global Admin without PIM

         │
         ▼

Phase 2.3: PRIORITY RANKING (postureiq_evaluators/priority_ranking.py)
    ROI-based remediation ranking:
    • PriorityScore = risk / √effort
    • Effort hours from _EFFORT_HOURS dict (50+ checks)
    • Labels: Fix Immediately / Fix Soon / Plan / Backlog
    • Quick wins: EffortHours ≤ 2 AND high risk

         │
         ▼

Phase 2.4: EXCEPTION TRACKING (postureiq_evaluators/suppressions.py)
    Enhanced suppression with audit trail:
    • owner, ticket, risk_accepted, created fields
    • Exception report: expired, expiring soon, missing approval

         │
         ▼

Phase 2.5: AI FIX RECOMMENDATIONS (postureiq_evaluators/ai_fix_recommendations.py)
    GPT-powered remediation for top-15 priority findings:
    • Azure CLI + PowerShell with exact resource names
    • Impact, downtime, prerequisites for each fix

         │
         ▼

Phase 3: DELTA & REPORT (postureiq_reports/)
    Delta comparison with previous runs
    PostureIQ-specific HTML and Markdown reports
    Full report suite (HTML, JSON, Excel, OSCAL, SARIF, PDF)
```

---

## PostureIQ vs Traditional Assessment

| Aspect | Traditional (`orchestrator.py`) | PostureIQ (`postureiq_orchestrator.py`) |
|--------|-------------------------------|---------------------------------------|
| **Purpose** | Framework compliance verification | Risk posture intelligence |
| **Scoring** | Severity-weighted (critical=4, high=3, medium=2, low=1) | Risk-weighted (severity × exploitability × blast radius) |
| **Output** | Compliance % per framework/domain | RiskScore 0–100 + RiskTier + AttackPaths + PriorityRanking |
| **Tiers** | None (percentage only) | Critical (≥80), High (≥60), Medium (≥40), Low (<40) |
| **Remediation** | Static recommendations per control | GPT-powered tenant-specific CLI/PowerShell scripts |
| **Ranking** | By severity | By ROI (risk/√effort) with quick wins |
| **Attack analysis** | None | Privilege escalation, lateral movement, exposed HV targets |
| **Exception tracking** | Basic suppression (reason + expiry) | Full audit trail (owner, ticket, risk_accepted) |
| **Agent tool** | `run_assessment` | `run_postureiq_assessment` |
| **SPA** | `ComplianceAssessment.html` | `PostureIQ.html` |
| **Evaluators** | `evaluators/` | `postureiq_evaluators/` (independent copies) |
| **Frameworks** | `frameworks/` | `postureiq_frameworks/` (independent copies) |
| **Reports** | `reports/` | `postureiq_reports/` (independent copies + PostureIQ-specific) |

---

## Pipeline Phases

### Phase 1: Evidence Collection

PostureIQ reuses the shared collector infrastructure — the same 64 async collectors
with `@register_collector` decorators, the same concurrent batching, and the same
checkpoint/resume logic. No duplicate API calls.

### Phase 2: Domain Evaluation

The PostureIQ evaluation engine (`postureiq_evaluators/engine.py`) processes evidence
against framework control mappings using the same 10-domain dispatch pattern as the
traditional engine. Each finding is tagged with an `EvaluationLogic` field linking it
to the specific check function that produced it.

### Phase 2.1–2.5: PostureIQ Intelligence Phases

See the sections below for details on each intelligence phase.

---

## Risk-Weighted Scoring

**Module:** `postureiq_evaluators/engine.py`

Traditional compliance scoring uses a simple severity weight (critical=4, high=3, etc.).
PostureIQ adds two additional dimensions:

### Exploitability

How easy is it for an attacker to exploit this finding?

The `_EXPLOITABILITY` dictionary maps 30+ check function names to a score between 0.0 and 1.0:

| Score | Meaning | Examples |
|-------|---------|---------|
| 0.9–1.0 | Trivially exploitable | Public storage, open management ports, no MFA |
| 0.6–0.8 | Moderately exploitable | Excessive RBAC permissions, stale credentials |
| 0.3–0.5 | Requires effort | Missing encryption, unpatched configurations |
| 0.1–0.2 | Hard to exploit | Missing audit logs, incomplete tagging |

### Blast Radius

How much damage can result from successful exploitation?

The `_BLAST_RADIUS` dictionary maps 10 evaluation domains to impact scores:

| Domain | Blast Radius | Rationale |
|--------|-------------|-----------|
| `access` | 0.9 | Compromised access = full environment control |
| `identity` | 0.9 | Identity is the perimeter |
| `data_protection` | 0.8 | Direct data exposure risk |
| `network` | 0.7 | Network pivoting enables lateral movement |
| `governance` | 0.6 | Governance gaps enable policy bypass |
| `logging` | 0.5 | Logging gaps delay detection |
| `incident_response` | 0.5 | Slow response increases damage |
| `change_management` | 0.4 | Change control gaps enable persistence |
| `business_continuity` | 0.4 | BC gaps enable destructive attacks |
| `asset_management` | 0.3 | Asset gaps enable shadow IT |

### Composite RiskScore

```
RiskScore = (severity × exploitability × blast_radius) / max_possible × 100
```

Each finding receives a `RiskScore` (0–100) and a `RiskTier` label:

| RiskTier | Score Range | Action |
|----------|-------------|--------|
| **Critical** | ≥ 80 | Immediate remediation required |
| **High** | 60–79 | Fix within current sprint |
| **Medium** | 40–59 | Schedule for next maintenance window |
| **Low** | < 40 | Monitor and plan |

The `RiskSummary` output includes counts per tier plus overall risk distribution.

---

## Attack Path Analysis

**Module:** `postureiq_evaluators/attack_paths.py`

Identifies exploitable attack chains by analyzing RBAC assignments, managed identity
configurations, and public-facing resource exposure.

### Privilege Escalation Detection

Scans for users or service principals that hold IAM-write roles (Owner,
User Access Administrator, Role Based Access Control Administrator) combined with
multiple other escalation roles. These represent paths where an attacker could
escalate from a compromised identity to full environment control.

### Lateral Movement Detection

Identifies managed identities that hold privileged roles across multiple resources.
A compromised workload with a privileged managed identity can move laterally to other
Azure resources without additional authentication.

### Exposed High-Value Target Detection

Flags high-value resources with public exposure:
- Storage accounts without network restrictions (public blob access)
- SQL servers without firewall rules
- Key Vaults without private endpoints
- Permanent Global Administrators without PIM (always-on privilege)

### Output Format

```json
{
  "attack_paths": [...],
  "summary": {
    "total_paths": 7,
    "critical_paths": 2,
    "privilege_escalation_count": 3,
    "lateral_movement_count": 2,
    "exposed_high_value_count": 2
  }
}
```

---

## Priority Ranking

**Module:** `postureiq_evaluators/priority_ranking.py`

Ranks all findings by remediation ROI to guide "fix first" decisions. The ranking
considers both the risk impact and the effort required to remediate.

### Algorithm

```
PriorityScore = RiskScore / √EffortHours
```

Higher `PriorityScore` = better ROI (more risk reduction per unit of effort).

### Effort Estimation

The `_EFFORT_HOURS` dictionary maps 50+ check function names to estimated remediation
hours based on typical operational complexity:

| Effort Range | Examples |
|-------------|---------|
| 0.5–1 hour | Enable MFA, enable HTTPS only, enable soft delete |
| 2–4 hours | Configure diagnostic settings, create NSG rules, enable encryption |
| 4–8 hours | Implement PIM, configure Sentinel, set up private endpoints |
| 8–16 hours | Redesign network architecture, implement zero-trust access model |

### Priority Labels

| Label | Criteria |
|-------|----------|
| **Fix Immediately** | RiskScore ≥ 80 OR top 5 by PriorityScore |
| **Fix Soon** | RiskScore ≥ 60 AND rank ≤ 20 |
| **Plan** | RiskScore ≥ 40 |
| **Backlog** | All others |

### Quick Wins

Findings with `EffortHours ≤ 2` AND `RiskScore ≥ 60` are flagged as **Quick Wins** —
high-impact fixes that can be implemented immediately.

### Output

```json
{
  "top_10": [...],
  "quick_wins": [...],
  "total_effort_hours": 145.5,
  "rankings": [
    {
      "PriorityRank": 1,
      "PriorityScore": 42.8,
      "EffortHours": 1.0,
      "PriorityLabel": "Fix Immediately",
      "ControlId": "AC-6",
      "RiskScore": 85.2
    }
  ]
}
```

---

## AI Fix Recommendations

**Module:** `postureiq_evaluators/ai_fix_recommendations.py`

Generates tenant-specific remediation scripts using GPT for the top-15 priority findings.
Unlike static remediation templates, these scripts include the **exact resource names and
IDs** from the assessed tenant.

### How It Works

1. Top-15 findings (by PriorityRank) are collected
2. Each finding's context (resource ID, current configuration, violation details) is sent to GPT
3. GPT generates Azure CLI and PowerShell commands with the actual resource identifiers
4. Each script includes impact assessment, downtime expectations, and prerequisites

### Output per Finding

```json
{
  "control_id": "SC-28",
  "resource_id": "/subscriptions/.../storageAccounts/mystorageaccount",
  "cli": "az storage account update --name mystorageaccount --resource-group myRG --https-only true --min-tls-version TLS1_2",
  "powershell": "Set-AzStorageAccount -ResourceGroupName myRG -Name mystorageaccount -EnableHttpsTrafficOnly $true -MinimumTlsVersion TLS1_2",
  "impact": "Enforces HTTPS-only access and TLS 1.2 minimum. Existing HTTP connections will be rejected.",
  "downtime": "No downtime. Existing HTTPS connections are unaffected.",
  "prerequisites": "Contributor role on the storage account's resource group"
}
```

### Safety

- Scripts are **read-only suggestions** — they are never executed automatically
- Each script includes prerequisite permissions so operators can verify before running
- Downtime impact is assessed to prevent unplanned outages

---

## Exception Tracking

**Module:** `postureiq_evaluators/suppressions.py`

PostureIQ extends the standard suppression system with governance-grade exception tracking.

### Enhanced Fields

| Field | Type | Description |
|-------|------|-------------|
| `owner` | string | Person or team responsible for the exception |
| `ticket` | string | Approval ticket reference (e.g., JIRA-1234) |
| `risk_accepted` | boolean | Whether the risk has been formally accepted |
| `created` | ISO date | When the suppression rule was created |

### Exception Report

The `generate_exception_report()` function produces:

| Metric | Description |
|--------|-------------|
| `TotalRules` | Total suppression rules loaded |
| `ExpiredRules` | Rules past their expiry date |
| `ExpiringSoon` | Rules expiring within 30 days |
| `MissingApproval` | Rules where `risk_accepted` is not `true` |
| `AuditEntries` | Full audit trail with all fields |

---

## Private Endpoint Adoption

**Module:** `postureiq_evaluators/network.py` — `_check_private_endpoint_adoption()`

PostureIQ tracks private endpoint adoption across 10 PaaS resource types:

| Resource Type | ARM Provider |
|---------------|-------------|
| Storage Accounts | `Microsoft.Storage/storageAccounts` |
| SQL Servers | `Microsoft.Sql/servers` |
| Cosmos DB Accounts | `Microsoft.DocumentDB/databaseAccounts` |
| Key Vaults | `Microsoft.KeyVault/vaults` |
| Container Registries | `Microsoft.ContainerRegistry/registries` |
| App Services | `Microsoft.Web/sites` |
| Function Apps | `Microsoft.Web/sites` (kind: functionapp) |
| AI Services | `Microsoft.CognitiveServices/accounts` |
| Event Hub Namespaces | `Microsoft.EventHub/namespaces` |
| Service Bus Namespaces | `Microsoft.ServiceBus/namespaces` |

The check reports overall adoption percentage and per-type breakdown.

---

## File Inventory

### Evaluators (`postureiq_evaluators/` — 18 files)

| File | Purpose |
|------|---------|
| `engine.py` | Evaluation engine with risk-weighted scoring |
| `access.py` | Access domain evaluator (8 functions) |
| `identity.py` | Identity domain evaluator (22 functions) |
| `data_protection.py` | Data protection evaluator (22 functions) |
| `network.py` | Network evaluator (17 functions, incl. private endpoint adoption) |
| `logging_eval.py` | Logging evaluator (13 functions) |
| `governance.py` | Governance evaluator (21 functions) |
| `incident_response.py` | Incident response evaluator (6 functions) |
| `change_management.py` | Change management evaluator (4 functions) |
| `business_continuity.py` | Business continuity evaluator (4 functions) |
| `asset_management.py` | Asset management evaluator (4 functions) |
| `attack_paths.py` | Attack path analysis |
| `priority_ranking.py` | Priority ranking |
| `ai_fix_recommendations.py` | AI fix recommendations |
| `suppressions.py` | Suppression rules with audit trail |
| `remediation.py` | Remediation hints |
| `plugins.py` | Plugin hooks |
| `__init__.py` | Package init |

### Frameworks (`postureiq_frameworks/` — 11 JSON files)

Same 11 frameworks as the traditional engine (NIST 800-53, FedRAMP, CIS, MCSB, PCI-DSS,
ISO 27001, SOC 2, HIPAA, NIST CSF, CSA CCM, GDPR) — 525 total controls. Independent copies
that can evolve separately.

### Reports (`postureiq_reports/` — 20 files)

Full report suite plus 2 PostureIQ-specific generators:
- `postureiq_report_html.py` — HTML report with risk scoring, attack paths, priority ranking
- `postureiq_report_md.py` — Markdown equivalent

---

## Agent Integration

PostureIQ is exposed as the 14th agent tool:

| Property | Value |
|----------|-------|
| **Tool name** | `run_postureiq_assessment` |
| **Parameters** | `scope` (optional: full/identity/network/data/governance), `frameworks` (optional: comma-separated) |
| **Module** | `postureiq_orchestrator.run_postureiq_assessment()` |
| **Result sections** | Risk Intelligence, Attack Paths, Priority Ranking, AI Fix Scripts, Report links |

### Example Prompts

- *"Run a PostureIQ assessment on my environment"*
- *"What are the top attack paths in my Azure tenant?"*
- *"Show me high-ROI security quick wins"*
- *"Run PostureIQ with FedRAMP and NIST frameworks"*

---

## Web Dashboard

PostureIQ has a dedicated SPA at `webapp/PostureIQ.html` with:
- Framework picker for selecting which compliance frameworks to evaluate
- Risk intelligence dashboard with RiskScore and RiskTier visualization
- Attack path summary with escalation and lateral movement counts
- Priority ranking table with quick wins highlighted
- AI fix script display with copy-to-clipboard buttons

---

## Extending PostureIQ

### Adding a New Check Function

1. Add the function to the appropriate domain evaluator in `postureiq_evaluators/`
2. Register it in the domain's dispatch dict
3. Add an exploitability score to `_EXPLOITABILITY` in `engine.py`
4. Add effort estimate to `_EFFORT_HOURS` in `priority_ranking.py`

### Adding a Custom Attack Path Rule

Add a new detection function to `attack_paths.py` and include it in the
`analyze_attack_paths()` pipeline. Return paths in the standard format with
`type`, `severity`, `description`, and `affected_resources`.

### Adding a New Framework

1. Create `postureiq_frameworks/<name>-mappings.json`
2. Add the key → filename entry to `AVAILABLE_FRAMEWORKS` in `postureiq_evaluators/engine.py`

> **Note:** PostureIQ frameworks are independent of the traditional engine's frameworks.
> Adding a framework to PostureIQ does NOT add it to the compliance assessment and vice versa.
