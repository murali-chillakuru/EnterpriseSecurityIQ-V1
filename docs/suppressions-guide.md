# PostureIQ Suppressions Guide

> **Author:** Murali Chillakuru
> All behaviour verified against `AIAgent/app/postureiq_evaluators/suppressions.py` source code.

> **Executive Summary** — How to suppress, mute, or accept-risk specific compliance findings.
> Covers the JSON suppression file format, regex-based control ID matching (`re.fullmatch`),
> resource pattern matching, expiration handling, audit trail, and CI/CD review workflows.
> This is the canonical suppressions reference.
>
> | | |
> |---|---|
> | **Audience** | Security engineers, compliance managers |
> | **Prerequisites** | [Evaluation Rules](evaluation-rules.md) for how findings are generated |
> | **Companion docs** | [CI/CD Integration](ci-cd-integration.md) for suppression management in pipelines |

## Overview

Finding suppressions let you mute specific compliance findings that are accepted risks, false positives, or covered by compensating controls. Suppressed findings are **excluded from compliance scores and reports** but remain **fully logged for audit**.

The system is implemented in `AIAgent/app/postureiq_evaluators/suppressions.py` with two functions:

| Function | Purpose |
|----------|---------|
| `load_suppressions(path)` | Load rules from JSON; accepts `[...]` or `{"suppressions": [...]}` formats; returns `[]` on missing file or parse error |
| `apply_suppressions(findings, suppressions)` | Returns `(active_findings, suppressed_findings)` tuple |

---

## Suppression File Format

Create `suppressions.json` in your working directory or pass a custom path via `--suppressions` on supported CLI scripts.

```json
[
  {
    "control_id": "AC-6",
    "resource": ".*",
    "reason": "Accepted risk — compensating control implemented via JIT access",
    "expires": "2026-12-31"
  },
  {
    "control_id": "SC-28.*",
    "resource": ".*temp-storage.*",
    "reason": "Temporary storage account — no sensitive data classification",
    "expires": "2026-06-30"
  },
  {
    "control_id": "IA-5",
    "reason": "Permanent exception — federated auth handles credential management"
  }
]
```

**Alternative envelope format** (also accepted):

```json
{
  "suppressions": [
    { "control_id": "AC-6", "resource": ".*", "reason": "..." }
  ]
}
```

---

## Rule Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `control_id` | **Yes** | string | Control ID pattern. Matched via `re.fullmatch()` — exact match or regex (e.g., `AC-6`, `SC-28.*`, `IA-\d+`) |
| `resource` | No | string | Regex pattern matched via `re.search()` against the finding's resource identifier. **Case-insensitive**. Default: `.*` (all resources) |
| `reason` | **Yes** | string | Human-readable justification — appears in audit logs and exported data |
| `expires` | No | string | ISO date (`YYYY-MM-DD`). Omit for permanent suppression |

---

## Matching Logic (Verified from Source)

The engine processes each finding against suppression rules in order. **First matching rule wins.**

### Step-by-Step Matching

1. **Check expiry** — If `expires` is set and the date has passed, the rule is **skipped** (not applied). Invalid date formats are also skipped with a warning.
2. **Match `control_id`** — Two-stage:
   - First: exact string equality (`rule.control_id == finding.ControlId`)
   - If no exact match: `re.fullmatch(rule.control_id, finding.ControlId)`
3. **Match `resource`** — If the rule has a `resource` field: `re.search(rule.resource, finding.ResourceId, re.IGNORECASE)`. If no `resource` field, the rule matches all resources.
4. **Both must pass** — A finding is suppressed only when both `control_id` and `resource` match (or `resource` is absent).

> **Note:** The old docs stated `re.search()` for `control_id`. The actual code uses `re.fullmatch()`, which requires the **entire** control ID to match the pattern. Use `AC-6.*` to match `AC-6` and `AC-6.1`, etc.

---

## Expiry Handling

| Scenario | Behaviour |
|----------|-----------|
| `expires` in the past | Rule **skipped**, logged at WARNING level |
| `expires` within 7 days | Rule **applied**, warning logged: "Expiring soon" |
| `expires` in the future | Rule applied normally |
| `expires` missing/omitted | **Permanent** — rule applies indefinitely |
| `expires` invalid format | Rule **skipped**, warning logged |

---

## Audit Trail

When a finding is suppressed, three fields are dynamically added to the finding dict:

| Field | Type | Description |
|-------|------|-------------|
| `suppressed_reason` | string | The `reason` from the matching rule |
| `suppressed_rule_index` | int | **1-based** index of the matching rule in the suppressions array |
| `suppressed_expires` | string or null | The `expires` date from the matching rule |

**These fields are NOT part of the `FindingRecord` dataclass** — they are injected dynamically at runtime.

### PostureIQ Enhanced Audit Trail

The PostureIQ engine (`postureiq_evaluators/suppressions.py`) extends the suppression system with additional
audit trail fields for governance and exception management:

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `owner` | No | string | Person or team responsible for the exception |
| `ticket` | No | string | Reference to an approval ticket (e.g., JIRA-1234, INC-5678) |
| `risk_accepted` | No | boolean | Whether the risk has been formally accepted |
| `created` | No | string | ISO date when the suppression rule was created |

**Example PostureIQ suppression with audit trail:**

```json
{
  "control_id": "AC-6",
  "resource": ".*",
  "reason": "Accepted risk — compensating control via JIT access",
  "expires": "2026-12-31",
  "owner": "security-team@contoso.com",
  "ticket": "SEC-2024-0142",
  "risk_accepted": true,
  "created": "2026-01-15"
}
```

The PostureIQ orchestrator generates an **Exception Report** (`generate_exception_report()`) that includes:
- Total suppression rules, expired rules, rules expiring within 30 days
- Rules missing formal approval (`risk_accepted` not set)
- Full audit entries with owner, ticket, and acceptance status

### What happens to suppressed findings:

- `apply_suppressions()` returns `(active_findings, suppressed_findings)` tuple
- **Active findings** → used for scoring and reports
- **Suppressed findings** → written to JSON data exports for audit review
- All suppression activity is logged at INFO level

---

## CLI Integration

Three CLI scripts accept `--suppressions`:

```bash
# Data Security Assessment
python run_data_security.py --tenant "..." --suppressions suppressions.json

# Copilot Readiness
python run_copilot_readiness.py --tenant "..." --suppressions suppressions.json

# AI Agent Security
python run_ai_agent_security.py --tenant "..." --suppressions suppressions.json
```

The PostureIQ orchestrator automatically loads `suppressions.json` from the working directory when running assessments via the agent chat interface.

---

## Pattern Examples

### Suppress a Single Control on All Resources

```json
{ "control_id": "AC-6", "reason": "Accepted: JIT compensating control" }
```

### Suppress a Control Family (Regex)

```json
{ "control_id": "SC-28.*", "reason": "SC-28 family exempted for dev subscriptions" }
```

### Suppress by Resource Name Pattern

```json
{
  "control_id": ".*",
  "resource": ".*-dev-.*|.*-test-.*",
  "reason": "Non-production resources excluded",
  "expires": "2026-12-31"
}
```

### Suspend Temporarily (7-Day Window)

```json
{
  "control_id": "IA-2",
  "reason": "MFA rollout in progress — tracking ticket ESIQ-1234",
  "expires": "2026-04-18"
}
```

### Framework-Specific Suppression

Control IDs are framework-prefixed in the output (e.g., `NIST-AC-6`, `PCI-8.3.1`):

```json
{ "control_id": "NIST-AC-6", "reason": "NIST-specific exception" }
```

```json
{ "control_id": "PCI-8\\.3\\..*", "reason": "PCI auth controls handled by SSO" }
```

---

## CI/CD Integration

Commit `suppressions.json` to version control alongside your config:

```
repo/
├── config/
│   └── enterprisesecurityiq.config.json
├── suppressions.json           ← Commit this
└── AIAgent/
```

In pipelines, pass the path:

```yaml
      - name: Assessment with Suppressions
        run: |
          python run_data_security.py \
            --tenant ${{ secrets.AZURE_TENANT_ID }} \
            --suppressions ../suppressions.json \
            --fail-on-severity critical
```

### Review Workflow

1. Run an initial assessment and review all findings
2. Identify accepted risks, false positives, or compensating controls
3. Create `suppressions.json` with specific rules and expiry dates
4. Re-run — suppressed findings excluded from score, still in JSON export
5. Periodically review: pipeline logs warn about rules expiring within 7 days
6. Remove or update expired rules to keep the file current

---

## Error Handling

| Condition | Behaviour |
|-----------|-----------|
| File not found | `load_suppressions()` returns `[]`, assessment runs without suppressions |
| Invalid JSON | Returns `[]`, warning logged |
| Missing `control_id` | Rule skipped |
| Missing `reason` | Rule still applied (reason defaults to empty) |
| Invalid regex in `control_id` | Rule skipped, error logged |
| Invalid regex in `resource` | Rule skipped, error logged |
