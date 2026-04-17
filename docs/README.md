# PostureIQ

> AI-powered compliance intelligence for Azure, Microsoft Entra ID, M365 Copilot, and AI Agent platforms

**Author:** Murali Chillakuru

## Overview

PostureIQ is a **read-only** compliance assessment platform that discovers Azure resources and Microsoft Entra configurations, collects evidence from control-plane and data-plane APIs, normalizes findings, maps them to 11 compliance frameworks (525 total controls), evaluates posture across 10 security domains with 120 check functions, and produces professional auditor-ready reports in 8 formats.

Built with Python and the Microsoft Agent Framework SDK, PostureIQ runs as an AI agent on Microsoft Foundry (12 tools) or standalone via 10 CLI scripts. It uses 68 async collectors with concurrency, retry logic, pagination, and checkpoint resume for production-grade evidence gathering across 200+ evidence types.

**PostureIQ never creates, modifies, or deletes any tenant resource.** All operations are strictly read-only.

## At a Glance

| Metric | Value |
|--------|-------|
| **Azure Collectors** | 50 (49 registered + 1 standalone RBAC) |
| **Entra ID Collectors** | 18 (17 registered + 1 standalone AI identity) |
| **Distinct Evidence Types** | 200+ |
| **Evaluation Domains** | 10 |
| **Evaluation Check Functions** | 120 |
| **Compliance Frameworks** | 11 (525 total controls) |
| **Agent Tools (Foundry)** | 12 |
| **CLI Scripts** | 10 assessment runners + 3 determinism validators |
| **Report Formats** | HTML, JSON, Markdown, Excel, OSCAL, SARIF, PDF, Webhook |
| **Report Generators** | 29 modules |
| **Standalone Engines** | 8 (query, risk, data security, Copilot readiness, AI agent security, data residency, remediation, continuous monitoring) |
| **Tests** | 1,357 test functions across 15 files |
| **Codebase** | ~50,000 lines of Python |

## Objectives

| Goal | Description |
|------|-------------|
| **Discover** | Enumerate Azure subscriptions, resource groups, resources, policies, RBAC, Entra ID, M365 services, and AI platforms |
| **Collect** | Gather structured evidence from control-plane and data-plane APIs (async, concurrent, with retry and pagination) |
| **Normalize** | Convert raw API outputs into a unified evidence model with deterministic IDs |
| **Map** | Map evidence to 11 compliance framework controls (525 total) across 10 evaluation domains |
| **Evaluate** | Assess compliance posture per control, domain, and framework with 120 check functions |
| **Report** | Generate professional reports in 8 formats — HTML (Fluent Design), JSON, Markdown, Excel, OSCAL, SARIF, PDF, and webhooks |

## Capabilities

| Capability | Agent Tool | CLI Script | Description |
|------------|-----------|------------|-------------|
| **Compliance Assessment** | `run_assessment` | `run_assessment.py` | Full multi-framework assessment across all 10 domains |
| **Query Results** | `query_results` | — | Search cached findings by control ID, domain, or severity |
| **Tenant Search** | `search_tenant` | `run_query.py` | Live Azure Resource Graph (KQL) and MS Graph queries with natural language |
| **Risk Analysis** | `analyze_risk` | `run_risk_analysis.py` | Security risk gap analysis across identity, network, Defender, and config |
| **Data Security** | `assess_data_security` | `run_data_security.py` | Data-layer posture: storage, database, Key Vault, encryption, classification |
| **RBAC Report** | `generate_rbac_report` | `run_rbac_report.py` | Interactive RBAC hierarchy tree with PIM, group expansion, risk analysis |
| **Copilot Readiness** | `assess_copilot_readiness` | `run_copilot_readiness.py` | M365 Copilot readiness: oversharing, labels, DLP, restricted search, governance |
| **AI Agent Security** | `assess_ai_agent_security` | `run_ai_agent_security.py` | Security posture for Copilot Studio, Foundry, and custom AI agents |
| **Report Generation** | `generate_report` | — | Regenerate reports from cached assessment results |
| **Permission Check** | `check_permissions` | — | Preflight verification of ARM/Graph/Entra permissions |
| **Run Comparison** | `compare_runs` | — | Delta comparison showing new/resolved findings and score drift |
| **Exposure Search** | `search_exposure` | — | Quick-scan of public-facing resources and sensitive data exposure |

## Documentation

| Document | Description |
|----------|-------------|
| [AI Agent README](AIAgent/README.md) | Agent architecture, 12 tools, deployment to Foundry |
| [Usage Guide](docs/PROMPTS.md) | Step-by-step instructions, all CLI commands, troubleshooting |
| [Architecture](docs/architecture.md) | Pipeline design, data flow, module interactions, sequence diagrams |
| [Agent Capabilities](docs/agent-capabilities.md) | Complete resource coverage, all collectors, evidence types, evaluators |
| [File Reference](docs/FILE-REFERENCE.md) | Detailed documentation of every file in the codebase |
| [Evaluation Rules](docs/evaluation-rules.md) | All 120 check functions, thresholds, scoring methodology |
| [Configuration Guide](docs/configuration-guide.md) | Full configuration reference with all engines and options |
| [Extending Frameworks](docs/extending-frameworks.md) | Guide for adding custom compliance frameworks |
| [CI/CD Integration](docs/ci-cd-integration.md) | GitHub Actions and Azure DevOps pipeline integration |
| [Suppressions Guide](docs/suppressions-guide.md) | Finding suppression rules and audit trail |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and resolutions for all engines |

## Supported Frameworks

| Framework | Controls | Mapping File |
|-----------|----------|-------------|
| NIST 800-53 Rev 5 | 83 | `nist-800-53-mappings.json` |
| FedRAMP Moderate | 69 | `fedramp-mappings.json` |
| CIS Azure Benchmark v2.0 | 53 | `cis-mappings.json` |
| Microsoft Cloud Security Benchmark | 53 | `mcsb-mappings.json` |
| PCI DSS v4.0 | 51 | `pci-dss-mappings.json` |
| ISO 27001:2022 | 51 | `iso-27001-mappings.json` |
| SOC 2 Type II | 47 | `soc2-mappings.json` |
| HIPAA Security Rule | 43 | `hipaa-mappings.json` |
| NIST Cybersecurity Framework | 29 | `nist-csf-mappings.json` |
| CSA Cloud Controls Matrix | 24 | `csa-ccm-mappings.json` |
| GDPR | 22 | `gdpr-mappings.json` |

## Evaluation Domains

| Domain | Check Functions | Key Checks |
|--------|----------------|------------|
| **Access Control** | 8 | RBAC separation, least privilege, conditional access, custom roles, account management, managed identity hygiene |
| **Identity & Auth** | 22 | MFA coverage, app credentials, user lifecycle, risky users, OAuth2 consent, cross-tenant, workload identity, auth methods |
| **Data Protection** | 22 | Encryption in transit/at rest, Key Vault expiry, VM/WebApp/SQL/AKS/CosmosDB/Functions/messaging/Redis hardening, Purview |
| **Logging & Monitoring** | 13 | Diagnostic coverage ≥80%, threat detection, flow logs, activity analysis, sign-in monitoring, audit logging, retention |
| **Network Security** | 16 | NSG rules, storage firewalls, Azure Firewall, route tables, DNS, AKS advanced, APIM, Front Door/CDN, WAF |
| **Governance & Risk** | 21 | Policy compliance ≥80%, Defender plans, PIM, access reviews, resource locks, AI governance, regulatory compliance |
| **Incident Response** | 6 | Security contacts, detection, alerting, investigation readiness, Sentinel monitoring, alert response coverage |
| **Change Management** | 4 | Change control policies, resource lock governance, change tracking, policy enforcement |
| **Business Continuity** | 4 | Backup configuration, geo-redundancy, VM availability, database resilience |
| **Asset Management** | 4 | Asset inventory, classification/tagging, authorized software, application inventory |

## Repository Structure

```
EnterpriseSecurityIQ/
├── README.md                              # This file
├── AIAgent/                               # Python AI Agent (primary implementation)
│   ├── main.py                            # Foundry agent hosting adapter (port 8088)
│   ├── agent.yaml                         # Agent definition for Foundry
│   ├── Dockerfile                         # Container build for deployment
│   ├── requirements.txt                   # Python dependencies (80+ packages)
│   ├── run_assessment.py                  # CLI: Full compliance assessment
│   ├── run_query.py                       # CLI: Interactive ARG/Graph query REPL
│   ├── run_risk_analysis.py               # CLI: Security risk gap analysis
│   ├── run_data_security.py               # CLI: Data security assessment
│   ├── run_rbac_report.py                 # CLI: RBAC hierarchy report
│   ├── run_copilot_readiness.py           # CLI: M365 Copilot readiness assessment
│   ├── run_ai_agent_security.py           # CLI: AI agent security assessment
│   └── app/
│       ├── agent.py                       # System prompt + 14 Foundry tools
│       ├── orchestrator.py                # Concurrent collector → evaluator → report pipeline
│       ├── auth.py                        # Multi-mode auth (Auto/ServicePrincipal/AzureCLI)
│       ├── config.py                      # Environment + JSON file configuration
│       ├── models.py                      # Typed dataclasses with deterministic UUIDs
│       ├── query_engine.py                # ARG + Graph interactive query engine
│       ├── risk_engine.py                 # Security risk gap analysis (4 categories)
│       ├── data_security_engine.py        # Data security assessment (12 categories)
│       ├── copilot_readiness_engine.py    # M365 Copilot readiness (9+ categories)
│       ├── ai_agent_security_engine.py    # AI agent security (6 platforms, 23+ areas)
│       ├── postureiq_orchestrator.py      # PostureIQ: independent risk-weighted posture assessment
│       ├── data_residency_engine.py       # Data residency compliance (5 checks)
│       ├── remediation_engine.py          # Automated remediation plan generation
│       ├── continuous_monitor.py          # Scheduled re-assessments with drift detection
│       ├── siem_integration.py            # Sentinel, Splunk, generic webhook export
│       ├── operational_integrations.py    # ServiceNow, Jira, Azure DevOps connectors
│       ├── collectors/
│       │   ├── registry.py                # Auto-discovery @register_collector decorator
│       │   ├── base.py                    # Retry logic, pagination, access-denied handling
│       │   ├── inventory.py               # Shared resource inventory cache
│       │   ├── azure/ (49 collectors)     # ARM SDK + data-plane: 29 resource categories
│       │   └── entra/ (18 collectors)     # Graph SDK: users, MFA, CA, roles, apps, PIM, risk…
│       ├── evaluators/
│       │   ├── engine.py                  # Multi-framework evaluation engine
│       │   └── ... (10 domain evaluators + plugins + suppressions)
│       ├── postureiq_evaluators/           # PostureIQ evaluators (18 files)
│       │   ├── engine.py                  # Risk-weighted scoring (severity × exploitability × blast radius)
│       │   ├── attack_paths.py            # Attack path analysis (privilege escalation, lateral movement)
│       │   ├── priority_ranking.py        # ROI-based remediation ranking
│       │   ├── ai_fix_recommendations.py  # GPT-powered remediation scripts
│       │   └── ... (10 domain evaluators + plugins + suppressions)
│       ├── postureiq_frameworks/ (11 JSON) # PostureIQ framework mappings (independent copies)
│       ├── postureiq_reports/ (20 files)  # PostureIQ report generators
│       ├── frameworks/ (11 mappings)      # Compliance framework control definitions
│       └── reports/ (29 modules)          # HTML, JSON, MD, Excel, OSCAL, SARIF, PDF…
├── webapp/                                # 11 self-contained HTML SPAs with MSAL auth
│   ├── index.html                         # Portal — card-grid launcher
│   ├── EnterpriseSecurityIQ.html          # Full dashboard
│   ├── PostureIQ.html                     # PostureIQ posture assessment
│   └── ... (8 more focused assessment SPAs)
├── config/
│   ├── enterprisesecurityiq.config.json   # Reference configuration file
│   └── config.schema.json                 # JSON Schema for config validation
├── schemas/                               # JSON schemas for data validation
├── examples/                              # Sample data for reference
├── docs/                                  # Documentation (MD + interactive HTML)
└── output/                                # Generated assessment outputs (gitignored)
```

## Prerequisites

- **Python 3.10+**
- Azure subscription with **Reader** + **Security Reader** roles
- Entra ID directory read permissions (for Graph collectors)
- Microsoft Foundry project with a deployed model (for agent mode)

### Required Azure Permissions (Read-Only)

| Role | Scope | Purpose |
|------|-------|---------|
| **Reader** | Subscription | All ARM resource enumeration and configuration reads |
| **Security Reader** | Subscription | Defender plans, security contacts, auto-provisioning |
| **Key Vault Secrets User** | Key Vault | Secret expiry data-plane audit |
| **Key Vault Certificates Officer** | Key Vault | Certificate expiry data-plane audit |
| **Key Vault Crypto User** | Key Vault | Key expiry data-plane audit |

### Required Microsoft Graph Permissions

| Permission | Purpose |
|-----------|---------|
| `Directory.Read.All` | Tenant info, OAuth2 grants, directory roles |
| `User.Read.All` | Users, group membership |
| `Group.Read.All` | Groups |
| `Application.Read.All` | App registrations, service principals, federated credentials |
| `RoleManagement.Read.All` | Role assignments, definitions, PIM eligibility, PIM policies |
| `Policy.Read.All` | CA policies, security defaults, auth policy, cross-tenant, named locations, auth methods |
| `AuditLog.Read.All` | Sign-in logs, directory audits (requires Entra ID P1/P2) |
| `UserAuthenticationMethod.Read.All` | MFA registration details |
| `IdentityRiskEvent.Read.All` | Risk detections (requires Entra ID P2) |
| `IdentityRiskyUser.Read.All` | Risky users |
| `IdentityRiskyServicePrincipal.Read.All` | Risky service principals |
| `AccessReview.Read.All` | Access review definitions |
| `EntitlementManagement.Read.All` | Access packages |
| `Agreement.Read.All` | Terms of use |
| `InformationProtection.Read` | Sensitivity labels (Purview) |

## Quick Start

### 1. Install dependencies

```bash
cd AIAgent
pip install -r requirements.txt
```

### 2. Authenticate

```bash
az login
```

The agent uses unified authentication — a single `DefaultAzureCredential` for both ARM and Graph operations (no browser popup required). A preflight check verifies permissions before the assessment starts.

| Mode | Configuration |
|------|---------------|
| **Auto** (default) | `az login` — used for both ARM and Graph |
| **ServicePrincipal** | Set `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` (uses SP for both) |

### 3. Configure (optional)

Set environment variables or point to a JSON config file:

```bash
# Environment variables
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export ENTERPRISESECURITYIQ_FRAMEWORKS="fedramp,cis,nist-800-53"

# Or use a JSON config file
export ENTERPRISESECURITYIQ_CONFIG="config/enterprisesecurityiq.config.json"
```

### 4. Run as AI Agent (Foundry)

```bash
python main.py
# Agent server starts on http://localhost:8088
```

### 5. Review Output

Assessment results are written to `output/<timestamp>/`:

| File | Description |
|------|-------------|
| `compliance-report.html` | Interactive HTML report with sidebar nav, score ring, domain cards, framework summaries, remediation roadmap |
| `compliance-report.json` | Structured JSON with all findings, evidence, and framework metadata |

## How It Works

```
┌──────────────────┐    ┌──────────────┐    ┌──────────────────┐    ┌───────────────┐    ┌──────────┐
│    Collectors     │───>│ Normalization│───>│    Evaluator     │───>│    Reports     │───>│  Output  │
│ 50 Azure + 18    │    │   Layer      │    │     Engine       │    │   Generator    │    │  Files   │
│ Entra (async)    │    │ (base.py)    │    │(11 frameworks,   │    │(29 modules,    │    │          │
│                  │    │              │    │ 10 domains,      │    │ 8 formats)     │    │          │
│                  │    │              │    │ 120 checks)      │    │                │    │          │
└──────────────────┘    └──────────────┘    └──────────────────┘    └───────────────┘    └──────────┘
      │                        │                    │                       │
      │ ARM + Graph SDK        │ 200+ evidence      │ Findings +           │ HTML, JSON, MD,
      │ (async, retry,         │ types (unified      │ control results      │ Excel, OSCAL,
      │  pagination,           │  PascalCase dicts)  │ (per framework)      │ SARIF, PDF
      │  checkpoint)           │                     │                      │
```

1. **Collectors** (68 async) call Azure ARM, data-plane, MS Graph, and Power Platform APIs with retry, pagination, and checkpoint resume
2. **Normalization** converts raw data into unified evidence dicts with deterministic UUID5 IDs
3. **Evaluator Engine** iterates all selected frameworks, dispatches to 10 domain evaluators running 120 check functions
4. **Report Generator** produces professional reports in 8 formats with SHA-256 integrity hashes

## Safety Guarantees

- **ALL operations are GET/READ only** — no PUT, POST, PATCH, DELETE calls
- Azure collectors use ARM SDK read-only methods
- Graph collectors use Graph SDK read-only methods
- No resource state is modified
- No secrets or credentials are stored in output files
- PII in user records is summarized (counts), not exported in full

## Report Integrity Verification

Every generated report includes a **SHA-256 hash** in its metadata — a cryptographic fingerprint computed from the report content at generation time. This serves as a tamper-evidence seal for audit purposes.

### Verifying a Report

Compare the hash shown in the report with a freshly computed hash of the file:

**PowerShell** (built-in):
```powershell
Get-FileHash "output\<timestamp>\MCSB\compliance-report.html" -Algorithm SHA256
```

**Command Prompt**:
```cmd
certutil -hashfile "output\<timestamp>\MCSB\compliance-report.html" SHA256
```

**Python**:
```python
python -c "import hashlib; print(hashlib.sha256(open(r'output\<timestamp>\MCSB\compliance-report.html','rb').read()).hexdigest())"
```

If the computed hash **matches** the hash in the report → the report is untampered.
If they **differ** → the report content was modified after generation.

> **Note:** The hash is computed before it is embedded in the report, so re-hashing the file will always produce a consistent result for verification. SHA-256 is computationally infeasible to forge.

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| `DefaultAzureCredential failed` | Run `az login` or set service principal env vars (ARM) |
| `Insufficient privileges` | Ensure Reader role and Graph read permissions |
| `Module not found` | Run `pip install -r AIAgent/requirements.txt` |
| `Partial collection` | The orchestrator continues on partial failures; check logs for errors |

## Using with GitHub Copilot

PostureIQ can be run directly from GitHub Copilot Chat in VS Code. Use the following example prompt:

```
provide Assessment on tenant "<TenantID>", using account "<USER UPN>" based on NIST, CIS, HIPAA, PCI-DSS, FedRAMP, SOC
```

**Example:**

```
provide Assessment on tenant "0527ecb7-06fb-4769-b324-fd4a3bb865eb", using account "admin@contoso.com" based on NIST, CIS, HIPAA, PCI-DSS, FedRAMP, SOC
```

> **Note:** Ensure you have already authenticated with `az login --tenant <TenantID>` before running the prompt. The authenticated user must have the required Azure and Entra ID roles listed in the [Prerequisites](#prerequisites) section.
| `Key Vault access denied` | Ensure Key Vault RBAC or access policy grants List permissions |

## License

Internal use only. Not for distribution.