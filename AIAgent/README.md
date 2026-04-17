# PostureIQ — AI Compliance Assessment Agent

**Author:** Murali Chillakuru

> **Executive Summary** — Quick reference for the AI Compliance Assessment Agent:
> architecture, 10 evaluation domains, 12 agent tools, 10 CLI scripts, and deployment guide.
>
> | | |
> |---|---|
> | **Audience** | Agent developers, operators |
> | **Prerequisites** | [README](../README.md) for project overview |
> | **Companion docs** | [Architecture](../docs/architecture.md) · [Usage Guide](../docs/PROMPTS.md) |

An AI-powered compliance assessment agent built with the Microsoft Agent Framework SDK. Runs as a hosted agent on Microsoft Foundry or standalone via CLI. Collects evidence from Azure subscriptions, Entra ID, M365 services, and AI platforms, evaluates against 11 compliance frameworks (525 controls), and generates professional compliance reports in 8 formats.

## Architecture

```
main.py                              Foundry agent hosting adapter (port 8088)
├── app/agent.py                     System prompt + 12 tools (see Agent Tools below)
├── app/orchestrator.py              Concurrent collector → evaluator → report pipeline
├── app/collectors/
│   ├── registry.py                  Auto-discovery @register_collector decorator
│   ├── base.py                      Retry logic, pagination, access-denied handling
│   ├── inventory.py                 Shared resource inventory cache
│   ├── azure/ (50 collectors)       ARM SDK + data-plane: 29 resource categories
│   └── entra/ (18 collectors)       Graph SDK: users, MFA, CA, roles, apps, PIM, risk…
├── app/evaluators/ (10 domains)     113 evaluation functions with compliance thresholds
├── app/frameworks/                  11 framework mappings (525 controls)
├── app/reports/                     28 report generators (HTML, MD, Excel, OSCAL, SARIF, PDF…)
├── app/query_engine.py              ARG + Graph interactive query engine (714 lines)
├── app/risk_engine.py               Security risk gap analysis — 4 categories (1,124 lines)
├── app/data_security_engine.py      Data security assessment — 12 categories (9,085 lines)
├── app/copilot_readiness_engine.py  M365 Copilot readiness — 9+ categories (5,090 lines)
├── app/ai_agent_security_engine.py  AI agent security — 6 platforms, 23+ areas (5,968 lines)
├── app/data_residency_engine.py     Data residency compliance — 5 checks (296 lines)
├── app/remediation_engine.py        Automated remediation plans — 7 rules (299 lines)
├── app/continuous_monitor.py        Scheduled re-assessments with drift detection (196 lines)
├── app/siem_integration.py          Sentinel, Splunk, generic webhook export (156 lines)
├── app/operational_integrations.py  ServiceNow, Jira, Azure DevOps connectors (443 lines)
├── app/auth.py                      Unified DefaultAzureCredential (ARM + Graph) with preflight
├── app/blob_store.py                Azure Blob Storage persistence for reports (upload/download/list)
├── app/config.py                    Environment-driven configuration with 17 thresholds
├── app/models.py                    Typed dataclasses with deterministic UUID5 IDs
├── app/i18n.py                      Locale-based string localization
└── app/logger.py                    Structured logging
```

## Domains & Controls (10 domains, 113 check functions)

| Domain | Evaluator | Controls | Key Checks |
|--------|-----------|----------|------------|
| **Access Control** | `access.py` | AC-2, AC-3, AC-5, AC-6 | RBAC separation, least privilege, conditional access |
| **Identity & Auth** | `identity.py` | IA-2, IA-5, IA-8 + 12 sub-controls | MFA coverage, app credentials, user lifecycle, risky users |
| **Data Protection** | `data_protection.py` | SC-8, SC-12, SC-13, SC-28 | Encryption in transit/at rest, Key Vault, VM/SQL/AKS security |
| **Logging & Monitoring** | `logging_eval.py` | AU-2, AU-6, SI-4 + 5 sub-controls | Diagnostic coverage ≥80%, threat detection, sign-in monitoring |
| **Network Security** | `network.py` | SC-7 + 4 sub-controls | NSG rules, storage firewall, Azure Firewall, route tables |
| **Governance & Risk** | `governance.py` | CM-2, CM-7, CA-7, RA-5, SI-2 + 7 sub-controls | Policy compliance ≥80%, Defender plans, PIM, access reviews |
| **Asset Management** | `asset_management.py` | AM-1 through AM-4 | Resource inventory, tagging, lifecycle tracking |
| **Change Management** | `change_management.py` | CM-3, CM-5 | Change control, deployment gates, approval workflows |
| **Incident Response** | `incident_response.py` | IR-4, IR-5, IR-6 | Incident playbooks, Sentinel integration, response automation |
| **Business Continuity** | `business_continuity.py` | CP-2, CP-4, CP-9, CP-10 | Backup coverage, disaster recovery, geo-redundancy |

## Agent Tools

The Foundry-hosted agent exposes 12 tools via `app/agent.py`:

| Tool | Description | Underlying Engine |
|------|-------------|-------------------|
| `run_assessment` | Run full or scoped compliance assessment. Accepts `scope`: `"full"` or comma-separated domains. | `orchestrator.py` |
| `query_results` | Query findings by control ID, domain, severity, or natural language question. | In-memory search |
| `search_tenant` | Live Azure Resource Graph (KQL) and MS Graph queries with natural-language support. | `query_engine.py` |
| `analyze_risk` | Security risk gap analysis across identity, network, Defender, and config categories. | `risk_engine.py` |
| `assess_data_security` | Data security assessment: storage exposure, DB security, encryption, key hygiene, classification. | `data_security_engine.py` |
| `generate_rbac_report` | RBAC hierarchy tree report (Management Groups → Subscriptions → RGs) with PIM and risk analysis. | `rbac_collector` + `rbac_report` |
| `assess_copilot_readiness` | M365 Copilot readiness: oversharing, sensitivity labels, DLP, restricted search, access governance. | `copilot_readiness_engine.py` |
| `assess_ai_agent_security` | AI agent security across Copilot Studio, Foundry, and custom agents. | `ai_agent_security_engine.py` |
| `generate_report` | Regenerate HTML/JSON reports from cached assessment results. | Report generators |
| `check_permissions` | Probe ARM access, Graph scopes, and Entra directory roles before running assessments. | `auth.py` preflight |
| `compare_runs` | Compare current vs. previous assessment: new findings, resolved, status changes, score drift. | `delta_report.py` |
| `search_exposure` | Surface exposure patterns: public storage, open NSGs, unencrypted VMs, unattached disks, public IPs. | `query_engine.py` ARG templates |

## CLI Tools

10 standalone scripts for running each capability directly from the command line. Run from the `AIAgent/` directory.

| Script | Purpose | Example |
|--------|---------|---------|
| `run_assessment.py` | Full compliance assessment against one or more frameworks | `python run_assessment.py --tenant <id> --framework PCI-DSS HIPAA` |
| `run_query.py` | Interactive query REPL for ARG and MS Graph | `python run_query.py --tenant <id>` |
| `run_risk_analysis.py` | Security risk gap analysis | `python run_risk_analysis.py --tenant <id>` |
| `run_data_security.py` | Data security assessment | `python run_data_security.py --tenant <id>` |
| `run_rbac_report.py` | RBAC hierarchy tree report with PIM and risk analysis | `python run_rbac_report.py --tenant <id>` |
| `run_copilot_readiness.py` | M365 Copilot readiness assessment | `python run_copilot_readiness.py --tenant <id>` |
| `run_ai_agent_security.py` | AI agent security assessment | `python run_ai_agent_security.py --tenant <id>` |
| `run_assessment_determinism_check.py` | Verify assessment pipeline produces deterministic results | `python run_assessment_determinism_check.py` |
| `run_rbac_determinism_check.py` | Verify RBAC report produces deterministic results | `python run_rbac_determinism_check.py` |
| `run_cr_determinism_check.py` | Verify Copilot readiness produces deterministic results | `python run_cr_determinism_check.py` |

## Prerequisites

- Python 3.10+
- Azure subscription with **Reader** + **Security Reader** roles
- Entra ID with directory read permissions (for Graph collectors)
- Microsoft Foundry project with a deployed model (e.g. `gpt-4.1`)

## Quick Start

### 1. Install dependencies

```bash
cd AIAgent
pip install -r requirements.txt
pip install debugpy agent-dev-cli --pre
```

### 2. Configure environment

```bash
cp .env.template .env
# Edit .env with your Foundry project endpoint and model deployment name
```

Required variables:

- `FOUNDRY_PROJECT_ENDPOINT` — Your Foundry project endpoint URL
- `FOUNDRY_MODEL_DEPLOYMENT_NAME` — Deployed model name (default: `gpt-4.1`)
- `AZURE_TENANT_ID` — (Optional) Target Azure AD tenant

### 3. Authenticate

```bash
az login
```

The agent uses unified authentication: a single `DefaultAzureCredential` for both ARM and Graph operations (picks up your `az login` session — no browser popup required). A preflight permissions check runs before each assessment to verify ARM access, Graph connectivity, and Entra directory roles.

### 4. Run locally

```bash
python main.py
# Agent server starts on http://localhost:8088
```

### 5. Debug with AI Toolkit Inspector

In VS Code, press **F5** and select **Debug PostureIQ Agent (HTTP Server)**. This launches the agent with `agentdev` instrumentation and opens the AI Toolkit Agent Inspector.

## Deploy to Foundry

### Build & push container

```bash
docker build --platform linux/amd64 -t enterprisesecurityiq-agent .
# Tag and push to your ACR
docker tag enterprisesecurityiq-agent <your-acr>.azurecr.io/enterprisesecurityiq-agent:latest
docker push <your-acr>.azurecr.io/enterprisesecurityiq-agent:latest
```

### Create hosted agent

Use the Foundry portal or CLI to create a hosted agent pointing to your container image. The agent exposes port 8088 and uses the `responses` protocol v1.

## SDK Versions

```
agent-framework-azure-ai==1.0.0rc3
agent-framework-core==1.0.0rc3
azure-ai-agentserver-agentframework==1.0.0b16
azure-ai-agentserver-core==1.0.0b16
msgraph-sdk==1.12.0
msgraph-beta-sdk==1.12.0
```

## Testing

15 test files · 1,357 test functions · 14,915 lines of test code.

| Category | Files | Coverage |
|----------|-------|----------|
| **Evaluator Unit Tests** | `test_evaluators.py` | All 10 evaluation domains, 113 check functions |
| **Engine Unit Tests** | `test_risk_engine.py`, `test_data_security_engine.py`, `test_copilot_readiness_engine.py`, `test_ai_agent_security_engine.py`, `test_query_engine.py` | All standalone engines |
| **Report Tests** | `test_reports.py`, `test_report_determinism.py` | 28 report generators, output determinism |
| **Determinism Tests** | `test_determinism.py`, `test_assessment_determinism.py`, `test_rbac_determinism.py`, `test_copilot_readiness_determinism.py`, `test_ai_agent_security_determinism.py` | Pipeline repeatability with fixed inputs |
| **Integration Tests** | `test_enhancements.py`, `test_dry_run_ds.py` | End-to-end pipeline, dry-run data security |

Run all tests:

```bash
cd AIAgent
python -m pytest tests/ -v
```
