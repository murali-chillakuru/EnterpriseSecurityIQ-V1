# Option A+B Architecture — SPA + Foundry Agent

> Author: Murali Chillakuru — April 12, 2026

## Overview

PostureIQ uses a **dual delivery model** combining two deployment options into a single Container App:

- **Option A (SPA)**: A web dashboard served from the Container App at `/`, using MSAL.js for SSO authentication. Provides an assessment runner, results viewer, and agent chat interface.
- **Option B (Foundry Agent)**: The agent is registered in the Foundry project via the Assistants API on container startup, making it visible in the ai.azure.com portal with built-in tracing, evaluations, and guardrails.

Both options share the **same 14 agent tools** and the same Azure OpenAI model backend. The Container App is the single deployment artifact.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Option A: SPA Dashboard                  Option B: Foundry Portal          │
│                                                                             │
│  ┌──────────────┐                        ┌─────────────────────┐           │
│  │   Browser     │                        │  ai.azure.com       │           │
│  │   (MSAL.js)  │                        │  Foundry Portal     │           │
│  └──────┬───────┘                        └──────────┬──────────┘           │
│         │ HTTPS                                     │ Assistants API       │
│         ▼                                           ▼                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Container App: esiqnew-agent (port 8088, FastAPI + uvicorn)       │   │
│  │                                                                     │   │
│  │  GET /         → SPA (static HTML/JS/CSS)                          │   │
│  │  POST /chat    → Agent chat (Azure OpenAI + function calling)      │   │
│  │  POST /assessments → Run assessment                                │   │
│  │  GET /assessments/{id} → Get results                               │   │
│  │  GET /health   → Health check                                      │   │
│  │                                                                     │   │
│  │  On Startup: Register agent in Foundry via Assistants API          │   │
│  │  Agent ID: asst_N4hpInCl30eZHaim3vtJTZiT                          │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  14 Agent Tools                                             │   │   │
│  │  │  run_postureiq_assessment · query_results · search_tenant    │   │   │
│  │  │  analyze_risk · assess_data_security · generate_rbac_report  │   │   │
│  │  │  generate_report · assess_copilot_readiness                  │   │   │
│  │  │  assess_ai_agent_security · check_permissions                │   │   │
│  │  │  compare_runs · search_exposure · generate_custom_report     │   │   │
│  │  │  query_assessment_history                                    │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │ Managed Identity                             │
│                             ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Azure OpenAI (gpt-4.1)  │  Microsoft Graph  │  Entra ID APIs      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | SPA web dashboard (static HTML/JS/CSS with MSAL.js) |
| `POST` | `/chat` | Agent chat — Azure OpenAI chat completions with function calling |
| `POST` | `/assessments` | Run a new security assessment |
| `GET` | `/assessments/{id}` | Retrieve assessment results by ID |
| `GET` | `/health` | Health check endpoint |

## Authentication Flows

### Option A — SPA Authentication

```
User → Browser → MSAL.js (Entra ID SSO)
  → Acquires Bearer token
  → POST /chat with Authorization: Bearer <token>
  → FastAPI validates token
  → Calls Azure OpenAI with function calling
  → Agent tools execute via Managed Identity
```

### Option B — Foundry Agent Authentication

```
User → ai.azure.com portal → Foundry Agent (Assistants API)
  → Azure OpenAI processes with function calling
  → Agent tools execute via Managed Identity
```

### Backend Authentication

```
Container App (Managed Identity)
  → Azure OpenAI: Cognitive Services OpenAI User role
  → Microsoft Graph / Entra ID: Security Reader role
  → Azure Resources: Reader role
```

## Agent Tools (14)

| # | Tool | Description | Key Parameters |
|---|------|-------------|----------------|
| 1 | `run_postureiq_assessment` | Run a full tenant security assessment | `tenant_id`, `assessment_type` |
| 2 | `query_results` | Query previous assessment results | `query`, `filters` |
| 3 | `search_tenant` | Search tenant configuration and policies | `search_term`, `scope` |
| 4 | `analyze_risk` | Analyze security risk posture | `tenant_id`, `risk_category` |
| 5 | `assess_data_security` | Evaluate data security controls | `tenant_id`, `data_scope` |
| 6 | `generate_rbac_report` | Generate RBAC role assignment report | `tenant_id`, `scope` |
| 7 | `generate_report` | Generate formatted security report | `assessment_id`, `format` |
| 8 | `assess_copilot_readiness` | Assess M365 Copilot readiness | `tenant_id` |
| 9 | `assess_ai_agent_security` | Assess AI agent security posture | `tenant_id` |
| 10 | `check_permissions` | Check current identity permissions | `resource_scope` |
| 11 | `compare_runs` | Compare two assessment runs | `run_id_1`, `run_id_2` |
| 12 | `search_exposure` | Search for security exposure indicators | `search_term`, `severity` |
| 13 | `generate_custom_report` | Generate custom cross-domain report | `domains`, `format` |
| 14 | `query_assessment_history` | Query and compare historical assessments | `query`, `time_range` |

## Foundry Agent Registration

On container startup, the agent self-registers in the Foundry project:

1. Container App starts FastAPI server on port 8088
2. Startup handler calls Azure OpenAI Assistants API
3. Creates/updates assistant with name `EnterpriseSecurityIQ`
4. Registers all 14 tools as function definitions
5. Agent becomes visible in ai.azure.com under the Foundry project
6. Agent ID: `asst_N4hpInCl30eZHaim3vtJTZiT`

The Foundry portal provides:
- **Tracing**: Built-in request/response tracing via Application Insights
- **Evaluations**: Run evals against the agent directly from the portal
- **Guardrails**: Content safety filters applied at the Azure OpenAI layer

## Deployment Steps (16)

| Step | Action |
|------|--------|
| 1 | Create Resource Group |
| 2 | Create Foundry Resource (AI Services) |
| 3 | Deploy gpt-4.1 model |
| 4 | Deploy gpt-5.1 model |
| 5 | Create Storage Account |
| 6 | Create Key Vault |
| 7 | Create Log Analytics Workspace |
| 8 | Create Application Insights |
| 9 | Create Container Registry |
| 10 | Create Foundry Project |
| 11 | Create Managed Identity |
| 12 | Assign RBAC roles |
| 13 | Create Container Apps Environment |
| 14 | Build & push Docker image to ACR |
| 15 | Create Container App (serves SPA + API) |
| 16 | Register Foundry Agent (Assistants API) |

## Prerequisites

- Azure subscription with Contributor access
- Azure CLI (`az`) installed
- Docker (for local builds)
- PowerShell 7+
- Azure OpenAI access enabled on the subscription
- Entra ID Directory Admin (for App Registration — optional, SPA works in demo mode without it)

## Container App Details

| Property | Value |
|----------|-------|
| Name | `esiqnew-agent` |
| FQDN | `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` |
| Image | `esiqnewacr.azurecr.io/esiqnew-agent:v4` |
| CPU / Memory | 1 vCPU / 2 GiB |
| Port | 8088 |
| Server | FastAPI + uvicorn |
| CORS | Enabled |
| Identity | ESIQNew-identity (user-assigned managed identity) |

## Foundry Agent Details

| Property | Value |
|----------|-------|
| Name | `EnterpriseSecurityIQ` |
| Agent ID | `asst_N4hpInCl30eZHaim3vtJTZiT` |
| Model | gpt-4.1 |
| Tools | 14 function-calling tools |
| Registration | Assistants API on container startup |
| Portal | Visible in ai.azure.com under ESIQNew-project |
