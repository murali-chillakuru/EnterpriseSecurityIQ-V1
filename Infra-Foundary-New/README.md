# Infra-Foundary-New — New Foundry Deployment

Infrastructure-as-Code for deploying EnterpriseSecurityIQ on **Microsoft Foundry** (New Architecture).

## Why "New Foundry"?

The classic deployment used **ML Hub + ML Project** (`Microsoft.MachineLearningServices/workspaces`) which only appeared in the **Foundry (classic)** portal.

The new architecture uses the **Current** resource model per [Microsoft Foundry docs](https://learn.microsoft.com/en-us/azure/foundry/what-is-foundry):
- **Foundry Resource** (`Microsoft.CognitiveServices/accounts`, kind: `AIServices`) with custom domain and `allowProjectManagement` enabled
- **Foundry Project** (`Microsoft.CognitiveServices/accounts/projects`) — child resource visible in the **New Foundry** portal at ai.azure.com

This makes the deployment **visible and manageable** in the Microsoft Foundry portal (New Foundry toggle ON).

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Resource Group: ESIQNew-RG  (swedencentral)                    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Foundry Resource: ESIQNew-AI                             │  │
│  │  (CognitiveServices/accounts, kind: AIServices)           │  │
│  │  custom domain: esiqnew-ai                                │  │
│  │  allowProjectManagement: true                             │  │
│  │  ├── model: gpt-4.1 (Standard 30K TPM)                   │  │
│  │  ├── model: gpt-5.1 (Standard 30K TPM)                   │  │
│  │  │                                                        │  │
│  │  └── Foundry Project: ESIQNew-project  ← visible in      │  │
│  │       New Foundry portal (ai.azure.com)                   │  │
│  │       (CognitiveServices/accounts/projects)               │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────┐                        │
│  │  ESIQNew-env (Container Apps Env)   │                        │
│  │  ┌───────────────────────────────┐  │                        │
│  │  │  esiqnew-agent                │  │                        │
│  │  │  1 vCPU / 2 GiB, port 8088   │  │                        │
│  │  │  external ingress             │  │                        │
│  │  └───────────────────────────────┘  │                        │
│  └─────────────────────────────────────┘                        │
│                                                                  │
│  ESIQNew-identity (MI) ─── RBAC: AcrPull, Reader,               │
│       Security Reader, Cognitive Services OpenAI User,           │
│       Azure AI Developer                                         │
└──────────────────────────────────────────────────────────────────┘
```

## Resources Created (12)

| # | Resource | Name | Type / SKU |
|---|----------|------|-----------|
| 1 | Resource Group | `ESIQNew-RG` | swedencentral |
| 2 | Foundry Resource | `ESIQNew-AI` | S0, custom domain, allowProjectManagement |
| 3 | Foundry Project | `ESIQNew-AI/ESIQNew-project` | CognitiveServices/accounts/projects |
| 4 | gpt-4.1 model | on ESIQNew-AI | Standard 30K TPM |
| 5 | gpt-5.1 model | on ESIQNew-AI | Standard 30K TPM |
| 6 | Storage Account | `esiqnewstorage` | Standard_LRS |
| 7 | Key Vault | `ESIQNew-kv` | Standard, RBAC auth |
| 8 | Log Analytics | `ESIQNew-law` | PerGB2018 |
| 9 | Application Insights | `ESIQNew-appinsights` | Workspace-based |
| 10 | Container Registry | `esiqnewacr` | Basic |
| 11 | Managed Identity | `ESIQNew-identity` | User-assigned |
| 12 | Container Apps Env | `ESIQNew-env` | Consumption |
| — | Container App | `esiqnew-agent` | 1 vCPU / 2 GiB |

## Scripts

| Script | Purpose |
|--------|---------|
| `deploy.ps1` | Full end-to-end deployment (14 steps, idempotent) |
| `redeploy-image.ps1` | Quick ACR rebuild + container restart after code changes |

## Usage

### Full Deployment

```powershell
.\Infra-Foundary-New\deploy.ps1
```

With custom parameters:

```powershell
.\Infra-Foundary-New\deploy.ps1 -BaseName "MyApp" -Location "eastus2" -SubscriptionName "MySubscription"
```

### Rebuild After Code Changes

```powershell
.\Infra-Foundary-New\redeploy-image.ps1
```

## Parameters (deploy.ps1)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-BaseName` | `ESIQNew` | Prefix for all resource names |
| `-Location` | `swedencentral` | Azure region |
| `-SubscriptionName` | `AI` | Subscription name |
| `-PrimaryModel` | `gpt-4.1` | Primary model deployment |
| `-FallbackModel` | `gpt-5.1` | Fallback model deployment |
| `-ModelSku` | `Standard` | Model SKU (Standard or GlobalStandard) |
| `-ModelCapacity` | `30` | Tokens-per-minute in thousands |
| `-TenantId` | (auto-detect) | Azure AD tenant ID |

---

## Option A+B: SPA + Foundry Agent

The deployment now supports a **combined dual delivery model** (Option A+B):

- **Option A (SPA)**: Web dashboard served from the Container App at `/`, using MSAL.js for SSO auth
- **Option B (Foundry Agent)**: Agent registered in Foundry via Assistants API on startup, visible in ai.azure.com

Both options share the same 12 agent tools and Azure OpenAI backend.

### Updated Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Resource Group: ESIQNew-RG                                              │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Foundry Resource: ESIQNew-AI (CognitiveServices/accounts)         │ │
│  │  ├── gpt-4.1 (Standard 30K TPM)                                    │ │
│  │  ├── gpt-5.1 (Standard 30K TPM)                                    │ │
│  │  └── Foundry Project: ESIQNew-project                              │ │
│  │       └── Foundry Agent: asst_N4hpInCl30eZHaim3vtJTZiT            │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Container App: esiqnew-agent (1 vCPU / 2 GiB, port 8088)         │ │
│  │                                                                     │ │
│  │  Option A Path:                  Option B Path:                     │ │
│  │  Browser → MSAL.js → SPA        ai.azure.com → Foundry Agent      │ │
│  │   └→ GET / (dashboard)           └→ Assistants API                 │ │
│  │   └→ POST /chat (agent)           └→ Same 12 tools                 │ │
│  │   └→ POST /assessments                                             │ │
│  │   └→ GET /assessments/{id}                                         │ │
│  │   └→ GET /health                                                   │ │
│  │                                                                     │ │
│  │  On Startup: Registers Foundry Agent via Assistants API            │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ESIQNew-identity (MI) → AcrPull, Reader, Security Reader,              │
│       Cognitive Services OpenAI User, Azure AI Developer                 │
│                                                                          │
│  App Registration: ESIQNew-Dashboard (PENDING — requires Directory admin)│
└──────────────────────────────────────────────────────────────────────────┘
```

### Updated Resource Count (14)

| # | Resource | Name | Type / SKU |
|---|----------|------|-----------|
| 1–12 | *(original resources)* | *(see above)* | *(see above)* |
| 13 | App Registration | `ESIQNew-Dashboard` | SPA, PENDING |
| 14 | Foundry Agent | `EnterpriseSecurityIQ` | Assistants API, 12 tools |

### Updated Deploy Steps (16)

`deploy.ps1` now has **16 steps** (was 14):

| Step | Action |
|------|--------|
| 1–14 | *(original steps)* |
| 15 | Create Container App (serves SPA + API) |
| 16 | Register Foundry Agent (Assistants API) |

## Prerequisites

- Azure CLI >= 2.67+
- Subscription with Contributor or Owner role
- `Microsoft.CognitiveServices` provider registered
