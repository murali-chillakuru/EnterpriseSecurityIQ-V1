# PostureIQ — Infrastructure Runbook

**Author:** Murali Chillakuru
**Last updated:** April 14, 2026

> **Purpose** — End-to-end technical runbook for provisioning, operating, rebuilding, and
> decommissioning the PostureIQ platform on any Azure tenant. Covers every Azure
> resource, identity configuration, deployment step, post-deployment validation, day-2
> operations, disaster recovery, and teardown procedures.
>
> | | |
> |---|---|
> | **Audience** | Platform engineers, DevOps, infrastructure operators |
> | **Prerequisites** | Azure CLI 2.67+, az logged in with Owner or Contributor + User Access Administrator on target subscription, Global Admin (or Privileged Role Admin) for Entra directory roles and Graph API consent |
> | **Companion docs** | [Infrastructure Blueprint](infrastructure-blueprint.md) · [Deployment Guide](deployment-guide.md) · [Authentication Architecture](authentication-architecture.md) · [Architecture](architecture.md) |

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Resource Inventory](#2-resource-inventory)
3. [Prerequisites & Pre-Flight](#3-prerequisites--pre-flight)
4. [Deployment Sequence — 16 Steps](#4-deployment-sequence--16-steps)
5. [Identity & RBAC Deep Dive](#5-identity--rbac-deep-dive)
6. [Post-Deployment Validation](#6-post-deployment-validation)
7. [Day-2 Operations](#7-day-2-operations)
8. [Rebuild in Same Tenant](#8-rebuild-in-same-tenant)
9. [Deploy to a Different Tenant](#9-deploy-to-a-different-tenant)
10. [Disaster Recovery & Rollback](#10-disaster-recovery--rollback)
11. [Monitoring & Alerting](#11-monitoring--alerting)
12. [Known Issues & Workarounds](#12-known-issues--workarounds)
13. [Teardown / Decommission](#13-teardown--decommission)
14. [Quick Reference — Commands](#14-quick-reference--commands)
15. [Permissions Deep Dive — Tool-to-Permission Mapping](#15-permissions-deep-dive--tool-to-permission-mapping)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        User Browser                                     │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  SPA (webapp/index.html)  — MSAL.js Redirect Flow       │           │
│  │  Framework selection · Theme toggle · SSE streaming       │           │
│  └──────────────────────┬───────────────────────────────────┘           │
│                         │ HTTPS + Bearer tokens (Graph + ARM)           │
└─────────────────────────┼───────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Azure Container Apps  (ESIQNew-env / esiqnew-agent)                    │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  FastAPI + Uvicorn (port 8088)                                │     │
│  │  POST /chat → SSE stream   GET /reports/* → file serving      │     │
│  │  AI Agent Engine — 13 Function-Calling Tools                  │     │
│  │  Uses USER-DELEGATED tokens for all assessments               │     │
│  └─────────┬────────────────────────┬────────────────────────────┘     │
│            │                        │                                   │
│   ┌────────▼────────┐    ┌─────────▼─────────────┐                     │
│   │ Azure AI Foundry │    │ Target Tenant APIs    │                     │
│   │ ESIQNew-AI       │    │ MS Graph v1.0 + beta  │                     │
│   │ gpt-4.1 (30K)   │    │ Azure ARM             │                     │
│   │ gpt-5.1 (30K)   │    │ (delegated tokens)    │                     │
│   └─────────────────┘    └───────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Authentication Model

| Identity | Used For | Token Type |
|----------|----------|------------|
| **User (MSAL.js)** | All assessments — Graph + ARM API calls | Delegated (user context) |
| **ESIQNew-identity (Managed Identity)** | ACR pull, Foundry agent registration, infrastructure-only | Application (no user context) |
| **ESIQNew-Dashboard (App Registration)** | SPA client — defines redirect URIs, declares delegated scopes | N/A (template only) |

> **Critical**: The `/chat` endpoint **requires** user-delegated tokens. Requests without valid `graph_token` and `arm_token` are rejected with HTTP 401. Assessments always run under the calling user's Entra permissions — no privilege escalation through the managed identity.

---

## 2. Resource Inventory

All resources use the `{BaseName}` prefix (production: `ESIQNew`).

| # | Resource | Type | Name | SKU | Region | Purpose |
|---|----------|------|------|-----|--------|---------|
| 1 | Resource Group | `Microsoft.Resources/resourceGroups` | `ESIQNew-RG` | — | northeurope | Logical container |
| 2 | Foundry Resource | `Microsoft.CognitiveServices/accounts` (kind: AIServices) | `ESIQNew-AI` | S0 | swedencentral | Azure OpenAI + Foundry hub |
| 3 | Foundry Project | `Microsoft.CognitiveServices/accounts/projects` | `ESIQNew-AI/ESIQNew-project` | — | swedencentral | ai.azure.com project |
| 4 | Primary Model | Model Deployment | `gpt-4.1` | Standard 30K TPM | swedencentral | Agent reasoning + tool calls |
| 5 | Fallback Model | Model Deployment | `gpt-5.1` | Standard 30K TPM | swedencentral | Complex / fallback tasks |
| 6 | Storage Account | `Microsoft.Storage/storageAccounts` | `esiqnewstorage` | Standard_LRS | swedencentral | Report blob persistence |
| 7 | Key Vault | `Microsoft.KeyVault/vaults` | `ESIQNew-kv` | Standard (RBAC) | swedencentral | Secrets management |
| 8 | Log Analytics | `Microsoft.OperationalInsights/workspaces` | `ESIQNew-law` | PerGB2018 | swedencentral | Log aggregation |
| 9 | App Insights | `Microsoft.Insights/components` | `ESIQNew-appinsights` | Workspace-based | swedencentral | Telemetry |
| 10 | Container Registry | `Microsoft.ContainerRegistry/registries` | `esiqnewacr` | Basic | swedencentral | Docker image hosting |
| 11 | Managed Identity | `Microsoft.ManagedIdentity/userAssignedIdentities` | `ESIQNew-identity` | — | swedencentral | Passwordless infra auth |
| 12 | Container Apps Env | `Microsoft.App/managedEnvironments` | `ESIQNew-env` | Consumption | northeurope | Serverless hosting |
| 13 | Container App | `Microsoft.App/containerApps` | `esiqnew-agent` | 1 vCPU / 2 GiB | northeurope | Runs agent + SPA |
| 14 | App Registration | Entra ID | `ESIQNew-Dashboard` | — | — | MSAL SPA authentication |

---

## 3. Prerequisites & Pre-Flight

### Required Tools

| Tool | Minimum Version | Install |
|------|----------------|---------|
| Azure CLI | 2.67+ | `winget install Microsoft.AzureCLI` |
| Git | 2.40+ | `winget install Git.Git` |
| PowerShell | 7.4+ | Pre-installed on Windows 11 |

### Required Permissions

| Scope | Role | Why |
|-------|------|-----|
| Target subscription | **Contributor** | Create all Azure resources |
| Target subscription | **User Access Administrator** | Assign RBAC roles to managed identity |
| Entra ID tenant | **Global Administrator** (or Privileged Role Admin) | Grant Graph API application permissions to MI, assign directory roles, grant admin consent on App Registration |

### Pre-Flight Checklist

```powershell
# 1. Login and verify subscription
az login
az account set --subscription "AI"
az account show --query "{name:name, id:id, tenantId:tenantId}" -o table

# 2. Verify CLI version
az version --query '"azure-cli"' -o tsv   # must be 2.67+

# 3. Verify you have Owner/Contributor
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) \
    --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{role:roleDefinitionName, scope:scope}" -o table

# 4. Clone repository
git clone https://github.com/<org>/EnterpriseSecurityIQ.git
cd EnterpriseSecurityIQ
```

---

## 4. Deployment Sequence — 16 Steps

### Sequence Diagram

See the [interactive HTML version](infrastructure-runbook.html#deployment-sequence) for the animated Mermaid sequence diagram showing the full 16-step deployment flow with all Azure API interactions.

### One-Command Deployment

```powershell
.\Infra-Foundary-New\deploy.ps1 `
    -BaseName "ESIQNew" `
    -Location "swedencentral" `
    -SubscriptionName "AI"
```

### Step-by-Step Breakdown

#### Step 1: Resource Group

```powershell
az group create --name ESIQNew-RG --location swedencentral
```

Creates the logical container for all resources. Idempotent — skips if exists.

#### Step 2: Foundry Resource (AI Services)

```powershell
az cognitiveservices account create \
    --name ESIQNew-AI --resource-group ESIQNew-RG \
    --kind "AIServices" --sku "S0" \
    --location swedencentral

# Set custom domain (required for Foundry projects)
az cognitiveservices account update --name ESIQNew-AI --resource-group ESIQNew-RG \
    --custom-domain esiqnew-ai

# Enable project management via ARM REST API
az rest --method PATCH \
    --uri "https://management.azure.com/subscriptions/{subId}/resourceGroups/ESIQNew-RG/providers/Microsoft.CognitiveServices/accounts/ESIQNew-AI?api-version=2025-04-01-preview" \
    --body '{"properties":{"allowProjectManagement":true}}'
```

- Creates CognitiveServices account with kind `AIServices`
- Custom domain is required before Foundry projects can be created
- `allowProjectManagement` is set via REST API (not yet in stable CLI)
- Script polls `provisioningState` until `Succeeded`

#### Step 3: Foundry Project

```powershell
az rest --method PUT \
    --uri "https://management.azure.com{aiId}/projects/ESIQNew-project?api-version=2025-06-01" \
    --body '{"location":"swedencentral","identity":{"type":"SystemAssigned"},"properties":{}}'
```

- Creates a child project resource under the Foundry Resource
- Uses ARM REST API directly (2025-06-01 API version)
- Visible in [ai.azure.com](https://ai.azure.com) under "New Foundry" view
- Project endpoint used for agent registration: `https://esiqnew-ai.services.ai.azure.com/api`

#### Step 4–5: Model Deployments

```powershell
# Primary model
az cognitiveservices account deployment create \
    --name ESIQNew-AI --resource-group ESIQNew-RG \
    --deployment-name gpt-4.1 \
    --model-name gpt-4.1 --model-version "2025-04-14" \
    --model-format "OpenAI" --sku-name Standard --sku-capacity 30

# Fallback model
az cognitiveservices account deployment create \
    --name ESIQNew-AI --resource-group ESIQNew-RG \
    --deployment-name gpt-5.1 \
    --model-name gpt-5.1 --model-version "2025-11-13" \
    --model-format "OpenAI" --sku-name Standard --sku-capacity 30
```

- Both models: Standard SKU, 30K TPM (tokens per minute)
- `gpt-4.1` = primary for agent reasoning and tool calls
- `gpt-5.1` = fallback for complex tasks

#### Step 6: Storage Account

```powershell
az storage account create \
    --name esiqnewstorage --resource-group ESIQNew-RG \
    --location swedencentral --sku "Standard_LRS" \
    --kind "StorageV2" --min-tls-version "TLS1_2"
```

- Standard LRS (locally redundant)
- TLS 1.2 minimum enforced
- **Note**: `allowSharedKeyAccess` may be `false` due to Azure Policy (see [Known Issues](#12-known-issues--workarounds))

#### Step 7: Key Vault

```powershell
az keyvault create \
    --name ESIQNew-kv --resource-group ESIQNew-RG \
    --location swedencentral \
    --enable-rbac-authorization true
```

- RBAC authorization mode (no access policies)
- Available for future secret management

#### Step 8–9: Monitoring

```powershell
# Log Analytics
az monitor log-analytics workspace create \
    --resource-group ESIQNew-RG --workspace-name ESIQNew-law

# Application Insights
az monitor app-insights component create \
    --app ESIQNew-appinsights --resource-group ESIQNew-RG \
    --location swedencentral \
    --workspace {lawId}
```

- Log Analytics: PerGB2018 pricing tier
- App Insights: workspace-based, linked to LAW

#### Step 10: Container Registry

```powershell
az acr create --name esiqnewacr --resource-group ESIQNew-RG --sku "Basic"
```

- Basic SKU (10 GiB storage, sufficient for single image)
- No admin user enabled — uses managed identity for pull

#### Step 11: User-Assigned Managed Identity

```powershell
az identity create --name ESIQNew-identity --resource-group ESIQNew-RG
```

- User-assigned (not system-assigned) — survives container app recreation
- Used only for infrastructure operations, NOT for assessments

#### Step 12: RBAC Role Assignments

```powershell
# Azure RBAC roles
az role assignment create --assignee {principalId} --role "AcrPull" --scope {acrId}
az role assignment create --assignee {principalId} --role "Reader" --scope /subscriptions/{subId}
az role assignment create --assignee {principalId} --role "Security Reader" --scope /subscriptions/{subId}
az role assignment create --assignee {principalId} --role "Cognitive Services OpenAI User" --scope {aiId}
az role assignment create --assignee {principalId} --role "Azure AI Developer" --scope {aiId}

# Microsoft Graph API application permissions (8 permissions)
# Requires Global Admin — assigned via REST API to the MI's service principal
```

**Azure RBAC Roles (5):**

| Role | Scope | Purpose |
|------|-------|---------|
| AcrPull | Container Registry | Pull Docker images |
| Reader | Subscription | Read Azure resources (for CLI scripts only) |
| Security Reader | Subscription | Read Defender posture data (for CLI scripts only) |
| Cognitive Services OpenAI User | Foundry Resource | Call Azure OpenAI API |
| Azure AI Developer | Foundry Resource | Register/manage Foundry agents |

**Graph API Application Permissions (8):**

| Permission | Purpose |
|------------|---------|
| Directory.Read.All | Read directory objects (users, groups, roles) |
| Policy.Read.All | Read conditional access, authentication policies |
| RoleManagement.Read.All | Read PIM role assignments |
| User.Read.All | Read user profiles |
| AuditLog.Read.All | Read sign-in and audit logs |
| UserAuthenticationMethod.Read.All | Read MFA registration status |
| IdentityRiskyUser.Read.All | Read Identity Protection risky users |
| Application.Read.All | Read app registrations and service principals |

> **Note**: Graph permissions are for the **Managed Identity** (used by CLI scripts only). Web dashboard users authenticate via their own delegated tokens — the MI graph permissions are NOT used during web-based assessments.

#### Step 13: Container Apps Environment

```powershell
az containerapp env create \
    --name ESIQNew-env --resource-group ESIQNew-RG \
    --logs-workspace-id {lawCustomerId} \
    --location swedencentral
```

- Consumption plan (serverless, pay-per-use)
- Linked to Log Analytics for container logs
- **Can take 5–10 minutes** on first creation

#### Step 14: Build Image + Create Container App

```powershell
# Build via ACR Tasks (remote build, no local Docker needed)
az acr build --registry esiqnewacr --image esiqnew-agent:v1 \
    --file AIAgent/Dockerfile . --no-logs

# Create container app
az containerapp create \
    --name esiqnew-agent --resource-group ESIQNew-RG \
    --environment ESIQNew-env \
    --image esiqnewacr.azurecr.io/esiqnew-agent:v1 \
    --registry-server esiqnewacr.azurecr.io \
    --registry-identity {identityId} \
    --user-assigned {identityId} \
    --cpu 1 --memory "2Gi" \
    --min-replicas 0 --max-replicas 3 \
    --target-port 8088 --ingress external \
    --env-vars \
        "AZURE_OPENAI_ENDPOINT={aiEndpoint}" \
        "AZURE_OPENAI_DEPLOYMENT=gpt-4.1" \
        "AZURE_OPENAI_FALLBACK_DEPLOYMENT=gpt-5.1" \
        "AZURE_OPENAI_API_VERSION=2025-01-01-preview" \
        "FOUNDRY_PROJECT_ENDPOINT={projectEndpoint}" \
        "AZURE_CLIENT_ID={clientId}" \
        "AZURE_TENANT_ID={tenantId}"
```

**Container App Configuration:**

| Setting | Value |
|---------|-------|
| CPU | 1 vCPU |
| Memory | 2 GiB |
| Min replicas | 0 (scale to zero) |
| Max replicas | 3 |
| Port | 8088 |
| Ingress | External (HTTPS) |
| FQDN | `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` |

#### Step 15: Entra App Registration

```powershell
az ad app create \
    --display-name ESIQNew-Dashboard \
    --sign-in-audience "AzureADMyOrg" \
    --enable-access-token-issuance true \
    --enable-id-token-issuance true

az ad app update --id {appClientId} \
    --spa-redirect-uris "http://localhost:8080" "https://{fqdn}"
```

- Single-tenant SPA
- Redirect URIs: localhost (dev) + container app FQDN (prod)
- ID tokens + access tokens enabled

#### Step 16: Patch SPA Config + Rebuild

```powershell
# Script patches webapp/index.html in the repo:
# - clientId: "YOUR-CLIENT-ID-HERE" → clientId: "{appClientId}"
# - YOUR-TENANT-ID-HERE → {tenantId}
# - AGENT_URL placeholder → empty (same-origin)
# Then rebuilds the image and updates the container app
```

---

## 5. Identity & RBAC Deep Dive

### Identity Objects

```
┌──────────────────────────────────────────────────────────┐
│                    Entra ID Tenant                        │
│                                                          │
│  ┌───────────────────────────┐                           │
│  │ App Registration          │                           │
│  │ "ESIQNew-Dashboard"       │ ← SPA client definition   │
│  │ Delegated scopes only     │                           │
│  └───────────┬───────────────┘                           │
│              │ auto-creates                              │
│  ┌───────────▼───────────────┐                           │
│  │ Service Principal (SPN)   │                           │
│  │ Runtime identity for SPA  │ ← Admin consent here      │
│  │ Delegated permissions     │                           │
│  └───────────────────────────┘                           │
│                                                          │
│  ┌───────────────────────────┐                           │
│  │ Managed Identity          │                           │
│  │ "ESIQNew-identity"        │ ← Infra only (ACR,       │
│  │ Application permissions   │   Foundry, CLI scripts)   │
│  └───────────────────────────┘                           │
└──────────────────────────────────────────────────────────┘
```

### Post-Deployment Manual Steps (Global Admin Required)

**1. Grant admin consent on the App Registration:**

Navigate to: `Entra ID → App registrations → ESIQNew-Dashboard → API permissions → Grant admin consent`

**2. Assign Entra directory roles to the Managed Identity:**

Navigate to: `Entra ID → Roles and administrators`

| Role | Purpose |
|------|---------|
| Directory Reader | Read all directory objects (for CLI scripts) |
| Global Reader | Read-only access to all tenant settings (for CLI scripts) |

**3. If needed, assign Entra directory roles to assessment users:**

Users running assessments via the web dashboard need sufficient Entra permissions under their own identity. Recommended minimum:
- Security Reader (Entra role)
- Global Reader (Entra role)

---

## 6. Post-Deployment Validation

### Automated Checks

```powershell
# 1. Container app is running
az containerapp show --name esiqnew-agent --resource-group ESIQNew-RG \
    --query "{status:properties.runningStatus, fqdn:properties.configuration.ingress.fqdn}" -o table

# 2. Health check
$fqdn = az containerapp show --name esiqnew-agent --resource-group ESIQNew-RG \
    --query "properties.configuration.ingress.fqdn" -o tsv
Invoke-RestMethod "https://$fqdn/health"

# 3. Container logs (last 100 lines)
az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --tail 100

# 4. Verify managed identity RBAC
az role assignment list --assignee $(az identity show --name ESIQNew-identity --resource-group ESIQNew-RG --query principalId -o tsv) \
    --query "[].{role:roleDefinitionName, scope:scope}" -o table

# 5. Verify model deployments
az cognitiveservices account deployment list --name ESIQNew-AI --resource-group ESIQNew-RG -o table

# 6. Verify App Registration
az ad app list --display-name ESIQNew-Dashboard --query "[].{appId:appId, displayName:displayName}" -o table
```

### Manual Validation

1. Open `https://{fqdn}` in a browser
2. Login with MSAL (should redirect to Entra login)
3. Send a message: "What permissions do I have?"
4. Run a quick assessment: "Run a risk analysis"

---

## 7. Day-2 Operations

### Quick Redeploy (Code Changes Only)

```powershell
# Option A: Use the redeploy script
.\Infra-Foundary-New\redeploy-image.ps1 -Tag "v32-myfix"

# Option B: Manual commands
az acr build --registry esiqnewacr --image esiqnew-agent:v32-myfix \
    --file AIAgent/Dockerfile . --no-logs \
    --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')

az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG \
    --image esiqnewacr.azurecr.io/esiqnew-agent:v32-myfix -o table
```

> **Important**: Always use a NEW tag to force Container Apps to re-pull the image. Reusing a tag (e.g. `:latest`) may serve a cached version.

### View Logs

```powershell
# Real-time streaming
az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --follow

# Historical via Log Analytics (KQL)
az monitor log-analytics query --workspace ESIQNew-law \
    --analytics-query "ContainerAppConsoleLogs_CL | where ContainerAppName_s == 'esiqnew-agent' | top 50 by TimeGenerated" \
    -o table
```

### Scale Configuration

```powershell
# Adjust min/max replicas
az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG \
    --min-replicas 1 --max-replicas 5

# Check current replica count
az containerapp replica list --name esiqnew-agent --resource-group ESIQNew-RG -o table
```

### Update Environment Variables

```powershell
az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG \
    --set-env-vars "NEW_VAR=value" "EXISTING_VAR=newvalue"
```

### Rotate / Update Model Deployments

```powershell
# Delete old deployment
az cognitiveservices account deployment delete \
    --name ESIQNew-AI --resource-group ESIQNew-RG --deployment-name gpt-4.1

# Create new deployment with updated model version
az cognitiveservices account deployment create \
    --name ESIQNew-AI --resource-group ESIQNew-RG \
    --deployment-name gpt-4.1 \
    --model-name gpt-4.1 --model-version "2025-06-01" \
    --model-format "OpenAI" --sku-name Standard --sku-capacity 30
```

---

## 8. Rebuild in Same Tenant

If all resources are deleted and you need to rebuild in the same tenant:

```powershell
# Full rebuild — single command
.\Infra-Foundary-New\deploy.ps1 `
    -BaseName "ESIQNew" `
    -Location "swedencentral" `
    -SubscriptionName "AI"
```

**What the script handles automatically:**
- All 14 Azure resources recreated (idempotent — skips existing)
- RBAC roles reassigned
- Graph API permissions reassigned (requires Global Admin)
- Docker image rebuilt and deployed
- App Registration recreated with redirect URIs
- SPA config patched and image rebuilt

**What requires manual action after rebuild:**
1. Grant admin consent on App Registration (Entra portal)
2. Assign Directory Reader + Global Reader to managed identity (Entra portal)
3. If the FQDN changes, update any bookmarks or external references

---

## 9. Deploy to a Different Tenant

```powershell
# Login to the new tenant
az login --tenant "new-tenant-id"
az account set --subscription "Target Subscription Name"

# Deploy with different BaseName for isolation
.\Infra-Foundary-New\deploy.ps1 `
    -BaseName "ClientABC" `
    -Location "westeurope" `
    -SubscriptionName "Target Subscription Name" `
    -TenantId "new-tenant-id"
```

**This creates a fully isolated deployment:**

| Original | New Tenant |
|----------|-----------|
| `ESIQNew-RG` | `ClientABC-RG` |
| `ESIQNew-AI` | `ClientABC-AI` |
| `esiqnewstorage` | `clientabcstorage` |
| `esiqnewacr` | `clientabcacr` |
| `esiqnew-agent` | `clientabc-agent` |
| `ESIQNew-Dashboard` | `ClientABC-Dashboard` |

**Cross-tenant checklist:**

- [ ] Azure CLI logged into the new tenant
- [ ] Subscription has sufficient quota for CognitiveServices (OpenAI models require region support)
- [ ] Global Admin available for Graph API permissions + directory roles
- [ ] Verify model availability in chosen region (`az cognitiveservices model list --location westeurope -o table`)
- [ ] After deployment: grant admin consent on App Registration
- [ ] After deployment: assign directory roles to managed identity

---

## 10. Disaster Recovery & Rollback

### Rollback to Previous Image Version

```powershell
# List available images
az acr repository show-tags --name esiqnewacr --repository esiqnew-agent -o table

# Rollback to a specific version
az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG \
    --image esiqnewacr.azurecr.io/esiqnew-agent:v30-customrpt -o table
```

### Rollback to Previous Revision

```powershell
# List revisions
az containerapp revision list --name esiqnew-agent --resource-group ESIQNew-RG \
    --query "[].{name:name, active:properties.active, created:properties.createdTime}" -o table

# Activate a previous revision
az containerapp revision activate --name esiqnew-agent --resource-group ESIQNew-RG \
    --revision {revision-name}
```

### Full Disaster Recovery

If the resource group is deleted:

1. Run `deploy.ps1` — fully idempotent, recreates everything
2. The FQDN will change (Container Apps generates a new one)
3. Update App Registration redirect URIs if FQDN changed
4. Manual steps: admin consent + directory roles

### Data Recovery

Assessment reports are stored locally in `/agent/output` inside the container. These are **not persistent** across container restarts (see [Known Issues](#12-known-issues--workarounds)). For important assessments, download reports from the SPA immediately after completion.

---

## 11. Monitoring & Alerting

### Current State

- **App Insights** (`ESIQNew-appinsights`): Collects telemetry from Container Apps environment
- **Log Analytics** (`ESIQNew-law`): Aggregates container logs

### Useful KQL Queries

```kusto
-- Container app errors (last 24h)
ContainerAppConsoleLogs_CL
| where ContainerAppName_s == "esiqnew-agent"
| where Log_s contains "ERROR" or Log_s contains "Traceback"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
| take 50

-- Request latency
ContainerAppSystemLogs_CL
| where ContainerAppName_s == "esiqnew-agent"
| where Reason_s == "HealthCheckSuccess"
| project TimeGenerated, Reason_s
| order by TimeGenerated desc
```

---

## 12. Known Issues & Workarounds

| Issue | Impact | Workaround |
|-------|--------|------------|
| **Storage `allowSharedKeyAccess: false`** | Azure Files volume mount fails with `VolumeMountFailure`. Cannot change — enforced by Azure Policy at subscription/management-group level. | Volume mount removed from container app config (as of v23). Reports save to local `/agent/output` — not persistent across restarts. |
| **No `.dockerignore` until v32** | ACR builds upload ~280MB including `output/`, `docs/`, `.git/` → ~30 min builds. | `.dockerignore` added in v32 — builds should now take ~2 min. |
| **Graph API permissions need Global Admin** | Step 12 may silently fail for non-Global-Admin operators. | Verify after deployment: `az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/{principalId}/appRoleAssignments"` |
| **Directory roles require manual assignment** | Managed Identity needs Directory Reader + Global Reader in Entra. Cannot be automated via CLI without Global Admin. | Navigate to `entra.microsoft.com → Roles and administrators` and assign manually. |
| **SPA config hardcoded in image** | `webapp/index.html` contains clientId/tenantId baked in at build time. Changing tenant requires rebuild. | Step 16 patches and rebuilds. For multi-tenant, consider runtime config injection. |

---

## 13. Teardown / Decommission

> **WARNING**: This is destructive and irreversible. All resources, data, and configurations will be permanently deleted.

```powershell
# Option 1: Delete entire resource group (removes all 13 Azure resources)
az group delete --name ESIQNew-RG --yes --no-wait

# Option 2: Also clean up Entra objects
az ad app delete --id $(az ad app list --display-name ESIQNew-Dashboard --query "[0].id" -o tsv)

# Verify deletion
az group exists --name ESIQNew-RG -o tsv   # should return "false"
```

**What is NOT cleaned up by resource group deletion:**
- Entra App Registration (`ESIQNew-Dashboard`) — must delete separately
- Entra directory role assignments on the managed identity — auto-removed when MI is deleted
- Graph API permission grants on the MI — auto-removed when MI is deleted

---

## 14. Quick Reference — Commands

| Task | Command |
|------|---------|
| Full deploy | `.\Infra-Foundary-New\deploy.ps1 -BaseName ESIQNew -Location swedencentral -SubscriptionName AI` |
| Quick redeploy | `.\Infra-Foundary-New\redeploy-image.ps1 -Tag v32-fix` |
| Build image | `az acr build --registry esiqnewacr --image esiqnew-agent:TAG --file AIAgent/Dockerfile . --no-logs --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')` |
| Update container | `az containerapp update --name esiqnew-agent --resource-group ESIQNew-RG --image esiqnewacr.azurecr.io/esiqnew-agent:TAG -o table` |
| View logs | `az containerapp logs show --name esiqnew-agent --resource-group ESIQNew-RG --follow` |
| Health check | `curl https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io/health` |
| List image tags | `az acr repository show-tags --name esiqnewacr --repository esiqnew-agent -o table` |
| List revisions | `az containerapp revision list --name esiqnew-agent --resource-group ESIQNew-RG -o table` |
| Check RBAC | `az role assignment list --assignee {principalId} -o table` |
| Teardown | `az group delete --name ESIQNew-RG --yes` |

---

## 15. Permissions Deep Dive — Tool-to-Permission Mapping

This section maps every permission to the specific assessment tools that require it, and explains what breaks when a permission is missing. This covers both **delegated permissions** (SPA / web dashboard users) and **application permissions** (Managed Identity / CLI scripts).

### Understanding the Two Permission Models

| Model | Identity | Used By | How Granted |
|-------|----------|---------|-------------|
| **Delegated** | Logged-in user (via MSAL.js) | Web dashboard — all 6 assessment tools | App Registration → API permissions → Admin consent |
| **Application** | Managed Identity (ESIQNew-identity) | CLI scripts (`run_assessment.py`, `run_risk_analysis.py`, etc.) | Graph REST API → `appRoleAssignments` on MI service principal |

**Key**: Web dashboard assessments always use **delegated** tokens — the agent can only see what the logged-in user can see. The MI's application permissions are only used by CLI scripts.

### Enterprise App vs App Registration

These are two views of the **same** SPA identity in Entra ID:

| View | Portal Location | What It Shows |
|------|----------------|---------------|
| **App Registration** (ESIQNew-Dashboard) | Entra → App registrations | Configuration: which permissions the app *requests*, redirect URIs, token settings |
| **Enterprise Application** (service principal) | Entra → Enterprise applications | Runtime state: which permissions are *granted*, user assignments, conditional access |

Admin consent granted on the Enterprise Application side is what actually enables the delegated permissions at runtime.

### SPA Delegated Permissions — Microsoft Graph (7)

These permissions are requested by the SPA (`webapp/index.html`) via MSAL.js and granted through admin consent on the Enterprise Application.

| Permission | Type | Assessment Tools That Require It | What Breaks Without It |
|-----------|------|----------------------------------|----------------------|
| **User.Read** | Delegated | All tools (login identity) | Cannot sign in at all |
| **Directory.Read.All** | Delegated | Tenant Assessment (identity domain), RBAC Report, Copilot Readiness, AI Agent Security | Users/groups/roles not enumerated. Tenant Assessment identity domain scores 0. RBAC tree empty. |
| **Policy.Read.All** | Delegated | Tenant Assessment (identity domain), Copilot Readiness (governance), Risk Analysis (identity) | Conditional access policies invisible. Copilot governance checks incomplete. DLP policy assessment skipped. |
| **RoleManagement.Read.All** | Delegated | Tenant Assessment (identity domain), Risk Analysis (identity), RBAC Report | PIM role assignments not visible. Privileged role analysis fails. RBAC Report missing Entra roles. |
| **AuditLog.Read.All** | Delegated | Risk Analysis (insider_risk), Tenant Assessment (logging domain) | Sign-in anomaly detection fails. Audit log analysis skipped. Insider risk scoring incomplete. |
| **UserAuthenticationMethod.Read.All** | Delegated | Tenant Assessment (identity domain), Copilot Readiness | MFA registration status unknown. "MFA coverage" finding always returns unknown. |
| **IdentityRiskyUser.Read.All** | Delegated | Risk Analysis (identity), Tenant Assessment (identity domain) | Identity Protection risky users not visible. Risk scores underestimate identity threats. |

### SPA Delegated Permissions — Azure Resource Manager (1)

| Permission | Type | Assessment Tools That Require It | What Breaks Without It |
|-----------|------|----------------------------------|----------------------|
| **user_impersonation** | Delegated (ARM) | ALL assessment tools that query Azure resources (Tenant Assessment network/data/compute domains, Risk Analysis, Data Security, Exposure Search) | No Azure resource visibility at all. All ARM-based checks return empty. Only Entra ID checks work. |

### Additional Implicit Scopes (3)

These are automatically included by MSAL.js and don't need explicit admin consent:

| Scope | Purpose |
|-------|---------|
| **openid** | Required for OIDC sign-in (returns ID token) |
| **profile** | Returns user's name and email in the ID token |
| **offline_access** | Enables refresh tokens for silent token renewal |

### Managed Identity Application Permissions — Microsoft Graph (8)

These are used by CLI scripts only (`run_assessment.py`, `run_risk_analysis.py`, etc.) when running assessments outside the web dashboard.

| Permission | CLI Scripts That Require It | Collectors That Use It | What Breaks Without It |
|-----------|---------------------------|----------------------|----------------------|
| **Directory.Read.All** | `run_assessment.py`, `run_copilot_readiness.py`, `run_ai_agent_security.py` | EntraTenant, CopilotStudio | Tenant info, directory objects, Copilot Studio agents not readable |
| **Policy.Read.All** | `run_assessment.py`, `run_risk_analysis.py`, `run_copilot_readiness.py` | EntraConditionalAccess, EntraSecurityPolicies, EntraRiskPolicies, M365DLPAlerts, M365Retention, M365InsiderRisk, M365eDiscovery | CA policies, DLP alerts, retention policies, insider risk policies all invisible |
| **RoleManagement.Read.All** | `run_assessment.py`, `run_rbac_report.py`, `run_risk_analysis.py` | EntraRoles | PIM and directory role assignments not enumerable |
| **User.Read.All** | `run_assessment.py`, `run_risk_analysis.py` | EntraUsers | User profiles and properties not accessible |
| **AuditLog.Read.All** | `run_assessment.py`, `run_risk_analysis.py` | EntraAuditLogs | Sign-in logs and audit trail not readable |
| **UserAuthenticationMethod.Read.All** | `run_assessment.py` | EntraUserDetails | MFA registration status queries fail |
| **IdentityRiskyUser.Read.All** | `run_assessment.py`, `run_risk_analysis.py` | EntraIdentityProtection | Risky user data from Identity Protection unavailable |
| **Application.Read.All** | `run_assessment.py`, `run_ai_agent_security.py` | EntraApplications, EntraWorkloadIdentity, EntraAIIdentity | App registrations, service principals, workload identities not enumerable |

### Managed Identity Azure RBAC Roles (5)

| Role | Scope | Used By | What Breaks Without It |
|------|-------|---------|----------------------|
| **AcrPull** | Container Registry | Container App (image pull) | Container App cannot start — image pull fails |
| **Reader** | Subscription | CLI scripts: all ARM-based collectors (AzureNetwork, AzureStorage, AzureCompute, AzurePolicy, etc.) | No Azure resource visibility in CLI mode |
| **Security Reader** | Subscription | CLI scripts: AzureDefenderPlans, AzureDefenderAdvanced, AzureSecurity | Defender for Cloud data not visible — secure score, alerts, recommendations missing |
| **Cognitive Services OpenAI User** | Foundry Resource | Container App (agent reasoning) | Agent cannot call LLM — all chat/assessment requests fail with 403 |
| **Azure AI Developer** | Foundry Resource | Container App (agent registration) | Cannot register or manage Foundry agents |

### Entra Directory Roles (2, Manual Assignment)

| Role | Assigned To | Used By | What Breaks Without It |
|------|------------|---------|----------------------|
| **Directory Readers** | ESIQNew-identity (MI) | CLI scripts: comprehensive directory enumeration | CLI scripts get partial directory data — some objects inaccessible |
| **Global Reader** | ESIQNew-identity (MI) | CLI scripts: tenant-wide policy assessment | CLI scripts cannot read all tenant-level settings |

### Permission Impact Summary by Assessment Tool

| Assessment Tool | Required Delegated Scopes (Web) | Required MI Permissions (CLI) | Minimum Azure RBAC |
|----------------|-------------------------------|-------------------------------|---------------------|
| **Tenant Assessment** | User.Read, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, IdentityRiskyUser.Read.All, user_impersonation | All 8 Graph + Reader + Security Reader | Reader + Security Reader |
| **Risk Analysis** | User.Read, Directory.Read.All, Policy.Read.All, RoleManagement.Read.All, AuditLog.Read.All, IdentityRiskyUser.Read.All, user_impersonation | Directory, Policy, RoleManagement, User, AuditLog, IdentityRiskyUser + Reader + Security Reader | Reader + Security Reader |
| **Data Security** | User.Read, Directory.Read.All, user_impersonation | Directory.Read.All + Reader | Reader |
| **Copilot Readiness** | User.Read, Directory.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All, user_impersonation | Directory, Policy, UserAuthenticationMethod + Reader | Reader |
| **AI Agent Security** | User.Read, Directory.Read.All, user_impersonation | Directory.Read.All, Application.Read.All + Reader | Reader |
| **RBAC Report** | User.Read, RoleManagement.Read.All, user_impersonation | RoleManagement.Read.All + Reader | Reader |
| **Exposure Search** | User.Read, user_impersonation | Reader | Reader |
| **Tenant Search** | User.Read, Directory.Read.All, user_impersonation | Directory.Read.All + Reader | Reader |
