# Deployment Guide — PostureIQ

**Author:** Murali Chillakuru

> **Executive Summary** — Complete, step-by-step guide to deploying PostureIQ to Microsoft Azure.
> Covers three deployment paths: Foundry hosted agent, Azure Container Apps, and Azure App Service.
> Includes infrastructure-as-code (Bicep), Docker build, environment configuration, and post-deployment validation.
>
> | | |
> |---|---|
> | **Audience** | Operators, platform engineers, DevOps |
> | **Prerequisites** | Azure subscription, Azure CLI, Docker |
> | **Time** | 30–60 minutes for first deployment |
> | **Companion docs** | [Architecture](architecture.md) · [Configuration Guide](configuration-guide.md) · [CI/CD Integration](ci-cd-integration.md) |

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Architecture Overview](#2-architecture-overview)
3. [Path 1 — Deploy to Microsoft Foundry (Hosted Agent)](#3-path-1--deploy-to-microsoft-foundry-hosted-agent)
4. [Path 2 — Deploy to Azure Container Apps](#4-path-2--deploy-to-azure-container-apps)
5. [Known Issues & Workarounds](#known-issues--workarounds)
6. [Path 3 — Deploy to Azure App Service (REST API)](#5-path-3--deploy-to-azure-app-service-rest-api)
7. [Environment Variables Reference](#6-environment-variables-reference)
8. [Identity & Permissions](#7-identity--permissions)
9. [Web Dashboard (Optional)](#8-web-dashboard-optional)
10. [Post-Deployment Validation](#9-post-deployment-validation)
11. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

Before you begin, ensure you have the following installed and configured.

### Tools

| Tool | Minimum Version | Install |
|------|----------------|---------|
| **Azure CLI** | 2.60+ | `winget install Microsoft.AzureCLI` or [docs](https://learn.microsoft.com/cli/azure/install-azure-cli) |
| **Docker Desktop** | 24+ | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| **Python** | 3.10+ | [python.org](https://www.python.org/downloads/) (needed only for local dev) |
| **Git** | 2.40+ | `winget install Git.Git` |

### Azure Resources

You will need:

1. **Azure Subscription** — with permissions to create resources (Contributor role on a resource group)
2. **Azure Container Registry (ACR)** — to store your Docker image (created automatically by the Bicep template, or you can use an existing one)
3. **Microsoft Foundry Project** — (Path 1 only) with a deployed model (e.g., `gpt-4.1` or `gpt-4o`)
4. **Entra ID App Registration** — (only if deploying the web dashboard)

### Authenticate

```bash
# Log in to Azure
az login

# Set your subscription (if you have multiple)
az account set --subscription "YOUR_SUBSCRIPTION_NAME"

# Verify
az account show --query "{name:name, id:id}" -o table
```

---

## 2. Architecture Overview

PostureIQ can run in three modes:

```
┌─────────────────────────────────────────────────────────────┐
│  Path 1: Foundry Hosted Agent                               │
│  ┌──────────┐    ┌────────────┐    ┌─────────────────────┐  │
│  │ Foundry  │───▶│ Container  │───▶│ EnterpriseSecurityIQ│  │
│  │ Portal   │    │ (port 8088)│    │ Agent + 14 Tools    │  │
│  └──────────┘    └────────────┘    └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  Path 2: Azure Container Apps                                │
│  ┌──────────┐    ┌────────────┐    ┌─────────────────────┐  │
│  │ Web      │───▶│ Container  │───▶│ EnterpriseSecurityIQ│  │
│  │ Dashboard│    │ App (8088) │    │ Agent + 14 Tools    │  │
│  └──────────┘    └────────────┘    └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  Path 3: Azure App Service (REST API only)                   │
│  ┌──────────┐    ┌────────────┐    ┌─────────────────────┐  │
│  │ API      │───▶│ App Service│───▶│ FastAPI (port 8000) │  │
│  │ Clients  │    │ Container  │    │ POST /assessments   │  │
│  └──────────┘    └────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

| Aspect | Path 1: Foundry | Path 2: Container Apps | Path 3: App Service |
|--------|----------------|----------------------|---------------------|
| **Interface** | Conversational AI | Web dashboard + AI | REST API only |
| **Port** | 8088 | 8088 | 8000 |
| **Protocol** | `responses` v1 | `responses` v1 | HTTP/JSON |
| **Entry point** | `main.py` | `main.py` | `app/api.py` |
| **Scaling** | Managed by Foundry | 0–3 replicas (auto) | App Service Plan |
| **Best for** | AI-powered Q&A | End-user dashboards | CI/CD automation |

---

## 3. Path 1 — Deploy to Microsoft Foundry (Hosted Agent)

This is the recommended path. The agent runs as a hosted Foundry agent that users interact with via natural language.

### Step 1: Create a Resource Group

```bash
# Choose a name and region
RESOURCE_GROUP="rg-esiq-prod"
LOCATION="eastus2"

az group create --name $RESOURCE_GROUP --location $LOCATION
```

### Step 2: Create a Foundry Project

1. Go to [Azure AI Foundry](https://ai.azure.com)
2. Click **+ New project**
3. Select your subscription and resource group
4. Choose a name (e.g., `esiq-foundry`)
5. Select a region that supports your desired model
6. Click **Create**

After creation:
- Go to **Project settings → Overview**
- Copy the **Project endpoint** (looks like `https://esiq-foundry.services.ai.azure.com/api`)

### Step 3: Deploy a Model

1. In your Foundry project, go to **Model catalog**
2. Search for and deploy **gpt-4.1** (or `gpt-4o`)
3. Note the **Deployment name** (default is the model name, e.g., `gpt-4.1`)

### Step 4: Create an Azure Container Registry

```bash
ACR_NAME="esiqacr"  # Must be globally unique, lowercase, no dashes

az acr create \
  --resource-group $RESOURCE_GROUP \
  --name $ACR_NAME \
  --sku Basic

# Enable admin (for initial testing — use managed identity in production)
az acr login --name $ACR_NAME
```

### Step 5: Build and Push the Docker Image

```bash
cd AIAgent

# Build for linux/amd64 (required for Azure)
docker build --platform linux/amd64 -t enterprisesecurityiq-agent .

# Tag for your ACR
docker tag enterprisesecurityiq-agent $ACR_NAME.azurecr.io/enterprisesecurityiq-agent:latest

# Push
docker push $ACR_NAME.azurecr.io/enterprisesecurityiq-agent:latest
```

### Step 6: Create the Hosted Agent

Using `agent.yaml` in the repository:

1. Go to your Foundry project in [Azure AI Foundry](https://ai.azure.com)
2. Navigate to **Agents → + New agent**
3. Select **Hosted agent** type
4. Configure:
   - **Container image:** `<your-acr>.azurecr.io/enterprisesecurityiq-agent:latest`
   - **Port:** `8088`
   - **Protocol:** `responses v1`
5. Set environment variables:
   - `FOUNDRY_PROJECT_ENDPOINT` = your project endpoint from Step 2
   - `FOUNDRY_MODEL_DEPLOYMENT_NAME` = your deployment name from Step 3
   - `AZURE_TENANT_ID` = the tenant ID you want to assess
6. Click **Create**

### Step 7: Test the Agent

In the Foundry portal, open your agent and try:

```
What permissions do I need to run assessments?
```

```
Run a full compliance assessment
```

```
What are the top 10 risks in my tenant?
```

---

## 4. Path 2 — Deploy to Azure Container Apps

Deploys the agent as a publicly accessible container with auto-scaling. Pair with the [web dashboard](#8-web-dashboard-optional) for a complete end-user experience.

### Option A: Deploy with Bicep (Recommended)

The `infra/` directory contains a ready-to-use Bicep template.

#### Step 1: Edit Parameters

Edit `infra/parameters.json`:

```json
{
  "parameters": {
    "baseName": { "value": "esiq" },
    "imageTag": { "value": "latest" },
    "foundryProjectEndpoint": { "value": "https://your-project.services.ai.azure.com/api" },
    "modelDeploymentName": { "value": "gpt-4.1" },
    "tenantId": { "value": "00000000-0000-0000-0000-000000000000" }
  }
}
```

#### Step 2: Create Resource Group and Deploy

```bash
RESOURCE_GROUP="rg-esiq-prod"
LOCATION="eastus2"

# Create the resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Deploy infrastructure
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file infra/main.bicep \
  --parameters infra/parameters.json

# The command outputs the Container App URL and ACR login server
```

#### Step 3: Build and Push Image

```bash
# Get the ACR login server from the deployment output
ACR_SERVER=$(az deployment group show \
  --resource-group $RESOURCE_GROUP \
  --name main \
  --query properties.outputs.acrLoginServer.value -o tsv)

# Log in to ACR
az acr login --name ${ACR_SERVER%%.*}

# Build and push
cd AIAgent
docker build --platform linux/amd64 -t $ACR_SERVER/enterprisesecurityiq-agent:latest .
docker push $ACR_SERVER/enterprisesecurityiq-agent:latest
```

#### Step 4: Verify Deployment

```bash
# Get the Container App URL
APP_URL=$(az deployment group show \
  --resource-group $RESOURCE_GROUP \
  --name main \
  --query properties.outputs.containerAppUrl.value -o tsv)

echo "Agent running at: $APP_URL"
```

### Option B: Deploy with Azure CLI

If you prefer not to use Bicep:

```bash
RESOURCE_GROUP="rg-esiq-prod"
LOCATION="eastus2"
ACR_NAME="esiqacr"
APP_NAME="esiq-agent"

# 1. Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# 2. Create ACR
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic
az acr login --name $ACR_NAME

# 3. Build and push
cd AIAgent
docker build --platform linux/amd64 -t $ACR_NAME.azurecr.io/enterprisesecurityiq-agent:latest .
docker push $ACR_NAME.azurecr.io/enterprisesecurityiq-agent:latest

# 4. Create Container App
az containerapp up \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --image $ACR_NAME.azurecr.io/enterprisesecurityiq-agent:latest \
  --ingress external \
  --target-port 8088 \
  --env-vars \
    FOUNDRY_PROJECT_ENDPOINT="https://your-project.services.ai.azure.com/api" \
    FOUNDRY_MODEL_DEPLOYMENT_NAME="gpt-4.1" \
    AZURE_TENANT_ID="your-tenant-id"
```

### Option C: Deploy with PowerShell (No Docker — ACR Tasks)

If Docker Desktop is not available, use `infra/deploy.ps1` which builds images in the cloud via ACR Tasks.

#### Prerequisites

- **Azure CLI** 2.60+ with the `containerapp` extension
- **PowerShell** 7+ (or Windows PowerShell 5.1)
- **No Docker Desktop required** — builds happen server-side via ACR Tasks

#### Quick Start

```powershell
# From the repository root
cd infra

# Deploy everything with a single command
.\deploy.ps1 -BaseName "ESIQ" -Location "swedencentral" -SubscriptionName "AI"
```

The script is fully **parameterized** and **idempotent** — re-running it skips resources that already exist.

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-BaseName` | Yes | — | Prefix for all resources (e.g., `ESIQ` → `ESIQ-RG`, `esiqacr`, `esiq-agent`) |
| `-Location` | Yes | — | Azure region (`swedencentral`, `eastus2`, etc.) |
| `-SubscriptionName` | Yes | — | Target Azure subscription name |
| `-PrimaryModel` | No | `gpt-4.1` | Primary model deployment |
| `-FallbackModel` | No | `gpt-5.1` | Fallback model (set to `""` to skip) |
| `-ModelSku` | No | `Standard` | Model SKU (`Standard` keeps data in-region) |
| `-TenantId` | No | auto-detected | Target tenant for security assessments |

#### What It Creates

| # | Resource | Naming Pattern | Example |
|---|----------|---------------|---------|
| 1 | Resource Group | `{Base}-RG` | `ESIQ-RG` |
| 2 | AI Services | `{Base}-AI` | `ESIQ-AI` |
| 3 | Model Deployments | `{model-name}` | `gpt-4.1`, `gpt-5.1` |
| 4 | Container Registry | `{base}acr` | `esiqacr` |
| 5 | Managed Identity | `{Base}-identity` | `ESIQ-identity` |
| 6 | Log Analytics | `{Base}-law` | `ESIQ-law` |
| 7 | Container App Env | `{Base}-env` | `ESIQ-env` |
| 8 | Container App | `{base}-agent` | `esiq-agent` |

The script also assigns RBAC roles: `AcrPull` (on ACR), `Reader` (subscription), `Security Reader` (subscription), and `Cognitive Services OpenAI User` (on AI Services).

#### Rebuild After Code Changes

Use the companion script for day-to-day redeployments:

```powershell
.\redeploy-image.ps1 -BaseName "ESIQ"
```

This rebuilds the image via ACR Tasks and restarts the container app — takes ~2 minutes.

#### Manual Step After Deployment

Entra ID directory roles cannot be assigned via CLI. After deployment, go to the Azure Portal:

1. **Entra ID → Roles and administrators → Directory Reader** → Add the managed identity
2. **Entra ID → Roles and administrators → Global Reader** → Add the managed identity

---

## Known Issues & Workarounds

Issues discovered during deployment (April 2026) and their fixes.

### Docker Layer Caching — Stale `webapp/` in ACR Builds (v23 fix)

**Symptom:** After updating `webapp/index.html`, the deployed container still serves the old version.

**Cause:** Docker layer caching in ACR reuses the `COPY webapp/ webapp/` layer when
Dockerfile lines above it haven't changed.

**Fix:** The Dockerfile now has `ARG CACHEBUST=1` before the `COPY webapp/` line.
Always pass `--build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')` when building:

```powershell
az acr build --registry esiqnewacr --image esiqnew-agent:v<N> `
  --file AIAgent/Dockerfile . --no-logs `
  --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')
```

### Azure Files Volume Mount Fails — `allowSharedKeyAccess: false` (v19→v25)

**Symptom:** Container App revision fails with `VolumeMountFailure: Permission denied`
when mounting an Azure Files share.

**Cause:** Azure Policy at the management group level forces `allowSharedKeyAccess: false`
on all storage accounts. Container Apps Azure Files mounts require shared key access.
This cannot be overridden.

**Resolution:** Do not use Azure Files volume mounts. Use Azure Blob Storage with managed
identity authentication instead (implemented in v25). Reports are uploaded to a blob
container after generation and downloaded on demand when requested.

### Multi-Tenant Sign-In Error (v24 fix)

**Symptom:** Users from external tenants see "Selected user account does not exist
in tenant 'Contoso'" when signing in via the web dashboard.

**Cause:** MSAL authority hardcoded to a specific tenant ID; app registration
`signInAudience` set to `AzureADMyOrg`.

**Fix:** Change MSAL authority to `https://login.microsoftonline.com/common` and update
the app registration to `AzureADMultipleOrgs`:

```bash
az ad app update --id <app-id> --sign-in-audience AzureADMultipleOrgs
```

### Reports Lost After Container Restart (v25 fix)

**Symptom:** `{"detail":"Report not found"}` for report URLs generated in a previous
container revision.

**Cause:** Reports stored in ephemeral container storage (`/agent/output`) are wiped
on every restart/redeployment.

**Fix:** v25 adds Azure Blob Storage persistence. Reports are automatically uploaded
after generation and downloaded on demand. See [Report Persistence](#report-persistence)
section below.

### Azure CLI 2.77.0 — Bicep `@secure()` Bug

**Symptom:** `az deployment group create` fails with `"The content for this response was already consumed"`.

**Cause:** Azure CLI 2.77.0 has a bug parsing `@secure()` parameters in Bicep templates.

**Workaround:** Use `infra/deploy.ps1` (Option C) which creates resources individually. The Bicep template (`infra/main.bicep`) is provided for reference but may fail on CLI 2.77.0.

### Dockerfile `FROM --platform` in ACR Tasks

**Symptom:** ACR Tasks build fails with `"unable to understand line FROM --platform=linux/amd64 python:3.12-slim"`.

**Cause:** ACR Tasks' dependency scanner cannot parse `--platform` in `FROM` directives.

**Fix:** Remove `--platform` from the `FROM` line. Pass `--platform linux/amd64` to `az acr build` instead. Already fixed in the repository.

### Missing `six` Module (Python 3.12 slim)

**Symptom:** Container crashes with `ModuleNotFoundError: No module named 'six'`.

**Cause:** `azure-mgmt-resourcegraph==8.0.0` imports `six` but Python 3.12-slim doesn't include it.

**Fix:** Added `six` to `requirements.txt`. Already fixed in the repository.

### Beta-Only Azure SDK Packages

**Symptom:** `pip install` fails with `"No matching distribution found"` for packages like `azure-mgmt-securityinsight>=2.0.0`.

**Cause:** Some `azure-mgmt-*` packages only have beta releases (e.g., `2.0.0b2`) which don't match `>=2.0.0`.

**Fix:** Changed version specifiers to `>=2.0.0b1` and added `--pre` flag to pip in Dockerfile. Already fixed in the repository.

### Container App Name Must Be Lowercase

**Symptom:** `az containerapp create` fails with `ContainerAppInvalidName`.

**Cause:** Container App names must consist of lowercase alphanumeric characters or hyphens.

**Fix:** The deploy script uses `$BaseName.ToLower() + "-agent"` for the container app name.

---

## 5. Path 3 — Deploy to Azure App Service (REST API)

Deploys the FastAPI REST API (`app/api.py`) for headless/CI-CD integration.

```bash
RESOURCE_GROUP="rg-esiq-prod"
APP_NAME="esiq-api"
ACR_NAME="esiqacr"

# Build with FastAPI as entry point
cd AIAgent
docker build --platform linux/amd64 \
  -t $ACR_NAME.azurecr.io/enterprisesecurityiq-api:latest \
  --build-arg CMD="uvicorn app.api:app --host 0.0.0.0 --port 8000" .

docker push $ACR_NAME.azurecr.io/enterprisesecurityiq-api:latest

# Create App Service
az appservice plan create \
  --name esiq-plan \
  --resource-group $RESOURCE_GROUP \
  --is-linux --sku B1

az webapp create \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --plan esiq-plan \
  --deployment-container-image-name $ACR_NAME.azurecr.io/enterprisesecurityiq-api:latest

# Set environment variables
az webapp config appsettings set \
  --name $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --settings \
    FOUNDRY_PROJECT_ENDPOINT="https://your-project.services.ai.azure.com/api" \
    FOUNDRY_MODEL_DEPLOYMENT_NAME="gpt-4.1" \
    AZURE_TENANT_ID="your-tenant-id"
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/assessments` | Start an assessment (async). Returns `assessment_id` |
| `GET` | `/assessments/{id}` | Get assessment status and results |
| `GET` | `/health` | Health check |

---

## 6. Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FOUNDRY_PROJECT_ENDPOINT` | Yes | — | Foundry project endpoint URL |
| `FOUNDRY_MODEL_DEPLOYMENT_NAME` | Yes | `gpt-4.1` | Deployed model name |
| `AZURE_TENANT_ID` | Recommended | — | Target tenant for assessments |
| `AZURE_CLIENT_ID` | Optional | — | Service principal client ID (for non-interactive auth) |
| `AZURE_CLIENT_SECRET` | Optional | — | Service principal secret (for non-interactive auth) |
| `REPORT_STORAGE_ACCOUNT` | Recommended | `esiqnewstorage` | Azure Storage account for persistent report storage |
| `REPORT_STORAGE_CONTAINER` | Optional | `reports` | Blob container name within the storage account |

> **Security note:** Never commit secrets to source control. Use Azure Key Vault or Container App secrets for production deployments. The Bicep template passes `foundryProjectEndpoint` as a `@secure()` parameter.

---

## 7. Identity & Permissions

The agent needs Azure RBAC roles to read your tenant's security posture.

### Required Roles

| Scope | Role | Purpose |
|-------|------|---------|
| Subscription | **Reader** | Read ARM resources (VMs, storage, networking, etc.) |
| Subscription | **Security Reader** | Read Defender for Cloud findings, security policies |
| Entra ID | **Directory Reader** | Read users, groups, app registrations, conditional access |
| Entra ID | **Global Reader** | Read MFA status, PIM assignments, risky users |

### Assign Roles to the Managed Identity

After deploying with Bicep, the managed identity's principal ID is in the outputs:

```bash
# Get the managed identity principal ID
PRINCIPAL_ID=$(az deployment group show \
  --resource-group $RESOURCE_GROUP \
  --name main \
  --query properties.outputs.identityPrincipalId.value -o tsv)

# Assign Reader at subscription scope
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Reader" \
  --scope "/subscriptions/$(az account show --query id -o tsv)"

# Assign Security Reader at subscription scope
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Security Reader" \
  --scope "/subscriptions/$(az account show --query id -o tsv)"
```

For Entra ID directory roles, use the Azure Portal:
1. Go to **Entra ID → Roles and administrators**
2. Find **Directory Reader** → **Add assignments** → select the managed identity
3. Repeat for **Global Reader**

---

## 8. Web Dashboard (Optional)

The web dashboard is a multi-SPA architecture served from `webapp/`. All 11 HTML files are
served as static files by the FastAPI container — no separate deployment needed.

### SPA Architecture

| File | Route | Purpose |
|------|-------|---------|
| `index.html` | `/` | Portal — card-grid launcher linking to all assessment SPAs |
| `EnterpriseSecurityIQ.html` | `/EnterpriseSecurityIQ.html` | Full dashboard (all capabilities) |
| `esiq.html` | `/esiq.html` | Full dashboard (alias) |
| `enterpriseIQ.html` | `/enterpriseIQ.html` | Full dashboard (alias) |
| `ComplianceAssessment.html` | `/ComplianceAssessment.html` | Focused: compliance assessment |
| `RiskAnalysis.html` | `/RiskAnalysis.html` | Focused: risk analysis |
| `DataSecurity.html` | `/DataSecurity.html` | Focused: data security |
| `RBACReport.html` | `/RBACReport.html` | Focused: RBAC report |
| `CopilotReadiness.html` | `/CopilotReadiness.html` | Focused: Copilot readiness |
| `AIAgentSecurity.html` | `/AIAgentSecurity.html` | Focused: AI agent security |
| `PostureIQ.html` | `/PostureIQ.html` | Focused: PostureIQ posture assessment (with framework picker) |

Each SPA is self-contained (~1,550 lines) with inline CSS + JS, MSAL.js v5.6.3 authentication,
and SSE streaming to the `/chat` endpoint. The focused SPAs have reduced sidebars showing
only their relevant assessment tool. The portal page provides a card-grid entry point.

The dashboard provides:
- **Microsoft Entra ID SSO login** (multi-tenant — works for users from any Entra tenant)
- **Persistent left sidebar** with categorized assessment tools
- **Draggable resizer** between sidebar and chat area
- **Real-time progress tracking** with tool-level phase indicator
- **Framework selection modal** to choose which compliance frameworks to evaluate
- **Agent chat interface** with SSE streaming
- **Report download buttons** (HTML, PDF, Excel, JSON, CSV) rendered from SSE events
- **Tenant badge** showing the signed-in user's organization

### App Registration (Multi-Tenant)

The SPA authentication requires an Entra ID app registration:

| Setting | Value |
|---------|-------|
| **App ID** | `ffb6f10d-6991-430e-b3d6-23a0101a92b1` (EnterpriseSecurityIQ-SPA) |
| **Sign-in audience** | `AzureADMultipleOrgs` (multi-tenant) |
| **MSAL Authority** | `https://login.microsoftonline.com/common` |
| **Redirect URI** | Container App FQDN (SPA platform) |
| **API Permissions** | `User.Read`, `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `SecurityEvents.Read.All` |

### Report Persistence

Reports are persisted in Azure Blob Storage so they survive container restarts and
redeployments. This is handled automatically by `app/blob_store.py`.

**Setup requirements:**

1. **Storage account** with a blob container (default: `esiqnewstorage` / `reports`)
2. **Public network access** enabled on the storage account
3. **RBAC**: `Storage Blob Data Contributor` role assigned to the container app's managed identity

```bash
# Create the blob container (requires Storage Blob Data Contributor on yourself)
az storage container create --name reports --account-name esiqnewstorage --auth-mode login

# Assign role to the managed identity
az role assignment create \
  --role "Storage Blob Data Contributor" \
  --assignee <managed-identity-principal-id> \
  --scope "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>"
```

**How it works:**
- After generating reports, the agent uploads all files to blob storage
- When a report is requested via `GET /reports/{path}`, the API checks local storage first
- If the file isn't found locally (e.g., after a restart), it downloads from blob storage on demand
- The `GET /reports` listing merges local and blob storage entries

> **Note:** `allowSharedKeyAccess` can be `false` — blob storage uses Entra ID (OAuth2)
> authentication via `DefaultAzureCredential`, not shared keys.

---

## 9. Post-Deployment Validation

### Check Agent Health

```bash
# For Container Apps / App Service
curl -s https://<your-app-url>/health | jq .
```

### Run a Permissions Check

If using the Foundry agent, ask:
```
Check my permissions
```

If using the REST API:
```bash
curl -X POST https://<your-app-url>/assessments \
  -H "Content-Type: application/json" \
  -d '{"scope": "permissions-check"}'
```

### Run a Scoped Assessment

Start with a single domain to verify everything works:

```
Run an assessment scoped to Access Control only
```

Or via API:
```bash
curl -X POST https://<your-app-url>/assessments \
  -H "Content-Type: application/json" \
  -d '{"scope": "access_control"}'
```

---

## 10. Troubleshooting

### Container won't start

```bash
# Check container logs
az containerapp logs show \
  --name esiq-agent \
  --resource-group $RESOURCE_GROUP \
  --follow
```

Common causes:
- **Missing env vars:** `FOUNDRY_PROJECT_ENDPOINT` is required
- **ACR pull failure:** Ensure the managed identity has `AcrPull` on the ACR
- **Port mismatch:** Ingress must target port 8088 (not 8000 or 80)

### Authentication failures

```bash
# Verify the managed identity has the required roles
az role assignment list \
  --assignee $PRINCIPAL_ID \
  --all \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

### Agent returns empty results

- The agent needs **Reader** + **Security Reader** at subscription scope
- Entra ID collectors need **Directory Reader** in the tenant
- Run `Check my permissions` to see which scopes are accessible

### Docker build fails

```bash
# Ensure you're building for the correct platform
docker build --platform linux/amd64 -t enterprisesecurityiq-agent .

# If pip install fails, check network connectivity and requirements.txt
docker build --no-cache --platform linux/amd64 -t enterprisesecurityiq-agent .
```

### Bicep deployment fails

```bash
# Validate the template first
az deployment group validate \
  --resource-group $RESOURCE_GROUP \
  --template-file infra/main.bicep \
  --parameters infra/parameters.json

# Check deployment errors
az deployment group show \
  --resource-group $RESOURCE_GROUP \
  --name main \
  --query properties.error
```

---

## Quick Reference

```bash
# ────────── One-liner: Full Container Apps Deployment ──────────
RESOURCE_GROUP="rg-esiq-prod" && LOCATION="eastus2" && \
az group create -n $RESOURCE_GROUP -l $LOCATION && \
az deployment group create -g $RESOURCE_GROUP \
  --template-file infra/main.bicep \
  --parameters infra/parameters.json && \
ACR=$(az deployment group show -g $RESOURCE_GROUP -n main \
  --query properties.outputs.acrLoginServer.value -o tsv) && \
az acr login --name ${ACR%%.*} && \
cd AIAgent && \
docker build --platform linux/amd64 -t $ACR/enterprisesecurityiq-agent:latest . && \
docker push $ACR/enterprisesecurityiq-agent:latest && \
echo "Deployed to: $(az deployment group show -g $RESOURCE_GROUP -n main \
  --query properties.outputs.containerAppUrl.value -o tsv)"
```
