# PostureIQ — Manual Infrastructure Runbook

**Author:** Murali Chillakuru
**Last updated:** April 14, 2026

> **Purpose** — Fully manual, step-by-step infrastructure build guide. Every command is
> copy-paste ready with variable capture between steps. No scripts, no automation — just
> Azure CLI commands with deep technical explanations and Microsoft Learn references.
>
> **Audience** — Anyone building this infrastructure for the first time, including those
> unfamiliar with Foundry, Container Apps, or Managed Identities.
>
> **Time** — 45–90 minutes for first deployment.

---

## Table of Contents

1. [Understanding the Architecture](#1-understanding-the-architecture)
2. [Prerequisites](#2-prerequisites)
3. [Step 0 — Login & Variable Setup](#3-step-0--login--variable-setup)
4. [Step 1 — Resource Group](#4-step-1--resource-group)
5. [Step 2 — Foundry Resource (AI Services)](#5-step-2--foundry-resource-ai-services)
6. [Step 3 — Foundry Project](#6-step-3--foundry-project)
7. [Step 4 — Primary Model Deployment (gpt-4.1)](#7-step-4--primary-model-deployment-gpt-41)
8. [Step 5 — Fallback Model Deployment (gpt-5.1)](#8-step-5--fallback-model-deployment-gpt-51)
9. [Step 6 — Storage Account](#9-step-6--storage-account)
10. [Step 7 — Key Vault](#10-step-7--key-vault)
11. [Step 8 — Log Analytics Workspace](#11-step-8--log-analytics-workspace)
12. [Step 9 — Application Insights](#12-step-9--application-insights)
13. [Step 10 — Container Registry](#13-step-10--container-registry)
14. [Step 11 — User-Assigned Managed Identity](#14-step-11--user-assigned-managed-identity)
15. [Step 12a — Azure RBAC Role Assignments](#15-step-12a--azure-rbac-role-assignments)
16. [Step 12b — Microsoft Graph API Permissions](#16-step-12b--microsoft-graph-api-permissions)
17. [Step 13 — Container Apps Environment](#17-step-13--container-apps-environment)
18. [Step 14 — Build Docker Image & Create Container App](#18-step-14--build-docker-image--create-container-app)
19. [Step 15 — Entra App Registration (SPA)](#19-step-15--entra-app-registration-spa)
20. [Step 16 — Patch SPA Config & Rebuild](#20-step-16--patch-spa-config--rebuild)
21. [Post-Deployment — Manual Entra Steps](#21-post-deployment--manual-entra-steps)
22. [Post-Deployment — Validation Checklist](#22-post-deployment--validation-checklist)
23. [Environment Variable Reference](#23-environment-variable-reference)
24. [Glossary](#24-glossary)
25. [Permissions Deep Dive — Tool-to-Permission Mapping](#25-permissions-deep-dive--tool-to-permission-mapping)

---

## 1. Understanding the Architecture

PostureIQ is an AI-powered compliance assessment platform that runs as a Docker container on Azure Container Apps. It uses:

- **Azure AI Foundry** — hosts the LLM (Large Language Model) that powers the AI agent
- **Azure Container Apps** — serverless container hosting (no VMs to manage)
- **MSAL.js (SPA)** — browser-based authentication so users log in with their own Entra ID credentials
- **User-delegated tokens** — the agent uses the logged-in user's permissions to query Azure and Entra, not a shared service account

**Key principle**: Assessments run under the user's own identity. The managed identity is only for infrastructure (pulling Docker images, calling the LLM).

### What You're Building

```
14 Azure Resources:
├── Resource Group (container for everything)
├── Foundry Resource (AI Services — hosts LLM models)
│   ├── Foundry Project (visible in ai.azure.com)
│   ├── gpt-4.1 deployment (primary model)
│   └── gpt-5.1 deployment (fallback model)
├── Storage Account (report persistence)
├── Key Vault (secrets management)
├── Log Analytics Workspace (log aggregation)
├── Application Insights (telemetry)
├── Container Registry (Docker image hosting)
├── Managed Identity (passwordless auth for infrastructure)
├── Container Apps Environment (serverless hosting platform)
├── Container App (runs the agent + web dashboard)
└── App Registration in Entra ID (SPA authentication)
```

**Learn more:**
- [What is Azure AI Foundry?](https://learn.microsoft.com/en-us/azure/ai-studio/what-is-ai-studio)
- [Azure Container Apps overview](https://learn.microsoft.com/en-us/azure/container-apps/overview)
- [What is MSAL.js?](https://learn.microsoft.com/en-us/entra/identity-platform/msal-overview)
- [Managed identities for Azure resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

---

## 2. Prerequisites

### Tools You Need

| Tool | Minimum Version | What It Does | Install |
|------|----------------|--------------|---------|
| **Azure CLI** | 2.67+ | Command-line interface to manage Azure resources | [Install Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| **Git** | 2.40+ | Clone the source code repository | [Install Git](https://git-scm.com/downloads) |
| **PowerShell** | 7.4+ | Shell for running commands (pre-installed on Windows 11) | [Install PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) |

> **Note**: You do NOT need Docker installed locally. Images are built remotely using ACR Tasks.

### Permissions You Need

| Permission | Where | Why | Learn More |
|-----------|-------|-----|------------|
| **Contributor** | Azure subscription | Create all Azure resources | [Azure built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles) |
| **User Access Administrator** | Azure subscription | Assign RBAC roles to the managed identity | [Assign Azure roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli) |
| **Global Administrator** (or Privileged Role Admin) | Entra ID | Grant Graph API permissions, assign directory roles, grant admin consent | [Entra ID roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference) |

### Clone the Repository

```powershell
git clone https://github.com/<your-org>/EnterpriseSecurityIQ.git
cd EnterpriseSecurityIQ
```

---

## 3. Step 0 — Login & Variable Setup

### What We're Doing

Setting up all the naming variables that every subsequent step will use. Every resource name is derived from a single `$BaseName` prefix, ensuring consistent naming across all 14 resources.

### Commands

```powershell
# ──────────────────────────────────────────────────
# LOGIN TO AZURE
# ──────────────────────────────────────────────────
az login

# Set to your target subscription
az account set --subscription "AI"

# Verify you're on the right subscription
az account show --query "{name:name, id:id, tenantId:tenantId}" -o table

# ──────────────────────────────────────────────────
# DEFINE ALL VARIABLES (change BaseName for different deployments)
# ──────────────────────────────────────────────────
$BaseName         = "ESIQNew"
$Location         = "swedencentral"

# Derived names (do not change these — they follow Azure naming rules)
$RG               = "$BaseName-RG"
$AIName           = "$BaseName-AI"
$CustomDomain     = $AIName.ToLower()                    # must be globally unique, lowercase
$ProjectName      = "$BaseName-project"
$StorageName      = "$($BaseName.ToLower())storage"      # storage names: lowercase, no dashes
$KVName           = "$BaseName-kv"
$LAWName          = "$BaseName-law"
$AppInsightsName  = "$BaseName-appinsights"
$ACRName          = "$($BaseName.ToLower())acr"          # ACR names: lowercase, no dashes
$IDName           = "$BaseName-identity"
$EnvName          = "$BaseName-env"
$AppName          = "$($BaseName.ToLower())-agent"
$DashName         = "$BaseName-Dashboard"

# Capture subscription and tenant IDs
$SubId    = az account show --query "id" -o tsv
$TenantId = az account show --query "tenantId" -o tsv

# Verify
Write-Host "Subscription:  $SubId"
Write-Host "Tenant:        $TenantId"
Write-Host "Base Name:     $BaseName"
Write-Host "Location:      $Location"
Write-Host "Resource Group: $RG"
```

### Why This Matters

All Azure resource names derive from `$BaseName`. This means:
- Changing `$BaseName` to `"ClientABC"` creates a fully isolated deployment
- Names follow Azure naming rules (storage/ACR: lowercase/no dashes, KV/AI: alphanumeric+hyphens)
- Idempotent — re-running any step with the same `$BaseName` skips existing resources

**Learn more:**
- [Azure resource naming conventions](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming)
- [Azure CLI: az account](https://learn.microsoft.com/en-us/cli/azure/account)

---

## 4. Step 1 — Resource Group

### What is a Resource Group?

A Resource Group is a logical container that holds related Azure resources. All 13 Azure resources will live in this RG. Deleting the RG deletes everything inside it.

### Commands

```powershell
# Check if it already exists
$rgExists = az group exists --name $RG -o tsv
Write-Host "RG exists: $rgExists"

# Create if it doesn't exist
if ($rgExists -eq "false") {
    az group create --name $RG --location $Location -o table
    Write-Host "Created resource group: $RG"
} else {
    Write-Host "Resource group $RG already exists — skipping."
}
```

### Verify

```powershell
az group show --name $RG --query "{name:name, location:location, state:properties.provisioningState}" -o table
```

Expected output:
```
Name        Location       State
----------  -------------  ---------
ESIQNew-RG  swedencentral  Succeeded
```

**Learn more:**
- [What is a resource group?](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal#what-is-a-resource-group)
- [az group create](https://learn.microsoft.com/en-us/cli/azure/group#az-group-create)

---

## 5. Step 2 — Foundry Resource (AI Services)

### What is a Foundry Resource?

Azure AI Foundry (formerly "Azure AI Studio") is Microsoft's platform for building AI applications. Under the hood, a Foundry Resource is a `CognitiveServices/accounts` resource with kind `AIServices`. It hosts:
- LLM model deployments (GPT-4.1, GPT-5.1, etc.)
- Foundry Projects (visible at [ai.azure.com](https://ai.azure.com))
- Agent registrations

Two special configurations are needed:
1. **Custom domain** — required before projects can be created (gives the resource a unique `{name}.openai.azure.com` endpoint)
2. **allowProjectManagement** — enables the "New Foundry" project model (child resources under the account)

### Commands

```powershell
# ──────────────────────────────────────────────────
# CREATE THE FOUNDRY RESOURCE
# ──────────────────────────────────────────────────
$aiExists = az cognitiveservices account show --name $AIName --resource-group $RG --query "name" -o tsv 2>$null

if (-not $aiExists) {
    Write-Host "Creating Foundry Resource: $AIName..."
    az cognitiveservices account create `
        --name $AIName `
        --resource-group $RG `
        --kind "AIServices" `
        --sku "S0" `
        --location $Location `
        --yes -o none
    Write-Host "Created."
} else {
    Write-Host "Foundry Resource $AIName already exists — skipping creation."
}

# ──────────────────────────────────────────────────
# SET CUSTOM DOMAIN (required for Foundry projects)
# ──────────────────────────────────────────────────
# A custom domain gives the resource a unique endpoint like:
# https://esiqnew-ai.openai.azure.com/
# Without this, you cannot create Foundry projects.
Write-Host "Setting custom domain: $CustomDomain..."
az cognitiveservices account update `
    --name $AIName `
    --resource-group $RG `
    --custom-domain $CustomDomain -o none
Write-Host "Custom domain set."

# ──────────────────────────────────────────────────
# ENABLE PROJECT MANAGEMENT (ARM REST API)
# ──────────────────────────────────────────────────
# This setting is not yet in the stable Azure CLI — we use the ARM REST API directly.
# It enables the "New Foundry" architecture where projects are child resources.
$aiUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.CognitiveServices/accounts/${AIName}?api-version=2025-04-01-preview"

# Create a temp file with the JSON body (az rest requires a file for --body)
$bodyFile = [System.IO.Path]::GetTempPath() + "esiq-allow-pm.json"
'{"properties":{"allowProjectManagement":true}}' | Set-Content $bodyFile -Encoding UTF8

Write-Host "Enabling allowProjectManagement via REST API..."
az rest --method PATCH --uri $aiUri --body "@$bodyFile" -o none

# Clean up temp file
Remove-Item -Force $bodyFile -ErrorAction SilentlyContinue
Write-Host "allowProjectManagement enabled."

# ──────────────────────────────────────────────────
# WAIT FOR PROVISIONING TO COMPLETE
# ──────────────────────────────────────────────────
Write-Host "Waiting for provisioning..."
do {
    $state = az cognitiveservices account show --name $AIName --resource-group $RG --query "properties.provisioningState" -o tsv
    if ($state -ne "Succeeded") {
        Write-Host "  State: $state — waiting 5 seconds..."
        Start-Sleep -Seconds 5
    }
} while ($state -ne "Succeeded")
Write-Host "Provisioning complete."

# ──────────────────────────────────────────────────
# CAPTURE OUTPUT VARIABLES (needed by later steps)
# ──────────────────────────────────────────────────
$AIEndpoint = az cognitiveservices account show --name $AIName --resource-group $RG --query "properties.endpoint" -o tsv
$AIId       = az cognitiveservices account show --name $AIName --resource-group $RG --query "id" -o tsv

Write-Host "AI Endpoint: $AIEndpoint"
Write-Host "AI Resource ID: $AIId"
```

### Verify

```powershell
az cognitiveservices account show --name $AIName --resource-group $RG `
    --query "{name:name, kind:kind, endpoint:properties.endpoint, state:properties.provisioningState, customDomain:properties.customSubDomainName}" -o table
```

Expected output:
```
Name        Kind        Endpoint                                    State      CustomDomain
----------  ----------  -----------------------------------------  ---------  ------------
ESIQNew-AI  AIServices  https://esiqnew-ai.openai.azure.com/       Succeeded  esiqnew-ai
```

### What is `az rest`?

`az rest` is the Azure CLI's tool for calling **any** Azure REST API directly. We use it here because `allowProjectManagement` is a new property not yet exposed as a CLI parameter. The `--method PATCH` sends a partial update to the resource, and `--body "@file"` reads the JSON from a file.

**Learn more:**
- [Azure AI Foundry — What is it?](https://learn.microsoft.com/en-us/azure/ai-studio/what-is-ai-studio)
- [CognitiveServices accounts REST API](https://learn.microsoft.com/en-us/rest/api/cognitiveservices/accountmanagement/accounts)
- [az cognitiveservices account create](https://learn.microsoft.com/en-us/cli/azure/cognitiveservices/account#az-cognitiveservices-account-create)
- [az rest — Call any Azure REST API](https://learn.microsoft.com/en-us/cli/azure/reference-index#az-rest)

---

## 6. Step 3 — Foundry Project

### What is a Foundry Project?

A Foundry Project is a **child resource** of the Foundry Resource. It represents a workspace visible in [ai.azure.com](https://ai.azure.com) where you can:
- Register AI agents
- View model deployments
- Monitor agent activity

The project is created via ARM REST API (not standard CLI) because it uses the newer `CognitiveServices/accounts/projects` resource type.

### Commands

```powershell
# ──────────────────────────────────────────────────
# CREATE FOUNDRY PROJECT
# ──────────────────────────────────────────────────
$ApiVersion = "2025-06-01"
$projUri    = "https://management.azure.com${AIId}/projects/${ProjectName}?api-version=$ApiVersion"

# Check if project already exists
$projExists = az rest --method GET --uri $projUri --query "properties.provisioningState" -o tsv 2>$null

if ($projExists -eq "Succeeded") {
    Write-Host "Foundry Project $ProjectName already exists — skipping."
} else {
    Write-Host "Creating Foundry Project: $ProjectName..."

    # Project body: location + system-assigned identity
    $projBodyFile = [System.IO.Path]::GetTempPath() + "esiq-project.json"
    @"
{
    "location": "$Location",
    "identity": { "type": "SystemAssigned" },
    "properties": {}
}
"@ | Set-Content $projBodyFile -Encoding UTF8

    az rest --method PUT --uri $projUri --body "@$projBodyFile" -o none
    Remove-Item -Force $projBodyFile -ErrorAction SilentlyContinue

    # Wait for provisioning
    Write-Host "Waiting for project provisioning..."
    do {
        $state = az rest --method GET --uri $projUri --query "properties.provisioningState" -o tsv 2>$null
        if ($state -ne "Succeeded") {
            Write-Host "  State: $state — waiting 5 seconds..."
            Start-Sleep -Seconds 5
        }
    } while ($state -ne "Succeeded")
    Write-Host "Project provisioning complete."
}

# ──────────────────────────────────────────────────
# CAPTURE PROJECT ENDPOINT (needed by Container App)
# ──────────────────────────────────────────────────
$ProjectEndpoint = az rest --method GET --uri $projUri --query "properties.endpoints.""AI Foundry API""" -o tsv 2>$null
Write-Host "Project Endpoint: $ProjectEndpoint"
```

### Verify

```powershell
az rest --method GET --uri $projUri --query "{name:name, state:properties.provisioningState}" -o json
```

### What is `api-version=2025-06-01`?

Every Azure REST API call requires an API version. This specifies which version of the resource provider's contract you're calling. Version `2025-06-01` supports the new Foundry project model with `CognitiveServices/accounts/projects`.

**Learn more:**
- [Azure AI Foundry projects](https://learn.microsoft.com/en-us/azure/ai-studio/concepts/create-projects)
- [Azure REST API versioning](https://learn.microsoft.com/en-us/rest/api/azure/#api-versioning)

---

## 7. Step 4 — Primary Model Deployment (gpt-4.1)

### What is a Model Deployment?

A Model Deployment makes an LLM available for API calls. You deploy a specific model (e.g., `gpt-4.1`) with a specific capacity (TPM = Tokens Per Minute). The deployment name becomes the identifier you use when calling the API.

### Commands

```powershell
$PrimaryModel   = "gpt-4.1"
$ModelSku        = "Standard"
$ModelCapacity   = 30            # 30K TPM (tokens per minute)

# Check if deployment exists
$m1Exists = az cognitiveservices account deployment show `
    --name $AIName --resource-group $RG `
    --deployment-name $PrimaryModel --query "name" -o tsv 2>$null

if ($m1Exists) {
    Write-Host "Model deployment $PrimaryModel already exists — skipping."
} else {
    Write-Host "Deploying model: $PrimaryModel ($ModelSku, ${ModelCapacity}K TPM)..."
    az cognitiveservices account deployment create `
        --name $AIName --resource-group $RG `
        --deployment-name $PrimaryModel `
        --model-name $PrimaryModel `
        --model-version "2025-04-14" `
        --model-format "OpenAI" `
        --sku-name $ModelSku `
        --sku-capacity $ModelCapacity -o none
    Write-Host "Deployed $PrimaryModel."
}
```

### Verify

```powershell
az cognitiveservices account deployment show `
    --name $AIName --resource-group $RG `
    --deployment-name $PrimaryModel `
    --query "{name:name, model:properties.model.name, version:properties.model.version, sku:sku.name, capacity:sku.capacity}" -o table
```

Expected output:
```
Name     Model    Version      Sku       Capacity
-------  -------  ----------   --------  --------
gpt-4.1  gpt-4.1  2025-04-14  Standard  30
```

### Understanding Model SKUs

| SKU | What It Means | Cost Model |
|-----|--------------|------------|
| **Standard** | Shared capacity, pay-per-token, quota limits apply | Per 1K tokens (input + output) |
| **GlobalStandard** | Microsoft routes to available region — better availability | Per 1K tokens |
| **ProvisionedManaged** | Dedicated throughput — guaranteed capacity | Hourly rate |

For most deployments, `Standard` at 30K TPM is sufficient.

**Learn more:**
- [Deploy Azure OpenAI models](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/create-resource)
- [Azure OpenAI quotas and limits](https://learn.microsoft.com/en-us/azure/ai-services/openai/quotas-limits)
- [Model availability by region](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/models)

---

## 8. Step 5 — Fallback Model Deployment (gpt-5.1)

### Why a Fallback Model?

The agent uses `gpt-4.1` for most operations. `gpt-5.1` is a more capable (and more expensive) model used as a fallback for complex tasks. The application code handles the failover automatically.

### Commands

```powershell
$FallbackModel = "gpt-5.1"

$m2Exists = az cognitiveservices account deployment show `
    --name $AIName --resource-group $RG `
    --deployment-name $FallbackModel --query "name" -o tsv 2>$null

if ($m2Exists) {
    Write-Host "Model deployment $FallbackModel already exists — skipping."
} else {
    Write-Host "Deploying model: $FallbackModel ($ModelSku, ${ModelCapacity}K TPM)..."
    az cognitiveservices account deployment create `
        --name $AIName --resource-group $RG `
        --deployment-name $FallbackModel `
        --model-name $FallbackModel `
        --model-version "2025-11-13" `
        --model-format "OpenAI" `
        --sku-name $ModelSku `
        --sku-capacity $ModelCapacity -o none
    Write-Host "Deployed $FallbackModel."
}
```

### Verify Both Models

```powershell
az cognitiveservices account deployment list --name $AIName --resource-group $RG -o table
```

---

## 9. Step 6 — Storage Account

### What is an Azure Storage Account?

A Storage Account provides cloud storage for blobs (files), queues, tables, and file shares. In this deployment, it stores assessment reports as blobs.

### Commands

```powershell
$stExists = az storage account show --name $StorageName --resource-group $RG --query "name" -o tsv 2>$null

if ($stExists) {
    Write-Host "Storage Account $StorageName already exists — skipping."
} else {
    Write-Host "Creating Storage Account: $StorageName..."
    az storage account create `
        --name $StorageName `
        --resource-group $RG `
        --location $Location `
        --sku "Standard_LRS" `
        --kind "StorageV2" `
        --min-tls-version "TLS1_2" -o none
    Write-Host "Created $StorageName."
}
```

### Understanding the Parameters

| Parameter | Value | Why |
|-----------|-------|-----|
| `--sku Standard_LRS` | Locally-Redundant Storage | 3 copies within one datacenter — cheapest option, sufficient for reports |
| `--kind StorageV2` | General-purpose v2 | Supports blobs, files, queues, tables — modern default |
| `--min-tls-version TLS1_2` | TLS 1.2 minimum | Security best practice — blocks TLS 1.0/1.1 connections |

### Verify

```powershell
az storage account show --name $StorageName --resource-group $RG `
    --query "{name:name, sku:sku.name, tls:minimumTlsVersion, httpsOnly:enableHttpsTrafficOnly}" -o table
```

**Learn more:**
- [Storage account overview](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview)
- [Storage redundancy options (LRS vs GRS vs ZRS)](https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy)
- [az storage account create](https://learn.microsoft.com/en-us/cli/azure/storage/account#az-storage-account-create)

---

## 10. Step 7 — Key Vault

### What is Azure Key Vault?

Key Vault is a managed service for storing secrets (passwords, connection strings), encryption keys, and certificates. We create it with RBAC authorization mode (instead of the older "access policies" model).

### Commands

```powershell
$kvExists = az keyvault show --name $KVName --resource-group $RG --query "name" -o tsv 2>$null

if ($kvExists) {
    Write-Host "Key Vault $KVName already exists — skipping."
} else {
    Write-Host "Creating Key Vault: $KVName (RBAC authorization)..."
    az keyvault create `
        --name $KVName `
        --resource-group $RG `
        --location $Location `
        --enable-rbac-authorization true -o none
    Write-Host "Created $KVName."
}
```

### Why RBAC Authorization?

Key Vault has two authorization models:
- **Vault access policies** (legacy) — permissions defined per-identity at the vault level
- **Azure RBAC** (recommended) — uses standard Azure role assignments, consistent with all other Azure resources

RBAC is the recommended approach because you manage all permissions in one place.

### Verify

```powershell
az keyvault show --name $KVName --resource-group $RG `
    --query "{name:name, enableRbacAuthorization:properties.enableRbacAuthorization}" -o table
```

**Learn more:**
- [What is Azure Key Vault?](https://learn.microsoft.com/en-us/azure/key-vault/general/overview)
- [Key Vault RBAC vs access policies](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [az keyvault create](https://learn.microsoft.com/en-us/cli/azure/keyvault#az-keyvault-create)

---

## 11. Step 8 — Log Analytics Workspace

### What is Log Analytics?

Log Analytics is Azure's centralized log storage and query engine. Container Apps, Application Insights, and other services send their logs here. You query logs using KQL (Kusto Query Language).

### Commands

```powershell
$lawExists = az monitor log-analytics workspace show `
    --resource-group $RG --workspace-name $LAWName --query "name" -o tsv 2>$null

if ($lawExists) {
    Write-Host "Log Analytics Workspace $LAWName already exists — skipping."
} else {
    Write-Host "Creating Log Analytics Workspace: $LAWName..."
    az monitor log-analytics workspace create `
        --resource-group $RG `
        --workspace-name $LAWName -o none
    Write-Host "Created $LAWName."
}

# ──────────────────────────────────────────────────
# CAPTURE IDs (needed by App Insights and Container Apps Env)
# ──────────────────────────────────────────────────
$LAWId         = az monitor log-analytics workspace show --resource-group $RG --workspace-name $LAWName --query "id" -o tsv
$LAWCustomerId = az monitor log-analytics workspace show --resource-group $RG --workspace-name $LAWName --query "customerId" -o tsv

Write-Host "LAW Resource ID: $LAWId"
Write-Host "LAW Customer ID: $LAWCustomerId"
```

### What is `customerId`?

The Log Analytics Workspace has two IDs:
- **Resource ID** (`$LAWId`) — the full ARM path, used to link App Insights
- **Customer ID** (`$LAWCustomerId`) — a GUID used by Container Apps Environment to send logs

### Verify

```powershell
az monitor log-analytics workspace show --resource-group $RG --workspace-name $LAWName `
    --query "{name:name, customerId:customerId, sku:sku.name}" -o table
```

**Learn more:**
- [Log Analytics workspace overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview)
- [KQL (Kusto Query Language) overview](https://learn.microsoft.com/en-us/kusto/query/)
- [az monitor log-analytics workspace](https://learn.microsoft.com/en-us/cli/azure/monitor/log-analytics/workspace)

---

## 12. Step 9 — Application Insights

### What is Application Insights?

Application Insights is Azure's Application Performance Monitoring (APM) service. It collects:
- Request traces (HTTP calls to your API)
- Dependency tracking (calls from your app to external services)
- Exceptions and error logs
- Custom metrics

It's linked to the Log Analytics Workspace, so all telemetry is queryable via KQL.

### Commands

```powershell
$aiInsExists = az monitor app-insights component show `
    --app $AppInsightsName --resource-group $RG --query "name" -o tsv 2>$null

if ($aiInsExists) {
    Write-Host "App Insights $AppInsightsName already exists — skipping."
} else {
    Write-Host "Creating Application Insights: $AppInsightsName (linked to $LAWName)..."
    az monitor app-insights component create `
        --app $AppInsightsName `
        --resource-group $RG `
        --location $Location `
        --workspace $LAWId -o none
    Write-Host "Created $AppInsightsName."
}
```

### Verify

```powershell
az monitor app-insights component show --app $AppInsightsName --resource-group $RG `
    --query "{name:name, connectionString:connectionString}" -o table
```

**Learn more:**
- [What is Application Insights?](https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview)
- [Workspace-based Application Insights](https://learn.microsoft.com/en-us/azure/azure-monitor/app/convert-classic-resource)

---

## 13. Step 10 — Container Registry

### What is Azure Container Registry (ACR)?

ACR is a managed Docker registry — it stores your Docker images. Think of it as a private Docker Hub. The built-in "ACR Tasks" feature lets you build images remotely (no local Docker needed).

### Commands

```powershell
$acrExists = az acr show --name $ACRName --resource-group $RG --query "name" -o tsv 2>$null

if ($acrExists) {
    Write-Host "Container Registry $ACRName already exists — skipping."
} else {
    Write-Host "Creating Container Registry: $ACRName (Basic SKU)..."
    az acr create `
        --name $ACRName `
        --resource-group $RG `
        --sku "Basic" -o none
    Write-Host "Created $ACRName."
}

# ──────────────────────────────────────────────────
# CAPTURE ACR ID (needed for RBAC AcrPull role)
# ──────────────────────────────────────────────────
$ACRId = az acr show --name $ACRName --resource-group $RG --query "id" -o tsv
Write-Host "ACR Resource ID: $ACRId"
```

### Understanding ACR SKUs

| SKU | Storage | Features | Use Case |
|-----|---------|----------|----------|
| **Basic** | 10 GiB | Pull/push, ACR Tasks | Single-app deployments (sufficient here) |
| **Standard** | 100 GiB | + Webhooks, geo-replication eligibility | Multi-app teams |
| **Premium** | 500 GiB | + Geo-replication, private endpoints, content trust | Enterprise production |

Basic is sufficient because we store a single image.

### Verify

```powershell
az acr show --name $ACRName --resource-group $RG `
    --query "{name:name, sku:sku.name, loginServer:loginServer}" -o table
```

Expected: `esiqnewacr  Basic  esiqnewacr.azurecr.io`

**Learn more:**
- [Azure Container Registry overview](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-intro)
- [ACR Tasks — Remote builds](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview)
- [ACR SKU comparison](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-skus)

---

## 14. Step 11 — User-Assigned Managed Identity

### What is a Managed Identity?

A Managed Identity is an Azure-managed service account that eliminates the need for secrets. Azure creates and manages the credentials automatically. There are two types:

| Type | Created by | Lifecycle | Use Case |
|------|-----------|-----------|----------|
| **System-assigned** | The resource itself (e.g., a Container App) | Tied to the resource — deleted when the resource is deleted | Quick, 1:1 mapping |
| **User-assigned** | You (standalone resource) | Independent of any resource — survives resource recreation | Shared across resources, resilient to recreation |

We use **user-assigned** because if the Container App is ever deleted and recreated, the identity (and all its RBAC role assignments) survives.

### Commands

```powershell
$idExists = az identity show --name $IDName --resource-group $RG --query "name" -o tsv 2>$null

if ($idExists) {
    Write-Host "Managed Identity $IDName already exists — skipping."
} else {
    Write-Host "Creating User-Assigned Managed Identity: $IDName..."
    az identity create --name $IDName --resource-group $RG -o none
    Write-Host "Created $IDName."
}

# ──────────────────────────────────────────────────
# CAPTURE IDENTITY IDs (needed by RBAC, Container App, Graph permissions)
# ──────────────────────────────────────────────────
$PrincipalId = az identity show --name $IDName --resource-group $RG --query "principalId" -o tsv
$ClientId    = az identity show --name $IDName --resource-group $RG --query "clientId" -o tsv
$IdentityId  = az identity show --name $IDName --resource-group $RG --query "id" -o tsv

Write-Host "Principal ID (object ID): $PrincipalId"
Write-Host "Client ID:                $ClientId"
Write-Host "Identity Resource ID:     $IdentityId"
```

### What Are These Three IDs?

| ID | What It Is | Where It's Used |
|----|-----------|----------------|
| **Principal ID** | The Entra ID object ID of the service principal backing this MI | RBAC role assignments, Graph API permission grants |
| **Client ID** | The application (client) ID | Passed as `AZURE_CLIENT_ID` env var to the container |
| **Identity Resource ID** | Full ARM resource path | `--user-assigned` and `--registry-identity` parameters when creating the Container App |

### Verify

```powershell
az identity show --name $IDName --resource-group $RG `
    --query "{name:name, principalId:principalId, clientId:clientId}" -o table
```

**Learn more:**
- [Managed identities overview](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [User-assigned vs system-assigned](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview#managed-identity-types)
- [az identity create](https://learn.microsoft.com/en-us/cli/azure/identity#az-identity-create)

---

## 15. Step 12a — Azure RBAC Role Assignments

### What is Azure RBAC?

Azure Role-Based Access Control assigns permissions to identities (users, groups, managed identities) at specific scopes (subscription, resource group, individual resource). Each role defines a set of allowed actions.

### Commands

```powershell
# Each role assignment: who (MI) → what role → on which scope
$roles = @(
    @{ Role = "AcrPull";                         Scope = $ACRId;                      Purpose = "Pull Docker images from ACR" },
    @{ Role = "Reader";                          Scope = "/subscriptions/$SubId";     Purpose = "Read Azure resources (CLI scripts)" },
    @{ Role = "Security Reader";                 Scope = "/subscriptions/$SubId";     Purpose = "Read Defender posture data (CLI scripts)" },
    @{ Role = "Cognitive Services OpenAI User";  Scope = $AIId;                       Purpose = "Call Azure OpenAI API" },
    @{ Role = "Azure AI Developer";              Scope = $AIId;                       Purpose = "Register/manage Foundry agents" }
)

foreach ($r in $roles) {
    Write-Host "Assigning role: $($r.Role) → scope: $($r.Scope) ..."
    az role assignment create `
        --assignee $PrincipalId `
        --role $r.Role `
        --scope $r.Scope -o none 2>$null
    Write-Host "  Done. Purpose: $($r.Purpose)"
}
Write-Host "All 5 Azure RBAC roles assigned."
```

### Understanding Each Role

| # | Role | Scope | What It Allows |
|---|------|-------|---------------|
| 1 | **AcrPull** | Container Registry | `docker pull` from the registry — Container Apps uses this to pull the image |
| 2 | **Reader** | Subscription | Read-only access to all Azure resources — used by CLI scripts for compliance scanning |
| 3 | **Security Reader** | Subscription | Read Defender for Cloud data (secure score, alerts, recommendations) — CLI scripts only |
| 4 | **Cognitive Services OpenAI User** | Foundry Resource | Send chat/completion requests to the deployed models |
| 5 | **Azure AI Developer** | Foundry Resource | Create and manage agents in the Foundry project |

> **Important**: Roles #2 and #3 (Reader, Security Reader) are used by CLI scripts only. Web dashboard users authenticate with their own tokens — the MI's Reader/Security Reader roles are NOT used during web-based assessments.

### Verify

```powershell
az role assignment list --assignee $PrincipalId `
    --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

**Learn more:**
- [What is Azure RBAC?](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)
- [Azure built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
- [az role assignment create](https://learn.microsoft.com/en-us/cli/azure/role/assignment#az-role-assignment-create)

---

## 16. Step 12b — Microsoft Graph API Permissions

### What Are Graph Application Permissions?

Microsoft Graph API is the unified API for Microsoft 365 and Entra ID. The managed identity needs **application permissions** (not delegated) to read directory data when running CLI scripts.

Application permissions let the MI access data without a signed-in user. This is different from the web dashboard, where users authenticate with their own delegated permissions.

### Requires: Global Administrator

This step **requires Global Admin** because you're granting application-level Graph permissions. If you don't have Global Admin, ask one to run these commands, or skip this step (the web dashboard still works — only CLI scripts are affected).

### Commands

```powershell
# ──────────────────────────────────────────────────
# LOOK UP THE MICROSOFT GRAPH SERVICE PRINCIPAL
# ──────────────────────────────────────────────────
# The Graph API has a well-known app ID. We need to find its service principal
# in your tenant to get the appRole IDs.
$GraphAppId = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph's fixed app ID

Write-Host "Looking up Microsoft Graph service principal..."
$graphSpResp = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,appRoles" 2>&1

$graphSpParsed = ($graphSpResp | Out-String | ConvertFrom-Json).value[0]
$GraphSpId     = $graphSpParsed.id
$graphRoles    = $graphSpParsed.appRoles

Write-Host "Graph SP Object ID: $GraphSpId"
Write-Host "Found $($graphRoles.Count) available app roles."

# ──────────────────────────────────────────────────
# GRANT 8 APPLICATION PERMISSIONS
# ──────────────────────────────────────────────────
$graphPerms = @(
    @{ Name = "Directory.Read.All";                    Purpose = "Read all directory objects (users, groups, roles)" },
    @{ Name = "Policy.Read.All";                       Purpose = "Read conditional access and authentication policies" },
    @{ Name = "RoleManagement.Read.All";               Purpose = "Read PIM role assignments" },
    @{ Name = "User.Read.All";                         Purpose = "Read user profiles and properties" },
    @{ Name = "AuditLog.Read.All";                     Purpose = "Read sign-in and audit logs" },
    @{ Name = "UserAuthenticationMethod.Read.All";     Purpose = "Read MFA registration status" },
    @{ Name = "IdentityRiskyUser.Read.All";            Purpose = "Read Identity Protection risky users" },
    @{ Name = "Application.Read.All";                  Purpose = "Read app registrations and service principals" }
)

foreach ($perm in $graphPerms) {
    # Find the appRole definition for this permission name
    $role = $graphRoles | Where-Object { $_.value -eq $perm.Name }

    if (-not $role) {
        Write-Host "  WARNING: Permission $($perm.Name) not found in Graph appRoles — skipping." -ForegroundColor Yellow
        continue
    }

    # Build the grant request body
    $body = @{
        principalId = $PrincipalId    # The managed identity's object ID
        resourceId  = $GraphSpId      # The Graph service principal's object ID
        appRoleId   = $role.id        # The specific permission's role ID
    } | ConvertTo-Json -Compress

    Write-Host "  Granting $($perm.Name) → $($perm.Purpose)..."
    try {
        az rest --method POST `
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" `
            --body $body `
            --headers "Content-Type=application/json" -o none 2>$null
        Write-Host "    Granted." -ForegroundColor Green
    } catch {
        Write-Host "    Already granted or insufficient privilege." -ForegroundColor DarkGray
    }
}

Write-Host "Graph API permissions grant complete."
```

### How This Works (Technical Detail)

1. **Find the Graph service principal** — Microsoft Graph has a fixed `appId` (`00000003-...`). We query the tenant's service principal for it to get the list of available `appRoles` (each permission is an appRole with a GUID).

2. **For each permission** — We find the matching `appRole` by its `value` field (e.g., `"Directory.Read.All"`), get its `id` (a GUID), and create an `appRoleAssignment` on the MI's service principal.

3. **The REST call** — `POST /servicePrincipals/{MI_principalId}/appRoleAssignments` creates a link: "This MI (`principalId`) is granted this permission (`appRoleId`) on this resource (`resourceId` = Graph SP)."

### Verify

```powershell
az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" `
    --query "value[].{permission:appRoleId, resource:resourceDisplayName}" -o table
```

**Learn more:**
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Grant application permissions to a managed identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-assign-app-role-managed-identity-cli)
- [Application vs delegated permissions](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)

---

## 17. Step 13 — Container Apps Environment

### What is a Container Apps Environment?

A Container Apps Environment is the hosting platform for one or more Container Apps. It provides:
- Shared networking (VNET)
- Log routing to Log Analytics
- Automatic scaling infrastructure

Think of it as a lightweight Kubernetes cluster that Azure manages for you.

### Commands

```powershell
$envExists = az containerapp env show --name $EnvName --resource-group $RG --query "name" -o tsv 2>$null

if ($envExists) {
    Write-Host "Container Apps Environment $EnvName already exists — skipping."
} else {
    Write-Host "Creating Container Apps Environment: $EnvName..."
    Write-Host "  (This may take 5-10 minutes on first creation)"
    az containerapp env create `
        --name $EnvName `
        --resource-group $RG `
        --logs-workspace-id $LAWCustomerId `
        --location $Location -o none
    Write-Host "Created $EnvName."
}
```

### Why Does It Take 5-10 Minutes?

The Environment provisions underlying infrastructure (a managed Kubernetes cluster, networking, load balancers). This is a one-time cost — subsequent Container App creations are fast.

### Verify

```powershell
az containerapp env show --name $EnvName --resource-group $RG `
    --query "{name:name, state:properties.provisioningState, defaultDomain:properties.defaultDomain}" -o table
```

**Learn more:**
- [Container Apps Environment overview](https://learn.microsoft.com/en-us/azure/container-apps/environment)
- [Consumption plan pricing](https://learn.microsoft.com/en-us/azure/container-apps/billing)
- [az containerapp env create](https://learn.microsoft.com/en-us/cli/azure/containerapp/env#az-containerapp-env-create)

---

## 18. Step 14 — Build Docker Image & Create Container App

### What We're Doing

Two actions in one step:
1. **Build the Docker image** remotely using ACR Tasks (no local Docker needed)
2. **Create the Container App** that runs the image

### Part A: Build the Docker Image

```powershell
# Navigate to the repository root (where Dockerfile expects the build context)
$RepoRoot = Get-Location   # should be the repo root: .../EnterpriseSecurityIQ

Write-Host "Building Docker image via ACR Tasks (remote build)..."
Write-Host "  This uploads the build context to ACR and builds in the cloud."
Write-Host "  The .dockerignore file excludes output/, docs/, .git/ etc."

az acr build `
    --registry $ACRName `
    --image "${AppName}:v1" `
    --file "AIAgent/Dockerfile" `
    "." `
    --no-logs `
    --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')

Write-Host "Image built: ${ACRName}.azurecr.io/${AppName}:v1"
```

### How ACR Tasks Works

Instead of building locally and pushing, `az acr build`:
1. Packages the build context (source files) into a `.tar.gz`
2. Uploads it to ACR
3. ACR runs `docker build` on its own servers
4. The resulting image is stored in the registry

The `--build-arg CACHEBUST=...` ensures the `webapp/` COPY layer is never cached (useful when only the SPA changes).

### Part B: Create the Container App

```powershell
$appExists = az containerapp show --name $AppName --resource-group $RG --query "name" -o tsv 2>$null

if ($appExists) {
    Write-Host "Container App $AppName already exists — updating image..."
    az containerapp update `
        --name $AppName `
        --resource-group $RG `
        --image "${ACRName}.azurecr.io/${AppName}:v1" -o none
} else {
    Write-Host "Creating Container App: $AppName..."
    az containerapp create `
        --name $AppName `
        --resource-group $RG `
        --environment $EnvName `
        --image "${ACRName}.azurecr.io/${AppName}:v1" `
        --registry-server "${ACRName}.azurecr.io" `
        --registry-identity $IdentityId `
        --user-assigned $IdentityId `
        --cpu 1 --memory "2Gi" `
        --min-replicas 0 --max-replicas 3 `
        --target-port 8088 `
        --ingress external `
        --env-vars "AZURE_OPENAI_ENDPOINT=$AIEndpoint" `
                   "AZURE_OPENAI_DEPLOYMENT=$PrimaryModel" `
                   "AZURE_OPENAI_FALLBACK_DEPLOYMENT=$FallbackModel" `
                   "AZURE_OPENAI_API_VERSION=2025-01-01-preview" `
                   "FOUNDRY_PROJECT_ENDPOINT=$ProjectEndpoint" `
                   "AZURE_CLIENT_ID=$ClientId" `
                   "AZURE_TENANT_ID=$TenantId" `
        -o none
    Write-Host "Created $AppName."
}

# ──────────────────────────────────────────────────
# CAPTURE THE FQDN (needed for App Registration redirect URI)
# ──────────────────────────────────────────────────
$FQDN = az containerapp show --name $AppName --resource-group $RG `
    --query "properties.configuration.ingress.fqdn" -o tsv
Write-Host "Container App FQDN: https://$FQDN"
```

### Understanding the Parameters

| Parameter | Value | Why |
|-----------|-------|-----|
| `--registry-server` | `esiqnewacr.azurecr.io` | Where to pull the image from |
| `--registry-identity` | (MI resource ID) | Authenticate to ACR using the managed identity (no passwords) |
| `--user-assigned` | (MI resource ID) | Attach the MI to the Container App |
| `--cpu 1 --memory 2Gi` | 1 vCPU, 2 GiB RAM | Sufficient for the agent workload |
| `--min-replicas 0` | Scale to zero | No cost when idle |
| `--max-replicas 3` | Auto-scale up to 3 | Handle concurrent users |
| `--target-port 8088` | The port the app listens on | Uvicorn serves FastAPI on 8088 |
| `--ingress external` | Publicly accessible via HTTPS | Makes the dashboard reachable from browsers |

### Verify

```powershell
az containerapp show --name $AppName --resource-group $RG `
    --query "{name:name, fqdn:properties.configuration.ingress.fqdn, status:properties.runningStatus}" -o table
```

**Learn more:**
- [Azure Container Apps overview](https://learn.microsoft.com/en-us/azure/container-apps/overview)
- [Container Apps with Managed Identity for ACR](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity-image-pull)
- [Container Apps scaling rules](https://learn.microsoft.com/en-us/azure/container-apps/scale-app)
- [ACR Tasks — Build and push images](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tutorial-quick-task)

---

## 19. Step 15 — Entra App Registration (SPA)

### What is an App Registration?

An App Registration is a **definition** of your application in Entra ID. It tells Entra:
- "This application exists with this client ID"
- "It's a Single-Page Application (SPA) using MSAL.js"
- "It should redirect back to these URLs after login"
- "It needs these delegated permissions"

When a user visits the dashboard and clicks "Login", MSAL.js uses this App Registration to initiate the OAuth 2.0 Authorization Code Flow with PKCE.

### Commands

```powershell
# ──────────────────────────────────────────────────
# CREATE THE APP REGISTRATION
# ──────────────────────────────────────────────────
$existingApp = az ad app list --display-name $DashName --query "[0].appId" -o tsv 2>$null

if ($existingApp) {
    Write-Host "App Registration $DashName already exists (appId=$existingApp)."
    $AppClientId = $existingApp
} else {
    Write-Host "Creating App Registration: $DashName..."
    $appJson = az ad app create `
        --display-name $DashName `
        --sign-in-audience "AzureADMyOrg" `
        --enable-access-token-issuance true `
        --enable-id-token-issuance true `
        -o json
    $AppClientId = ($appJson | ConvertFrom-Json).appId
    Write-Host "Created: appId=$AppClientId"
}

# ──────────────────────────────────────────────────
# SET SPA REDIRECT URIs
# ──────────────────────────────────────────────────
# Two URIs: localhost for local development, Container App FQDN for production
Write-Host "Setting SPA redirect URIs..."
az ad app update --id $AppClientId `
    --spa-redirect-uris "http://localhost:8080" "https://$FQDN" -o none

Write-Host "  http://localhost:8080  (local dev)"
Write-Host "  https://$FQDN  (production)"
Write-Host "App Client ID: $AppClientId"
```

### Understanding the Parameters

| Parameter | Value | Why |
|-----------|-------|-----|
| `--sign-in-audience AzureADMyOrg` | Single tenant only | Only users in YOUR Entra tenant can log in |
| `--enable-access-token-issuance true` | Issue access tokens | MSAL.js needs access tokens for Graph + ARM APIs |
| `--enable-id-token-issuance true` | Issue ID tokens | Identifies the logged-in user |
| `--spa-redirect-uris` | Localhost + FQDN | Where Entra redirects after login (must match exactly) |

### What is PKCE?

PKCE (Proof Key for Code Exchange) is a security enhancement for OAuth 2.0. SPAs can't securely store client secrets, so PKCE uses a dynamically generated code verifier/challenge instead. MSAL.js handles this automatically.

### Verify

```powershell
az ad app show --id $AppClientId `
    --query "{appId:appId, displayName:displayName, audience:signInAudience}" -o table
```

**Learn more:**
- [App registration overview](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
- [Single-page application (SPA) auth](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-spa-overview)
- [OAuth 2.0 authorization code flow with PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [MSAL.js overview](https://learn.microsoft.com/en-us/entra/identity-platform/msal-overview)

---

## 20. Step 16 — Patch SPA Config & Rebuild

### What We're Doing

The SPA (`webapp/index.html`) has placeholder values for the MSAL configuration. We replace them with the real values from our deployment, rebuild the Docker image, and update the Container App.

### Commands

```powershell
# ──────────────────────────────────────────────────
# PATCH webapp/index.html WITH LIVE CONFIGURATION
# ──────────────────────────────────────────────────
$webappFile = Join-Path (Get-Location) "webapp" "index.html"

if (Test-Path $webappFile) {
    Write-Host "Patching webapp/index.html with live configuration..."

    $html = Get-Content $webappFile -Raw -Encoding UTF8

    # Replace MSAL client ID placeholder
    $html = $html.Replace('clientId: "YOUR-CLIENT-ID-HERE"', "clientId: `"$AppClientId`"")

    # Replace tenant ID placeholder
    $html = $html.Replace('YOUR-TENANT-ID-HERE', $TenantId)

    # Replace agent URL placeholder (empty = same-origin, which is what Container Apps provides)
    $html = $html.Replace('const AGENT_URL = "https://YOUR-AGENT-URL-HERE"', 'const AGENT_URL = ""')

    Set-Content $webappFile -Value $html -Encoding UTF8
    Write-Host "  Patched: clientId=$AppClientId"
    Write-Host "  Patched: tenantId=$TenantId"
    Write-Host "  Patched: AGENT_URL='' (same-origin)"

    # ──────────────────────────────────────────────
    # REBUILD IMAGE WITH PATCHED SPA
    # ──────────────────────────────────────────────
    Write-Host "Rebuilding image with patched SPA..."
    az acr build `
        --registry $ACRName `
        --image "${AppName}:v1" `
        --file "AIAgent/Dockerfile" `
        "." `
        --no-logs `
        --build-arg CACHEBUST=$(Get-Date -Format 'yyyyMMddHHmmss')

    # ──────────────────────────────────────────────
    # UPDATE CONTAINER APP WITH NEW IMAGE
    # ──────────────────────────────────────────────
    Write-Host "Updating Container App with patched image..."
    az containerapp update `
        --name $AppName `
        --resource-group $RG `
        --image "${ACRName}.azurecr.io/${AppName}:v1" -o none

    Write-Host "Container App updated with patched SPA."
} else {
    Write-Host "WARNING: webapp/index.html not found at $webappFile" -ForegroundColor Red
    Write-Host "  Make sure you're in the repository root directory."
}
```

### Why Is the SPA Config Baked Into the Image?

The SPA (`webapp/index.html`) is a static HTML file served by the same Container App. Since it needs to know the `clientId` and `tenantId` at load time (before any API calls), these values are embedded in the HTML during the build. This approach:
- **Pro**: Simple, no runtime config injection needed
- **Con**: Changing tenant or App Registration requires an image rebuild

**Learn more:**
- [MSAL.js initialization](https://learn.microsoft.com/en-us/entra/identity-platform/msal-js-initializing-client-applications)

---

## 21. Post-Deployment — Manual Entra Steps

These steps require **Global Administrator** access in the Entra portal. The Azure CLI cannot perform them without Global Admin credentials.

### A. Grant Admin Consent on the App Registration

1. Go to **[entra.microsoft.com](https://entra.microsoft.com)**
2. Navigate to **Identity → Applications → App registrations**
3. Find **ESIQNew-Dashboard** (or search by the appId)
4. Go to **API permissions**
5. Click **Grant admin consent for [your tenant]**
6. Confirm

This grants the delegated permissions (`User.Read`, `Directory.Read.All`, `Policy.Read.All`, `RoleManagement.Read.All`) so users don't need to individually consent.

### B. Assign Entra Directory Roles to the Managed Identity

1. Go to **[entra.microsoft.com](https://entra.microsoft.com)**
2. Navigate to **Identity → Roles & admins → Roles & admins** (yes, double)
3. Search for **Directory Readers**
4. Click **+ Add assignments**
5. Search for **ESIQNew-identity** and add it
6. Repeat for **Global Reader**

| Role | Purpose |
|------|---------|
| **Directory Readers** | Read all directory objects (needed by CLI scripts for comprehensive Entra assessment) |
| **Global Reader** | Read-only access to all tenant settings (needed by CLI scripts for policy assessment) |

> **Note**: These roles are for CLI scripts only. Web dashboard users operate under their own Entra permissions.

**Learn more:**
- [Grant admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)
- [Assign Entra ID roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/manage-roles-portal)

---

## 22. Post-Deployment — Validation Checklist

Run each of these to confirm the deployment is fully operational:

```powershell
# ──────────────────────────────────────────────────
# 1. CONTAINER APP IS RUNNING
# ──────────────────────────────────────────────────
az containerapp show --name $AppName --resource-group $RG `
    --query "{name:name, fqdn:properties.configuration.ingress.fqdn, running:properties.runningStatus}" -o table

# ──────────────────────────────────────────────────
# 2. HEALTH ENDPOINT RESPONDS
# ──────────────────────────────────────────────────
$FQDN = az containerapp show --name $AppName --resource-group $RG `
    --query "properties.configuration.ingress.fqdn" -o tsv
Invoke-RestMethod "https://$FQDN/health"

# ──────────────────────────────────────────────────
# 3. CONTAINER LOGS (check for startup errors)
# ──────────────────────────────────────────────────
az containerapp logs show --name $AppName --resource-group $RG --tail 50

# ──────────────────────────────────────────────────
# 4. ALL 5 RBAC ROLES ASSIGNED
# ──────────────────────────────────────────────────
az role assignment list --assignee $PrincipalId `
    --query "[].{role:roleDefinitionName, scope:scope}" -o table

# ──────────────────────────────────────────────────
# 5. GRAPH PERMISSIONS GRANTED
# ──────────────────────────────────────────────────
az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" `
    --query "value | length(@)"
# Should return 8

# ──────────────────────────────────────────────────
# 6. BOTH MODEL DEPLOYMENTS ACTIVE
# ──────────────────────────────────────────────────
az cognitiveservices account deployment list --name $AIName --resource-group $RG `
    --query "[].{name:name, model:properties.model.name, state:properties.provisioningState}" -o table

# ──────────────────────────────────────────────────
# 7. APP REGISTRATION EXISTS WITH CORRECT REDIRECT URIs
# ──────────────────────────────────────────────────
az ad app show --id $AppClientId `
    --query "{appId:appId, spa:spa.redirectUris}" -o json

# ──────────────────────────────────────────────────
# 8. OPEN DASHBOARD IN BROWSER
# ──────────────────────────────────────────────────
Write-Host "`nDashboard URL: https://$FQDN"
Write-Host "Open in browser → login → send: 'What permissions do I have?'"
```

---

## 23. Environment Variable Reference

These environment variables are set on the Container App in Step 14:

| Variable | Example Value | Where It Comes From |
|----------|--------------|-------------------|
| `AZURE_OPENAI_ENDPOINT` | `https://esiqnew-ai.openai.azure.com/` | Step 2: `$AIEndpoint` |
| `AZURE_OPENAI_DEPLOYMENT` | `gpt-4.1` | Step 4: `$PrimaryModel` |
| `AZURE_OPENAI_FALLBACK_DEPLOYMENT` | `gpt-5.1` | Step 5: `$FallbackModel` |
| `AZURE_OPENAI_API_VERSION` | `2025-01-01-preview` | Fixed value |
| `FOUNDRY_PROJECT_ENDPOINT` | `https://esiqnew-ai.services.ai.azure.com/api` | Step 3: `$ProjectEndpoint` |
| `AZURE_CLIENT_ID` | `d5d10273-...` | Step 11: `$ClientId` (MI client ID) |
| `AZURE_TENANT_ID` | `4a3eb5f4-...` | Step 0: `$TenantId` |

---

## 24. Glossary

| Term | Definition |
|------|-----------|
| **ARM** | Azure Resource Manager — the deployment and management layer for Azure resources. Every `az` CLI command calls ARM under the hood. [Learn more](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/overview) |
| **ACR** | Azure Container Registry — managed Docker registry for storing container images. [Learn more](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-intro) |
| **ACR Tasks** | A feature of ACR that builds Docker images in the cloud — no local Docker installation required. [Learn more](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-tasks-overview) |
| **Container App** | A serverless container hosting service. Azure manages the infrastructure — you just provide a Docker image and configuration. [Learn more](https://learn.microsoft.com/en-us/azure/container-apps/overview) |
| **Delegated permissions** | Permissions that act on behalf of a signed-in user. The app can only do what the user can do. [Learn more](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview) |
| **Application permissions** | Permissions that let an app act as itself (no user context). Used by managed identities and background services. [Learn more](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview) |
| **Entra ID** | Microsoft's identity and access management service (formerly Azure Active Directory / Azure AD). [Learn more](https://learn.microsoft.com/en-us/entra/fundamentals/whatis) |
| **FQDN** | Fully Qualified Domain Name — the complete URL of your Container App (e.g., `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io`). |
| **Foundry** | Azure AI Foundry — Microsoft's platform for building and deploying AI applications. [Learn more](https://learn.microsoft.com/en-us/azure/ai-studio/what-is-ai-studio) |
| **KQL** | Kusto Query Language — used to query data in Log Analytics and other Azure data stores. [Learn more](https://learn.microsoft.com/en-us/kusto/query/) |
| **Managed Identity** | An Azure-managed service account. Azure creates and rotates the credentials automatically — no passwords to manage. [Learn more](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview) |
| **Microsoft Graph** | The unified API for reading and writing data in Microsoft 365 and Entra ID (users, groups, policies, etc.). [Learn more](https://learn.microsoft.com/en-us/graph/overview) |
| **MSAL.js** | Microsoft Authentication Library for JavaScript — handles OAuth 2.0 login flows in SPAs. [Learn more](https://learn.microsoft.com/en-us/entra/identity-platform/msal-overview) |
| **PKCE** | Proof Key for Code Exchange — a security enhancement for OAuth 2.0 in public clients (SPAs, mobile apps) that don't have a client secret. [Learn more](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) |
| **RBAC** | Role-Based Access Control — Azure's permission system where roles (sets of permissions) are assigned to identities at specific scopes. [Learn more](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview) |
| **SPA** | Single-Page Application — a web app that runs entirely in the browser, making API calls to a backend. [Learn more](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-spa-overview) |
| **SSE** | Server-Sent Events — a protocol for streaming data from server to browser over HTTP. The agent uses SSE to stream assessment progress in real-time. [Learn more](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events) |
| **TPM** | Tokens Per Minute — the rate limit for Azure OpenAI model deployments. 30K TPM = 30,000 tokens per minute. |

---

## 25. Permissions Deep Dive — Tool-to-Permission Mapping

This section maps every permission to the specific assessment tools that require it, and explains what breaks when a permission is missing. This covers both **delegated permissions** (SPA / web dashboard users) and **application permissions** (Managed Identity / CLI scripts).

### Understanding the Two Permission Models

| Model | Identity | Used By | How Granted |
|-------|----------|---------|-------------|
| **Delegated** | Logged-in user (via MSAL.js) | Web dashboard — all 6 assessment tools | App Registration → API permissions → Admin consent |
| **Application** | Managed Identity (ESIQNew-identity) | CLI scripts (`run_assessment.py`, `run_risk_analysis.py`, etc.) | Graph REST API → `appRoleAssignments` on MI service principal |

> **Key**: Web dashboard assessments always use **delegated** tokens — the agent can only see what the logged-in user can see. The MI's application permissions are only used by CLI scripts.

### Enterprise App vs App Registration

These are two views of the **same** SPA identity in Entra ID:

| View | Portal Location | What It Shows |
|------|----------------|---------------|
| **App Registration** (ESIQNew-Dashboard) | Entra → App registrations | Configuration: which permissions the app *requests*, redirect URIs, token settings |
| **Enterprise Application** (service principal) | Entra → Enterprise applications | Runtime state: which permissions are *granted*, user assignments, conditional access |

> Admin consent granted on the Enterprise Application side is what actually enables the delegated permissions at runtime.

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
