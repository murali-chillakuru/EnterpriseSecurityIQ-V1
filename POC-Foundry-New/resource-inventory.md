# Resource Inventory — ESIQNew

> All resources created on **12 April 2026** in subscription **AI** (`d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0`).

## Resource Group

| Property | Value |
|---|---|
| Name | `ESIQNew-RG` |
| Location | `swedencentral` |
| Subscription | AI |

## Resources

### 1. AI Services

| Property | Value |
|---|---|
| Name | `ESIQNew-AI` |
| Type | `Microsoft.CognitiveServices/accounts` |
| Kind | `AIServices` |
| SKU | S0 |
| Location | `swedencentral` |
| Custom Domain | `esiqnew-ai` |
| allowProjectManagement | `true` |
| Endpoint | `https://esiqnew-ai.cognitiveservices.azure.com/` |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/Microsoft.CognitiveServices/accounts/ESIQNew-AI` |

**Model Deployments:**

| Model | Version | SKU | Capacity |
|---|---|---|---|
| gpt-4.1 | 2025-04-14 | Standard | 30K TPM |
| gpt-5.1 | 2025-11-13 | Standard | 30K TPM |

### 2. Storage Account

| Property | Value |
|---|---|
| Name | `esiqnewstorage` |
| Type | `Microsoft.Storage/storageAccounts` |
| Kind | StorageV2 |
| SKU | Standard_LRS |
| Location | `swedencentral` |
| TLS | 1.2 |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/Microsoft.Storage/storageAccounts/esiqnewstorage` |

### 3. Key Vault

| Property | Value |
|---|---|
| Name | `ESIQNew-kv` |
| Type | `Microsoft.KeyVault/vaults` |
| Location | `swedencentral` |
| Auth Model | RBAC |
| Vault URI | `https://esiqnew-kv.vault.azure.net/` |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/Microsoft.KeyVault/vaults/ESIQNew-kv` |

### 4. Log Analytics Workspace

| Property | Value |
|---|---|
| Name | `ESIQNew-law` |
| Type | `Microsoft.OperationalInsights/workspaces` |
| Location | `swedencentral` |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/Microsoft.OperationalInsights/workspaces/ESIQNew-law` |

### 5. Application Insights

| Property | Value |
|---|---|
| Name | `ESIQNew-appinsights` |
| Type | `Microsoft.Insights/components` |
| Location | `swedencentral` |
| App ID | `202d6802-fce9-448f-9226-3fb451400908` |
| Workspace | `ESIQNew-law` |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/microsoft.insights/components/ESIQNew-appinsights` |

### 6. Container Registry

| Property | Value |
|---|---|
| Name | `esiqnewacr` |
| Type | `Microsoft.ContainerRegistry/registries` |
| SKU | Basic |
| Location | `swedencentral` |
| Login Server | `esiqnewacr.azurecr.io` |
| Admin Enabled | No |

### 7. Foundry Project

| Property | Value |
|---|---|
| Name | `ESIQNew-AI/ESIQNew-project` |
| Type | `Microsoft.CognitiveServices/accounts/projects` |
| Parent | `ESIQNew-AI` |
| Location | `swedencentral` |
| Project Endpoint | `https://esiqnew-ai.services.ai.azure.com/api/projects/ESIQNew-project` |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/Microsoft.CognitiveServices/accounts/ESIQNew-AI/projects/ESIQNew-project` |

### 8. Container App

| Property | Value |
|---|---|
| Name | `esiqnew-agent` |
| Type | `Microsoft.App/containerApps` |
| Image | `esiqnewacr.azurecr.io/esiqnew-agent:v4` |
| CPU / Memory | 1 vCPU / 2 GiB |
| Location | `northeurope` |
| FQDN | `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` |
| Port | 8088 |
| Ingress | External |
| Server | FastAPI + uvicorn |
| Identity | ESIQNew-identity (user-assigned) |

### 9. Foundry Agent (Assistants API)

| Property | Value |
|---|---|
| Name | `EnterpriseSecurityIQ` |
| Agent ID | `asst_N4hpInCl30eZHaim3vtJTZiT` |
| Model | gpt-4.1 |
| Tools | 12 function-calling tools |
| Registration | Via Assistants API on container startup |
| Portal | Visible in ai.azure.com under ESIQNew-project |

### 10. Entra App Registration

| Property | Value |
|---|---|
| Name | `ESIQNew-Dashboard` |
| Status | **PENDING** (requires Directory admin) |
| Type | SPA (Single Page Application) |
| Redirect URIs | `http://localhost:8080`, `https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` |

### 8. Managed Identity

| Property | Value |
|---|---|
| Name | `ESIQNew-identity` |
| Type | `Microsoft.ManagedIdentity/userAssignedIdentities` |
| Principal ID | `d742617c-6f14-4215-be65-e1f7b68866de` |
| Client ID | `d5d10273-4a8b-4251-9b9d-00fe035df97a` |
| Resource ID | `/subscriptions/d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0/resourceGroups/ESIQNew-RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ESIQNew-identity` |

### 9. Container Apps Environment

| Property | Value |
|---|---|
| Name | `ESIQNew-env` |
| Type | `Microsoft.App/managedEnvironments` |
| Location | `northeurope` (fallback from swedencentral) |
| Log Analytics | `ESIQNew-law` |

### 10. Container App

| Property | Value |
|---|---|
| Name | `esiqnew-agent` |
| Type | `Microsoft.App/containerApps` |
| Image | `esiqnewacr.azurecr.io/esiqnew-agent:v1` |
| FQDN | `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` |
| Port | 8088 |
| Ingress | External |
| CPU / Memory | 1.0 vCPU / 2.0 GiB |
| Replicas | 0–3 |
| Identity | `ESIQNew-identity` (user-assigned) |

## Environment Variables (Container App)

| Variable | Value |
|---|---|
| `AZURE_OPENAI_ENDPOINT` | `https://esiqnew-ai.cognitiveservices.azure.com/` |
| `AZURE_OPENAI_API_VERSION` | `2025-01-01-preview` |
| `AZURE_OPENAI_DEPLOYMENT` | `gpt-4.1` |
| `AZURE_OPENAI_FALLBACK_DEPLOYMENT` | `gpt-5.1` |
| `FOUNDRY_PROJECT_ENDPOINT` | `https://esiqnew-ai.services.ai.azure.com/api/projects/ESIQNew-project` |
| `AZURE_CLIENT_ID` | `d5d10273-4a8b-4251-9b9d-00fe035df97a` |
| `AZURE_TENANT_ID` | `4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67` |
| `REPORT_STORAGE_ACCOUNT` | `esiqnewstorage` |
| `REPORT_STORAGE_CONTAINER` | `reports` |
