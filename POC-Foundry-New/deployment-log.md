# Deployment Log — New Foundry (ESIQNew)

> Deployed on **12 April 2026** using Azure CLI + `az ml` extension.

## Prerequisites Verified

- Azure CLI: `2.77.0`
- ML extension: `v2.42.0`
- azd: `v1.23.11`
- Subscription: **AI** (`d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0`)
- Tenant: `4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67`
- Signed-in user: `admin@MngEnvMCAP250477.onmicrosoft.com`

## Step-by-Step Log

### Step 1 — Resource Group

```
az group create --name "ESIQNew-RG" --location "swedencentral"
```

- **Result**: `provisioningState: Succeeded`

### Step 2 — AI Services (S0)

```
az cognitiveservices account create --name "ESIQNew-AI" --resource-group "ESIQNew-RG"
  --kind "AIServices" --sku "S0" --location "swedencentral" --yes
```

- **Result**: `provisioningState: Succeeded`
- **Endpoint**: `https://swedencentral.api.cognitive.microsoft.com/`

### Step 3 — Model: gpt-4.1

```
az cognitiveservices account deployment create --name "ESIQNew-AI" --resource-group "ESIQNew-RG"
  --deployment-name "gpt-4.1" --model-name "gpt-4.1" --model-version "2025-04-14"
  --model-format "OpenAI" --sku-name "Standard" --sku-capacity 30
```

- **Result**: `provisioningState: Succeeded` (30K TPM, Standard)

### Step 4 — Model: gpt-5.1

```
az cognitiveservices account deployment create --name "ESIQNew-AI" --resource-group "ESIQNew-RG"
  --deployment-name "gpt-5.1" --model-name "gpt-5.1" --model-version "2025-11-13"
  --model-format "OpenAI" --sku-name "Standard" --sku-capacity 30
```

- **Result**: `provisioningState: Succeeded` (30K TPM, Standard)

### Step 5 — Storage Account

```
az storage account create --name "esiqnewstorage" --resource-group "ESIQNew-RG"
  --location "swedencentral" --sku "Standard_LRS" --kind "StorageV2" --min-tls-version "TLS1_2"
```

- **Result**: `provisioningState: Succeeded`

### Step 6 — Key Vault

```
az keyvault create --name "ESIQNew-kv" --resource-group "ESIQNew-RG"
  --location "swedencentral" --enable-rbac-authorization true
```

- **Result**: `provisioningState: Succeeded`
- **URI**: `https://esiqnew-kv.vault.azure.net/`

### Step 7 — Log Analytics Workspace

```
az monitor log-analytics workspace create --workspace-name "ESIQNew-law"
  --resource-group "ESIQNew-RG" --location "swedencentral"
```

- **Result**: `provisioningState: Succeeded`

### Step 8 — Application Insights

```
az monitor app-insights component create --app "ESIQNew-appinsights"
  --resource-group "ESIQNew-RG" --location "swedencentral"
  --workspace "/subscriptions/.../workspaces/ESIQNew-law"
```

- **Result**: `provisioningState: Succeeded`
- **AppId**: `202d6802-fce9-448f-9226-3fb451400908`

### Step 9 — Container Registry

```
az acr create --name "esiqnewacr" --resource-group "ESIQNew-RG"
  --location "swedencentral" --sku "Basic" --admin-enabled false
```

- **Result**: Login server: `esiqnewacr.azurecr.io`

### Step 10 — AI Hub

```
az ml workspace create --kind hub --name "ESIQNew-hub" --resource-group "ESIQNew-RG"
  --location "swedencentral" --storage-account <storageId> --key-vault <kvId>
  --application-insights <aiId> --container-registry <acrId>
```

- **Result**: Created in 41s
- This is the `MachineLearningServices/workspaces` resource with `kind: hub`

### Step 11 — AI Services Connection

```
az ml connection create --file esiqnew-ai-connection.yaml
  --resource-group "ESIQNew-RG" --workspace-name "ESIQNew-hub"
```

- **Connection YAML**: `type: azure_ai_services`, points to ESIQNew-AI endpoint + API key
- **Result**: `{name: ESIQNew-AI, type: azure_ai_services}`

### Step 12 — AI Project

```
az ml workspace create --kind project --name "ESIQNew-project"
  --resource-group "ESIQNew-RG" --hub-id <hubId>
```

- **Result**: Created in 46s
- This is the `MachineLearningServices/workspaces` resource with `kind: project`
- **Now visible in ai.azure.com**

### Step 13 — Managed Identity

```
az identity create --name "ESIQNew-identity" --resource-group "ESIQNew-RG"
```

- **Principal ID**: `d742617c-6f14-4215-be65-e1f7b68866de`
- **Client ID**: `d5d10273-4a8b-4251-9b9d-00fe035df97a`

### Step 14 — RBAC Assignments (5 roles)

| Role | Scope | Status |
|---|---|---|
| AcrPull | `esiqnewacr` | Assigned |
| Reader | Subscription | Assigned |
| Security Reader | Subscription | Assigned |
| Cognitive Services OpenAI User | `ESIQNew-AI` | Assigned |
| Azure AI Developer | `ESIQNew-hub` | Assigned |

### Step 15 — Container Apps Environment

```
az containerapp env create --name "ESIQNew-env" --resource-group "ESIQNew-RG"
  --location "northeurope" --logs-workspace-id <lawCustomerId>
```

- **Note**: `swedencentral` failed with `AKSCapacityHeavyUsage` error (free-tier AKS capacity exhausted). Used `northeurope` as fallback.
- **Result**: `provisioningState: Succeeded`

### Step 16 — ACR Build + Container App

```
az acr build --registry "esiqnewacr" --image "esiqnew-agent:v1" --file "AIAgent/Dockerfile" "AIAgent/"
az containerapp create --name "esiqnew-agent" --resource-group "ESIQNew-RG"
  --environment "ESIQNew-env" --image "esiqnewacr.azurecr.io/esiqnew-agent:v1"
  --registry-server "esiqnewacr.azurecr.io" --registry-identity <identityId>
  --user-assigned <identityId> --ingress external --target-port 8088
  --cpu 1.0 --memory 2.0Gi --min-replicas 0 --max-replicas 3
  --env-vars AZURE_OPENAI_ENDPOINT=... PRIMARY_MODEL=gpt-4.1 ...
```

- **FQDN**: `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io`
- **Running Status**: Running

## Summary

All 16 steps completed successfully. Total resources: **14** Azure resources across `swedencentral` (AI + supporting services) and `northeurope` (Container Apps).
