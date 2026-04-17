# POC — New Foundry Deployment

## Overview

This Proof-of-Concept deploys **EnterpriseSecurityIQ** on the **new Microsoft Foundry** architecture (Hub → Project) so the AI resources are visible and manageable through [ai.azure.com](https://ai.azure.com).

| Property | Value |
|---|---|
| **Prefix** | `ESIQNew` |
| **Subscription** | AI (`d33fc1a7-56aa-4c30-a4a0-98b1e04fafd0`) |
| **Resource Group** | `ESIQNew-RG` |
| **AI Services Region** | `swedencentral` |
| **Container Apps Region** | `northeurope` (AKS capacity fallback) |
| **Deployment Date** | 12 Apr 2026 |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  ESIQNew-RG  (swedencentral)                            │
│                                                         │
│  ┌──────────────────┐   ┌─────────────────────────────┐ │
│  │  ESIQNew-AI      │   │  ESIQNew-hub  (AI Hub)      │ │
│  │  (AIServices S0) │◄──│    └─ ESIQNew-project       │ │
│  │  gpt-4.1         │   │       (AI Project)          │ │
│  │  gpt-5.1         │   └─────────────────────────────┘ │
│  └──────────────────┘                                   │
│                                                         │
│  ┌──────────────┐  ┌───────────┐  ┌─────────────────┐  │
│  │ esiqnewacr   │  │ESIQNew-kv │  │ esiqnewstorage  │  │
│  │ (ACR)        │  │(Key Vault)│  │ (Storage)       │  │
│  └──────────────┘  └───────────┘  └─────────────────┘  │
│                                                         │
│  ┌───────────────────┐  ┌────────────────────────────┐  │
│  │ ESIQNew-law       │  │ ESIQNew-appinsights        │  │
│  │ (Log Analytics)   │  │ (Application Insights)     │  │
│  └───────────────────┘  └────────────────────────────┘  │
│                                                         │
│  ┌───────────────────┐                                  │
│  │ESIQNew-identity   │                                  │
│  │(Managed Identity) │                                  │
│  └───────────────────┘                                  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│  ESIQNew-env  (northeurope — Container Apps)            │
│                                                         │
│  ┌────────────────────────────────────────────────────┐ │
│  │  esiqnew-agent                                     │ │
│  │  esiqnewacr.azurecr.io/esiqnew-agent:v1           │ │
│  │  Port 8088 · External Ingress · 1 vCPU / 2 GiB    │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Classic vs. New Foundry

| Aspect | Classic (ESIQ) | New Foundry (ESIQNew) |
|---|---|---|
| AI resource type | `CognitiveServices/accounts` (kind: OpenAI) | `CognitiveServices/accounts` (kind: AIServices) |
| Foundry portal | **Not visible** in ai.azure.com | **Visible** in ai.azure.com |
| Hub | None | `ESIQNew-hub` (MachineLearningServices/workspaces, kind: hub) |
| Project | None | `ESIQNew-project` (MachineLearningServices/workspaces, kind: project) |
| Connection | Direct endpoint | AI Services connection via Hub |
| Supporting resources | Minimal | Storage, Key Vault, LAW, App Insights, ACR |

## Endpoints

| Service | URL |
|---|---|
| **Container App** | `https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io/` |
| **AI Services** | `https://swedencentral.api.cognitive.microsoft.com/` |
| **Key Vault** | `https://esiqnew-kv.vault.azure.net/` |
| **ACR** | `esiqnewacr.azurecr.io` |

## Files in This Folder

| File | Description |
|---|---|
| [README.md](README.md) | This overview |
| [deployment-log.md](deployment-log.md) | Step-by-step deployment log with timestamps |
| [resource-inventory.md](resource-inventory.md) | Full resource inventory with Azure IDs |
| [rbac-assignments.md](rbac-assignments.md) | RBAC role assignments for the managed identity |
| [known-issues.md](known-issues.md) | Known issues and workarounds |
| [teardown.ps1](teardown.ps1) | Script to delete all ESIQNew resources |
| [rebuild.ps1](rebuild.ps1) | Script to rebuild the entire environment |

## Quick Commands

```powershell
# Check container status
az containerapp show -n esiqnew-agent -g ESIQNew-RG --query "properties.runningStatus" -o tsv

# View logs
az containerapp logs show -n esiqnew-agent -g ESIQNew-RG --type console

# Rebuild image
..\Infra-Foundary-New\redeploy-image.ps1 -BaseName ESIQNew -ResourceGroup ESIQNew-RG

# Tear down everything
.\teardown.ps1
```
