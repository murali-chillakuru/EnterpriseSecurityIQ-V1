# Known Issues — ESIQNew

## 1. AKS Free-Tier Capacity in swedencentral

**Error**: `AKSCapacityHeavyUsage` — Creating a free tier cluster is unavailable at this time in region swedencentral.

**Impact**: Container Apps Environment cannot be created in `swedencentral`.

**Workaround**: Created the Container Apps Environment in `northeurope` instead. The container app calls the AI Services endpoint in `swedencentral` via HTTPS, adding ~5–10 ms latency per request.

**Resolution**: Monitor AKS capacity in `swedencentral`. When capacity returns, recreate the environment:
```powershell
az containerapp env delete -n ESIQNew-env -g ESIQNew-RG --yes
az containerapp env create -n ESIQNew-env -g ESIQNew-RG --location swedencentral `
  --logs-workspace-id (az monitor log-analytics workspace show -g ESIQNew-RG `
    -n ESIQNew-law --query customerId -o tsv)
```

## 2. ML Extension Preview Warnings (RESOLVED — No Longer Applicable)

**Symptom**: `az ml connection create` and `az ml workspace create` emitted experimental class warnings.

**Resolution**: The `az ml` extension is no longer required. The new architecture uses `Microsoft.CognitiveServices/accounts` with `allowProjectManagement` and child `CognitiveServices/accounts/projects`, which are managed via the core Azure CLI (2.67+) without any ML extension.

## 3. Container App Scale-to-Zero

**Symptom**: First request after idle period takes 10–30 seconds (cold start).

**Impact**: Min replicas is set to 0 to save costs. When all replicas are scaled down, the first incoming request triggers a new container to start.

**Workaround**: Set `--min-replicas 1` if cold starts are unacceptable:
```powershell
az containerapp update -n esiqnew-agent -g ESIQNew-RG --min-replicas 1
```

**Cost Impact**: ~$50/month additional for keeping 1 replica always running.

## 4. Dockerfile Build Context

**Symptom**: `az acr build` with repo root as context fails with `COPY failed: file not found`.

**Impact**: The Dockerfile uses `COPY requirements.txt .` which expects the file in the build context root.

**Resolution**: Use `AIAgent/` as the build context:
```powershell
az acr build --registry esiqnewacr --image esiqnew-agent:v1 --file AIAgent/Dockerfile AIAgent/
```

## 5. Classic ESIQ Resources Still Running

**Note**: The old classic Foundry resources in `ESIQ-RG` (swedencentral) are still provisioned. They cost approximately $5/month idle but are not connected to the new deployment.

**To clean up**:
```powershell
az group delete --name ESIQ-RG --yes --no-wait
```

## 6. Classic Foundry (ML Hub/Project) Not Visible in New Foundry Portal (RESOLVED)

**Symptom**: Initial deployment used `Microsoft.MachineLearningServices/workspaces` (kind: `hub` + kind: `project`). These resources appeared in the *Foundry (classic)* portal but were invisible when switching to "New Foundry" in ai.azure.com.

**Root Cause**: The classic ML Hub/Project resource model is not recognized by the new Foundry portal. Only `Microsoft.CognitiveServices/accounts` with `allowProjectManagement: true` and child `CognitiveServices/accounts/projects` resources are visible.

**Resolution**: Migrated to the new resource model:
- Replaced `ESIQNew-hub` (MachineLearningServices/workspaces, kind: Hub) → `ESIQNew-AI` (CognitiveServices/accounts, kind: AIServices, custom domain: `esiqnew-ai`, allowProjectManagement: true)
- Replaced `ESIQNew-project` (MachineLearningServices/workspaces, kind: Project) → `ESIQNew-AI/ESIQNew-project` (CognitiveServices/accounts/projects)
- deploy.ps1 reduced from 16 steps to 14 (no ML extension, no AI Hub, no AI Connection)
- RBAC "Azure AI Developer" now scoped to `ESIQNew-AI` instead of `ESIQNew-hub`
- Endpoint changed to `https://esiqnew-ai.cognitiveservices.azure.com/`

**Status**: ✅ Resolved — April 12, 2026
