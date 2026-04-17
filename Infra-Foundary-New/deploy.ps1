<#
.SYNOPSIS
    Deploy EnterpriseSecurityIQ on Microsoft Foundry (New Architecture).

.DESCRIPTION
    Creates a full Microsoft Foundry deployment visible in ai.azure.com (New Foundry toggle ON):
      - Resource Group
      - Foundry Resource (CognitiveServices/accounts, kind: AIServices) with custom domain
        and allowProjectManagement enabled
      - Foundry Project (CognitiveServices/accounts/projects) — VISIBLE in New Foundry portal
      - Model Deployments (gpt-4.1 primary, gpt-5.1 fallback)
      - Storage Account, Key Vault (for app secrets)
      - Application Insights + Log Analytics (observability)
      - Container Registry
      - User-Assigned Managed Identity + RBAC
      - Container Apps Environment + Container App

    Uses Azure CLI + ARM REST API (no ML extension required). Idempotent — safe to re-run.

    Resource model follows the "Current" Foundry architecture per:
      https://learn.microsoft.com/en-us/azure/foundry/what-is-foundry
      https://learn.microsoft.com/en-us/azure/foundry/concepts/general-availability

.PARAMETER BaseName
    Prefix for all resources. Default: ESIQNew

.PARAMETER Location
    Azure region. Default: swedencentral

.PARAMETER SubscriptionName
    Azure subscription name. Default: AI

.PARAMETER PrimaryModel
    Primary model deployment name. Default: gpt-4.1

.PARAMETER FallbackModel
    Fallback model deployment name. Default: gpt-5.1

.NOTES
    Author: Murali Chillakuru
    Date:   April 12, 2026
    Requires: Azure CLI 2.67+
#>

[CmdletBinding()]
param(
    [string]$BaseName              = "ESIQNew",
    [string]$Location              = "swedencentral",
    [string]$ContainerAppsLocation = "northeurope",
    [string]$SubscriptionName      = "AI",
    [string]$PrimaryModel          = "gpt-4.1",
    [string]$FallbackModel         = "gpt-5.1",
    [string]$ModelSku              = "Standard",
    [int]   $ModelCapacity         = 30,
    [string]$TenantId              = ""
)

$ErrorActionPreference = "Stop"
$RG            = "$BaseName-RG"
$AIName        = "$BaseName-AI"
$CustomDomain  = $AIName.ToLower()          # must be globally unique
$ProjectName   = "$BaseName-project"
$StorageName   = "$($BaseName.ToLower())storage"
$KVName        = "$BaseName-kv"
$AppInsights   = "$BaseName-appinsights"
$LAWName       = "$BaseName-law"
$ACRName       = "$($BaseName.ToLower())acr"
$IDName        = "$BaseName-identity"
$EnvName       = "$BaseName-env"
$AppName       = "$($BaseName.ToLower())-agent"
$DashName      = "$BaseName-Dashboard"
$ApiVersion    = "2025-06-01"               # ARM API for CognitiveServices projects

Write-Host "`n╔════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  EnterpriseSecurityIQ — New Foundry Deployment     ║" -ForegroundColor Cyan
Write-Host "║  Prefix: $BaseName  Region: $Location   (16 steps) ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# ── Pre-flight ──
Write-Host "[Pre-flight] Checking Azure CLI..." -ForegroundColor DarkGray
az account set --subscription $SubscriptionName 2>$null
Write-Host "  Subscription: $SubscriptionName" -ForegroundColor DarkGray

$SubId = az account show --query "id" -o tsv
if (-not $TenantId) { $TenantId = az account show --query "tenantId" -o tsv }

# ═══════════════════════════════════════════════════════
# Step 1: Resource Group
# ═══════════════════════════════════════════════════════
Write-Host "[1/16] Creating resource group $RG..." -ForegroundColor Yellow
$rgExists = az group exists --name $RG -o tsv
if ($rgExists -eq "true") {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az group create --name $RG --location $Location -o none
}

# ═══════════════════════════════════════════════════════
# Step 2: Foundry Resource (AI Services + custom domain + allowProjectManagement)
# ═══════════════════════════════════════════════════════
Write-Host "[2/16] Creating Foundry Resource $AIName (S0, custom domain: $CustomDomain)..." -ForegroundColor Yellow
$aiExists = az cognitiveservices account show --name $AIName --resource-group $RG --query "name" -o tsv 2>$null
if ($aiExists) {
    Write-Host "  Already exists — updating custom domain..." -ForegroundColor DarkGray
} else {
    az cognitiveservices account create `
        --name $AIName --resource-group $RG `
        --kind "AIServices" --sku "S0" `
        --location $Location --yes -o none
}

# Set custom domain (required for Foundry projects)
az cognitiveservices account update --name $AIName --resource-group $RG --custom-domain $CustomDomain -o none

# Enable allowProjectManagement via ARM REST API (not yet in stable CLI)
$aiUri = "https://management.azure.com/subscriptions/$SubId/resourceGroups/$RG/providers/Microsoft.CognitiveServices/accounts/${AIName}?api-version=2025-04-01-preview"
$bodyFile = [System.IO.Path]::GetTempPath() + "esiq-allow-pm.json"
[System.IO.File]::WriteAllText($bodyFile, '{"properties":{"allowProjectManagement":true}}', [System.Text.Encoding]::UTF8)
az rest --method PATCH --uri $aiUri --body "@$bodyFile" -o none
Remove-Item -Force $bodyFile -ErrorAction SilentlyContinue

# Wait for provisioning
$state = ""
do {
    $state = az cognitiveservices account show --name $AIName --resource-group $RG --query "properties.provisioningState" -o tsv
    if ($state -ne "Succeeded") { Start-Sleep -Seconds 5 }
} while ($state -ne "Succeeded")

$AIEndpoint = az cognitiveservices account show --name $AIName --resource-group $RG --query "properties.endpoint" -o tsv
$AIId = az cognitiveservices account show --name $AIName --resource-group $RG --query "id" -o tsv
Write-Host "  Endpoint: $AIEndpoint" -ForegroundColor DarkGray

# ═══════════════════════════════════════════════════════
# Step 3: Foundry Project (CognitiveServices child resource)
# ═══════════════════════════════════════════════════════
Write-Host "[3/16] Creating Foundry Project $ProjectName (visible in New Foundry portal)..." -ForegroundColor Yellow
$projUri = "https://management.azure.com${AIId}/projects/${ProjectName}?api-version=$ApiVersion"
$projExists = az rest --method GET --uri $projUri --query "properties.provisioningState" -o tsv 2>$null
if ($projExists -eq "Succeeded") {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    $projBodyFile = [System.IO.Path]::GetTempPath() + "esiq-project.json"
    [System.IO.File]::WriteAllText($projBodyFile, "{`"location`":`"$Location`",`"identity`":{`"type`":`"SystemAssigned`"},`"properties`":{}}", [System.Text.Encoding]::UTF8)
    az rest --method PUT --uri $projUri --body "@$projBodyFile" -o none
    Remove-Item -Force $projBodyFile -ErrorAction SilentlyContinue

    # Wait for provisioning
    $state = ""
    do {
        $state = az rest --method GET --uri $projUri --query "properties.provisioningState" -o tsv 2>$null
        if ($state -ne "Succeeded") { Start-Sleep -Seconds 5 }
    } while ($state -ne "Succeeded")
}
$ProjectEndpoint = az rest --method GET --uri $projUri --query "properties.endpoints.\"AI Foundry API\"" -o tsv 2>$null
Write-Host "  Project endpoint: $ProjectEndpoint" -ForegroundColor DarkGray

# ═══════════════════════════════════════════════════════
# Step 4: Primary model
# ═══════════════════════════════════════════════════════
Write-Host "[4/16] Deploying $PrimaryModel model ($ModelSku, $($ModelCapacity)K TPM)..." -ForegroundColor Yellow
$m1Exists = az cognitiveservices account deployment show --name $AIName --resource-group $RG --deployment-name $PrimaryModel --query "name" -o tsv 2>$null
if ($m1Exists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az cognitiveservices account deployment create `
        --name $AIName --resource-group $RG `
        --deployment-name $PrimaryModel `
        --model-name $PrimaryModel --model-version "2025-04-14" `
        --model-format "OpenAI" --sku-name $ModelSku --sku-capacity $ModelCapacity -o none
}

# ═══════════════════════════════════════════════════════
# Step 5: Fallback model
# ═══════════════════════════════════════════════════════
Write-Host "[5/16] Deploying $FallbackModel model ($ModelSku, $($ModelCapacity)K TPM)..." -ForegroundColor Yellow
$m2Exists = az cognitiveservices account deployment show --name $AIName --resource-group $RG --deployment-name $FallbackModel --query "name" -o tsv 2>$null
if ($m2Exists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az cognitiveservices account deployment create `
        --name $AIName --resource-group $RG `
        --deployment-name $FallbackModel `
        --model-name $FallbackModel --model-version "2025-11-13" `
        --model-format "OpenAI" --sku-name $ModelSku --sku-capacity $ModelCapacity -o none
}

# ═══════════════════════════════════════════════════════
# Step 6: Storage Account
# ═══════════════════════════════════════════════════════
Write-Host "[6/16] Creating Storage Account $StorageName..." -ForegroundColor Yellow
$stExists = az storage account show --name $StorageName --resource-group $RG --query "name" -o tsv 2>$null
if ($stExists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az storage account create `
        --name $StorageName --resource-group $RG `
        --location $Location --sku "Standard_LRS" `
        --kind "StorageV2" --min-tls-version "TLS1_2" -o none
}

# Create blob container for persistent report storage
$containerExists = az storage container show --name "reports" --account-name $StorageName --auth-mode login --query "name" -o tsv 2>$null
if ($containerExists) {
    Write-Host "  Blob container 'reports' already exists — skipping." -ForegroundColor DarkGray
} else {
    az storage container create --name "reports" --account-name $StorageName --auth-mode login -o none 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  NOTE: Could not create blob container via login auth. Will retry after RBAC assignment." -ForegroundColor DarkGray
    } else {
        Write-Host "  Created blob container 'reports'" -ForegroundColor DarkGray
    }
}

# ═══════════════════════════════════════════════════════
# Step 7: Key Vault
# ═══════════════════════════════════════════════════════
Write-Host "[7/16] Creating Key Vault $KVName..." -ForegroundColor Yellow
$kvExists = az keyvault show --name $KVName --resource-group $RG --query "name" -o tsv 2>$null
if ($kvExists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az keyvault create `
        --name $KVName --resource-group $RG `
        --location $Location `
        --enable-rbac-authorization true -o none
}

# ═══════════════════════════════════════════════════════
# Step 8: Log Analytics Workspace
# ═══════════════════════════════════════════════════════
Write-Host "[8/16] Creating Log Analytics Workspace $LAWName..." -ForegroundColor Yellow
$lawExists = az monitor log-analytics workspace show --resource-group $RG --workspace-name $LAWName --query "name" -o tsv 2>$null
if ($lawExists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az monitor log-analytics workspace create --resource-group $RG --workspace-name $LAWName -o none
}
$LAWId = az monitor log-analytics workspace show --resource-group $RG --workspace-name $LAWName --query "id" -o tsv
$LAWCustomerId = az monitor log-analytics workspace show --resource-group $RG --workspace-name $LAWName --query "customerId" -o tsv

# ═══════════════════════════════════════════════════════
# Step 9: Application Insights
# ═══════════════════════════════════════════════════════
Write-Host "[9/16] Creating Application Insights $AppInsights..." -ForegroundColor Yellow
$aiInsExists = az monitor app-insights component show --app $AppInsights --resource-group $RG --query "name" -o tsv 2>$null
if ($aiInsExists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az monitor app-insights component create `
        --app $AppInsights --resource-group $RG `
        --location $Location `
        --workspace $LAWId -o none
}

# ═══════════════════════════════════════════════════════
# Step 10: Container Registry
# ═══════════════════════════════════════════════════════
Write-Host "[10/16] Creating Container Registry $ACRName..." -ForegroundColor Yellow
$acrExists = az acr show --name $ACRName --resource-group $RG --query "name" -o tsv 2>$null
if ($acrExists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az acr create --name $ACRName --resource-group $RG --sku "Basic" -o none
}
$ACRId = az acr show --name $ACRName --resource-group $RG --query "id" -o tsv

# ═══════════════════════════════════════════════════════
# Step 11: Managed Identity
# ═══════════════════════════════════════════════════════
Write-Host "[11/16] Creating Managed Identity $IDName..." -ForegroundColor Yellow
$idExists = az identity show --name $IDName --resource-group $RG --query "name" -o tsv 2>$null
if ($idExists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az identity create --name $IDName --resource-group $RG -o none
}
$PrincipalId = az identity show --name $IDName --resource-group $RG --query "principalId" -o tsv
$ClientId    = az identity show --name $IDName --resource-group $RG --query "clientId" -o tsv
$IdentityId  = az identity show --name $IDName --resource-group $RG --query "id" -o tsv

# ═══════════════════════════════════════════════════════
# Step 12: RBAC Assignments
# ═══════════════════════════════════════════════════════
Write-Host "[12/16] Assigning RBAC roles to $IDName..." -ForegroundColor Yellow
$StorageId = az storage account show --name $StorageName --resource-group $RG --query "id" -o tsv
$roles = @(
    @{ Role = "AcrPull";                              Scope = $ACRId },
    @{ Role = "Reader";                               Scope = "/subscriptions/$SubId" },
    @{ Role = "Security Reader";                      Scope = "/subscriptions/$SubId" },
    @{ Role = "Cognitive Services OpenAI User";       Scope = $AIId },
    @{ Role = "Azure AI Developer";                   Scope = $AIId },
    @{ Role = "Storage Blob Data Contributor";        Scope = $StorageId }
)
foreach ($r in $roles) {
    Write-Host "  Assigning $($r.Role)..." -ForegroundColor DarkGray
    az role assignment create --assignee $PrincipalId --role $r.Role --scope $r.Scope -o none 2>$null
}

# ────── Microsoft Graph API permissions (requires Global Admin) ──────
Write-Host "  Assigning Microsoft Graph API permissions..." -ForegroundColor Cyan
$GraphAppId = "00000003-0000-0000-c000-000000000000"
$graphSpResp = az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id,appRoles" 2>&1
$graphSpParsed = ($graphSpResp | Out-String | ConvertFrom-Json).value[0]
$GraphSpId = $graphSpParsed.id
$graphRoles = $graphSpParsed.appRoles

$graphPerms = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.All",
    "User.Read.All",
    "AuditLog.Read.All",
    "UserAuthenticationMethod.Read.All",
    "IdentityRiskyUser.Read.All",
    "Application.Read.All"
)
foreach ($perm in $graphPerms) {
    $role = $graphRoles | Where-Object { $_.value -eq $perm }
    if ($role) {
        $body = @{ principalId = $PrincipalId; resourceId = $GraphSpId; appRoleId = $role.id } | ConvertTo-Json -Compress
        try {
            az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" `
                --body $body --headers "Content-Type=application/json" -o none 2>$null
            Write-Host "    Granted $perm" -ForegroundColor DarkGray
        } catch {
            Write-Host "    $perm — already granted or insufficient privilege" -ForegroundColor DarkGray
        }
    }
}

# ═══════════════════════════════════════════════════════
# Step 13: Container Apps Environment
# ═══════════════════════════════════════════════════════
Write-Host "[13/16] Creating Container Apps Environment $EnvName (may take 5-10 min)..." -ForegroundColor Yellow
$envExists = az containerapp env show --name $EnvName --resource-group $RG --query "name" -o tsv 2>$null
if ($envExists) {
    Write-Host "  Already exists — skipping." -ForegroundColor DarkGray
} else {
    az containerapp env create `
        --name $EnvName --resource-group $RG `
        --logs-workspace-id $LAWCustomerId `
        --location $ContainerAppsLocation -o none
}

# ═══════════════════════════════════════════════════════
# Step 14: Build image + Create Container App
# ═══════════════════════════════════════════════════════
Write-Host "[14/16] Building image and creating Container App $AppName..." -ForegroundColor Yellow

# Build image
$RepoRoot = Split-Path -Parent $PSScriptRoot
Write-Host "  Building image via ACR Tasks..." -ForegroundColor DarkGray
Push-Location $RepoRoot
try {
    az acr build --registry $ACRName --image "${AppName}:v1" --file "AIAgent/Dockerfile" "." --no-logs
} finally {
    Pop-Location
}

# Create container app
$appExists = az containerapp show --name $AppName --resource-group $RG --query "name" -o tsv 2>$null
if ($appExists) {
    Write-Host "  Container app exists — updating image..." -ForegroundColor DarkGray
    az containerapp update --name $AppName --resource-group $RG `
        --image "${ACRName}.azurecr.io/${AppName}:v1" -o none
} else {
    az containerapp create `
        --name $AppName --resource-group $RG `
        --environment $EnvName `
        --image "${ACRName}.azurecr.io/${AppName}:v1" `
        --registry-server "${ACRName}.azurecr.io" `
        --registry-identity $IdentityId `
        --user-assigned $IdentityId `
        --cpu 1 --memory "2Gi" `
        --min-replicas 0 --max-replicas 3 `
        --target-port 8088 --ingress external `
        --env-vars "AZURE_OPENAI_ENDPOINT=$AIEndpoint" `
                   "AZURE_OPENAI_DEPLOYMENT=$PrimaryModel" `
                   "AZURE_OPENAI_FALLBACK_DEPLOYMENT=$FallbackModel" `
                   "AZURE_OPENAI_API_VERSION=2025-01-01-preview" `
                   "FOUNDRY_PROJECT_ENDPOINT=$ProjectEndpoint" `
                   "AZURE_CLIENT_ID=$ClientId" `
                   "AZURE_TENANT_ID=$TenantId" `
                   "REPORT_STORAGE_ACCOUNT=$StorageName" `
                   "REPORT_STORAGE_CONTAINER=reports" `
        -o none
}

$FQDN = az containerapp show --name $AppName --resource-group $RG --query "properties.configuration.ingress.fqdn" -o tsv

# ═══════════════════════════════════════════════════════
# Step 15: Entra App Registration (SPA authentication)
# ═══════════════════════════════════════════════════════
Write-Host "[15/16] Creating Entra App Registration $DashName..." -ForegroundColor Yellow
$existingApp = az ad app list --display-name $DashName --query "[0].appId" -o tsv 2>$null
if ($existingApp) {
    Write-Host "  Already exists (appId=$existingApp) — updating redirect URIs..." -ForegroundColor DarkGray
    $AppClientId = $existingApp
} else {
    $appJson = az ad app create `
        --display-name $DashName `
        --sign-in-audience "AzureADMyOrg" `
        --enable-access-token-issuance true `
        --enable-id-token-issuance true `
        -o json
    $AppClientId = ($appJson | ConvertFrom-Json).appId
    Write-Host "  Created: appId=$AppClientId" -ForegroundColor DarkGray
}

# Set SPA redirect URIs (localhost for dev + Container App for production)
az ad app update --id $AppClientId `
    --spa-redirect-uris "http://localhost:8080" "https://$FQDN" -o none

Write-Host "  Redirect URIs: http://localhost:8080, https://$FQDN" -ForegroundColor DarkGray

# ═══════════════════════════════════════════════════════
# Step 16: Update webapp config and prepare for serving
# ═══════════════════════════════════════════════════════
Write-Host "[16/16] Patching webapp/index.html with live config..." -ForegroundColor Yellow
$RepoRoot = Split-Path -Parent $PSScriptRoot
$webappFile = Join-Path $RepoRoot "webapp" "index.html"
if (Test-Path $webappFile) {
    $html = Get-Content $webappFile -Raw -Encoding UTF8
    $html = $html.Replace('clientId: "YOUR-CLIENT-ID-HERE"', "clientId: `"$AppClientId`"")
    $html = $html.Replace('YOUR-TENANT-ID-HERE', $TenantId)
    $html = $html.Replace('const AGENT_URL = "https://YOUR-AGENT-URL-HERE"', 'const AGENT_URL = ""')
    Set-Content $webappFile -Value $html -Encoding UTF8
    Write-Host "  Patched MSAL clientId, tenantId, and AGENT_URL" -ForegroundColor DarkGray

    # Rebuild container so the patched webapp is included in the image
    Write-Host "  Rebuilding image with patched webapp..." -ForegroundColor DarkGray
    Push-Location $RepoRoot
    try {
        az acr build --registry $ACRName --image "${AppName}:v1" --file "AIAgent/Dockerfile" "." --no-logs
    } finally {
        Pop-Location
    }
    az containerapp update --name $AppName --resource-group $RG `
        --image "${ACRName}.azurecr.io/${AppName}:v1" -o none
    Write-Host "  Container restarted with updated SPA" -ForegroundColor DarkGray
} else {
    Write-Host "  WARNING: webapp/index.html not found — skipping SPA config" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════
Write-Host "`n╔════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  DEPLOYMENT COMPLETE — Option A+B Architecture      ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Resource Group:    $RG" -ForegroundColor Cyan
Write-Host "  Foundry Resource:  $AIName  (CognitiveServices/accounts)" -ForegroundColor Cyan
Write-Host "  Foundry Project:   $AIName/$ProjectName  (CognitiveServices/accounts/projects)" -ForegroundColor Cyan
Write-Host "  AI Endpoint:       $AIEndpoint" -ForegroundColor Cyan
Write-Host "  Project Endpoint:  $ProjectEndpoint" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ── Option A: Web Dashboard (SPA) ──" -ForegroundColor Magenta
Write-Host "  Dashboard URL:     https://$FQDN" -ForegroundColor Cyan
Write-Host "  App Registration:  $DashName (appId=$AppClientId)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ── Option B: Foundry Agent ──" -ForegroundColor Magenta
Write-Host "  Foundry Portal:    https://ai.azure.com" -ForegroundColor Cyan
Write-Host "  Agent auto-registered on container startup (Assistants API)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Identity:          $IDName ($PrincipalId)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  PENDING: Assign Entra ID roles (Directory Reader, Global Reader)" -ForegroundColor Yellow
Write-Host "           via entra.microsoft.com — requires Global Admin" -ForegroundColor Yellow
Write-Host ""
