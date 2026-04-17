<#
.SYNOPSIS
    Rebuild and redeploy the container image for ESIQNew Foundry deployment.

.DESCRIPTION
    Rebuilds the Docker image via ACR Tasks and updates the container app.
    Use after code changes in AIAgent/.

.PARAMETER BaseName
    Resource naming prefix. Default: ESIQNew

.PARAMETER ResourceGroup
    Resource group. Default: <BaseName>-RG

.PARAMETER Tag
    Image tag. Default: v1

.NOTES
    Author: Murali Chillakuru
    Date:   April 12, 2026
#>

[CmdletBinding()]
param(
    [string]$BaseName      = "ESIQNew",
    [string]$ResourceGroup = "",
    [string]$Tag           = "v1"
)

$ErrorActionPreference = "Stop"
if (-not $ResourceGroup) { $ResourceGroup = "$BaseName-RG" }
$ACRName = "$($BaseName.ToLower())acr"
$AppName = "$($BaseName.ToLower())-agent"
$Image   = "${AppName}:$Tag"

Write-Host "`n═══ Redeploy Image ($Image) ═══`n" -ForegroundColor Cyan

# Step 1: Build via ACR Tasks
Write-Host "[1/3] Building image via ACR Tasks..." -ForegroundColor Yellow
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot
try {
    az acr build --registry $ACRName --image $Image --file "AIAgent/Dockerfile" "." --no-logs
} finally {
    Pop-Location
}
Write-Host "  Built: ${ACRName}.azurecr.io/$Image" -ForegroundColor Green

# Step 2: Update container app image
Write-Host "[2/3] Updating container app image..." -ForegroundColor Yellow
az containerapp update `
    --name $AppName `
    --resource-group $ResourceGroup `
    --image "${ACRName}.azurecr.io/$Image" -o none

# Step 3: Restart active revision
Write-Host "[3/3] Restarting active revision..." -ForegroundColor Yellow
$rev = az containerapp revision list --name $AppName --resource-group $ResourceGroup --query "[0].name" -o tsv
if ($rev) {
    az containerapp revision restart --name $AppName --resource-group $ResourceGroup --revision $rev -o none
    Write-Host "  Restarted revision: $rev" -ForegroundColor Green
}

Write-Host "`n✅ Redeployment complete.`n" -ForegroundColor Green
