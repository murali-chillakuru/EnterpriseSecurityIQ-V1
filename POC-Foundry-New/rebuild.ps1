<#
.SYNOPSIS
  Rebuilds the entire ESIQNew environment from scratch.
.DESCRIPTION
  Runs the full Infra-Foundary-New/deploy.ps1 deployment script,
  then rebuilds and deploys the container image.
.PARAMETER BaseName
  Resource name prefix. Default: ESIQNew
.PARAMETER Location
  Primary Azure region. Default: swedencentral
.PARAMETER ContainerAppsLocation
  Region for Container Apps Environment. Default: northeurope
#>

param(
    [string]$BaseName        = "ESIQNew",
    [string]$Location        = "swedencentral",
    [string]$ContainerAppsLocation = "northeurope",
    [string]$SubscriptionName = "AI"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "===  ESIQNew Full Rebuild  ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Base Name        : $BaseName" -ForegroundColor Gray
Write-Host "Primary Region   : $Location" -ForegroundColor Gray
Write-Host "Container Region : $ContainerAppsLocation" -ForegroundColor Gray
Write-Host "Subscription     : $SubscriptionName" -ForegroundColor Gray
Write-Host ""

# Step 1: Run the infrastructure deployment
Write-Host "[1/2] Running infrastructure deployment..." -ForegroundColor Cyan
$deployScript = Join-Path $repoRoot "Infra-Foundary-New" "deploy.ps1"
if (-not (Test-Path $deployScript)) {
    Write-Error "Deploy script not found: $deployScript"
}
& $deployScript -BaseName $BaseName -Location $Location -SubscriptionName $SubscriptionName

# Step 2: Build and deploy container
Write-Host ""
Write-Host "[2/2] Building and deploying container image..." -ForegroundColor Cyan
$redeployScript = Join-Path $repoRoot "Infra-Foundary-New" "redeploy-image.ps1"
if (-not (Test-Path $redeployScript)) {
    Write-Error "Redeploy script not found: $redeployScript"
}
& $redeployScript -BaseName $BaseName -ResourceGroup "$BaseName-RG"

Write-Host ""
Write-Host "===  Rebuild Complete  ===" -ForegroundColor Green
Write-Host ""
$fqdn = az containerapp show -n "$($BaseName.ToLower())-agent" -g "$BaseName-RG" --query "properties.configuration.ingress.fqdn" -o tsv 2>$null
if ($fqdn) {
    Write-Host "App URL: https://$fqdn/" -ForegroundColor Green
}
