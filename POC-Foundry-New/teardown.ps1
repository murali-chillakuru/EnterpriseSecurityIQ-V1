<#
.SYNOPSIS
  Tears down all ESIQNew resources.
.DESCRIPTION
  Deletes the ESIQNew-RG resource group, which removes all resources inside it
  (Foundry Resource, Foundry Project, Storage, Key Vault, ACR, Identity, etc.).
  The Container Apps Environment in northeurope is also in ESIQNew-RG.
.PARAMETER Confirm
  If set to $false, skips the confirmation prompt.
#>

param(
    [string]$ResourceGroup = "ESIQNew-RG",
    [bool]$Confirm = $true
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "===  ESIQNew Teardown  ===" -ForegroundColor Red
Write-Host ""
Write-Host "This will DELETE the entire resource group: $ResourceGroup" -ForegroundColor Yellow
Write-Host "All resources inside will be permanently removed." -ForegroundColor Yellow
Write-Host ""

if ($Confirm) {
    $answer = Read-Host "Type 'yes' to confirm deletion"
    if ($answer -ne "yes") {
        Write-Host "Aborted." -ForegroundColor Cyan
        exit 0
    }
}

Write-Host ""
Write-Host "[1/2] Purging Key Vault (soft-delete protection)..." -ForegroundColor Cyan
$kvExists = az keyvault show --name "ESIQNew-kv" --resource-group $ResourceGroup --query "name" -o tsv 2>$null
if ($kvExists) {
    Write-Host "  Key Vault found. It will be soft-deleted with the RG, then purged." -ForegroundColor Gray
}

Write-Host "[2/2] Deleting resource group: $ResourceGroup ..." -ForegroundColor Cyan
az group delete --name $ResourceGroup --yes --no-wait
Write-Host "  Deletion queued (runs async in Azure)." -ForegroundColor Gray

Write-Host ""
Write-Host "Teardown initiated. The resource group will be fully removed in 5-10 minutes." -ForegroundColor Green
Write-Host "To purge the Key Vault after deletion completes:" -ForegroundColor Gray
Write-Host "  az keyvault purge --name ESIQNew-kv" -ForegroundColor Gray
Write-Host ""
