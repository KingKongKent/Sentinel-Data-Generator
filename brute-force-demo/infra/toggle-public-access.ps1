<#
.SYNOPSIS
    Toggle public network access for the Brute Force Demo resources.

.PARAMETER Action
    "on"  — Enable public access (before demo)
    "off" — Disable public access (after demo)

.EXAMPLE
    .\toggle-public-access.ps1 on
    .\toggle-public-access.ps1 off
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet("on", "off")]
    [string]$Action
)

$rg           = "Sentinel-BruteForce"
$storageAcct  = "sentinelbfbfsa"
$functionApp  = "sentinel-bf-bf-func"

$enabled = if ($Action -eq "on") { "Enabled" } else { "Disabled" }
$emoji   = if ($Action -eq "on") { "ON" } else { "OFF" }

Write-Host "`n=== Switching public access $emoji ===" -ForegroundColor Cyan

# Storage account
Write-Host "Storage account ($storageAcct): publicNetworkAccess -> $enabled"
az storage account update `
    --name $storageAcct `
    --resource-group $rg `
    --public-network-access $enabled `
    -o none

# Function app
if ($Action -eq "on") {
    Write-Host "Function app ($functionApp): starting..."
    az functionapp start --name $functionApp --resource-group $rg -o none
} else {
    Write-Host "Function app ($functionApp): stopping..."
    az functionapp stop --name $functionApp --resource-group $rg -o none
}

Write-Host "`nDone! Public access is $emoji.`n" -ForegroundColor Green
