<#
.SYNOPSIS
    Delete and recreate the BruteForceDemo_CL table for a fresh demo.

.DESCRIPTION
    Purges all existing data by deleting the custom log table, then
    redeploys the Bicep template to recreate it with the correct schema.
    The DCE and DCR are left untouched (idempotent deploy).

    Run this BEFORE a demo so attendees start with a clean table.

.PARAMETER SkipDelete
    Skip the delete step (just redeploy to create if missing).

.EXAMPLE
    # Full reset: delete table + recreate
    .\reset-demo-table.ps1

    # Just recreate (table was already deleted manually)
    .\reset-demo-table.ps1 -SkipDelete
#>
param(
    [switch]$SkipDelete
)

# ---------------------------------------------------------------------------
# Configuration — update these if your environment differs
# ---------------------------------------------------------------------------
$subscriptionId = "0033cb93-1cd3-4180-8adc-2aa069f39475"
$resourceGroup  = "Sentinel"
$workspaceName  = "SDLWS"
$tableName      = "BruteForceDemo_CL"

$repoRoot       = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)  # brute-force-demo/infra -> brute-force-demo -> repo root
$bicepFile      = Join-Path (Join-Path $repoRoot "infra") "main.bicep"
$paramFile      = Join-Path (Join-Path $repoRoot "infra") "main.bicepparam"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Brute Force Demo Table Reset ===" -ForegroundColor Cyan
Write-Host "  Subscription:  $subscriptionId"
Write-Host "  Resource Group: $resourceGroup"
Write-Host "  Workspace:      $workspaceName"
Write-Host "  Table:           $tableName"
Write-Host ""

# Verify az CLI is logged in
$account = az account show --query "name" -o tsv 2>$null
if (-not $account) {
    Write-Host "[!] Not logged in to Azure CLI. Run 'az login' first." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Logged in as: $account" -ForegroundColor Green

# Set subscription
az account set --subscription $subscriptionId -o none

# ---------------------------------------------------------------------------
# Step 1: Delete the table
# ---------------------------------------------------------------------------
if (-not $SkipDelete) {
    Write-Host ""
    Write-Host "--- Step 1: Deleting table $tableName ---" -ForegroundColor Yellow

    $tableExists = az monitor log-analytics workspace table show `
        --resource-group $resourceGroup `
        --workspace-name $workspaceName `
        --name $tableName `
        --query "name" -o tsv 2>$null

    if ($tableExists) {
        Write-Host "  Table exists. Deleting..."
        az monitor log-analytics workspace table delete `
            --resource-group $resourceGroup `
            --workspace-name $workspaceName `
            --name $tableName `
            --yes `
            -o none
        Write-Host "  [OK] Table deleted." -ForegroundColor Green

        # Wait for deletion to propagate
        Write-Host "  Waiting 30 seconds for deletion to propagate..."
        Start-Sleep -Seconds 30
    }
    else {
        Write-Host "  Table does not exist. Skipping delete." -ForegroundColor DarkGray
    }
}
else {
    Write-Host "--- Step 1: Skipped (SkipDelete flag) ---" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Step 2: Redeploy Bicep to recreate the table
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Step 2: Redeploying Bicep template ---" -ForegroundColor Yellow
Write-Host "  Template:   $bicepFile"
Write-Host "  Parameters: $paramFile"
Write-Host ""

if (-not (Test-Path $bicepFile)) {
    Write-Host "[!] Bicep file not found: $bicepFile" -ForegroundColor Red
    exit 1
}

az deployment group create `
    --resource-group $resourceGroup `
    --template-file $bicepFile `
    --parameters $paramFile `
    --mode Incremental `
    --name "demo-reset-$(Get-Date -Format 'yyyyMMdd-HHmmss')" `
    -o table

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[OK] Table $tableName recreated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  The table is empty and ready for a fresh demo." -ForegroundColor Cyan
    Write-Host "  Data sent via DCE/DCR will now flow into the new table." -ForegroundColor Cyan
    Write-Host ""
}
else {
    Write-Host ""
    Write-Host "[!] Deployment failed. Check the output above for errors." -ForegroundColor Red
    exit 1
}
