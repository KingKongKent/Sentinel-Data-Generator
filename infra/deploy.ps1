# ============================================================================
# Deploy Sentinel Data Generator infrastructure (DCE + DCR + custom tables)
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Bicep CLI installed (az bicep install)
#
# Usage:
#   .\deploy.ps1 -ResourceGroup <name> [-Location <region>] [-SubscriptionId <id>]
#
# Example:
#   .\deploy.ps1 -ResourceGroup rg-sentinel-demo -Location norwayeast
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $false)]
    [string]$Location = "norwayeast",

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Set subscription if provided
if ($SubscriptionId) {
    Write-Host "Setting subscription to: $SubscriptionId"
    az account set --subscription $SubscriptionId
}

# Ensure resource group exists
Write-Host "Ensuring resource group '$ResourceGroup' exists in '$Location'..."
az group create --name $ResourceGroup --location $Location --output none

# Deploy Bicep template
$DeploymentName = "sentinel-datagen-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

Write-Host ""
Write-Host "Deploying DCE + DCR infrastructure..."
Write-Host "  Resource Group: $ResourceGroup"
Write-Host "  Location:       $Location"
Write-Host "  Template:       $ScriptDir\main.bicep"
Write-Host ""

az deployment group create `
    --name $DeploymentName `
    --resource-group $ResourceGroup `
    --template-file "$ScriptDir\main.bicep" `
    --parameters "$ScriptDir\main.bicepparam" `
    --output table

Write-Host ""
Write-Host "Deployment complete. Retrieving outputs..."
Write-Host ""

# Show key outputs
$outputs = az deployment group show `
    --name $DeploymentName `
    --resource-group $ResourceGroup `
    --query "properties.outputs" `
    --output json | ConvertFrom-Json

Write-Host "DCE Endpoint:              $($outputs.dceEndpoint.value)"
Write-Host "DCR Immutable ID:          $($outputs.dcrImmutableId.value)"
Write-Host "SecurityEvent Stream:      $($outputs.securityEventStreamName.value)"
Write-Host "SigninLog Stream:           $($outputs.signinLogStreamName.value)"
Write-Host "Syslog Stream:             $($outputs.syslogStreamName.value)"
Write-Host "CommonSecurityLog Stream:  $($outputs.commonSecurityLogStreamName.value)"

Write-Host ""
Write-Host "============================================"
Write-Host "Next steps:"
Write-Host "  1. Copy the DCE Endpoint and DCR Immutable ID above"
Write-Host "  2. Update config/config.yaml with these values"
Write-Host "  3. Assign 'Monitoring Metrics Publisher' role to your identity on the DCR:"
Write-Host ""
Write-Host "     az role assignment create --assignee <your-object-id> \"
Write-Host "       --role 'Monitoring Metrics Publisher' \"
Write-Host "       --scope $($outputs.dcrId.value)"
Write-Host "============================================"
