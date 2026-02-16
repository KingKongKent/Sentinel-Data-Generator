#!/usr/bin/env bash
# ============================================================================
# Deploy Sentinel Data Generator infrastructure (DCE + DCR + custom tables)
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Bicep CLI installed (az bicep install)
#
# Usage:
#   ./deploy.sh -g <resource-group> [-l <location>] [-s <subscription-id>]
#
# Example:
#   ./deploy.sh -g rg-sentinel-demo -l norwayeast
# ============================================================================

set -euo pipefail

# Defaults
LOCATION="norwayeast"
SUBSCRIPTION=""
RESOURCE_GROUP=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $0 -g <resource-group> [-l <location>] [-s <subscription-id>]"
    echo ""
    echo "Options:"
    echo "  -g    Resource group name (required)"
    echo "  -l    Azure region (default: norwayeast)"
    echo "  -s    Subscription ID (uses current default if omitted)"
    exit 1
}

while getopts "g:l:s:h" opt; do
    case $opt in
        g) RESOURCE_GROUP="$OPTARG" ;;
        l) LOCATION="$OPTARG" ;;
        s) SUBSCRIPTION="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$RESOURCE_GROUP" ]; then
    echo "ERROR: Resource group (-g) is required."
    usage
fi

# Set subscription if provided
if [ -n "$SUBSCRIPTION" ]; then
    echo "Setting subscription to: $SUBSCRIPTION"
    az account set --subscription "$SUBSCRIPTION"
fi

# Ensure resource group exists
echo "Ensuring resource group '$RESOURCE_GROUP' exists in '$LOCATION'..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

# Deploy Bicep template
echo ""
echo "Deploying DCE + DCR infrastructure..."
echo "  Resource Group: $RESOURCE_GROUP"
echo "  Location:       $LOCATION"
echo "  Template:       $SCRIPT_DIR/main.bicep"
echo ""

DEPLOYMENT_NAME="sentinel-datagen-$(date +%Y%m%d-%H%M%S)"

az deployment group create \
    --name "$DEPLOYMENT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$SCRIPT_DIR/main.bicep" \
    --parameters "$SCRIPT_DIR/main.bicepparam" \
    --output table

echo ""
echo "Deployment complete. Retrieving outputs..."
echo ""

# Show key outputs
az deployment group show \
    --name "$DEPLOYMENT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.outputs" \
    --output table

echo ""
echo "============================================"
echo "Next steps:"
echo "  1. Copy the DCE Endpoint and DCR Immutable ID above"
echo "  2. Update config/config.yaml with these values"
echo "  3. Assign 'Monitoring Metrics Publisher' role to your identity on the DCR"
echo "============================================"
