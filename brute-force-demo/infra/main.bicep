// ============================================================================
// Brute Force Demo — Azure Static Web App + Function App
//
// Deploys:
//   1. Storage Account (required by Function App)
//   2. Blob container for Flex Consumption deployment
//   3. App Service Plan (Flex Consumption / FC1)
//   4. Azure Function App (Python 3.11, v2 model)
//   5. Azure Static Web App (Free tier)
//   6. SWA linked backend
//
// Pre-requisites:
//   - DCE + DCR from the parent infra/main.bicep must already be deployed.
//   - After deployment, grant the Function App managed identity
//     "Monitoring Metrics Publisher" on the DCR.
// ============================================================================

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Azure region for Static Web App (must be in a supported SWA region).')
param swaLocation string = 'eastus2'

@description('Friendly name prefix for resources.')
param namePrefix string = 'sentinel-datagen'

@description('Data Collection Endpoint URL (from main infra deployment).')
param dceEndpoint string

@description('Data Collection Rule immutable ID (from main infra deployment).')
param dcrImmutableId string

@description('Stream name for the BruteForceDemo_CL table.')
param streamName string = 'Custom-BruteForceDemo_CL'

@description('The secret 4-digit PIN that the audience tries to guess.')
@secure()
param secretPin string = '1337'

@description('Tags to apply to all resources.')
param tags object = {
  project: 'Sentinel-Data-Generator'
  purpose: 'brute-force-demo'
}

// ============================================================================
// Variables
// ============================================================================

var functionAppName = '${namePrefix}-bf-func'
var appServicePlanName = '${namePrefix}-bf-plan'
var storageAccountName = replace('${namePrefix}bfsa', '-', '')
var swaName = '${namePrefix}-bf-swa'
var deploymentContainerName = 'deployments'

// ============================================================================
// Storage Account (required by Function App)
// ============================================================================

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}

// Blob service + deployment container for Flex Consumption
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
}

resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: deploymentContainerName
}

// ============================================================================
// App Service Plan (Flex Consumption / FC1)
// ============================================================================

resource appServicePlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  kind: 'functionapp'
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  properties: {
    reserved: true
  }
}

// ============================================================================
// Function App (Python 3.11, Flex Consumption, v2 model)
// ============================================================================

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageAccount.properties.primaryEndpoints.blob}${deploymentContainerName}'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      runtime: {
        name: 'python'
        version: '3.11'
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 40
        instanceMemoryMB: 2048
      }
    }
    siteConfig: {
      cors: {
        allowedOrigins: [
          'https://${staticWebApp.properties.defaultHostname}'
          'http://localhost:4280'
        ]
      }
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName', value: storageAccount.name }
        { name: 'DCE_ENDPOINT', value: dceEndpoint }
        { name: 'DCR_IMMUTABLE_ID', value: dcrImmutableId }
        { name: 'STREAM_NAME', value: streamName }
        { name: 'SECRET_PIN', value: secretPin }
      ]
    }
  }
}

// ============================================================================
// Static Web App (Free tier)
// ============================================================================

resource staticWebApp 'Microsoft.Web/staticSites@2023-12-01' = {
  name: swaName
  location: swaLocation
  tags: tags
  sku: {
    name: 'Free'
    tier: 'Free'
  }
  properties: {}
}

// ============================================================================
// Outputs
// ============================================================================

@description('Static Web App default hostname.')
output swaUrl string = 'https://${staticWebApp.properties.defaultHostname}'

@description('Function App default hostname.')
output functionAppUrl string = 'https://${functionApp.properties.defaultHostName}'

@description('Function App system-assigned managed identity principal ID. Grant this "Monitoring Metrics Publisher" role on the DCR.')
output functionAppPrincipalId string = functionApp.identity.principalId
