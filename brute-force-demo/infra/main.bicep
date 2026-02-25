// ============================================================================
// Brute Force Demo — Azure Static Web App + Function App
//
// Deploys:
//   1. App Service Plan (Consumption / Y1)
//   2. Storage Account (required by Function App)
//   3. Azure Function App (Python 3.11, v2 model)
//   4. Azure Static Web App (Free tier)
//
// Pre-requisites:
//   - DCE + DCR from the parent infra/main.bicep must already be deployed.
//   - A managed identity with "Monitoring Metrics Publisher" on the DCR.
// ============================================================================

@description('Azure region for all resources.')
param location string = resourceGroup().location

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

// ============================================================================
// App Service Plan (Consumption)
// ============================================================================

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  kind: 'functionapp'
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
}

// ============================================================================
// Function App (Python 3.11, v2 model)
// ============================================================================

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      pythonVersion: '3.11'
      linuxFxVersion: 'PYTHON|3.11'
      cors: {
        allowedOrigins: [
          'https://${swaName}.azurestaticapps.net'
          'http://localhost:4280'  // SWA CLI local dev
        ]
      }
      appSettings: [
        { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}' }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
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
  location: location
  tags: tags
  sku: {
    name: 'Free'
    tier: 'Free'
  }
  properties: {}
}

// Link the Function App as the SWA backend
resource swaBackend 'Microsoft.Web/staticSites/linkedBackends@2023-12-01' = {
  parent: staticWebApp
  name: 'backend'
  properties: {
    backendResourceId: functionApp.id
    region: location
  }
}

// ============================================================================
// Outputs
// ============================================================================

@description('Static Web App default hostname.')
output swaUrl string = 'https://${staticWebApp.properties.defaultHostname}'

@description('Function App default hostname.')
output functionAppUrl string = 'https://${functionApp.properties.defaultHostname}'

@description('Function App system-assigned managed identity principal ID. Grant this "Monitoring Metrics Publisher" role on the DCR.')
output functionAppPrincipalId string = functionApp.identity.principalId
