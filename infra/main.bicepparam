using 'main.bicep'

// Update these values for your environment
param location = 'eastus'
param workspaceResourceId = '/subscriptions/0033cb93-1cd3-4180-8adc-2aa069f39475/resourceGroups/Sentinel/providers/Microsoft.OperationalInsights/workspaces/SDLWS'
param namePrefix = 'sentinel-datagen'
param tags = {
  project: 'Sentinel-Data-Generator'
  purpose: 'demo-log-generation'
}
