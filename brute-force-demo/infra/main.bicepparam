using 'main.bicep'

// Update these values from the output of the parent infra/main.bicep deployment
param location = 'eastus'
param namePrefix = 'sentinel-datagen'
param dceEndpoint = '<DCE_ENDPOINT_FROM_MAIN_DEPLOYMENT>'
param dcrImmutableId = '<DCR_IMMUTABLE_ID_FROM_MAIN_DEPLOYMENT>'
param streamName = 'Custom-BruteForceDemo_CL'
param secretPin = '1337'
param tags = {
  project: 'Sentinel-Data-Generator'
  purpose: 'brute-force-demo'
}
