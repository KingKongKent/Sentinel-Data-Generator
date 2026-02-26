using 'main.bicep'

// Update these values from the output of the parent infra/main.bicep deployment
param location = 'eastus'
param namePrefix = 'sentinel-bf'
param dceEndpoint = 'https://sentinel-datagen-dce-r385.eastus-1.ingest.monitor.azure.com'
param dcrImmutableId = 'dcr-293aa91fc3fc4f578b838c830e2fa6f3'
param streamName = 'Custom-BruteForceDemo_CL'
param secretPin = '1337'
param tags = {
  project: 'Sentinel-Data-Generator'
  purpose: 'brute-force-demo'
}
