// ============================================================================
// Sentinel Data Generator — DCE + DCR + Custom Log Tables
// Deploys the Azure Monitor infrastructure needed for the Logs Ingestion API.
//
// Resources created:
//   1. Data Collection Endpoint (DCE)
//   2. Custom Log Analytics tables (_CL) for each log type
//   3. Data Collection Rule (DCR) with streams and destinations
// ============================================================================

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Resource ID of the existing Log Analytics workspace.')
param workspaceResourceId string

@description('Friendly name prefix for resources.')
param namePrefix string = 'sentinel-datagen'

@description('Tags to apply to all resources.')
param tags object = {
  project: 'Sentinel-Data-Generator'
  purpose: 'demo-log-generation'
}

// ============================================================================
// Variables
// ============================================================================

var dceName = '${namePrefix}-dce'
var dcrName = '${namePrefix}-dcr'

// Custom table names (must end in _CL for custom logs)
var securityEventTable = 'SecurityEventDemo_CL'
var signinLogTable = 'SigninLogDemo_CL'
var syslogTable = 'SyslogDemo_CL'
var commonSecurityLogTable = 'CommonSecurityLogDemo_CL'

// Stream names (must start with Custom-)
var securityEventStream = 'Custom-${securityEventTable}'
var signinLogStream = 'Custom-${signinLogTable}'
var syslogStream = 'Custom-${syslogTable}'
var commonSecurityLogStream = 'Custom-${commonSecurityLogTable}'

// Native table streams for live tables
var commonSecurityLogNativeStream = 'Custom-CommonSecurityLogNative'
var syslogNativeStream = 'Custom-SyslogNative'

// ============================================================================
// Data Collection Endpoint
// ============================================================================

resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dceName
  location: location
  tags: tags
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ============================================================================
// Custom Log Analytics Tables
// ============================================================================

// Extract workspace name from resource ID for the table resources
var workspaceName = last(split(workspaceResourceId, '/'))

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource securityEventDemoTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: securityEventTable
  properties: {
    schema: {
      name: securityEventTable
      columns: [
        { name: 'TimeGenerated', type: 'dateTime', description: 'Event timestamp in UTC' }
        { name: 'Computer', type: 'string', description: 'Hostname of the Windows machine' }
        { name: 'EventID', type: 'int', description: 'Windows Security event ID' }
        { name: 'Activity', type: 'string', description: 'Human-readable event description' }
        { name: 'Account', type: 'string', description: 'Account name involved in the event' }
        { name: 'AccountType', type: 'string', description: 'Account type (User or Machine)' }
        { name: 'LogonType', type: 'int', description: 'Logon type number' }
        { name: 'IpAddress', type: 'string', description: 'Source IP address' }
        { name: 'WorkstationName', type: 'string', description: 'Source workstation name' }
        { name: 'Status', type: 'string', description: 'Event status code' }
        { name: 'SubStatus', type: 'string', description: 'Event sub-status code' }
      ]
    }
    retentionInDays: 30
  }
}

resource signinLogDemoTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: signinLogTable
  properties: {
    schema: {
      name: signinLogTable
      columns: [
        { name: 'TimeGenerated', type: 'dateTime', description: 'Event timestamp in UTC' }
        { name: 'UserPrincipalName', type: 'string', description: 'UPN of the signing-in user' }
        { name: 'UserDisplayName', type: 'string', description: 'Display name of the user' }
        { name: 'AppDisplayName', type: 'string', description: 'Application display name' }
        { name: 'IPAddress', type: 'string', description: 'Source IP address' }
        { name: 'Location', type: 'string', description: 'Geographic location' }
        { name: 'ResultType', type: 'string', description: 'Sign-in result code' }
        { name: 'ResultDescription', type: 'string', description: 'Result description' }
        { name: 'ClientAppUsed', type: 'string', description: 'Client application used' }
        { name: 'ConditionalAccessStatus', type: 'string', description: 'CA policy result' }
        { name: 'RiskLevelDuringSignIn', type: 'string', description: 'Risk level during sign-in' }
        { name: 'RiskLevelAggregated', type: 'string', description: 'Aggregated risk level' }
      ]
    }
    retentionInDays: 30
  }
}

resource syslogDemoTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: syslogTable
  properties: {
    schema: {
      name: syslogTable
      columns: [
        { name: 'TimeGenerated', type: 'dateTime', description: 'Event timestamp in UTC' }
        { name: 'Computer', type: 'string', description: 'Hostname of the source machine' }
        { name: 'HostIP', type: 'string', description: 'IP address of the source machine' }
        { name: 'Facility', type: 'string', description: 'Syslog facility' }
        { name: 'SeverityLevel', type: 'string', description: 'Syslog severity' }
        { name: 'ProcessName', type: 'string', description: 'Process name' }
        { name: 'SyslogMessage', type: 'string', description: 'Syslog message body' }
      ]
    }
    retentionInDays: 30
  }
}

resource commonSecurityLogDemoTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: commonSecurityLogTable
  properties: {
    schema: {
      name: commonSecurityLogTable
      columns: [
        { name: 'TimeGenerated', type: 'dateTime', description: 'Event timestamp in UTC' }
        { name: 'DeviceVendor', type: 'string', description: 'Vendor of the reporting device' }
        { name: 'DeviceProduct', type: 'string', description: 'Product name' }
        { name: 'DeviceVersion', type: 'string', description: 'Version of the device' }
        { name: 'DeviceEventClassID', type: 'string', description: 'Event class identifier' }
        { name: 'Activity', type: 'string', description: 'Event name' }
        { name: 'LogSeverity', type: 'string', description: 'Log severity' }
        { name: 'SourceIP', type: 'string', description: 'Source IP address' }
        { name: 'DestinationIP', type: 'string', description: 'Destination IP address' }
        { name: 'SourcePort', type: 'int', description: 'Source port number' }
        { name: 'DestinationPort', type: 'int', description: 'Destination port number' }
        { name: 'Protocol', type: 'string', description: 'Network protocol' }
        { name: 'RequestURL', type: 'string', description: 'Requested URL' }
      ]
    }
    retentionInDays: 30
  }
}

// ============================================================================
// Data Collection Rule
// ============================================================================

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  tags: tags
  dependsOn: [
    securityEventDemoTable
    signinLogDemoTable
    syslogDemoTable
    commonSecurityLogDemoTable
  ]
  properties: {
    dataCollectionEndpointId: dataCollectionEndpoint.id
    streamDeclarations: {
      '${securityEventStream}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Computer', type: 'string' }
          { name: 'EventID', type: 'int' }
          { name: 'Activity', type: 'string' }
          { name: 'Account', type: 'string' }
          { name: 'AccountType', type: 'string' }
          { name: 'LogonType', type: 'int' }
          { name: 'IpAddress', type: 'string' }
          { name: 'WorkstationName', type: 'string' }
          { name: 'Status', type: 'string' }
          { name: 'SubStatus', type: 'string' }
        ]
      }
      '${signinLogStream}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'UserPrincipalName', type: 'string' }
          { name: 'UserDisplayName', type: 'string' }
          { name: 'AppDisplayName', type: 'string' }
          { name: 'IPAddress', type: 'string' }
          { name: 'Location', type: 'string' }
          { name: 'ResultType', type: 'string' }
          { name: 'ResultDescription', type: 'string' }
          { name: 'ClientAppUsed', type: 'string' }
          { name: 'ConditionalAccessStatus', type: 'string' }
          { name: 'RiskLevelDuringSignIn', type: 'string' }
          { name: 'RiskLevelAggregated', type: 'string' }
        ]
      }
      '${syslogStream}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Computer', type: 'string' }
          { name: 'HostIP', type: 'string' }
          { name: 'Facility', type: 'string' }
          { name: 'SeverityLevel', type: 'string' }
          { name: 'ProcessName', type: 'string' }
          { name: 'SyslogMessage', type: 'string' }
        ]
      }
      '${commonSecurityLogStream}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'DeviceVendor', type: 'string' }
          { name: 'DeviceProduct', type: 'string' }
          { name: 'DeviceVersion', type: 'string' }
          { name: 'DeviceEventClassID', type: 'string' }
          { name: 'Activity', type: 'string' }
          { name: 'LogSeverity', type: 'string' }
          { name: 'SourceIP', type: 'string' }
          { name: 'DestinationIP', type: 'string' }
          { name: 'SourcePort', type: 'int' }
          { name: 'DestinationPort', type: 'int' }
          { name: 'Protocol', type: 'string' }
          { name: 'RequestURL', type: 'string' }
        ]
      }
      // Stream for native CommonSecurityLog table (CEF schema)
      '${commonSecurityLogNativeStream}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'DeviceVendor', type: 'string' }
          { name: 'DeviceProduct', type: 'string' }
          { name: 'DeviceVersion', type: 'string' }
          { name: 'DeviceEventClassID', type: 'string' }
          { name: 'Activity', type: 'string' }
          { name: 'LogSeverity', type: 'string' }
          { name: 'SourceIP', type: 'string' }
          { name: 'DestinationIP', type: 'string' }
          { name: 'SourcePort', type: 'int' }
          { name: 'DestinationPort', type: 'int' }
          { name: 'Protocol', type: 'string' }
          { name: 'RequestURL', type: 'string' }
        ]
      }
      // Stream for native Syslog table
      '${syslogNativeStream}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Computer', type: 'string' }
          { name: 'HostIP', type: 'string' }
          { name: 'Facility', type: 'string' }
          { name: 'SeverityLevel', type: 'string' }
          { name: 'ProcessName', type: 'string' }
          { name: 'SyslogMessage', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: 'sentinel-workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [ securityEventStream ]
        destinations: [ 'sentinel-workspace' ]
        transformKql: 'source'
        outputStream: securityEventStream
      }
      {
        streams: [ signinLogStream ]
        destinations: [ 'sentinel-workspace' ]
        transformKql: 'source'
        outputStream: signinLogStream
      }
      {
        streams: [ syslogStream ]
        destinations: [ 'sentinel-workspace' ]
        transformKql: 'source'
        outputStream: syslogStream
      }
      {
        streams: [ commonSecurityLogStream ]
        destinations: [ 'sentinel-workspace' ]
        transformKql: 'source'
        outputStream: commonSecurityLogStream
      }
      {
        streams: [ commonSecurityLogNativeStream ]
        destinations: [ 'sentinel-workspace' ]
        transformKql: 'source'
        outputStream: 'Microsoft-CommonSecurityLog'
      }
      {
        streams: [ syslogNativeStream ]
        destinations: [ 'sentinel-workspace' ]
        transformKql: 'source'
        outputStream: 'Microsoft-Syslog'
      }
    ]
  }
}

// ============================================================================
// Outputs
// ============================================================================

@description('Data Collection Endpoint URI for the Logs Ingestion API.')
output dceEndpoint string = dataCollectionEndpoint.properties.logsIngestion.endpoint

@description('Data Collection Endpoint resource ID.')
output dceId string = dataCollectionEndpoint.id

@description('Data Collection Rule immutable ID (used in API calls).')
output dcrImmutableId string = dataCollectionRule.properties.immutableId

@description('Data Collection Rule resource ID.')
output dcrId string = dataCollectionRule.id

@description('Stream name for SecurityEvent demo data.')
output securityEventStreamName string = securityEventStream

@description('Stream name for SigninLog demo data.')
output signinLogStreamName string = signinLogStream

@description('Stream name for Syslog demo data.')
output syslogStreamName string = syslogStream

@description('Stream name for CommonSecurityLog demo data.')
output commonSecurityLogStreamName string = commonSecurityLogStream

@description('Stream name for native CommonSecurityLog table.')
output commonSecurityLogNativeStreamName string = commonSecurityLogNativeStream

@description('Stream name for native Syslog table.')
output syslogNativeStreamName string = syslogNativeStream
