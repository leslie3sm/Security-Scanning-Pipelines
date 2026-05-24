targetScope = 'resourceGroup'

@description('Intentionally insecure sample used to validate scanner output.')
param location string = resourceGroup().location

resource insecureNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'demo-insecure-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-from-anywhere'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'allow-rdp-from-anywhere'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
    ]
  }
}

resource insecureStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'demoinsecurestorage${uniqueString(resourceGroup().id)}'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
    allowBlobPublicAccess: true
    allowSharedKeyAccess: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
}

resource insecureSql 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: 'demo-insecure-sql-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: 'HardcodedSqlPassword123!'
    publicNetworkAccess: 'Enabled'
    minimalTlsVersion: '1.0'
  }
}
