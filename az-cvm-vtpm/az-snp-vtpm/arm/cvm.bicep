param location string
param subnetId string = ''
param virtualMachineName string
param imageId string = ''
param osDiskType string = 'Premium_LRS'
param osDiskDeleteOption string = 'Delete'
param virtualMachineSize string = 'Standard_DC2as_v5'
param nicDeleteOption string = 'Delete'
param adminUsername string = 'azureuser'
param assignPublicIP bool = false
@secure()
param adminPublicKey string
param securityType string = 'ConfidentialVM'
param secureBoot bool = true
param vTPM bool = true

var networkInterfaceName = '${virtualMachineName}-nic'
var publicIPName = '${virtualMachineName}-ip'
var virtualNetworkName = '${virtualMachineName}-vnet'
var subnetName = '${virtualMachineName}-subnet'
var subnetAddressPrefix = '10.1.0.0/24'
var addressPrefix = '10.1.0.0/16'

resource publicIP_resource 'Microsoft.Network/publicIPAddresses@2022-07-01' = if (assignPublicIP == true) {
  name: publicIPName
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}

resource virtualNetwork_resource 'Microsoft.Network/virtualNetworks@2021-05-01' = if (subnetId == '') {
  name: virtualNetworkName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
  }
}

resource subnet_resource 'Microsoft.Network/virtualNetworks/subnets@2021-05-01' = if (subnetId == '') {
  parent: virtualNetwork_resource
  name: subnetName
  properties: {
    addressPrefix: subnetAddressPrefix
  }
}

resource networkInterfaceName_resource 'Microsoft.Network/networkInterfaces@2021-08-01' = {
  name: networkInterfaceName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig'
        properties: {
          subnet: {
            #disable-next-line use-resource-id-functions
            id: (subnetId == '') ? subnet_resource.id : subnetId
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: assignPublicIP ? {
            id: publicIP_resource.id
          } : null
        }
      }
    ]
  }
}

resource virtualMachineName_resource 'Microsoft.Compute/virtualMachines@2022-03-01' = {
  name: virtualMachineName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: virtualMachineSize
    }
    storageProfile: {
      osDisk: {
        createOption: 'fromImage'
        managedDisk: {
          storageAccountType: osDiskType
          securityProfile: {
            securityEncryptionType: 'VMGuestStateOnly'
          }
        }
        deleteOption: osDiskDeleteOption
      }
      imageReference: imageId != '' ? {
        #disable-next-line use-resource-id-functions
        id: imageId
      } : {
        publisher: 'canonical'
        offer: '0001-com-ubuntu-confidential-vm-jammy'
        sku: '22_04-lts-cvm'
        version: 'latest'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterfaceName_resource.id
          properties: {
            deleteOption: nicDeleteOption
          }
        }
      ]
    }
    osProfile: {
      computerName: virtualMachineName
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminPublicKey
            }
          ]
        }
      }
    }
    securityProfile: {
      securityType: securityType
      uefiSettings: {
        secureBootEnabled: secureBoot
        vTpmEnabled: vTPM
      }
    }
  }
}

resource virtualMachineName_GuestAttestation 'Microsoft.Compute/virtualMachines/extensions@2018-10-01' = {
  parent: virtualMachineName_resource
  name: 'GuestAttestation'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Security.LinuxAttestation'
    type: 'GuestAttestation'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    settings: {
      AttestationConfig: {
        MaaSettings: {
          maaEndpoint: ''
          maaTenantName: 'GuestAttestation'
        }
        AscSettings: {
          ascReportingEndpoint: ''
          ascReportingFrequency: ''
        }
        useCustomToken: 'false'
        disableAlerts: 'false'
      }
    }
  }
}

output adminUsername string = adminUsername
