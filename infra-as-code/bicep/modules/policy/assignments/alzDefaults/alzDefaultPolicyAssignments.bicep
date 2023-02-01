// SCOPE
targetScope = 'managementGroup'

// METADATA
metadata name = 'ALZ Bicep - ALZ Default Policy Assignments'
metadata description = 'This policy assignment will assign the ALZ Default Policy to management groups'

// PARAMETERS
@sys.description('Prefix for the management group hierarchy.')
@minLength(2)
@maxLength(10)
param parTopLevelManagementGroupPrefix string = 'alz'

@sys.description('The region where the Log Analytics Workspace & Automation Account are deployed.')
param parLogAnalyticsWorkSpaceAndAutomationAccountLocation string = 'eastus'

@sys.description('Log Analytics Workspace Resource ID.')
param parLogAnalyticsWorkspaceResourceId string = ''

@sys.description('Number of days of log retention for Log Analytics Workspace.')
param parLogAnalyticsWorkspaceLogRetentionInDays string = '365'

@sys.description('Automation account name.')
param parAutomationAccountName string = 'alz-automation-account'

@sys.description('An e-mail address that you want Microsoft Defender for Cloud alerts to be sent to.')
param parMsDefenderForCloudEmailSecurityContact string = 'security_contact@replace_me.com'

@sys.description('ID of the DdosProtectionPlan which will be applied to the Virtual Networks. If left empty, the policy Enable-DDoS-VNET will not be assigned at connectivity or landing zone Management Groups to avoid VNET deployment issues.')
param parDdosProtectionPlanId string = ''

@sys.description('Resource ID of the Resource Group that conatin the Private DNS Zones. If left empty, the policy Deploy-Private-DNS-Zones will not be assigned to the corp Management Group.')
param parPrivateDnsResourceGroupId string = ''

@sys.description('An object describing which Policy Assignments to deploy. See default value for format. Default: deploy all Policy Assignments')
param parDeployAssignments object = {
  intRoot: {
    deployMDFCConfig: true
    deployAzActivityLog: true
    deployASCMonitoring: true
    deployResourceDiag: true
    deployVMMonitoring: true
    deployVMSSMonitoring: true
  }
  platformConnectivity: {
    enableDDoSVNET: true
  }
  platformIdentity: {
    denyPublicIP: true
    denyRDPFromInternet: true
    denySubnetWithoutNsg: true
    deployVMBackup: true
  }
  platformManagement: {
    deployLogAnalytics: true
  }
  landingZones: {
    denyIPForwarding: true
    denyRDPFromInternet: true
    denySubnetWithoutNsg: true
    deployVMBackup: true
    denyStoragehttp: true
    deployAksPolicy: true
    denyPrivEscalationAKS: true
    denyPrivContainersAKS: true
    enforceAKSHTTPS: true
    enforceTLSSSL: true
    deploySQLDBAuditing: true
    deploySQLThreat: true
    enableDDoSVNET: true
  }
  landingZonesCorp: {
    denyPublicEndpoints: true
    denyDataBPip: true
    denyDataBSku: true
    denyDataBVnet: true
    deployPrivateDnsZones: true
  }
}

@sys.description('Set Parameter to true to Opt-out of deployment telemetry')
param parTelemetryOptOut bool = false



// VARIABLES
var varLogAnalyticsWorkspaceName = split(parLogAnalyticsWorkspaceResourceId, '/')[8]

var varLogAnalyticsWorkspaceResourceGroupName = split(parLogAnalyticsWorkspaceResourceId, '/')[4]

// Customer Usage Attribution Id
var varCuaid = '98cef979-5a6b-403b-83c7-10c8f04ac9a2'

// Orchestration Module Variables
var varDeploymentNameWrappers = {
  basePrefix: 'ALZBicep'
  #disable-next-line no-loc-expr-outside-params //Policies resources are not deployed to a region, like other resources, but the metadata is stored in a region hence requiring this to keep input parameters reduced. See https://github.com/Azure/ALZ-Bicep/wiki/FAQ#why-are-some-linter-rules-disabled-via-the-disable-next-line-bicep-function for more information
  baseSuffixTenantAndManagementGroup: '${deployment().location}-${uniqueString(deployment().location, parTopLevelManagementGroupPrefix)}'
}

// RBAC Role Definitions Variables - Used For Policy Assignments
var varRbacRoleDefinitionIds = {
  owner: '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
  contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c'
  networkContributor: '4d97b98b-1d4f-4787-a291-c67834d212e7'
  aksContributor: 'ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8'
}

// Management Groups Variables - Used For Policy Assignments
var varManagementGroupIds = {
  intRoot: parTopLevelManagementGroupPrefix
  platform: '${parTopLevelManagementGroupPrefix}-platform'
  platformManagement: '${parTopLevelManagementGroupPrefix}-platform-management'
  platformConnectivity: '${parTopLevelManagementGroupPrefix}-platform-connectivity'
  platformIdentity: '${parTopLevelManagementGroupPrefix}-platform-identity'
  landingZones: '${parTopLevelManagementGroupPrefix}-landingzones'
  landingZonesCorp: '${parTopLevelManagementGroupPrefix}-landingzones-corp'
  landingZonesOnline: '${parTopLevelManagementGroupPrefix}-landingzones-online'
  decommissioned: '${parTopLevelManagementGroupPrefix}-decommissioned'
  sandbox: '${parTopLevelManagementGroupPrefix}-sandbox'
}

var varTopLevelManagementGroupResourceId = '/providers/Microsoft.Management/managementGroups/${varManagementGroupIds.intRoot}'

var varPrivateDnsZonesResourceGroupSubscriptionId = !empty(parPrivateDnsResourceGroupId) ? split(parPrivateDnsResourceGroupId, '/')[2] : ''

var varPrivateDnsZonesBaseResourceId = '${parPrivateDnsResourceGroupId}/providers/Microsoft.Network/privateDnsZones/'

// Policy Assignment definitions with properties that will be the same everywhere the Policy Assignment is deployed
var varPolicyAssignmentDefinitions = {
  denyDataBPip: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Databricks-NoPublicIp'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_databricks_public_ip.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyDataBSku: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Databricks-Sku'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_databricks_sku.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyDataBVnet: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Databricks-VirtualNetwork'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_databricks_vnet.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  enforceAKSHTTPS: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1a5b4dca-0b6f-4cf5-907c-56316bc1bf3d'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_http_ingress_aks.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyIPForwarding: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/88c0b9da-ce96-4b03-9635-f29a937e2900'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_ip_forwarding.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyPrivContainersAKS: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/95edb821-ddaf-4404-9732-666045e056b4'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_priv_containers_aks.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyPrivEscalationAKS: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/1c6e92c9-99f0-4e55-9cf2-0c234dc48f99'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_priv_escalation_aks.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyPublicEndpoints: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deny-PublicPaaSEndpoints'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_public_endpoints.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyPublicIP: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_public_ip.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyRDPFromInternet: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-RDP-From-Internet'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_rdp_from_internet.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denyStoragehttp: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_storage_http.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  denySubnetWithoutNsg: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policyDefinitions/Deny-Subnet-Without-Nsg'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deny_subnet_without_nsg.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  deployAKSPolicy: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/a8eff44f-8c92-45c3-a3fb-9880802d67a7'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_aks_policy.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.aksContributor
    ]
    identityRoleassignmentSubs: []
  }
  deployASCMonitoring: {
    definitionId: '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_asc_monitoring.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  deployAzActivityLog: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/2465583e-4e78-4c15-b6be-a36cbc7c8b0f'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_azactivity_log.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  deployLogAnalytics: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/8e3e61b3-0b32-22d5-4edf-55f87fdb5955'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_log_analytics.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  deployMDFCConfig: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-MDFC-Config'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_mdfc_config.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  deployPrivateDNSZones: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-Private-DNS-Zones'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_private_dns_zones.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.networkContributor
    ]
    identityRoleassignmentSubs: []
    identityRoleAssignmentSubs: [
      varPrivateDnsZonesResourceGroupSubscriptionId
    ]
  }
  deployResourceDiag: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Deploy-Diagnostics-LogAnalytics'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_resource_diag.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  deploySQLDBAuditing: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_sql_db_auditing.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  deploySQLThreat: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/36d49e87-48c4-4f2e-beed-ba4ed02b71f5'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_sql_threat.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
  deployVMBackup: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/98d0b9f8-fd90-49c9-88e2-d3baf3b0dd86'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_vm_backup.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  deployVMMonitoring: {
    definitionId: '/providers/Microsoft.Authorization/policySetDefinitions/55f3eceb-5573-4f18-9695-226972c6d74a'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_vm_monitoring.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  deployVMSSMonitoring: {
    definitionId: '/providers/Microsoft.Authorization/policySetDefinitions/75714362-cae7-409e-9b99-a8e5075b7fad'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_deploy_vmss_monitoring.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.owner
    ]
    identityRoleassignmentSubs: []
  }
  enableDDoSVNET: {
    definitionId: '/providers/Microsoft.Authorization/policyDefinitions/94de2ad3-e0c1-4caf-ad78-5d47bbc83d3d'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_enable_ddos_vnet.tmpl.json')
    roleDefinitionIds: [
      varRbacRoleDefinitionIds.networkContributor
    ]
    identityRoleassignmentSubs: []
  }
  enforceTLSSSL: {
    definitionId: '${varTopLevelManagementGroupResourceId}/providers/Microsoft.Authorization/policySetDefinitions/Enforce-EncryptTransit'
    libDefinition: loadJsonContent('../../../policy/assignments/lib/policy_assignments/policy_assignment_es_enforce_tls_ssl.tmpl.json')
    roleDefinitionIds: []
    identityRoleAssignmentSubs: []
  }
}

/* Specific Policy Assignments for each scope with properties that might vary between each scope the Policy Assignment is deployed at.
 * Until Bicep gets custom types, here is the explanation:
 * name: A key from varPolicyAssignmentDefinitions. The Policy Assignment definition that will be used for this specific Policy Assignment.
 * parameterOverrides: Parameter overrides for this specific Policy Assignment.
 * condition: boolean specifying whether the Policy Assignment should be deployed. For example used to conditionally deploy DDoS policies depending on whether a DDoS protection plan ID is given.
*/
var varPolicyAssignments = {
  intRoot: [
    {
      name: 'deployMDFCConfig'
      parameterOverrides: {
        emailSecurityContact: {
          value: parMsDefenderForCloudEmailSecurityContact
        }
        ascExportResourceGroupLocation: {
          value: parLogAnalyticsWorkSpaceAndAutomationAccountLocation
        }
        logAnalytics: {
          value: parLogAnalyticsWorkspaceResourceId
        }
      }
      condition: true
    }
    {
      name: 'deployAzActivityLog'
      parameterOverrides: {
        logAnalytics: {
          value: parLogAnalyticsWorkspaceResourceId
        }
      }
      condition: true
    }
    {
      name: 'deployASCMonitoring'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'deployResourceDiag'
      parameterOverrides: {
        logAnalytics: {
          value: parLogAnalyticsWorkspaceResourceId
        }
      }
      condition: true
    }
    {
      name: 'deployVMMonitoring'
      parameterOverrides: {
        logAnalytics_1: {
          value: parLogAnalyticsWorkspaceResourceId
        }
      }
      condition: true
    }
    {
      name: 'deployVMSSMonitoring'
      parameterOverrides: {
        logAnalytics_1: {
          value: parLogAnalyticsWorkspaceResourceId
        }
      }
      condition: true
    }
  ]
  platformConnectivity: [
    {
      name: 'enableDDoSVNET'
      parameterOverrides: {
        ddosPlan: {
          value: parDdosProtectionPlanId
        }
      }
      condition: !empty(parDdosProtectionPlanId)
    }
  ]
  platformIdentity: [
    {
      name: 'denyPublicIP'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyRDPFromInternet'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denySubnetWithoutNsg'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'deployVMBackup'
      parameterOverrides: {}
      condition: true
    }
  ]
  platformManagement: [
    {
      name: 'deployLogAnalytics'
      parameterOverrides: {
        rgName: {
          value: varLogAnalyticsWorkspaceResourceGroupName
        }
        workspaceName: {
          value: varLogAnalyticsWorkspaceName
        }
        workspaceRegion: {
          value: parLogAnalyticsWorkSpaceAndAutomationAccountLocation
        }
        dataRetention: {
          value: parLogAnalyticsWorkspaceLogRetentionInDays
        }
        automationAccountName: {
          value: parAutomationAccountName
        }
        automationRegion: {
          value: parLogAnalyticsWorkSpaceAndAutomationAccountLocation
        }
      }
      condition: true
    }
  ]
  landingZones: [
    {
      name: 'denyIPForwarding'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyRDPFromInternet'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denySubnetWithoutNsg'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'deployVMBackup'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyStoragehttp'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'deployAksPolicy'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyPrivEscalationAKS'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyPrivContainersAKS'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'enforceAKSHTTPS'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'enforceTLSSSL'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'deploySQLDBAuditing'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'deploySQLThreat'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'enableDDoSVNET'
      parameterOverrides: {
        ddosPlan: {
          value: parDdosProtectionPlanId
        }
      }
      condition: !empty(parDdosProtectionPlanId)
    }
  ]
  landingZonesCorp: [
    {
      name: 'denyPublicEndpoints'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyDataBPip'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyDataBSku'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'denyDataBVnet'
      parameterOverrides: {}
      condition: true
    }
    {
      name: 'deployPrivateDnsZones'
      parameterOverrides: {
        azureFilePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.afs.azure.net' }
        azureAutomationWebhookPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azure-automation.net' }
        azureAutomationDSCHybridPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azure-automation.net' }
        azureCosmosSQLPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.documents.azure.com' }
        azureCosmosMongoPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.mongo.cosmos.azure.com' }
        azureCosmosCassandraPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.cassandra.cosmos.azure.com' }
        azureCosmosGremlinPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.gremlin.cosmos.azure.com' }
        azureCosmosTablePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.table.cosmos.azure.com' }
        azureDataFactoryPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.datafactory.azure.net' }
        azureDataFactoryPortalPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.adf.azure.com' }
        azureHDInsightPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azurehdinsight.net' }
        azureMigratePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.prod.migration.windowsazure.com' }
        azureStorageBlobPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.blob.core.windows.net' }
        azureStorageBlobSecPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.blob.core.windows.net' }
        azureStorageQueuePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.queue.core.windows.net' }
        azureStorageQueueSecPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.queue.core.windows.net' }
        azureStorageFilePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.file.core.windows.net' }
        azureStorageStaticWebPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.web.core.windows.net' }
        azureStorageStaticWebSecPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.web.core.windows.net' }
        azureStorageDFSPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.dfs.core.windows.net' }
        azureStorageDFSSecPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.dfs.core.windows.net' }
        azureSynapseSQLPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.sql.azuresynapse.net' }
        azureSynapseSQLODPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.sql.azuresynapse.net' }
        azureSynapseDevPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.dev.azuresynapse.net' }
        azureMediaServicesKeyPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.media.azure.net' }
        azureMediaServicesLivePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.media.azure.net' }
        azureMediaServicesStreamPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.media.azure.net' }
        azureMonitorPrivateDnsZoneId1: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.monitor.azure.com' }
        azureMonitorPrivateDnsZoneId2: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.oms.opinsights.azure.com' }
        azureMonitorPrivateDnsZoneId3: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.ods.opinsights.azure.com' }
        azureMonitorPrivateDnsZoneId4: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.agentsvc.azure-automation.net' }
        azureMonitorPrivateDnsZoneId5: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.blob.core.windows.net' }
        azureWebPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.webpubsub.azure.com' }
        azureBatchPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.batch.azure.com' }
        azureAppPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azconfig.io' }
        azureAsrPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.siterecovery.windowsazure.com' }
        azureIotPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azure-devices-provisioning.net' }
        azureKeyVaultPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.vaultcore.azure.net' }
        azureSignalRPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.service.signalr.net' }
        azureAppServicesPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azurewebsites.net' }
        azureEventGridTopicsPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.eventgrid.azure.net' }
        azureDiskAccessPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.blob.core.windows.net' }
        azureCognitiveServicesPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.cognitiveservices.azure.com' }
        azureIotHubsPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azure-devices.net' }
        azureEventGridDomainsPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.eventgrid.azure.net' }
        azureRedisCachePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.redis.cache.windows.net' }
        azureAcrPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.azurecr.io' }
        azureEventHubNamespacePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.servicebus.windows.net' }
        azureMachineLearningWorkspacePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.api.azureml.ms' }
        azureServiceBusNamespacePrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.servicebus.windows.net' }
        azureCognitiveSearchPrivateDnsZoneId: { value: '${varPrivateDnsZonesBaseResourceId}privatelink.search.windows.net' }
      }
      condition: !empty(parPrivateDnsResourceGroupId)
    }
  ]
}

/* The Policy Assignments from varPolicyAssignments flattened into a single array that can be deployed with a for loop (see modPolicyAssignments)
 * This can be made more readable once user-defined functions and types are made available in Bicep.
 * Explained shortly, an array of arrays containing objects of the type {
 *   managementGroupName: 'intRoot' | 'landingZones' | 'landingZonesCorp' | 'platformConnectivity' | 'platformIdentity' | 'platformManagement'
 *   assignmentDefinitionName: string // key from varPolicyAssignmentDefinitions
 *   parameterOverrides: object
 *   doDeply: bool // whether this Policy Assignment should actually be deployed
 *   assignmentDefinition: object // a copy of the Policy Assignment definition for convenience
 * }
 * this 2D array is then flattened to be able to iterate over it with a for loop
*/
var varPolicyAssignmentsFlattened = flatten(
  map(
    items(varPolicyAssignments), // [{key: 'intRoot', value: [{name: 'deployMDFCConfig', parametersOverrides: {...}, condition: true}, ...]}, ...]
    mg => map(
      mg.value,
      specificAssignment => {
        managementGroupName: string(mg.key)
        assignmentDefinitionName: string(specificAssignment.name)
        parameterOverrides: specificAssignment.parameterOverrides
        doDeploy: bool(specificAssignment.condition) && parDeployAssignments[mg.key][specificAssignment.name]

        // include a copy of the assignment definition so we don't have to reference varPolicyAssignmentDefinitions all the time in modPolicyAssignments
        assignmentDefinition: varPolicyAssignmentDefinitions[specificAssignment.name]
      }
    ) // [{managementGroup: 'intRoot', assignmentDefinitionName: 'deployMDFCConfig'}, ...]
  ) // [[{managementGroup: 'intRoot', assignmentDefinitionName: 'deployMDFCConfig'}, ...], [{managementGroup: 'enableDDoSVNET', assignmentDefinitionName: 'enableDDoSVNET'}, ...], ...]
) // [{managementGroup: 'intRoot', assignmentDefinitionName: 'deployMDFCConfig'}, ..., {managementGroup: 'enableDDoSVNET', assignmentDefinitionName: 'enableDDoSVNET'}, ...]


// MODULES
module modPolicyAssignments '../../../policy/assignments/policyAssignmentManagementGroup.bicep' = [for policyAssignment in varPolicyAssignmentsFlattened: if (policyAssignment.doDeploy) {
  scope: managementGroup(varManagementGroupIds[policyAssignment.managementGroupName])
  name: take('${varDeploymentNameWrappers.basePrefix}-${policyAssignment.assignmentDefinitionName}-${policyAssignment.managementGroupName}-${varDeploymentNameWrappers.baseSuffixTenantAndManagementGroup}', 64)
  params: {
    parPolicyAssignmentDefinitionId: policyAssignment.assignmentDefinition.definitionId
    parPolicyAssignmentName: policyAssignment.assignmentDefinition.libDefinition.name
    parPolicyAssignmentDisplayName: policyAssignment.assignmentDefinition.libDefinition.properties.displayName
    parPolicyAssignmentDescription: policyAssignment.assignmentDefinition.libDefinition.properties.description
    parPolicyAssignmentParameters: policyAssignment.assignmentDefinition.libDefinition.properties.parameters
    parPolicyAssignmentEnforcementMode: policyAssignment.assignmentDefinition.libDefinition.properties.enforcementMode
    parPolicyAssignmentIdentityType: policyAssignment.assignmentDefinition.libDefinition.identity.type
    parPolicyAssignmentParameterOverrides: policyAssignment.parameterOverrides
    parPolicyAssignmentIdentityRoleDefinitionIds: policyAssignment.assignmentDefinition.roleDefinitionIds
    parPolicyAssignmentIdentityRoleAssignmentsSubs: policyAssignment.assignmentDefinition.identityRoleAssignmentSubs
    parTelemetryOptOut: parTelemetryOptOut
  }
}]

// Optional Deployment for Customer Usage Attribution
module modCustomerUsageAttribution '../../../../CRML/customerUsageAttribution/cuaIdManagementGroup.bicep' = if (!parTelemetryOptOut) {
  #disable-next-line no-loc-expr-outside-params //Only to ensure telemetry data is stored in same location as deployment. See https://github.com/Azure/ALZ-Bicep/wiki/FAQ#why-are-some-linter-rules-disabled-via-the-disable-next-line-bicep-function for more information
  name: 'pid-${varCuaid}-${uniqueString(deployment().location)}'
  params: {}
}
