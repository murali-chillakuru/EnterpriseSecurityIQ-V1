"""Cloud Explorer ARG query templates.

All KQL templates used exclusively by Cloud Explorer live here.
Shared infrastructure (``query_resource_graph`` function) remains
in ``query_evaluators.arg_queries``.
"""

from __future__ import annotations

ARG_TEMPLATES: dict[str, str] = {
    "all_resources": """
        Resources
        | project name, type, location, resourceGroup, subscriptionId, tags
        | order by type, name
    """,
    "public_ips": """
        Resources
        | where type =~ 'microsoft.network/publicipaddresses'
        | project name, resourceGroup, location, properties.ipAddress,
                  properties.publicIPAllocationMethod, subscriptionId
    """,
    "vms_without_disk_encryption": """
        Resources
        | where type =~ 'microsoft.compute/virtualmachines'
        | extend osDisk = properties.storageProfile.osDisk
        | extend encryption = osDisk.managedDisk.securityProfile.diskEncryptionSet
        | where isnull(encryption)
        | project name, resourceGroup, location, subscriptionId
    """,
    "storage_public_access": """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | where properties.allowBlobPublicAccess == true
               or properties.publicNetworkAccess == 'Enabled'
        | project name, resourceGroup, location,
                  properties.allowBlobPublicAccess,
                  properties.publicNetworkAccess, subscriptionId
    """,
    "nsg_open_rules": """
        Resources
        | where type =~ 'microsoft.network/networksecuritygroups'
        | mv-expand rules = properties.securityRules
        | where rules.properties.access == 'Allow'
              and rules.properties.direction == 'Inbound'
              and rules.properties.sourceAddressPrefix in ('*', 'Internet', '0.0.0.0/0')
        | project nsgName=name, ruleName=rules.name,
                  destinationPort=rules.properties.destinationPortRange,
                  priority=rules.properties.priority,
                  resourceGroup, subscriptionId
    """,
    "sql_servers": """
        Resources
        | where type =~ 'microsoft.sql/servers'
        | project name, resourceGroup, location,
                  properties.administratorLogin,
                  properties.publicNetworkAccess, subscriptionId
    """,
    "keyvaults": """
        Resources
        | where type =~ 'microsoft.keyvault/vaults'
        | project name, resourceGroup, location,
                  properties.enableSoftDelete,
                  properties.enablePurgeProtection,
                  properties.publicNetworkAccess, subscriptionId
    """,
    "aks_clusters": """
        Resources
        | where type =~ 'microsoft.containerservice/managedclusters'
        | project name, resourceGroup, location,
                  properties.kubernetesVersion,
                  properties.networkProfile.networkPlugin,
                  properties.apiServerAccessProfile.enablePrivateCluster,
                  subscriptionId
    """,
    "unattached_disks": """
        Resources
        | where type =~ 'microsoft.compute/disks'
        | where isnull(managedBy) or managedBy == ''
        | project name, resourceGroup, location,
                  sku.name, properties.diskSizeGB, subscriptionId
    """,
    "resource_counts_by_type": """
        Resources
        | summarize count() by type
        | order by count_ desc
    """,
    "resources_by_location": """
        Resources
        | summarize count() by location
        | order by count_ desc
    """,
    "web_apps": """
        Resources
        | where type =~ 'microsoft.web/sites'
        | project name, kind, resourceGroup, location,
                  properties.state, properties.httpsOnly,
                  properties.siteConfig.minTlsVersion,
                  properties.publicNetworkAccess, subscriptionId
    """,
    "function_apps": """
        Resources
        | where type =~ 'microsoft.web/sites'
        | where kind contains 'functionapp'
        | project name, kind, resourceGroup, location,
                  properties.state, properties.httpsOnly, subscriptionId
    """,
    "cosmosdb": """
        Resources
        | where type =~ 'microsoft.documentdb/databaseaccounts'
        | project name, resourceGroup, location,
                  properties.publicNetworkAccess,
                  properties.isVirtualNetworkFilterEnabled,
                  properties.disableLocalAuth, subscriptionId
    """,
    "postgres_mysql": """
        Resources
        | where type contains 'microsoft.dbforpostgresql'
              or type contains 'microsoft.dbformysql'
        | project name, type, resourceGroup, location,
                  properties.publicNetworkAccess,
                  properties.sslEnforcement, subscriptionId
    """,
    "container_registries": """
        Resources
        | where type =~ 'microsoft.containerregistry/registries'
        | project name, resourceGroup, location, sku.name,
                  properties.adminUserEnabled,
                  properties.publicNetworkAccess, subscriptionId
    """,
    "vnets_subnets": """
        Resources
        | where type =~ 'microsoft.network/virtualnetworks'
        | mv-expand subnet = properties.subnets
        | project vnetName=name, subnetName=subnet.name,
                  addressPrefix=subnet.properties.addressPrefix,
                  nsg=subnet.properties.networkSecurityGroup.id,
                  resourceGroup, location, subscriptionId
    """,
    "private_endpoints": """
        Resources
        | where type =~ 'microsoft.network/privateendpoints'
        | mv-expand conn = properties.privateLinkServiceConnections
        | project name, resourceGroup, location,
                  targetResource=conn.properties.privateLinkServiceId,
                  groupIds=conn.properties.groupIds, subscriptionId
    """,
    "diagnostic_settings": """
        Resources
        | where type =~ 'microsoft.insights/diagnosticsettings'
        | project name, resourceGroup, properties.workspaceId,
                  properties.storageAccountId, subscriptionId
    """,
    "managed_identities": """
        Resources
        | where type =~ 'microsoft.managedidentity/userassignedidentities'
        | project name, resourceGroup, location,
                  properties.clientId, properties.principalId, subscriptionId
    """,
    "ai_services": """
        Resources
        | where type contains 'microsoft.cognitiveservices'
              or type contains 'microsoft.machinelearningservices'
        | project name, type, resourceGroup, location, sku.name,
                  properties.publicNetworkAccess,
                  properties.disableLocalAuth, subscriptionId
    """,
    "apim": """
        Resources
        | where type =~ 'microsoft.apimanagement/service'
        | project name, resourceGroup, location, sku.name,
                  properties.publicNetworkAccess,
                  properties.virtualNetworkType, subscriptionId
    """,
    "firewalls": """
        Resources
        | where type =~ 'microsoft.network/azurefirewalls'
        | project name, resourceGroup, location,
                  properties.sku.tier,
                  properties.threatIntelMode, subscriptionId
    """,
    "load_balancers": """
        Resources
        | where type =~ 'microsoft.network/loadbalancers'
        | project name, resourceGroup, location, sku.name,
                  properties.frontendIPConfigurations, subscriptionId
    """,
    "redis": """
        Resources
        | where type =~ 'microsoft.cache/redis'
        | project name, resourceGroup, location,
                  properties.sku.name, properties.sku.capacity,
                  properties.enableNonSslPort,
                  properties.publicNetworkAccess, subscriptionId
    """,
    "app_gateways": """
        Resources
        | where type =~ 'microsoft.network/applicationgateways'
        | project name, resourceGroup, location, sku=properties.sku.name,
                  tier=properties.sku.tier,
                  wafEnabled=properties.webApplicationFirewallConfiguration.enabled,
                  subscriptionId
    """,
    "policy_compliance": """
        PolicyResources
        | where type =~ 'microsoft.policyinsights/policystates'
        | where properties.complianceState == 'NonCompliant'
        | summarize nonCompliantCount=count() by
            policyName=tostring(properties.policyDefinitionName),
            category=tostring(properties.policyDefinitionCategory)
        | order by nonCompliantCount desc
    """,
    "defender_plans": """
        Resources
        | where type =~ 'microsoft.security/pricings'
        | project name, properties.pricingTier, properties.subPlan,
                  properties.freeTrialRemainingTime
    """,
    "tags_search": """
        Resources
        | where isnotempty(tags)
        | mv-expand bagexpansion=array tags
        | summarize count() by tostring(tags[0])
        | order by count_ desc
    """,
    "untagged_resources": """
        Resources
        | where isnull(tags) or tags == '{}'
        | project name, type, resourceGroup, location, subscriptionId
        | take 200
    """,
    "subscriptions": """
        ResourceContainers
        | where type =~ 'microsoft.resources/subscriptions'
        | project name, subscriptionId=subscriptionId, state=properties.state,
                  id
        | order by name
    """,
    "resource_groups": """
        ResourceContainers
        | where type =~ 'microsoft.resources/subscriptions/resourcegroups'
        | project name, subscriptionId, location, tags, id
        | order by name
    """,
    "all_vms": """
        Resources
        | where type =~ 'microsoft.compute/virtualmachines'
        | project name, resourceGroup, location,
                  vmSize=properties.hardwareProfile.vmSize,
                  osType=properties.storageProfile.osDisk.osType,
                  powerState=properties.extended.instanceView.powerState.displayStatus,
                  subscriptionId
    """,
    "resource_counts_by_subscription": """
        Resources
        | summarize resourceCount=count() by subscriptionId
        | order by resourceCount desc
    """,
    "resources_by_subscription": """
        Resources
        | summarize count() by type, subscriptionId
        | order by subscriptionId, count_ desc
    """,
    "management_groups": """
        ResourceContainers
        | where type =~ 'microsoft.management/managementgroups'
        | project name, displayName=properties.displayName,
                  parentId=properties.details.parent.id, id
    """,
    "role_assignments": """
        AuthorizationResources
        | where type =~ 'microsoft.authorization/roleassignments'
        | extend roleId = tostring(properties.roleDefinitionId),
                 principalId = tostring(properties.principalId),
                 principalType = tostring(properties.principalType),
                 scope = tostring(properties.scope)
        | project name, roleId, principalId, principalType, scope, subscriptionId
        | take 200
    """,
    "security_recommendations": """
        SecurityResources
        | where type =~ 'microsoft.security/assessments'
        | where properties.status.code == 'Unhealthy'
        | project name=properties.displayName,
                  severity=properties.metadata.severity,
                  category=properties.metadata.categories,
                  status=properties.status.code,
                  resourceId=properties.resourceDetails.Id,
                  subscriptionId
        | take 200
    """,
    "secure_score": """
        SecurityResources
        | where type =~ 'microsoft.security/securescores'
        | project name, currentScore=properties.score.current,
                  maxScore=properties.score.max,
                  percentage=properties.score.percentage,
                  weight=properties.weight,
                  subscriptionId
    """,
    "log_analytics_workspaces": """
        Resources
        | where type =~ 'microsoft.operationalinsights/workspaces'
        | project name, resourceGroup, location,
                  sku=sku.name, retentionDays=properties.retentionInDays,
                  subscriptionId
    """,
    "alert_rules": """
        Resources
        | where type contains 'microsoft.insights/metricalerts'
              or type contains 'microsoft.insights/activitylogalerts'
              or type contains 'microsoft.insights/scheduledqueryrules'
        | project name, type, resourceGroup, location,
                  enabled=properties.enabled, severity=properties.severity,
                  subscriptionId
    """,
    "container_apps": """
        Resources
        | where type =~ 'microsoft.app/containerapps'
        | project name, resourceGroup, location,
                  runningStatus=properties.runningStatus,
                  ingressFqdn=properties.configuration.ingress.fqdn,
                  subscriptionId
    """,
    "sql_databases_detailed": """
        Resources
        | where type =~ 'microsoft.sql/servers/databases'
        | where name != 'master'
        | project name, resourceGroup, location,
                  serverName=split(id,'/')[8],
                  sku=sku.name, tier=sku.tier,
                  status=properties.status,
                  transparentDataEncryption=properties.transparentDataEncryption,
                  subscriptionId
    """,
    "sql_firewall_rules": """
        Resources
        | where type =~ 'microsoft.sql/servers/firewallrules'
        | project name, resourceGroup,
                  serverName=split(id,'/')[8],
                  startIp=properties.startIpAddress,
                  endIp=properties.endIpAddress,
                  subscriptionId
    """,
    "keyvault_detailed": """
        Resources
        | where type =~ 'microsoft.keyvault/vaults'
        | project name, resourceGroup, location,
                  softDelete=properties.enableSoftDelete,
                  purgeProtection=properties.enablePurgeProtection,
                  publicAccess=properties.publicNetworkAccess,
                  rbacAuth=properties.enableRbacAuthorization,
                  sku=sku.name,
                  subscriptionId
    """,
    "webapp_detailed": """
        Resources
        | where type =~ 'microsoft.web/sites'
        | project name, kind, resourceGroup, location,
                  state=properties.state,
                  httpsOnly=properties.httpsOnly,
                  minTls=properties.siteConfig.minTlsVersion,
                  publicAccess=properties.publicNetworkAccess,
                  ftpsState=properties.siteConfig.ftpsState,
                  http20=properties.siteConfig.http20Enabled,
                  subscriptionId
    """,
    "event_hubs": """
        Resources
        | where type =~ 'microsoft.eventhub/namespaces'
        | project name, resourceGroup, location, sku=sku.name,
                  isAutoInflateEnabled=properties.isAutoInflateEnabled,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,
    "service_bus": """
        Resources
        | where type =~ 'microsoft.servicebus/namespaces'
        | project name, resourceGroup, location, sku=sku.name,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,
    "backup_vaults": """
        Resources
        | where type =~ 'microsoft.recoveryservices/vaults'
              or type =~ 'microsoft.dataprotection/backupvaults'
        | project name, type, resourceGroup, location, sku=sku.name,
                  subscriptionId
    """,
    "openai_deployments": """
        Resources
        | where type =~ 'microsoft.cognitiveservices/accounts'
        | where kind =~ 'OpenAI' or kind =~ 'AIServices'
        | project name, kind, resourceGroup, location,
                  publicAccess=properties.publicNetworkAccess,
                  disableLocalAuth=properties.disableLocalAuth,
                  sku=sku.name,
                  subscriptionId
    """,
    "ml_workspaces": """
        Resources
        | where type =~ 'microsoft.machinelearningservices/workspaces'
        | project name, kind, resourceGroup, location,
                  publicAccess=properties.publicNetworkAccess,
                  hbiWorkspace=properties.hbiWorkspace,
                  sku=sku.name,
                  subscriptionId
    """,
    "policy_assignments": """
        PolicyResources
        | where type =~ 'microsoft.authorization/policyassignments'
        | project name, displayName=properties.displayName,
                  policyDefinitionId=properties.policyDefinitionId,
                  scope=properties.scope,
                  enforcementMode=properties.enforcementMode,
                  subscriptionId
        | take 200
    """,
    "resource_locks": """
        Resources
        | where type =~ 'microsoft.authorization/locks'
        | project name, resourceGroup, lockLevel=properties.level,
                  notes=properties.notes, subscriptionId
    """,
    "network_interfaces": """
        Resources
        | where type =~ 'microsoft.network/networkinterfaces'
        | project name, resourceGroup, location,
                  vm=properties.virtualMachine.id,
                  subscriptionId
        | take 200
    """,
    "route_tables": """
        Resources
        | where type =~ 'microsoft.network/routetables'
        | project name, resourceGroup, location,
                  routeCount=array_length(properties.routes),
                  subscriptionId
    """,
    "sentinel_workspaces": """
        Resources
        | where type =~ 'microsoft.securityinsights/settings'
              or type =~ 'microsoft.operationsmanagement/solutions'
        | where name contains 'SecurityInsights'
        | project name, resourceGroup, location, subscriptionId
    """,
    "purview_accounts": """
        Resources
        | where type =~ 'microsoft.purview/accounts'
        | project name, resourceGroup, location,
                  publicAccess=properties.publicNetworkAccess,
                  sku=sku.name,
                  subscriptionId
    """,

    # ── v54 — Compute & VM Scale Sets ─────────────────────────────────
    "vmss": """
        Resources
        | where type =~ 'microsoft.compute/virtualmachinescalesets'
        | project name, resourceGroup, location,
                  sku=sku.name, capacity=sku.capacity,
                  upgradePolicy=properties.upgradePolicy.mode,
                  subscriptionId
    """,
    "dedicated_hosts": """
        Resources
        | where type =~ 'microsoft.compute/hostgroups'
              or type =~ 'microsoft.compute/hostgroups/hosts'
        | project name, type, resourceGroup, location,
                  sku=sku.name, subscriptionId
    """,
    "availability_sets": """
        Resources
        | where type =~ 'microsoft.compute/availabilitysets'
        | project name, resourceGroup, location,
                  faultDomains=properties.platformFaultDomainCount,
                  updateDomains=properties.platformUpdateDomainCount,
                  vmCount=array_length(properties.virtualMachines),
                  subscriptionId
    """,
    "disk_overview": """
        Resources
        | where type =~ 'microsoft.compute/disks'
        | project name, resourceGroup, location,
                  diskState=properties.diskState,
                  diskSizeGB=properties.diskSizeGB,
                  sku=sku.name,
                  encryption=properties.encryption.type,
                  subscriptionId
    """,
    "vm_extensions": """
        Resources
        | where type =~ 'microsoft.compute/virtualmachines/extensions'
        | project name, resourceGroup, location,
                  publisher=properties.publisher,
                  extensionType=properties.type,
                  provisioningState=properties.provisioningState,
                  subscriptionId
    """,
    "images_snapshots": """
        Resources
        | where type =~ 'microsoft.compute/images'
              or type =~ 'microsoft.compute/snapshots'
        | project name, type, resourceGroup, location,
                  provisioningState=properties.provisioningState,
                  subscriptionId
    """,

    # ── v54 — Networking (Advanced) ───────────────────────────────────
    "front_door": """
        Resources
        | where type =~ 'microsoft.cdn/profiles'
              or type =~ 'microsoft.network/frontdoors'
        | project name, type, resourceGroup, location,
                  sku=sku.name, subscriptionId
    """,
    "expressroute": """
        Resources
        | where type =~ 'microsoft.network/expressroutecircuits'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  bandwidthInMbps=properties.bandwidthInMbps,
                  peeringLocation=properties.peeringLocation,
                  serviceProviderName=properties.serviceProviderProperties.serviceProviderName,
                  subscriptionId
    """,
    "vpn_gateways": """
        Resources
        | where type =~ 'microsoft.network/virtualnetworkgateways'
        | project name, resourceGroup, location,
                  gatewayType=properties.gatewayType,
                  vpnType=properties.vpnType,
                  sku=properties.sku.name,
                  subscriptionId
    """,
    "bastion_hosts": """
        Resources
        | where type =~ 'microsoft.network/bastionhosts'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  subscriptionId
    """,
    "ddos_protection": """
        Resources
        | where type =~ 'microsoft.network/ddosprotectionplans'
        | project name, resourceGroup, location,
                  vnets=array_length(properties.virtualNetworks),
                  subscriptionId
    """,
    "virtual_wan": """
        Resources
        | where type =~ 'microsoft.network/virtualwans'
              or type =~ 'microsoft.network/virtualhubs'
        | project name, type, resourceGroup, location,
                  subscriptionId
    """,
    "dns_zones": """
        Resources
        | where type =~ 'microsoft.network/dnszones'
              or type =~ 'microsoft.network/privatednszones'
        | project name, type, resourceGroup, location,
                  recordCount=properties.numberOfRecordSets,
                  subscriptionId
    """,
    "traffic_manager": """
        Resources
        | where type =~ 'microsoft.network/trafficmanagerprofiles'
        | project name, resourceGroup, location,
                  routingMethod=properties.trafficRoutingMethod,
                  monitorStatus=properties.monitorConfig.profileMonitorStatus,
                  subscriptionId
    """,
    "nat_gateways": """
        Resources
        | where type =~ 'microsoft.network/natgateways'
        | project name, resourceGroup, location,
                  publicIpCount=array_length(properties.publicIpAddresses),
                  subscriptionId
    """,
    "network_watchers": """
        Resources
        | where type =~ 'microsoft.network/networkwatchers'
        | project name, resourceGroup, location,
                  provisioningState=properties.provisioningState,
                  subscriptionId
    """,
    "nsg_flow_logs": """
        Resources
        | where type =~ 'microsoft.network/networkwatchers/flowlogs'
        | project name, resourceGroup, location,
                  enabled=properties.enabled,
                  retentionDays=properties.retentionPolicy.days,
                  subscriptionId
    """,
    "ip_groups": """
        Resources
        | where type =~ 'microsoft.network/ipgroups'
        | project name, resourceGroup, location,
                  ipCount=array_length(properties.ipAddresses),
                  subscriptionId
    """,
    "peerings": """
        Resources
        | where type =~ 'microsoft.network/virtualnetworks'
        | mv-expand peering = properties.virtualNetworkPeerings
        | project vnetName=name, peeringName=peering.name,
                  peeringState=peering.properties.peeringState,
                  remoteVnet=peering.properties.remoteVirtualNetwork.id,
                  resourceGroup, subscriptionId
    """,

    # ── v54 — Integration & Messaging ─────────────────────────────────
    "logic_apps": """
        Resources
        | where type =~ 'microsoft.logic/workflows'
              or type =~ 'microsoft.web/sites' and kind contains 'workflowapp'
        | project name, type, resourceGroup, location,
                  state=properties.state,
                  subscriptionId
    """,
    "event_grid": """
        Resources
        | where type =~ 'microsoft.eventgrid/topics'
              or type =~ 'microsoft.eventgrid/domains'
              or type =~ 'microsoft.eventgrid/systemtopics'
              or type =~ 'microsoft.eventgrid/namespaces'
        | project name, type, resourceGroup, location,
                  subscriptionId
    """,
    "relay_namespaces": """
        Resources
        | where type =~ 'microsoft.relay/namespaces'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  subscriptionId
    """,
    "notification_hubs": """
        Resources
        | where type =~ 'microsoft.notificationhubs/namespaces'
              or type =~ 'microsoft.notificationhubs/namespaces/notificationhubs'
        | project name, type, resourceGroup, location,
                  sku=sku.name,
                  subscriptionId
    """,
    "signalr": """
        Resources
        | where type =~ 'microsoft.signalrservice/signalr'
              or type =~ 'microsoft.signalrservice/webpubsub'
        | project name, type, resourceGroup, location,
                  sku=sku.name,
                  subscriptionId
    """,

    # ── v54 — Containers ──────────────────────────────────────────────
    "container_instances": """
        Resources
        | where type =~ 'microsoft.containerinstance/containergroups'
        | project name, resourceGroup, location,
                  osType=properties.osType,
                  ipType=properties.ipAddress.type,
                  containerCount=array_length(properties.containers),
                  subscriptionId
    """,
    "aro_clusters": """
        Resources
        | where type =~ 'microsoft.redhatopenshift/openshiftclusters'
        | project name, resourceGroup, location,
                  version=properties.clusterProfile.version,
                  apiServerVisibility=properties.apiserverProfile.visibility,
                  subscriptionId
    """,

    # ── v54 — Databases (Extended) ────────────────────────────────────
    "sql_managed_instances": """
        Resources
        | where type =~ 'microsoft.sql/managedinstances'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  publicEndpoint=properties.publicDataEndpointEnabled,
                  subscriptionId
    """,
    "mariadb": """
        Resources
        | where type =~ 'microsoft.dbformariadb/servers'
        | project name, resourceGroup, location,
                  version=properties.version,
                  sslEnforcement=properties.sslEnforcement,
                  subscriptionId
    """,
    "elastic_pools": """
        Resources
        | where type =~ 'microsoft.sql/servers/elasticpools'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  maxSizeBytes=properties.maxSizeBytes,
                  subscriptionId
    """,
    "sql_virtual_machines": """
        Resources
        | where type =~ 'microsoft.sqlvirtualmachine/sqlvirtualmachines'
        | project name, resourceGroup, location,
                  sqlImageOffer=properties.sqlImageOffer,
                  sqlManagement=properties.sqlManagement,
                  subscriptionId
    """,

    # ── v54 — Big Data & Analytics ────────────────────────────────────
    "synapse": """
        Resources
        | where type =~ 'microsoft.synapse/workspaces'
        | project name, resourceGroup, location,
                  managedVirtualNetwork=properties.managedVirtualNetwork,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,
    "data_factory": """
        Resources
        | where type =~ 'microsoft.datafactory/factories'
        | project name, resourceGroup, location,
                  provisioningState=properties.provisioningState,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,
    "databricks": """
        Resources
        | where type =~ 'microsoft.databricks/workspaces'
        | project name, resourceGroup, location,
                  pricingTier=sku.name,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,
    "data_explorer": """
        Resources
        | where type =~ 'microsoft.kusto/clusters'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  state=properties.state,
                  subscriptionId
    """,
    "stream_analytics": """
        Resources
        | where type =~ 'microsoft.streamanalytics/streamingjobs'
        | project name, resourceGroup, location,
                  jobState=properties.jobState,
                  sku=sku.name,
                  subscriptionId
    """,
    "hdinsight": """
        Resources
        | where type =~ 'microsoft.hdinsight/clusters'
        | project name, resourceGroup, location,
                  clusterVersion=properties.clusterVersion,
                  osType=properties.osType,
                  tier=properties.tier,
                  subscriptionId
    """,
    "analysis_services": """
        Resources
        | where type =~ 'microsoft.analysisservices/servers'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  state=properties.state,
                  subscriptionId
    """,
    "power_bi_embedded": """
        Resources
        | where type =~ 'microsoft.powerbidedicated/capacities'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  state=properties.state,
                  subscriptionId
    """,

    # ── v54 — IoT ─────────────────────────────────────────────────────
    "iot_hubs": """
        Resources
        | where type =~ 'microsoft.devices/iothubs'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  state=properties.state,
                  subscriptionId
    """,
    "iot_central": """
        Resources
        | where type =~ 'microsoft.iotcentral/iotapps'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  state=properties.state,
                  subscriptionId
    """,
    "iot_dps": """
        Resources
        | where type =~ 'microsoft.devices/provisioningservices'
        | project name, resourceGroup, location,
                  state=properties.state,
                  allocationPolicy=properties.allocationPolicy,
                  subscriptionId
    """,
    "digital_twins": """
        Resources
        | where type =~ 'microsoft.digitaltwins/digitaltwinsinstances'
        | project name, resourceGroup, location,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,

    # ── v54 — Hybrid & Migration ──────────────────────────────────────
    "arc_servers": """
        Resources
        | where type =~ 'microsoft.hybridcompute/machines'
        | project name, resourceGroup, location,
                  osType=properties.osType,
                  status=properties.status,
                  agentVersion=properties.agentVersion,
                  subscriptionId
    """,
    "arc_kubernetes": """
        Resources
        | where type =~ 'microsoft.kubernetes/connectedclusters'
        | project name, resourceGroup, location,
                  kubernetesVersion=properties.kubernetesVersion,
                  agentVersion=properties.agentVersion,
                  connectivityStatus=properties.connectivityStatus,
                  subscriptionId
    """,
    "site_recovery": """
        Resources
        | where type =~ 'microsoft.recoveryservices/vaults'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  provisioningState=properties.provisioningState,
                  subscriptionId
    """,
    "migrate_projects": """
        Resources
        | where type =~ 'microsoft.migrate/migrateprojects'
              or type =~ 'microsoft.migrate/assessmentprojects'
        | project name, type, resourceGroup, location,
                  subscriptionId
    """,
    "stack_hci": """
        Resources
        | where type =~ 'microsoft.azurestackhci/clusters'
        | project name, resourceGroup, location,
                  status=properties.status,
                  lastSyncTimestamp=properties.lastSyncTimestamp,
                  subscriptionId
    """,

    # ── v54 — Developer & DevOps ──────────────────────────────────────
    "devtest_labs": """
        Resources
        | where type =~ 'microsoft.devtestlab/labs'
        | project name, resourceGroup, location,
                  environmentPermission=properties.environmentPermission,
                  subscriptionId
    """,
    "devops_pipelines": """
        Resources
        | where type =~ 'microsoft.devops/pipelines'
        | project name, resourceGroup, location,
                  subscriptionId
    """,
    "dev_center": """
        Resources
        | where type =~ 'microsoft.devcenter/devcenters'
              or type =~ 'microsoft.devcenter/projects'
        | project name, type, resourceGroup, location,
                  subscriptionId
    """,
    "load_testing": """
        Resources
        | where type =~ 'microsoft.loadtestservice/loadtests'
        | project name, resourceGroup, location,
                  provisioningState=properties.provisioningState,
                  subscriptionId
    """,
    "managed_grafana": """
        Resources
        | where type =~ 'microsoft.dashboard/grafana'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,
    "managed_prometheus": """
        Resources
        | where type =~ 'microsoft.monitor/accounts'
        | project name, resourceGroup, location,
                  subscriptionId
    """,

    # ── v54 — Security (Advanced) ─────────────────────────────────────
    "defender_auto_provisioning": """
        SecurityResources
        | where type =~ 'microsoft.security/autoprovisioningsettings'
        | project name, autoProvision=properties.autoProvision,
                  subscriptionId
    """,
    "defender_assessments": """
        SecurityResources
        | where type =~ 'microsoft.security/assessments'
        | where properties.status.code == 'Unhealthy'
        | project name, displayName=properties.displayName,
                  severity=properties.metadata.severity,
                  resourceId=properties.resourceDetails.Id,
                  subscriptionId
        | take 200
    """,
    "defender_alerts": """
        SecurityResources
        | where type =~ 'microsoft.security/alerts'
        | where properties.Status == 'Active'
        | project alertName=properties.AlertDisplayName,
                  severity=properties.Severity,
                  status=properties.Status,
                  compromisedEntity=properties.CompromisedEntity,
                  subscriptionId
        | take 200
    """,
    "regulatory_compliance": """
        SecurityResources
        | where type =~ 'microsoft.security/regulatorycompliancestandards'
        | project name, state=properties.state,
                  passedControls=properties.passedControls,
                  failedControls=properties.failedControls,
                  subscriptionId
    """,
    "jit_policies": """
        SecurityResources
        | where type =~ 'microsoft.security/jitnetworkaccesspolicies'
        | project name, resourceGroup, location,
                  vmCount=array_length(properties.virtualMachines),
                  subscriptionId
    """,
    "adaptive_app_controls": """
        SecurityResources
        | where type =~ 'microsoft.security/applicationwhitelistings'
        | project name, enforcementMode=properties.enforcementMode,
                  configurationStatus=properties.configurationStatus,
                  subscriptionId
    """,

    # ── v54 — Storage (Extended) ──────────────────────────────────────
    "storage_accounts": """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | project name, resourceGroup, location,
                  kind=kind, sku=sku.name, accessTier=properties.accessTier,
                  httpsOnly=properties.supportsHttpsTrafficOnly,
                  publicAccess=properties.allowBlobPublicAccess,
                  minimumTlsVersion=properties.minimumTlsVersion,
                  subscriptionId
    """,
    "data_lake_stores": """
        Resources
        | where type =~ 'microsoft.datalakestore/accounts'
              or type =~ 'microsoft.datalakeanalytics/accounts'
        | project name, type, resourceGroup, location,
                  state=properties.state,
                  subscriptionId
    """,
    "file_shares": """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | where properties.primaryEndpoints.file != ''
        | project name, resourceGroup, location,
                  fileEndpoint=properties.primaryEndpoints.file,
                  sku=sku.name,
                  subscriptionId
    """,
    "managed_disks_encryption": """
        Resources
        | where type =~ 'microsoft.compute/disks'
        | project name, resourceGroup, location,
                  diskState=properties.diskState,
                  encryptionType=properties.encryption.type,
                  diskEncryptionSetId=properties.encryption.diskEncryptionSetId,
                  subscriptionId
    """,
    "netapp_accounts": """
        Resources
        | where type =~ 'microsoft.netapp/netappaccounts'
              or type =~ 'microsoft.netapp/netappaccounts/capacitypools'
        | project name, type, resourceGroup, location,
                  subscriptionId
    """,

    # ── v54 — Identity & Governance ───────────────────────────────────
    "custom_roles": """
        AuthorizationResources
        | where type =~ 'microsoft.authorization/roledefinitions'
        | where properties.type == 'CustomRole'
        | project roleName=properties.roleName,
                  description=properties.description,
                  assignableScopes=properties.assignableScopes,
                  subscriptionId
    """,
    "deny_assignments": """
        AuthorizationResources
        | where type =~ 'microsoft.authorization/denyassignments'
        | project name, displayName=properties.displayName,
                  scope=properties.scope,
                  subscriptionId
    """,
    "blueprint_assignments": """
        Resources
        | where type =~ 'microsoft.blueprint/blueprintassignments'
        | project name, resourceGroup, location,
                  blueprintId=properties.blueprintId,
                  lockMode=properties.locks.mode,
                  subscriptionId
    """,
    "policy_exemptions": """
        PolicyResources
        | where type =~ 'microsoft.authorization/policyexemptions'
        | project name, category=properties.exemptionCategory,
                  policyAssignmentId=properties.policyAssignmentId,
                  expiresOn=properties.expiresOn,
                  subscriptionId
    """,
    "policy_definitions_custom": """
        PolicyResources
        | where type =~ 'microsoft.authorization/policydefinitions'
        | where properties.policyType == 'Custom'
        | project name, displayName=properties.displayName,
                  policyType=properties.policyType,
                  mode=properties.mode,
                  subscriptionId
    """,

    # ── v54 — App Platform (Extended) ─────────────────────────────────
    "static_web_apps": """
        Resources
        | where type =~ 'microsoft.web/staticsites'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  defaultHostname=properties.defaultHostname,
                  subscriptionId
    """,
    "app_service_plans": """
        Resources
        | where type =~ 'microsoft.web/serverfarms'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  workerSize=properties.workerSize,
                  numberOfWorkers=properties.numberOfWorkers,
                  subscriptionId
    """,
    "app_service_environments": """
        Resources
        | where type =~ 'microsoft.web/hostingenvironments'
        | project name, resourceGroup, location,
                  version=kind,
                  internalLoadBalancingMode=properties.internalLoadBalancingMode,
                  subscriptionId
    """,
    "spring_apps": """
        Resources
        | where type =~ 'microsoft.appplatform/spring'
        | project name, resourceGroup, location,
                  sku=sku.name, tier=sku.tier,
                  subscriptionId
    """,
    "app_configuration": """
        Resources
        | where type =~ 'microsoft.appconfiguration/configurationstores'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,

    # ── v54 — Media & CDN ─────────────────────────────────────────────
    "cdn_profiles": """
        Resources
        | where type =~ 'microsoft.cdn/profiles'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  subscriptionId
    """,
    "media_services": """
        Resources
        | where type =~ 'microsoft.media/mediaservices'
        | project name, resourceGroup, location,
                  storageAccounts=properties.storageAccounts,
                  subscriptionId
    """,
    "communication_services": """
        Resources
        | where type =~ 'microsoft.communication/communicationservices'
        | project name, resourceGroup, location,
                  dataLocation=properties.dataLocation,
                  subscriptionId
    """,

    # ── v54 — Search & Maps ───────────────────────────────────────────
    "search_services": """
        Resources
        | where type =~ 'microsoft.search/searchservices'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  publicAccess=properties.publicNetworkAccess,
                  replicaCount=properties.replicaCount,
                  partitionCount=properties.partitionCount,
                  subscriptionId
    """,
    "maps_accounts": """
        Resources
        | where type =~ 'microsoft.maps/accounts'
        | project name, resourceGroup, location,
                  sku=sku.name,
                  subscriptionId
    """,

    # ── v54 — Blockchain & Confidential ───────────────────────────────
    "confidential_ledger": """
        Resources
        | where type =~ 'microsoft.confidentialledger/ledgers'
        | project name, resourceGroup, location,
                  ledgerType=properties.ledgerType,
                  subscriptionId
    """,
    "managed_hsm": """
        Resources
        | where type =~ 'microsoft.keyvault/managedhsms'
        | project name, resourceGroup, location,
                  publicAccess=properties.publicNetworkAccess,
                  subscriptionId
    """,

    # ── v54 — Automation & Management ─────────────────────────────────
    "automation_accounts": """
        Resources
        | where type =~ 'microsoft.automation/automationaccounts'
        | project name, resourceGroup, location,
                  state=properties.state,
                  sku=sku.name,
                  subscriptionId
    """,
    "maintenance_configs": """
        Resources
        | where type =~ 'microsoft.maintenance/maintenanceconfigurations'
        | project name, resourceGroup, location,
                  maintenanceScope=properties.maintenanceScope,
                  subscriptionId
    """,
    "update_manager": """
        PatchAssessmentResources
        | where type =~ 'microsoft.compute/virtualmachines/patchassessmentresults/latest'
        | project vmName=split(id,'/')[8],
                  status=properties.status,
                  criticalAndSecurityPatchCount=properties.availablePatchCountByClassification.critical + properties.availablePatchCountByClassification.security,
                  lastAssessedTime=properties.lastModifiedDateTime,
                  subscriptionId
        | take 200
    """,
    "action_groups": """
        Resources
        | where type =~ 'microsoft.insights/actiongroups'
        | project name, resourceGroup, location,
                  enabled=properties.enabled,
                  emailReceivers=array_length(properties.emailReceivers),
                  smsReceivers=array_length(properties.smsReceivers),
                  webhookReceivers=array_length(properties.webhookReceivers),
                  subscriptionId
    """,
    "service_health": """
        ServiceHealthResources
        | where type =~ 'microsoft.resourcehealth/events'
        | where properties.EventType == 'ServiceIssue'
              and properties.Status == 'Active'
        | project title=properties.Title,
                  impact=properties.Impact,
                  status=properties.Status,
                  lastUpdateTime=properties.LastUpdateTime,
                  subscriptionId
        | take 100
    """,

    # ── v54 — Cost & Advisor ──────────────────────────────────────────
    "advisor_recommendations": """
        AdvisorResources
        | where type =~ 'microsoft.advisor/recommendations'
        | project category=properties.category,
                  impact=properties.impact,
                  shortDescription=properties.shortDescription.solution,
                  resourceId=properties.resourceMetadata.resourceId,
                  subscriptionId
        | take 200
    """,
    "advisor_cost_recommendations": """
        AdvisorResources
        | where type =~ 'microsoft.advisor/recommendations'
        | where properties.category == 'Cost'
        | project impact=properties.impact,
                  shortDescription=properties.shortDescription.solution,
                  savingsAmount=properties.extendedProperties.savingsAmount,
                  resourceId=properties.resourceMetadata.resourceId,
                  subscriptionId
        | take 100
    """,

    # ── v54 — Compliance & Guest Config ───────────────────────────────
    "guest_configuration": """
        GuestConfigurationResources
        | where type =~ 'microsoft.guestconfiguration/guestconfigurationassignments'
        | project name, complianceStatus=properties.complianceStatus,
                  lastComplianceStatusChecked=properties.lastComplianceStatusChecked,
                  assignmentType=properties.guestConfiguration.assignmentType,
                  subscriptionId
        | take 200
    """,

    # ── v54 — Batch & HPC ────────────────────────────────────────────
    "batch_accounts": """
        Resources
        | where type =~ 'microsoft.batch/batchaccounts'
        | project name, resourceGroup, location,
                  publicAccess=properties.publicNetworkAccess,
                  poolAllocationMode=properties.poolAllocationMode,
                  subscriptionId
    """,

    # ── v54 — Miscellaneous ───────────────────────────────────────────
    "managed_environments": """
        Resources
        | where type =~ 'microsoft.app/managedenvironments'
        | project name, resourceGroup, location,
                  infrastructureSubnetId=properties.vnetConfiguration.infrastructureSubnetId,
                  logAnalyticsWorkspace=properties.appLogsConfiguration.logAnalyticsConfiguration.customerId,
                  subscriptionId
    """,
    "chaos_experiments": """
        Resources
        | where type =~ 'microsoft.chaos/experiments'
        | project name, resourceGroup, location,
                  provisioningState=properties.provisioningState,
                  subscriptionId
    """,
    "health_models": """
        Resources
        | where type =~ 'microsoft.workloadmonitor/monitors'
        | project name, health=properties.currentMonitorState,
                  previousHealth=properties.previousMonitorState,
                  subscriptionId
        | take 200
    """,
    "cost_exports": """
        Resources
        | where type =~ 'microsoft.costmanagement/exports'
        | project name, resourceGroup,
                  deliveryInfo=properties.deliveryInfo,
                  schedule=properties.schedule,
                  subscriptionId
    """,
    "budgets": """
        Resources
        | where type =~ 'microsoft.consumption/budgets'
        | project name, amount=properties.amount,
                  timeGrain=properties.timeGrain,
                  currentSpend=properties.currentSpend.amount,
                  subscriptionId
    """,
}
