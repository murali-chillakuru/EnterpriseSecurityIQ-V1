# PostureIQ Agent — Resource Coverage & Capabilities

**Author:** Murali Chillakuru

> **Executive Summary** — The deepest technical reference: every collector with its SDK methods,
> evidence types, and data collected. 64 registered collectors (49 Azure + 13 Entra + 2 standalone),
> 218 distinct evidence types, 10 evaluation domains, 113 check functions, and complete permission
> requirements. This is the canonical collector and capability reference.
>
> | | |
> |---|---|
> | **Audience** | Security engineers, integration developers, permission administrators |
> | **Prerequisites** | [Architecture](architecture.md) for pipeline overview |
> | **Companion docs** | [Evaluation Rules](evaluation-rules.md) for check function details · [Configuration Guide](configuration-guide.md) for collector tuning · [FILE-REFERENCE](FILE-REFERENCE.md) for file inventory |

---

## Agent Tools & CLI Entry Points

The agent exposes **14 Foundry agent tools** (registered in [`agent.py → TOOLS`](../AIAgent/app/agent.py)) and **8 CLI scripts**. Each tool is an `async` function with `Annotated` type hints, registered via `tools=[...]` on the `AzureAIClient.as_agent()` call in [`main.py`](../AIAgent/main.py).

| # | Capability | Agent Tool | CLI Script | Engine / Module |
|---|------------|-----------|------------|-----------------|
| 1 | Query cached findings | `query_results` | — | In-memory `_session_state` |
| 2 | Live Azure / Entra queries | `search_tenant` | `run_query.py` | [`query_engine.py`](../AIAgent/app/query_engine.py) + `query_evaluators/` |
| 3 | Security risk gap analysis | `analyze_risk` | `run_risk_analysis.py` | [`risk_orchestrator.py`](../AIAgent/app/risk_orchestrator.py) + `risk_evaluators/` |
| 4 | Data security assessment | `assess_data_security` | `run_data_security.py` | [`data_security_engine.py`](../AIAgent/app/data_security_engine.py) |
| 5 | RBAC hierarchy report | `generate_rbac_report` | `run_rbac_report.py` | [`rbac_orchestrator.py`](../AIAgent/app/rbac_orchestrator.py) + `rbac_evaluators/` |
| 6 | Report regeneration | `generate_report` | — | [`html_report.py`](../AIAgent/app/reports/html_report.py), [`json_report.py`](../AIAgent/app/reports/json_report.py) |
| 7 | M365 Copilot readiness | `assess_copilot_readiness` | `run_copilot_readiness.py` | [`copilot_orchestrator.py`](../AIAgent/app/copilot_orchestrator.py) + `copilot_evaluators/` |
| 8 | AI agent security | `assess_ai_agent_security` | `run_ai_agent_security.py` | [`aiagentsec_orchestrator.py`](../AIAgent/app/aiagentsec_orchestrator.py) + `aiagentsec_evaluators/` |
| 9 | Permission check | `check_permissions` | — | [`auth.py → preflight_check()`](../AIAgent/app/auth.py) |
| 10 | Run comparison | `compare_runs` | — | [`delta_report.py`](../AIAgent/app/reports/delta_report.py) |
| 11 | Exposure search | `search_exposure` | — | [`query_engine.py → ARG_TEMPLATES`](../AIAgent/app/query_engine.py) |
| 12 | Custom report generation | `generate_custom_report` | — | Report generators with custom framework/format selection |
| 13 | PostureIQ posture assessment | `run_postureiq_assessment` | — | [`postureiq_orchestrator.py`](../AIAgent/app/postureiq_orchestrator.py) |
| 14 | Assessment history queries | `query_assessment_history` | — | [`evidence_history.py`](../AIAgent/app/evidence_history.py) (blob-backed: list, trend, detail, compare) |
| — | Foundry agent server | — | `main.py` | [`agent.py`](../AIAgent/app/agent.py) |

---

## At a Glance

| Metric | Value |
|--------|-------|
| **Azure Collectors** | **50** (49 registered via `@register_collector` + 1 standalone) |
| **Entra ID Collectors** | **18** (17 registered via `@register_collector` + 1 standalone) |
| **Distinct Evidence Types** | **218** |
| **Evaluation Domains** | **10** |
| **Evaluation Check Functions** | **~113** |
| **Compliance Frameworks** | **11** (525 total controls) |
| **Data Plane Operations** | Key Vault secrets/certs/keys, Storage containers, CosmosDB databases/containers/RBAC, SQL detailed (VA/ATP/TDE/auditing/firewall), ACR repositories, APIM APIs/products/subscriptions/named-values/backends/certificates, WebApp detailed (auth/IP/CORS), RDBMS detailed (PostgreSQL/MySQL firewall, parameters) |
| **Control Plane Operations** | All other Azure + Entra operations via ARM SDK and Microsoft Graph |

---

## Azure Resource Coverage — Control Plane (39 registered collectors)

All collectors auto-register via the [`@register_collector`](../AIAgent/app/collectors/registry.py) decorator and are discovered at import time by `discover_collectors()` in [`postureiq_orchestrator.py`](../AIAgent/app/postureiq_orchestrator.py). Sorted by `priority` (lower = runs earlier).

### 1. Resources & Management Groups

**File:** [`collectors/azure/resources.py`](../AIAgent/app/collectors/azure/resources.py) · **Priority:** 10

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Management Groups | `ManagementGroupsAPI.management_groups.list()` | `azure-resource` |
| Resource Groups | `ResourceManagementClient.resource_groups.list()` | `azure-resource-group` |
| All ARM Resources | `ResourceManagementClient.resources.list()` | `azure-resource` |

**Data Collected:** Resource names, types, locations, tags, resource group membership, management group hierarchy, per-subscription resource counts.

---

### 2. RBAC

**File:** [`collectors/azure/rbac.py`](../AIAgent/app/collectors/azure/rbac.py) · **Priority:** 20

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Role Assignments | `AuthorizationManagementClient.role_assignments.list_for_subscription()` | `azure-role-assignment` |
| Role Definitions | `AuthorizationManagementClient.role_definitions.get_by_id()` | `azure-role-assignment` |

**19 Privileged Role Names** (from `PRIVILEGED_ROLES` constant):

| # | Role | # | Role |
|---|------|---|------|
| 1 | Owner | 11 | SQL Server Contributor |
| 2 | Contributor | 12 | SQL Security Manager |
| 3 | User Access Administrator | 13 | Monitoring Contributor |
| 4 | Security Admin | 14 | Log Analytics Contributor |
| 5 | Global Administrator | 15 | Automation Operator |
| 6 | Key Vault Administrator | 16 | Managed Identity Operator |
| 7 | Key Vault Secrets Officer | 17 | Role Based Access Control Administrator |
| 8 | Storage Account Contributor | 18 | Azure Kubernetes Service Cluster Admin Role |
| 9 | Virtual Machine Contributor | 19 | Azure Kubernetes Service RBAC Admin |
| 10 | Network Contributor | | |

**Data Collected:** Role name, principal type, scope level (ManagementGroup / Subscription / ResourceGroup / Resource), whether role is privileged, whether role is custom, cached role definition resolution to avoid N+1 API calls.

---

### 3. Azure Policy

**File:** [`collectors/azure/policy.py`](../AIAgent/app/collectors/azure/policy.py) · **Priority:** 30

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Policy Assignments | `PolicyClient.policy_assignments.list()` | `azure-policy-assignment` |
| Policy Definitions | `PolicyClient.policy_definitions.list()` | `azure-policy-definition` |

**Data Collected:** Enforcement mode, policy vs. initiative distinction, display name, policy type (BuiltIn / Custom).

---

### 4. Policy Compliance

**File:** [`collectors/azure/policy_compliance.py`](../AIAgent/app/collectors/azure/policy_compliance.py) · **Priority:** 80

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Policy Compliance States | `PolicyInsightsClient.policy_states.list_query_results_for_subscription()` | `azure-policy-compliance` |

**Data Collected:** Compliance state per resource, compliant / non-compliant / exempt counts, compliance percentage.

---

### 5. Diagnostic Settings

**File:** [`collectors/azure/diagnostics.py`](../AIAgent/app/collectors/azure/diagnostics.py) · **Priority:** 40 · **Concurrency:** `asyncio.Semaphore(10)`

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Diagnostic Settings | `MonitorManagementClient.diagnostic_settings.list()` | `azure-diagnostic-setting` |

**Target Resource Types Scanned** (from `DIAGNOSTIC_RESOURCE_TYPES`):

| # | Resource Type | # | Resource Type |
|---|--------------|---|--------------|
| 1 | `Microsoft.KeyVault/vaults` | 18 | `Microsoft.Sql/servers/databases` |
| 2 | `Microsoft.Network/networkSecurityGroups` | 19 | `Microsoft.DBforPostgreSQL/flexibleServers` |
| 3 | `Microsoft.Network/applicationGateways` | 20 | `Microsoft.DBforMySQL/flexibleServers` |
| 4 | `Microsoft.Sql/servers` | 21 | `Microsoft.DocumentDB/databaseAccounts` |
| 5 | `Microsoft.Storage/storageAccounts` | 22 | `Microsoft.Cache/redis` |
| 6 | `Microsoft.Web/sites` | 23 | `Microsoft.Network/frontDoors` |
| 7 | `Microsoft.Compute/virtualMachines` | 24 | `Microsoft.Network/trafficManagerProfiles` |
| 8 | `Microsoft.ContainerService/managedClusters` | 25 | `Microsoft.Network/bastionHosts` |
| 9 | `Microsoft.Network/azureFirewalls` | 26 | `Microsoft.Network/expressRouteCircuits` |
| 10 | `Microsoft.Network/loadBalancers` | 27 | `Microsoft.Network/vpnGateways` |
| 11 | `Microsoft.Network/publicIPAddresses` | 28 | `Microsoft.Network/privateDnsZones` |
| 12 | `Microsoft.Network/virtualNetworkGateways` | 29 | `Microsoft.Compute/virtualMachineScaleSets` |
| 13 | `Microsoft.Cdn/profiles` | 30 | `Microsoft.App/containerApps` |
| 14 | `Microsoft.EventHub/namespaces` | 31 | `Microsoft.ContainerInstance/containerGroups` |
| 15 | `Microsoft.ServiceBus/namespaces` | 32 | `Microsoft.ApiManagement/service` |
| 16 | `Microsoft.Devices/IotHubs` | 33 | `Microsoft.Logic/workflows` |
| 17 | `Microsoft.ContainerRegistry/registries` | 34+ | EventGrid, SignalR, CognitiveServices, … |

**Data Collected:** Whether diagnostics are configured per resource, Log Analytics workspace destination, storage account destination, Event Hub destination.

---

### 6. Activity Logs & Resource Locks

**File:** [`collectors/azure/activity_logs.py`](../AIAgent/app/collectors/azure/activity_logs.py) · **Priority:** 50

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Activity Logs (90 days) | `MonitorManagementClient.activity_logs.list()` | `azure-activity-log`, `azure-activity-event` |
| Resource Locks | `ManagementLockClient.management_locks.list_at_subscription_level()` | `azure-resource-lock` |

**Data Collected:** Total events, failed operations, write operations, delete operations, individual event details (caller, timestamp, resource), lock level (CanNotDelete / ReadOnly).

---

### 7. Network Security

**File:** [`collectors/azure/network.py`](../AIAgent/app/collectors/azure/network.py) · **Priority:** 70

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| NSG Rules | `NetworkManagementClient.network_security_groups.list_all()` | `azure-nsg-rule` |
| Virtual Networks | `NetworkManagementClient.virtual_networks.list_all()` | `azure-virtual-network` |
| Storage Account Security | `StorageManagementClient.storage_accounts.list()` | `azure-storage-security` |

**Data Collected:**
- **NSG:** Direction, access, priority, source/destination address prefixes, port ranges, `IsAllowAnyInbound` flag for internet-exposed management ports
- **VNet:** Address space, subnet count, DDoS protection status
- **Storage:** HTTPS enforcement, TLS version, public blob access, shared key access, network firewall default action

---

### 8. Network Expanded

**File:** [`collectors/azure/network_expanded.py`](../AIAgent/app/collectors/azure/network_expanded.py) · **Priority:** 71

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Azure Firewalls | `NetworkManagementClient.azure_firewalls.list_all()` | `azure-firewall` |
| Route Tables | `NetworkManagementClient.route_tables.list_all()` | `azure-route-table` |
| NSG Flow Logs | `NetworkManagementClient.flow_logs.list()` | `azure-nsg-flow-log` |

**Data Collected:** Firewall threat intel mode, SKU tier, rule collection counts; default route to NVA, BGP propagation; flow log retention and enabled status.

---

### 9. Compute

**File:** [`collectors/azure/compute.py`](../AIAgent/app/collectors/azure/compute.py) · **Priority:** 100 · **Concurrency:** `asyncio.Semaphore(8)` for parallel VM extension fetch

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Virtual Machines | `ComputeManagementClient.virtual_machines.list_all()` | `azure-vm-config` |
| VM Extensions | `ComputeManagementClient.virtual_machine_extensions.list()` | (enriches `azure-vm-config`) |
| Web Apps | `WebSiteManagementClient.web_apps.list()` | `azure-webapp-config` |
| SQL Servers + AD Admin | `SqlManagementClient.servers.list()` / `.server_azure_ad_administrators.list_by_server()` | `azure-sql-server` |
| AKS Clusters | `ContainerServiceClient.managed_clusters.list()` | `azure-aks-cluster` |

**Data Collected:**
- **VMs:** Size, OS type, disk encryption (OS + data), managed identity, MDE extension (parallel `asyncio.gather` fetch per VM), boot diagnostics
- **Web Apps:** HTTPS only, TLS version, FTPS state, remote debugging, managed identity
- **SQL:** Azure AD admin configured, auditing, public network access, TLS version
- **AKS:** Kubernetes version, RBAC, AAD integration, network policy, private cluster, Defender

---

### 10. Monitoring

**File:** [`collectors/azure/monitoring.py`](../AIAgent/app/collectors/azure/monitoring.py) · **Priority:** 110

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Log Analytics Workspaces | `LogAnalyticsManagementClient.workspaces.list()` | `azure-log-analytics` |
| Metric Alert Rules | `MonitorManagementClient.metric_alerts.list_by_subscription()` | `azure-alert-rule` |
| Action Groups | `MonitorManagementClient.action_groups.list_by_subscription_id()` | `azure-action-group` |

**Data Collected:** Workspace retention days, SKU, alert severity/enabled status, action group receivers (email, SMS, webhook).

---

### 11. Security & Key Vault

**File:** [`collectors/azure/security.py`](../AIAgent/app/collectors/azure/security.py) · **Priority:** 60

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Key Vaults (mgmt plane) | `KeyVaultManagementClient.vaults.list_by_subscription()` | `azure-keyvault` |
| Managed Identities | `ResourceManagementClient.resources.list(filter=...)` | `azure-managed-identity` |
| Secrets (data plane) | `SecretClient.list_properties_of_secrets()` | `azure-keyvault-secret-expiry` |
| Certificates (data plane) | `CertificateClient.list_properties_of_certificates()` | `azure-keyvault-cert-expiry` |
| Keys (data plane) | `KeyClient.list_properties_of_keys()` | `azure-keyvault-key-expiry` |

**Data Collected:** Soft delete, purge protection, RBAC authorization, network ACL default action, managed identity count. **Data-plane expiry audit:** total count, expired count, expiring-within-30-days count per vault. Only metadata — never reads secret values.

---

### 12. Defender Basic

**File:** [`collectors/azure/defender_plans.py`](../AIAgent/app/collectors/azure/defender_plans.py) · **Priority:** 90

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Defender Pricing Plans | `SecurityCenter.pricings.list()` | `azure-defender-pricing` |
| Auto-Provisioning | `SecurityCenter.auto_provisioning_settings.list()` | `azure-auto-provisioning` |
| Security Contacts | `SecurityCenter.security_contacts.list()` | `azure-security-contact` |

**Data Collected:** Pricing tier (Free / Standard) per plan, auto-provisioning status, alert notification settings, security contact emails/phone.

---

### 13. Defender Advanced

**File:** [`collectors/azure/defender_advanced.py`](../AIAgent/app/collectors/azure/defender_advanced.py) · **Priority:** 91

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Secure Score | `SecurityCenter.secure_scores.list()` | `azure-secure-score` |
| Security Assessments | `SecurityCenter.assessments.list()` | `azure-security-assessment` |
| Regulatory Compliance | `SecurityCenter.regulatory_compliance_standards.list()` | `azure-regulatory-compliance` |
| JIT Access Policies | `SecurityCenter.jit_network_access_policies.list()` | `azure-jit-policy` |
| Security Alerts | `SecurityCenter.alerts.list()` | `azure-security-alert` |

**Data Collected:** Secure score percentage, unhealthy assessments, regulatory standard pass rates, JIT access policies, security alert severity distribution.

---

### 14. Sentinel

**File:** [`collectors/azure/sentinel.py`](../AIAgent/app/collectors/azure/sentinel.py) · **Priority:** 92

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Sentinel Workspaces | `SecurityInsights.operations.list()` | `azure-sentinel-workspace` |
| Data Connectors | `SecurityInsights.data_connectors.list()` | `azure-sentinel-connector` |
| Analytics Rules | `SecurityInsights.alert_rules.list()` | `azure-sentinel-rule` |
| Incidents | `SecurityInsights.incidents.list()` | `azure-sentinel-incident` |
| Automation Rules | `SecurityInsights.automation_rules.list()` | `azure-sentinel-automation` |
| Watchlists | `SecurityInsights.watchlists.list()` | `azure-sentinel-watchlist` |

**Data Collected:** Connector counts by type, analytics rules (enabled/disabled), incident severity distribution, automation rule counts, watchlist metadata.

---

### 15. Additional Services

**File:** [`collectors/azure/additional_services.py`](../AIAgent/app/collectors/azure/additional_services.py) · **Priority:** 120

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Private Endpoints | `NetworkManagementClient.private_endpoints.list_by_subscription()` | `azure-private-endpoint` |
| Recovery Vaults | `RecoveryServicesClient.vaults.list_by_subscription_id()` | `azure-recovery-vault` |
| Disk Encryption Sets | `ComputeManagementClient.disk_encryption_sets.list()` | `azure-disk-encryption-set` |

**Data Collected:** Private endpoint target resources, recovery vault encryption/immutability, disk encryption set key source.

---

### 16. AI Services

**File:** [`collectors/azure/ai_services.py`](../AIAgent/app/collectors/azure/ai_services.py) · **Priority:** 130

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Cognitive Services Accounts | `CognitiveServicesManagementClient.accounts.list()` | `azure-cognitive-account` |
| OpenAI Model Deployments | `CognitiveServicesManagementClient.deployments.list()` | `azure-ai-deployment` |
| ML Workspaces | `MachineLearningServicesMgmtClient.workspaces.list_by_subscription()` | `azure-ml-workspace` |

**Data Collected:** Account SKU, kind, public network access, custom subdomain, deployment model names and provisioning state, ML workspace encryption and identity settings.

---

### 17. Functions

**File:** [`collectors/azure/functions.py`](../AIAgent/app/collectors/azure/functions.py) · **Priority:** 135

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Function Apps | `WebSiteManagementClient.web_apps.list()` | `azure-function-app` |
| Function Details | `WebSiteManagementClient.web_apps.list_functions()` | `azure-function-detail` |
| Deployment Slots | `WebSiteManagementClient.web_apps.list_slots()` | `azure-function-slot` |

**Data Collected:** HTTPS enforcement, TLS version, managed identity, runtime stack, CORS settings, deployment slot configurations.

---

### 18. Storage

**File:** [`collectors/azure/storage.py`](../AIAgent/app/collectors/azure/storage.py) · **Priority:** 140

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Storage Accounts | `StorageManagementClient.storage_accounts.list()` | `azure-storage-account` |

**Data Collected:** Encryption services, infrastructure encryption, soft delete (blob + container), versioning, lifecycle management policies, access tier, replication type.

---

### 19. DNS

**File:** [`collectors/azure/dns.py`](../AIAgent/app/collectors/azure/dns.py) · **Priority:** 140

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| DNS Zones | `DnsManagementClient.zones.list()` | `azure-dns-zone` |
| Private DNS Zones | `PrivateDnsManagementClient.private_zones.list()` | `azure-private-dns-zone` |
| Traffic Manager Profiles | `TrafficManagerManagementClient.profiles.list_by_subscription()` | `azure-traffic-manager` |

**Data Collected:** Zone types, record set counts, Traffic Manager monitoring protocol (HTTP/HTTPS), routing methods.

---

### 20. Front Door & CDN

**File:** [`collectors/azure/frontdoor_cdn.py`](../AIAgent/app/collectors/azure/frontdoor_cdn.py) · **Priority:** 142

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Front Door | `FrontDoorManagementClient.front_doors.list()` | `azure-front-door` |
| WAF Policies | `FrontDoorManagementClient.policies.list_by_subscription()` | `azure-waf-policy` |
| CDN Profiles | `CdnManagementClient.profiles.list()` | `azure-cdn-profile` |
| CDN Endpoints | `CdnManagementClient.endpoints.list_by_profile()` | `azure-cdn-endpoint` |

**Data Collected:** WAF mode (Prevention/Detection), managed rule sets, custom rules, CDN origin security, HTTPS enforcement.

---

### 21. Messaging

**File:** [`collectors/azure/messaging.py`](../AIAgent/app/collectors/azure/messaging.py) · **Priority:** 145

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Service Bus Namespaces | `ServiceBusManagementClient.namespaces.list()` | `azure-servicebus-namespace` |
| Service Bus Queues | `ServiceBusManagementClient.queues.list_by_namespace()` | `azure-servicebus-queue` |
| Service Bus Topics | `ServiceBusManagementClient.topics.list_by_namespace()` | `azure-servicebus-topic` |
| Event Hub Namespaces | `EventHubManagementClient.namespaces.list()` | `azure-eventhub-namespace` |
| Event Hubs | `EventHubManagementClient.event_hubs.list_by_namespace()` | `azure-eventhub` |

**Data Collected:** TLS version, local auth disabled, public network access, private endpoints, Kafka support, auto-inflate.

---

### 22. Containers

**File:** [`collectors/azure/containers.py`](../AIAgent/app/collectors/azure/containers.py) · **Priority:** 150

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Container Registries | `ContainerRegistryManagementClient.registries.list()` | `azure-container-registry` |
| Container Apps | `ContainerAppsAPIClient.container_apps.list_by_subscription()` | `azure-container-app` |

**Data Collected:** Admin user enabled, public network access, content trust, zone redundancy, Container App ingress, managed identity.

---

### 23. Data Analytics

**File:** [`collectors/azure/data_analytics.py`](../AIAgent/app/collectors/azure/data_analytics.py) · **Priority:** 150

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Synapse Workspaces | `SynapseManagementClient.workspaces.list()` | `azure-synapse-workspace` |
| Data Factory | `DataFactoryManagementClient.factories.list()` | `azure-data-factory` |
| Databricks Workspaces | `AzureDatabricksManagementClient.workspaces.list_by_subscription()` | `azure-databricks-workspace` |

**Data Collected:** Managed VNet, public access, CMK encryption, managed identity, no-public-IP policy (Databricks), Spark/SQL pool types.

---

### 24. Redis / IoT / Logic

**File:** [`collectors/azure/redis_iot_logic.py`](../AIAgent/app/collectors/azure/redis_iot_logic.py) · **Priority:** 155

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Redis Cache | `RedisManagementClient.redis.list_by_subscription()` | `azure-redis-cache` |
| IoT Hub | `IotHubClient.iot_hub_resource.list_by_subscription()` | `azure-iot-hub` |
| Logic Apps | `LogicManagementClient.workflows.list_by_subscription()` | `azure-logic-app` |

**Data Collected:** TLS version, SSL enforcement, public access, private endpoints, shared access policies.

---

### 25. Databases

**File:** [`collectors/azure/databases.py`](../AIAgent/app/collectors/azure/databases.py) · **Priority:** 160

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| CosmosDB Accounts | `CosmosDBManagementClient.database_accounts.list()` | `azure-cosmosdb-account` |
| PostgreSQL Servers | `PostgreSQLManagementClient.servers.list()` | `azure-database-server` |
| MySQL Servers | `MySQLManagementClient.servers.list()` | `azure-database-server` |

**Data Collected:** Consistency policy, public network access, local auth, TLS version, VNet filtering, private endpoints, server version.

---

### 26. AKS Deep

**File:** [`collectors/azure/aks_in_cluster.py`](../AIAgent/app/collectors/azure/aks_in_cluster.py) · **Priority:** 160

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Cluster Config | `ContainerServiceClient.managed_clusters.list()` | `azure-aks-cluster-config` |
| Addon Profiles | (extracted from cluster) | `azure-aks-addon` |
| Node Pools | `ContainerServiceClient.agent_pools.list()` | `azure-aks-node-pool` |

**Data Collected:** RBAC, AAD profile, network policy, private cluster, authorized IPs, Defender for Containers, OIDC issuer, auto-upgrade channel, node pool FIPS, encryption at host.

---

### 27. Batch & ACI

**File:** [`collectors/azure/batch_aci.py`](../AIAgent/app/collectors/azure/batch_aci.py) · **Priority:** 165

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Batch Accounts | `BatchManagementClient.batch_account.list()` | `azure-batch-account` |
| Container Groups | `ContainerInstanceManagementClient.container_groups.list()` | `azure-container-instance` |

**Data Collected:** Pool allocation mode, encryption key source, authentication modes, container group OS type, IP address type, VNet integration.

---

### 28. Managed Disks

**File:** [`collectors/azure/managed_disks.py`](../AIAgent/app/collectors/azure/managed_disks.py) · **Priority:** 170

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Managed Disks | `ComputeManagementClient.disks.list()` | `azure-managed-disk` |
| Snapshots | `ComputeManagementClient.snapshots.list()` | `azure-snapshot` |
| Disk Encryption Sets | `ComputeManagementClient.disk_encryption_sets.list()` | `azure-disk-encryption-set` |

**Data Collected:** Encryption type, DES ID, network access policy, public network access, auto key rotation.

---

### 29. Purview / DLP

**File:** [`collectors/azure/purview_dlp.py`](../AIAgent/app/collectors/azure/purview_dlp.py) · **Priority:** 170

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Purview Accounts | `PurviewManagementClient.accounts.list_by_subscription()` | `azure-purview-account` |
| Sensitivity Labels | Graph `/informationProtection/policy/labels` | `m365-sensitivity-label` |
| DLP Sensitivity Labels | (enriched from above) | `m365-dlp-sensitivity-label` |

**Data Collected:** Purview public network, managed resource group, sensitivity label priorities and tooltips.

---

### 30. App Gateway

**File:** [`collectors/azure/app_gateway.py`](../AIAgent/app/collectors/azure/app_gateway.py) · **Priority:** 170

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Application Gateways | `NetworkManagementClient.application_gateways.list_all()` | `azure-app-gateway` |
| WAF Policies | `NetworkManagementClient.web_application_firewall_policies.list_all()` | `azure-waf-policy` |

**Data Collected:** WAF enabled, WAF mode, firewall policy association, SSL policies, listener protocols, backend pool health.

---

### 31. ML & Cognitive Extended

**File:** [`collectors/azure/ml_cognitive.py`](../AIAgent/app/collectors/azure/ml_cognitive.py) · **Priority:** 175

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| ML Workspaces | `MachineLearningServicesMgmtClient.workspaces.list_by_subscription()` | `azure-ml-workspace` |
| ML Compute | `MachineLearningServicesMgmtClient.compute.list()` | `azure-ml-compute` |
| Cognitive Accounts | `CognitiveServicesManagementClient.accounts.list()` | `azure-cognitive-account` |

**Data Collected:** HBI workspace, compute types, network ACLs, IP/VNet rules, private endpoint count, CMK.

---

### 32. API Management

**File:** [`collectors/azure/api_management.py`](../AIAgent/app/collectors/azure/api_management.py) · **Priority:** 180

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| APIM Instances | `ApiManagementClient.api_management_service.list()` | `azure-apim-instance` |

**Data Collected:** VNet type, public network access, platform version, publisher info, hostname configurations.

---

### 33. Arc & Hybrid

**File:** [`collectors/azure/arc_hybrid.py`](../AIAgent/app/collectors/azure/arc_hybrid.py) · **Priority:** 180

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Arc Servers | `HybridComputeManagementClient.machines.list_by_subscription()` | `azure-arc-server` |
| Arc Extensions | `HybridComputeManagementClient.machine_extensions.list()` | `azure-arc-extension` |
| Arc Kubernetes | `ResourceManagementClient.resources.list(filter=...)` | `azure-arc-kubernetes` |

**Data Collected:** Agent version, OS type/version, connectivity status, extension auto-upgrade, K8s distribution.

---

### 34. SharePoint / OneDrive

**File:** [`collectors/azure/sharepoint_onedrive.py`](../AIAgent/app/collectors/azure/sharepoint_onedrive.py) · **Priority:** 180 · **~366 lines** — complex multi-endpoint collector

| Resource Type | SDK / API Method | Evidence Type |
|---------------|-----------------|---------------|
| Site Inventory | Graph `/sites` | `spo-site-inventory` |
| Site Permissions | Graph `/sites/{id}/permissions` | `spo-site-permissions` |
| Sharing Links | Graph `/sites/{id}/drive/sharedWithMe` | `spo-sharing-links` |
| Tenant Sharing Config | SharePoint Admin REST | `spo-tenant-sharing-config` |
| Label Summary | (aggregated) | `spo-label-summary` |

**Data Collected:** Site count, external sharing level, anonymous link policy, default sharing scope, sensitivity label application per site, sharing link audit.

---

### 35. M365 Sensitivity Labels

**File:** [`collectors/azure/m365_sensitivity_labels.py`](../AIAgent/app/collectors/azure/m365_sensitivity_labels.py) · **Priority:** 182

| Resource Type | Graph API | Evidence Type |
|---------------|----------|---------------|
| Label Definitions | `GET /informationProtection/policy/labels` | `m365-sensitivity-label-definition` |
| Label Summary | (aggregated) | `m365-label-summary` |
| Label Policy Summary | (aggregated) | `m365-label-policy-summary` |
| DLP Label Integration | (cross-referenced) | `m365-dlp-label-integration` |

**Data Collected:** Label hierarchy, auto-labeling config, protection settings (encryption, watermark), parent/child relationships.

---

### 36. Backup & DR

**File:** [`collectors/azure/backup_dr.py`](../AIAgent/app/collectors/azure/backup_dr.py) · **Priority:** 185

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Recovery Vaults | `RecoveryServicesClient.vaults.list_by_subscription_id()` | `azure-recovery-vault` |
| Backup Policies | `RecoveryServicesBackupClient.backup_policies.list()` | `azure-backup-policy` |
| Backup Items | `RecoveryServicesBackupClient.backup_protected_items.list()` | `azure-backup-item` |

**Data Collected:** Vault encryption, immutability, soft delete, cross-region restore, storage redundancy, backup health status, last backup time.

---

### 37. Copilot Studio

**File:** [`collectors/azure/copilot_studio.py`](../AIAgent/app/collectors/azure/copilot_studio.py) · **Priority:** 185 · **~370 lines** — Power Platform REST API collector

| Resource Type | API Method | Evidence Type |
|---------------|-----------|---------------|
| Power Platform Environments | PP Admin REST | `pp-environment` |
| DLP Policies | PP Admin REST | `pp-dlp-policy` |
| Copilot Studio Bots | PP Admin REST | `copilot-studio-bot` |
| Custom Connectors | PP Admin REST | `pp-custom-connector` |
| M365 Copilot Settings | Graph | `m365-copilot-settings` |
| Audit Configuration | Graph | `m365-audit-config` |

**Data Collected:** Environment types, DLP policy connector groups, bot authentication settings, connector security, Copilot tenant settings, audit log status.

---

### 38. Foundry Config

**File:** [`collectors/azure/foundry_config.py`](../AIAgent/app/collectors/azure/foundry_config.py) · **Priority:** 188 · **~1,081 lines** — largest collector

| Evidence Type | Description |
|---------------|-------------|
| `azure-ai-service` | Foundry AI Services account |
| `foundry-project` | Foundry project configuration |
| `foundry-connection` | Project connections |
| `foundry-deployment` | Model deployments |
| `foundry-agent-application` | Agent applications |
| `foundry-capability-host` | Agent capability hosts |
| `foundry-data-source` | Data source configurations |
| `foundry-content-filter` | Content safety filter configs |
| `foundry-network-config` | Network isolation settings |
| `foundry-identity-config` | Identity & RBAC |
| `foundry-monitoring-config` | Logging & tracing |
| `foundry-secrets-config` | Secrets management |
| `foundry-model-catalog` | Available model catalog |
| `foundry-compute-config` | Compute settings |
| `foundry-evaluation-config` | Evaluation pipeline |
| `foundry-governance-summary` | Aggregated governance |

**Data Collected:** Full Foundry project topology: AI Services, projects, connections, deployments, agents, capability hosts, content filters, network isolation, identity config, monitoring, secrets, model catalog, evaluation pipelines.

---

### 39. Cost & Billing

**File:** [`collectors/azure/cost_billing.py`](../AIAgent/app/collectors/azure/cost_billing.py) · **Priority:** 190

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Budgets | `CostManagementClient.budgets.list()` | `azure-budget` |
| Advisor Recommendations | `AdvisorManagementClient.recommendations.list()` | `azure-advisor-cost-recommendation` |

**Data Collected:** Budget amount, time grain, current spend, notification thresholds, cost savings impact.

---

## Azure Resource Coverage — Data Plane (8 collectors)

Data-plane collectors use `plane="data"` registration and access resource-level APIs beyond ARM management.

### 40. Storage Data Plane

**File:** [`collectors/azure/storage_data_plane.py`](../AIAgent/app/collectors/azure/storage_data_plane.py) · **Priority:** 200

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Storage Containers | `BlobServiceClient.list_containers()` | `azure-storage-container` |

**Data Collected:** Container public access level, lease state, metadata, immutability policies.

---

### 41. SQL Detailed

**File:** [`collectors/azure/sql_detailed.py`](../AIAgent/app/collectors/azure/sql_detailed.py) · **Priority:** 210

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| SQL Vulnerability Assessment | `SqlManagementClient.database_vulnerability_assessments` | `azure-sql-detailed` |
| SQL Advanced Threat Protection | `SqlManagementClient.server_advanced_threat_protection_settings` | `azure-sql-detailed` |
| SQL TDE | `SqlManagementClient.transparent_data_encryptions` | `azure-sql-detailed` |
| SQL Auditing | `SqlManagementClient.server_blob_auditing_policies` | `azure-sql-detailed` |
| SQL Firewall Rules | `SqlManagementClient.firewall_rules.list_by_server()` | `azure-sql-detailed` |

**Data Collected:** VA scan enabled, ATP state, TDE status, audit destination, firewall allow-all-Azure flag.

---

### 42. AI Content Safety

**File:** [`collectors/azure/ai_content_safety.py`](../AIAgent/app/collectors/azure/ai_content_safety.py) · **Priority:** 210

| Resource Type | SDK / REST | Evidence Type |
|---------------|-----------|---------------|
| AI Deployment Safety | `CognitiveServicesManagementClient` + REST | `azure-ai-deployment-safety` |
| AI Governance | (aggregated per account) | `azure-ai-governance` |
| Content Safety Blocklists | REST `/contentsafety/text/blocklists` | `azure-content-safety-blocklist` |

**Data Collected:** Content filter presence per deployment, filter severity thresholds, blocklist names & term counts, public network access, local auth disabled.

---

### 43. CosmosDB Deep

**File:** [`collectors/azure/cosmosdb_data_plane.py`](../AIAgent/app/collectors/azure/cosmosdb_data_plane.py) · **Priority:** 215

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| CosmosDB Accounts | `CosmosDBManagementClient.database_accounts.list()` | `azure-cosmosdb-account` |
| Databases | `CosmosDBManagementClient.sql_resources.list_sql_databases()` | `azure-cosmosdb-database` |
| Containers | `CosmosDBManagementClient.sql_resources.list_sql_containers()` | `azure-cosmosdb-container` |
| RBAC Role Assignments | `CosmosDBManagementClient.sql_resources.list_sql_role_assignments()` | `azure-cosmosdb-role-assignment` |

**Data Collected:** Partition keys, indexing policies, TTL settings, unique key policies, throughput type, role assignment scopes, default consistency.

---

### 44. WebApp Detailed

**File:** [`collectors/azure/webapp_detailed.py`](../AIAgent/app/collectors/azure/webapp_detailed.py) · **Priority:** 220

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| Auth Settings | `WebSiteManagementClient.web_apps.get_auth_settings_v2()` | `azure-webapp-detailed` |
| IP Restrictions | `WebSiteManagementClient.web_apps.get_configuration()` | `azure-webapp-detailed` |
| CORS Settings | (extracted from config) | `azure-webapp-detailed` |

**Data Collected:** Authentication provider, client secret setting, IP restriction rules, CORS allowed origins, vNet route all enabled.

---

### 45. APIM Deep

**File:** [`collectors/azure/apim_data_plane.py`](../AIAgent/app/collectors/azure/apim_data_plane.py) · **Priority:** 220

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| APIM Services | `ApiManagementClient.api_management_service.list()` | `azure-apim-service` |
| APIs | `ApiManagementClient.api.list_by_service()` | `azure-apim-api` |
| Products | `ApiManagementClient.product.list_by_service()` | `azure-apim-product` |
| Subscriptions | `ApiManagementClient.subscription.list()` | `azure-apim-subscription` |
| Certificates | `ApiManagementClient.certificate.list_by_service()` | `azure-apim-certificate` |
| Named Values | `ApiManagementClient.named_value.list_by_service()` | `azure-apim-named-value` |
| Backends | `ApiManagementClient.backend.list_by_service()` | `azure-apim-backend` |

**Data Collected:** VNet type, client certificates, hostname configs, subscription requirements, Key Vault–backed secrets, backend URL patterns, certificate expiry.

---

### 46. RDBMS Detailed

**File:** [`collectors/azure/rdbms_detailed.py`](../AIAgent/app/collectors/azure/rdbms_detailed.py) · **Priority:** 230

| Resource Type | SDK Method | Evidence Type |
|---------------|-----------|---------------|
| PostgreSQL Firewall Rules | `PostgreSQLManagementClient.firewall_rules.list_by_server()` | `azure-database-config` |
| PostgreSQL Configuration | `PostgreSQLManagementClient.configurations.list_by_server()` | `azure-database-config` |
| MySQL Firewall Rules | `MySQLManagementClient.firewall_rules.list_by_server()` | `azure-database-config` |
| MySQL Configuration | `MySQLManagementClient.configurations.list_by_server()` | `azure-database-config` |

**Data Collected:** Firewall allow-all-Azure flag, SSL enforcement, connection throttling, log settings, configuration parameter audit.

---

### 47. ACR Data Plane

**File:** [`collectors/azure/acr_data_plane.py`](../AIAgent/app/collectors/azure/acr_data_plane.py) · **Priority:** 240

| Resource Type | SDK / REST | Evidence Type |
|---------------|-----------|---------------|
| ACR Repositories | REST `GET /acr/v1/_catalog` | `azure-acr-repository` |

**Data Collected:** Repository names, tag counts, manifest counts — repository-level audit for security scanning coverage.

---

## Standalone Collectors (not auto-registered)

These collectors are not registered in the assessment pipeline via `@register_collector`. They are invoked directly by specific tools and CLI scripts.

### `rbac_collector.py` — Hierarchical RBAC Tree

**File:** [`collectors/azure/rbac_collector.py`](../AIAgent/app/collectors/azure/rbac_collector.py) · **~983 lines**

**6-phase collection pipeline:**

| Phase | Operation |
|-------|-----------|
| 1 | Build management group → subscription hierarchy |
| 2 | Enumerate resource groups per subscription |
| 3 | Collect all role assignments across scopes |
| 4 | Batch principal resolution (1,000 at a time via Graph `$batch`) |
| 5 | PIM eligibility schedule collection |
| 6 | Group membership expansion for nested group assignments |

**19 privileged role names** tracked (identical to `rbac.py`). Produces structured data consumed by [`rbac_report.py`](../AIAgent/app/reports/rbac_report.py) for interactive HTML output.

---

### `ai_identity.py` — AI Identity Enrichment

**File:** [`collectors/entra/ai_identity.py`](../AIAgent/app/collectors/entra/ai_identity.py) · **~419 lines**

| Evidence Type | Description |
|---------------|-------------|
| `entra-ai-service-principal` | Filtered + enriched AI-related service principals |
| `entra-ai-consent-grant` | OAuth consent grants to AI applications |
| `entra-cross-tenant-policy` | Cross-tenant access posture for AI services |

Identifies AI-related apps by matching against **7 well-known Microsoft AI application IDs** (`_AI_APP_IDS`) and display-name patterns (`_AI_NAME_PATTERNS`: openai, copilot, foundry, cognitive, etc.).

---

## Microsoft Entra ID Resource Coverage (18 collectors)

12 registered collectors in [`collectors/entra/`](../AIAgent/app/collectors/entra/) + 5 registered M365 compliance collectors (in [`collectors/azure/m365_compliance.py`](../AIAgent/app/collectors/azure/m365_compliance.py), registered with `source="entra"`) + 1 standalone (`ai_identity.py`).

### 1. Tenant

**File:** [`collectors/entra/tenant.py`](../AIAgent/app/collectors/entra/tenant.py) · **Priority:** 10

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /organization` | `entra-tenant-info` |

**Data Collected:** Tenant ID, display name, verified domains, license plans (P1/P2 detection), on-premises sync status, technical notification emails.

---

### 2. Users

**File:** [`collectors/entra/users.py`](../AIAgent/app/collectors/entra/users.py) · **Priority:** 20

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /users` | `entra-user-summary` |
| `GET /groups` | `entra-group-summary` |

**Data Collected:** Total users, member vs. guest, synced, enabled/disabled, guest-to-member ratio, group counts by type.

---

### 3. User Details + MFA

**File:** [`collectors/entra/user_details.py`](../AIAgent/app/collectors/entra/user_details.py) · **Priority:** 30 — custom pagination with sample limit

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /users` (with `$select=signInActivity`) | `entra-user-detail`, `entra-user-lifecycle-summary` |
| `GET /reports/authenticationMethods/userRegistrationDetails` | `entra-mfa-registration`, `entra-mfa-summary` |
| `GET /oauth2PermissionGrants` | `entra-oauth2-grant` |

**Data Collected:**
- **Per-User:** Stale status (90-day threshold), never-signed-in, last sign-in date, on-prem sync, admin status
- **MFA:** Per-user MFA registered, passwordless capable, SSPR registered, default MFA method
- **OAuth2:** Client ID, consent type, granted scopes, principal ID

---

### 4. Conditional Access

**File:** [`collectors/entra/conditional_access.py`](../AIAgent/app/collectors/entra/conditional_access.py) · **Priority:** 40

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /identity/conditionalAccess/policies` | `entra-conditional-access-policy` |

**Data Collected:** State (enabled/disabled/report-only), MFA requirement, device compliance requirement, target users/groups/roles, grant/session controls.

---

### 5. Roles & PIM

**File:** [`collectors/entra/roles.py`](../AIAgent/app/collectors/entra/roles.py) · **Priority:** 50

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /roleManagement/directory/roleDefinitions` | `entra-role-definition` |
| `GET /roleManagement/directory/roleAssignments` | `entra-role-assignment` |
| `GET /roleManagement/directory/roleEligibilityScheduleInstances` | `entra-pim-eligible-assignment` |
| `GET /directoryRoles/{id}/members` | `entra-directory-role-member` |

**Data Collected:** Active + eligible role assignments, role names, principal types, PIM eligibility duration.

---

### 6. Applications

**File:** [`collectors/entra/applications.py`](../AIAgent/app/collectors/entra/applications.py) · **Priority:** 60

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /applications` | `entra-application` |
| `GET /servicePrincipals` | `entra-service-principal` |

**Data Collected:** Sign-in audience, credential counts (password + key), expired/expiring credentials, multi-tenant status, SP type, account enabled status.

---

### 7. Workload Identity

**File:** [`collectors/entra/workload_identity.py`](../AIAgent/app/collectors/entra/workload_identity.py) · **Priority:** 65

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /applications/{id}/federatedIdentityCredentials` | `entra-federated-credential` |
| `GET /servicePrincipals` (filtered) | `entra-managed-identity-sp` |
| (computed) | `entra-workload-credential-review` |

**Data Collected:** Federated credential issuer, subject, audiences; managed identity SP status; apps using password vs. federation.

---

### 8. Risk Policies

**File:** [`collectors/entra/risk_policies.py`](../AIAgent/app/collectors/entra/risk_policies.py) · **Priority:** 66

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /identity/conditionalAccess/namedLocations` | `entra-named-location` |
| `GET /policies/authenticationMethodsPolicy` | `entra-auth-methods-policy` |
| `GET /policies/authenticationStrengthPolicies` | `entra-auth-strength-policy` |

**Data Collected:** Named location trust settings, enabled auth methods, custom auth strength policies.

---

### 9. Security Policies

**File:** [`collectors/entra/security_policies.py`](../AIAgent/app/collectors/entra/security_policies.py) · **Priority:** 70

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /policies/identitySecurityDefaultsEnforcementPolicy` | `entra-security-defaults` |
| `GET /policies/authorizationPolicy` | `entra-authorization-policy` |
| `GET /policies/crossTenantAccessPolicy` | `entra-cross-tenant-policy` |
| `GET /policies/crossTenantAccessPolicy/partners` | `entra-cross-tenant-partner` |
| `GET /policies/authenticationMethodsPolicy` | `entra-auth-method-config` |

**Data Collected:** Security defaults enabled, MSOL PowerShell blocked, guest user role, invitation restrictions, cross-tenant allowed cloud endpoints, partner trust settings.

---

### 10. Governance

**File:** [`collectors/entra/governance.py`](../AIAgent/app/collectors/entra/governance.py) · **Priority:** 80

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /policies/roleManagementPolicies` | `entra-pim-policy` |
| `GET /policies/roleManagementPolicies/{id}/rules` | `entra-pim-policy-rule` |
| `GET /identityGovernance/accessReviews/definitions` | `entra-access-review` |
| `GET /identityGovernance/entitlementManagement/accessPackages` | `entra-access-package` |
| `GET /identityGovernance/termsOfUse/agreements` | `entra-terms-of-use` |

**Data Collected:** PIM activation duration, MFA requirement for activation, access review scope/status, access package visibility, terms of use acceptance requirements.

---

### 11. Identity Protection

**File:** [`collectors/entra/identity_protection.py`](../AIAgent/app/collectors/entra/identity_protection.py) · **Priority:** 90

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /identityProtection/riskyUsers` | `entra-risky-user` |
| `GET /identityProtection/riskyServicePrincipals` | `entra-risky-service-principal` |
| `GET /identityProtection/riskDetections` | `entra-risk-detection`, `entra-risk-summary` |

**Data Collected:** Risk level (high/medium/low), risk state, compromised status, risk event type, IP address, detection timestamps. Requires Entra ID P2 license.

---

### 12. Audit Logs

**File:** [`collectors/entra/audit_logs.py`](../AIAgent/app/collectors/entra/audit_logs.py) · **Priority:** 100

| Graph API Endpoint | Evidence Type |
|-------------------|---------------|
| `GET /auditLogs/signIns` (30 days) | `entra-signin-summary` |
| `GET /auditLogs/directoryAudits` | `entra-directory-audit-summary` |

**Data Collected:** Total sign-ins, failure rate, CA-blocked sign-ins, MFA success rate, risk sign-ins, audit categories breakdown. Requires Entra ID P1/P2 license.

---

### 13–17. M365 Compliance (5 registered collectors)

**File:** [`collectors/azure/m365_compliance.py`](../AIAgent/app/collectors/azure/m365_compliance.py) — registered with `source="entra"`, collecting via Graph beta APIs

| # | Collector Name | Evidence Types |
|---|---------------|----------------|
| 13 | `m365_retention` | `m365-retention-label`, `m365-retention-summary` |
| 14 | `m365_label_analytics` | `m365-label-analytics`, `m365-label-usage-summary` |
| 15 | `m365_dlp_alerts` | `m365-dlp-alert`, `m365-dlp-alert-summary` |
| 16 | `m365_insider_risk` | `m365-insider-risk-policy`, `m365-insider-risk-summary` |
| 17 | `m365_ediscovery` | `m365-ediscovery-case`, `m365-ediscovery-summary` |

**Data Collected:** Retention labels/policies, data classification usage, DLP alert trends, insider risk policy state, eDiscovery case inventory.

---

## Compliance Evaluation Capabilities

### Frameworks Supported

All frameworks are loaded from JSON mapping files in [`AIAgent/app/postureiq_frameworks/`](../AIAgent/app/postureiq_frameworks/). Each mapping file defines controls with `evaluation_logic` keys that dispatch to check functions.

| Framework | Controls | Mapping File |
|-----------|----------|-------------|
| NIST 800-53 | 83 | `nist-800-53-mappings.json` |
| FedRAMP | 69 | `fedramp-mappings.json` |
| CIS Benchmarks | 53 | `cis-mappings.json` |
| MCSB | 53 | `mcsb-mappings.json` |
| PCI DSS | 51 | `pci-dss-mappings.json` |
| ISO 27001 | 51 | `iso-27001-mappings.json` |
| SOC 2 | 47 | `soc2-mappings.json` |
| HIPAA | 43 | `hipaa-mappings.json` |
| NIST CSF | 29 | `nist-csf-mappings.json` |
| CSA CCM | 24 | `csa-ccm-mappings.json` |
| GDPR | 22 | `gdpr-mappings.json` |
| **Total** | **525** | |

### Evaluation Domain Summary

10 evaluation domains are defined in [`postureiq_evaluators/engine.py → DOMAIN_EVALUATORS`](../AIAgent/app/postureiq_evaluators/engine.py):

| Domain | Evaluator Module | Check Functions | Key Compliance Areas |
|--------|-----------------|----------------|---------------------|
| **Access Control** | `access.py` | 7 | Privileged access separation, least privilege, conditional access enforcement, custom owner roles, account management, managed identity hygiene, session management |
| **Identity & Authentication** | `identity.py` | 19 | Centralized identity, MFA coverage, app credentials, user lifecycle, guest review, risky users, OAuth2 consent, cross-tenant access, workload identity, auth methods, legacy auth blocking, service principal hygiene, named locations |
| **Data Protection** | `data_protection.py` | 23 | Encryption in transit/at rest, Key Vault security + expiry, VM/WebApp/SQL/AKS hardening, CMK, storage containers, SQL detailed, RDBMS config, Functions, messaging, Redis, CosmosDB advanced, analytics, Purview classification |
| **Logging & Monitoring** | `logging_eval.py` | 11 | Diagnostic coverage, threat detection, NSG flow logs, activity analysis, sign-in monitoring, audit logging, monitoring coverage, log retention, alert response |
| **Network Security** | `network.py` | 16 | Network segmentation, NSG rule analysis (RDP/SSH), storage firewalls, Azure Firewall, route tables, ML network, App Gateway, WAF, container apps, APIM, WebApp detailed, ACR repos, DNS, AKS advanced, APIM advanced, Front Door/CDN |
| **Governance** | `governance.py` | 19 | Policy compliance, Defender plans, resource locks, PIM, access reviews, vulnerability scanning, AI content safety, regulatory compliance, backup recovery, AI governance, security awareness |
| **Incident Response** | `incident_response.py` | 6 | Security contacts, incident detection, alerting, investigation readiness, Sentinel monitoring, alert response coverage |
| **Change Management** | `change_management.py` | 4 | Change control policies, resource lock governance, change tracking, policy enforcement |
| **Business Continuity** | `business_continuity.py` | 4 | Backup configuration, geo-redundancy, VM availability, database resilience |
| **Asset Management** | `asset_management.py` | 4 | Asset inventory, classification tagging, authorized software, application inventory |
| **Total** | | **~113–120** | |

Scoring uses severity-weighted compliance with partial credit: `_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}`.

---

## Required Permissions — Complete Reference

### Azure RBAC Roles

| Role | Scope | Purpose |
|------|-------|---------|
| **Reader** | Subscription | All ARM resource enumeration and configuration reads |
| **Security Reader** | Subscription | Defender plans, secure score, security contacts, auto-provisioning, assessments |
| **Key Vault Secrets User** | Key Vault | Secret expiry data-plane audit |
| **Key Vault Certificates Officer** | Key Vault | Certificate expiry data-plane audit |
| **Key Vault Crypto User** | Key Vault | Key expiry data-plane audit |

### Microsoft Graph API Permissions (Application or Delegated)

| Permission | Purpose |
|-----------|---------|
| `Directory.Read.All` | Tenant info, OAuth2 grants, directory roles |
| `User.Read.All` | Users, group membership, sign-in activity |
| `Group.Read.All` | Groups |
| `Application.Read.All` | App registrations, service principals, federated credentials |
| `RoleManagement.Read.All` | Role assignments, definitions, PIM eligibility, PIM policies |
| `Policy.Read.All` | CA policies, security defaults, auth policy, cross-tenant policy, named locations, auth methods |
| `AuditLog.Read.All` | Sign-in logs, directory audits, sign-in activity on user objects |
| `UserAuthenticationMethod.Read.All` | MFA registration details |
| `IdentityRiskEvent.Read.All` | Risk detections |
| `IdentityRiskyUser.Read.All` | Risky users |
| `IdentityRiskyServicePrincipal.Read.All` | Risky service principals |
| `AccessReview.Read.All` | Access review definitions |
| `EntitlementManagement.Read.All` | Access packages |
| `Agreement.Read.All` | Terms of use |
| `InformationProtection.Read` | Sensitivity labels (Purview / MIP) |

---

## Safety Guarantees

- **All operations are strictly read-only** — no PUT, POST, PATCH, DELETE calls
- Azure SDK methods are exclusively `list()` and `get()` operations
- Graph API calls are exclusively `GET` requests
- No resource state is modified, created, or deleted
- No secret values are read — only metadata (expiry dates, counts)
- PII is summarized (counts, rates) not exported in full
