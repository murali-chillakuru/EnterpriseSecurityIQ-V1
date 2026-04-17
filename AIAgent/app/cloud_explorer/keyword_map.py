"""Cloud Explorer keyword → template mapping.

Maps natural-language keywords to ARG template names and Entra query types.
Used by the Cloud Explorer dispatcher for step-3 keyword matching.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# ARG keyword map  (keyword list → template name)
# ---------------------------------------------------------------------------

NL_ARG_MAP: list[tuple[list[str], str]] = [
    (["public ip", "public address", "exposed ip"], "public_ips"),
    (["vm without encryption", "unencrypted vm", "disk encryption"], "vms_without_disk_encryption"),
    (["vm", "virtual machine"], "all_vms"),
    (["storage", "blob", "public access", "public blob", "storage account"], "storage_public_access"),
    (["nsg", "network security", "open port", "inbound rule", "exposed port"], "nsg_open_rules"),
    (["sql server", "database server"], "sql_servers"),
    (["sql database", "sql db", "sql audit"], "sql_databases_detailed"),
    (["sql firewall"], "sql_firewall_rules"),
    (["key vault", "keyvault"], "keyvault_detailed"),
    (["aks", "kubernetes", "k8s"], "aks_clusters"),
    (["unattached disk", "orphaned disk", "unused disk"], "unattached_disks"),
    (["resource count", "how many resource", "resource summary"], "resource_counts_by_type"),
    (["location", "region", "where are"], "resources_by_location"),
    (["all resource", "list resource", "inventory"], "all_resources"),
    (["web app", "app service", "webapp"], "webapp_detailed"),
    (["function app", "functionapp", "azure function"], "function_apps"),
    (["cosmos", "cosmosdb", "documentdb"], "cosmosdb"),
    (["postgres", "mysql", "postgresql"], "postgres_mysql"),
    (["container registry", "acr", "registry"], "container_registries"),
    (["vnet", "virtual network", "subnet"], "vnets_subnets"),
    (["private endpoint", "private link"], "private_endpoints"),
    (["diagnostic setting", "diagnostics", "monitoring config"], "diagnostic_settings"),
    (["managed identity", "user assigned identity", "system assigned identity"], "managed_identities"),
    (["openai", "cognitive", "ai service", "machine learning", "ml workspace"], "ai_services"),
    (["api management", "apim"], "apim"),
    (["firewall", "azure firewall"], "firewalls"),
    (["load balancer", "lb"], "load_balancers"),
    (["redis", "cache"], "redis"),
    (["application gateway", "app gateway", "waf"], "app_gateways"),
    (["policy compliance", "non-compliant policy", "policy violation"], "policy_compliance"),
    (["defender plan", "defender status", "security pricing"], "defender_plans"),
    (["tag", "tagging", "tags"], "tags_search"),
    (["untagged", "no tag", "missing tag"], "untagged_resources"),
    # ── v49 keyword mappings ──
    (["subscription", "list subscription"], "subscriptions"),
    (["resource group", "rg", "list rg"], "resource_groups"),
    (["resource per subscription", "count per subscription", "resources by subscription"], "resource_counts_by_subscription"),
    (["management group", "mg hierarchy"], "management_groups"),
    (["role assignment", "rbac assignment"], "role_assignments"),
    (["security recommendation", "defender recommendation", "unhealthy assessment"], "security_recommendations"),
    (["secure score", "security score"], "secure_score"),
    (["log analytics", "la workspace", "workspace"], "log_analytics_workspaces"),
    (["alert rule", "metric alert", "activity alert"], "alert_rules"),
    (["container app", "containerapp"], "container_apps"),
    (["event hub", "eventhub"], "event_hubs"),
    (["service bus", "servicebus"], "service_bus"),
    (["backup vault", "recovery vault", "backup"], "backup_vaults"),
    (["openai deployment", "azure openai", "ai model"], "openai_deployments"),
    (["ml workspace", "machine learning workspace", "foundry", "ai hub", "ai project"], "ml_workspaces"),
    (["policy assignment", "assigned policy"], "policy_assignments"),
    (["resource lock", "lock", "delete lock"], "resource_locks"),
    (["nic", "network interface"], "network_interfaces"),
    (["route table", "udr", "user defined route"], "route_tables"),
    (["sentinel", "siem", "security insight"], "sentinel_workspaces"),
    (["purview", "data governance"], "purview_accounts"),
    # ── v53 composite queries ──
    (["hierarchy", "tree", "full tree", "mg tree", "tenant tree",
     "management group tree", "all the way down", "subscription tree"], "hierarchy_tree"),
    (["security snapshot", "security posture", "exposure summary",
     "what is exposed", "security overview"], "security_snapshot"),
    (["drill down", "deep inventory", "all resources by subscription",
     "full inventory", "resource drill"], "resource_drill_down"),
    # ── v54 — Compute & VM Scale Sets ──
    (["vmss", "scale set", "virtual machine scale set"], "vmss"),
    (["dedicated host", "host group", "isolated vm"], "dedicated_hosts"),
    (["availability set"], "availability_sets"),
    (["disk", "managed disk", "disk overview", "all disks"], "disk_overview"),
    (["vm extension", "extension"], "vm_extensions"),
    (["image", "snapshot", "vm image", "disk snapshot"], "images_snapshots"),
    # ── v54 — Networking (Advanced) ──
    (["front door", "frontdoor", "afd"], "front_door"),
    (["expressroute", "express route"], "expressroute"),
    (["vpn gateway", "virtual network gateway", "vpn"], "vpn_gateways"),
    (["bastion", "bastion host"], "bastion_hosts"),
    (["ddos", "ddos protection", "ddos plan"], "ddos_protection"),
    (["virtual wan", "vwan", "vhub", "virtual hub"], "virtual_wan"),
    (["dns zone", "dns", "private dns"], "dns_zones"),
    (["traffic manager", "traffic routing"], "traffic_manager"),
    (["nat gateway"], "nat_gateways"),
    (["network watcher"], "network_watchers"),
    (["nsg flow log", "flow log"], "nsg_flow_logs"),
    (["ip group"], "ip_groups"),
    (["vnet peering", "peering"], "peerings"),
    # ── v54 — Integration & Messaging ──
    (["logic app", "workflow"], "logic_apps"),
    (["event grid", "eventgrid"], "event_grid"),
    (["relay", "relay namespace"], "relay_namespaces"),
    (["notification hub", "push notification"], "notification_hubs"),
    (["signalr", "web pubsub"], "signalr"),
    # ── v54 — Containers ──
    (["container instance", "aci", "container group"], "container_instances"),
    (["aro", "openshift", "red hat openshift"], "aro_clusters"),
    # ── v54 — Databases (Extended) ──
    (["sql managed instance", "sql mi", "managed instance"], "sql_managed_instances"),
    (["mariadb", "maria"], "mariadb"),
    (["elastic pool", "sql pool"], "elastic_pools"),
    (["sql vm", "sql virtual machine", "sql on vm"], "sql_virtual_machines"),
    # ── v54 — Big Data & Analytics ──
    (["synapse", "synapse workspace"], "synapse"),
    (["data factory", "adf", "pipeline factory"], "data_factory"),
    (["databricks", "spark workspace"], "databricks"),
    (["data explorer", "kusto", "adx"], "data_explorer"),
    (["stream analytics", "streaming job"], "stream_analytics"),
    (["hdinsight", "hdi", "hadoop"], "hdinsight"),
    (["analysis services", "ssas"], "analysis_services"),
    (["power bi", "power bi embedded"], "power_bi_embedded"),
    # ── v54 — IoT ──
    (["iot hub", "iothub"], "iot_hubs"),
    (["iot central"], "iot_central"),
    (["device provisioning", "iot dps"], "iot_dps"),
    (["digital twin", "digital twins"], "digital_twins"),
    # ── v54 — Hybrid & Migration ──
    (["arc server", "azure arc", "hybrid server", "arc machine"], "arc_servers"),
    (["arc kubernetes", "arc k8s", "connected cluster"], "arc_kubernetes"),
    (["site recovery", "asr", "disaster recovery"], "site_recovery"),
    (["migrate project", "migration", "assessment project"], "migrate_projects"),
    (["stack hci", "azure stack", "hci"], "stack_hci"),
    # ── v54 — Developer & DevOps ──
    (["devtest lab", "lab"], "devtest_labs"),
    (["devops pipeline", "azure devops"], "devops_pipelines"),
    (["dev center", "devcenter", "dev box"], "dev_center"),
    (["load testing", "load test"], "load_testing"),
    (["grafana", "managed grafana"], "managed_grafana"),
    (["prometheus", "managed prometheus", "azure monitor metrics"], "managed_prometheus"),
    # ── v54 — Security (Advanced) ──
    (["auto provisioning", "defender provisioning"], "defender_auto_provisioning"),
    (["unhealthy assessment", "defender assessment", "security assessment"], "defender_assessments"),
    (["security alert", "defender alert", "active alert"], "defender_alerts"),
    (["regulatory compliance", "compliance standard"], "regulatory_compliance"),
    (["jit", "just in time", "jit access", "jit policy"], "jit_policies"),
    (["adaptive application", "app control", "application whitelist"], "adaptive_app_controls"),
    # ── v54 — Storage (Extended) ──
    (["storage account detail", "all storage accounts"], "storage_accounts"),
    (["data lake", "adls", "data lake store"], "data_lake_stores"),
    (["file share", "azure files"], "file_shares"),
    (["disk encryption detail", "encryption disk"], "managed_disks_encryption"),
    (["netapp", "azure netapp", "netapp files"], "netapp_accounts"),
    # ── v54 — Identity & Governance ──
    (["custom role", "custom rbac role"], "custom_roles"),
    (["deny assignment"], "deny_assignments"),
    (["blueprint", "blueprint assignment"], "blueprint_assignments"),
    (["policy exemption", "exemption"], "policy_exemptions"),
    (["custom policy", "custom policy definition"], "policy_definitions_custom"),
    # ── v54 — App Platform (Extended) ──
    (["static web app", "swa", "static site"], "static_web_apps"),
    (["app service plan", "server farm"], "app_service_plans"),
    (["app service environment", "ase"], "app_service_environments"),
    (["spring app", "azure spring"], "spring_apps"),
    (["app configuration", "app config"], "app_configuration"),
    # ── v54 — Media & CDN ──
    (["cdn", "content delivery"], "cdn_profiles"),
    (["media service", "media services"], "media_services"),
    (["communication service", "acs", "azure communication"], "communication_services"),
    # ── v54 — Search & Maps ──
    (["ai search", "search service", "cognitive search"], "search_services"),
    (["maps", "azure maps"], "maps_accounts"),
    # ── v54 — Blockchain & Confidential ──
    (["confidential ledger", "ledger"], "confidential_ledger"),
    (["managed hsm", "hardware security module", "hsm"], "managed_hsm"),
    # ── v54 — Automation & Management ──
    (["automation account", "runbook"], "automation_accounts"),
    (["maintenance config", "maintenance window"], "maintenance_configs"),
    (["update manager", "patch assessment", "os update"], "update_manager"),
    (["action group", "alert action"], "action_groups"),
    (["service health", "health event", "outage"], "service_health"),
    # ── v54 — Cost & Advisor ──
    (["advisor", "recommendation", "advisor recommendation"], "advisor_recommendations"),
    (["cost recommendation", "cost saving", "advisor cost"], "advisor_cost_recommendations"),
    # ── v54 — Compliance & Guest Config ──
    (["guest configuration", "guest config", "policy guest"], "guest_configuration"),
    # ── v54 — Batch & HPC ──
    (["batch account", "batch"], "batch_accounts"),
    # ── v54 — Miscellaneous ──
    (["managed environment", "container app environment"], "managed_environments"),
    (["chaos experiment", "chaos engineering"], "chaos_experiments"),
    (["health model", "workload monitor"], "health_models"),
    (["cost export", "export schedule"], "cost_exports"),
    (["budget", "spending budget"], "budgets"),
]

# ---------------------------------------------------------------------------
# Entra keyword map  (keyword list → Entra query type)
# ---------------------------------------------------------------------------

NL_ENTRA_MAP: list[tuple[list[str], str]] = [
    (["disabled user", "inactive user", "blocked user"], "disabled_users"),
    (["guest", "external user", "b2b"], "guest_users"),
    # v50 — "admin users" flat view must come BEFORE "directory_roles" so
    # queries like "users with admin roles" get the user-centric table
    (["admin user", "administrative role", "users with role", "users who has",
     "users who have", "who has admin", "who have admin", "list admin",
     "all admin", "users with admin", "privileged user"], "admin_users"),
    (["global admin", "admin role", "privileged role", "directory role"], "directory_roles"),
    (["conditional access", "ca policy"], "conditional_access"),
    (["app registration", "application"], "apps"),
    (["service principal", "enterprise app"], "service_principals"),
    (["entra group", "security group", "m365 group", "microsoft 365 group",
     "distribution group", "list group", "all group", "show group"], "groups"),
    (["stale user", "dormant", "not signed in"], "stale_users"),
    (["risky user", "risk level", "identity protection", "at risk user"], "risky_users"),
    (["named location", "trusted location", "ip range"], "named_locations"),
    (["auth method", "authentication method", "passwordless", "fido", "authenticator"], "auth_methods"),
    (["pim", "eligible role", "privileged identity", "just-in-time"], "pim_eligible"),
    (["user", "all user", "list user"], "users"),
    # ── v49 Entra entries ──
    (["organization", "tenant info", "tenant detail", "license", "domain", "verified domain"], "organization_info"),
    (["security default", "security defaults"], "security_defaults"),
    (["risk detection", "risk event", "sign-in risk"], "risk_detections"),
    (["risky service principal", "risky sp", "risky app"], "risky_service_principals"),
    (["access review", "review"], "access_reviews"),
    (["consent grant", "oauth grant", "permission grant", "delegated permission"], "consent_grants"),
    (["federated credential", "workload identity", "federated identity"], "federated_credentials"),
    (["cross tenant", "cross-tenant", "external collaboration", "b2b policy"], "cross_tenant_access"),
    (["sharepoint", "spo site", "sharepoint site"], "sharepoint_sites"),
    (["sensitivity label", "classification label", "information protection"], "sensitivity_labels"),
    (["dlp policy", "data loss prevention"], "dlp_policies"),
]
