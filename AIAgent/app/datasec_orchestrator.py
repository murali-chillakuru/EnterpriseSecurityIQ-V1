"""
Data Security Assessment Orchestrator.

Coordinates evidence collection, evaluator invocation, and result aggregation.
Mirrors the PostureIQ orchestrator pattern.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from app.auth import ComplianceCredentials
from app.datasec_evaluators.finding import ds_finding as _ds_finding, DS_FINDING_NS as _DS_FINDING_NS, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS
from app.datasec_evaluators.scoring import compute_data_security_scores, compute_trend_analysis
from app.datasec_evaluators.enrichment import (
    enrich_compliance_mapping,
    enrich_per_resource_details,
    compute_remediation_impact,
    consolidate_findings,
)
from app.datasec_evaluators.storage import analyze_storage_exposure
from app.datasec_evaluators.database import analyze_database_security
from app.datasec_evaluators.cosmosdb import analyze_cosmosdb_security
from app.datasec_evaluators.postgres_mysql import analyze_postgres_mysql_security
from app.datasec_evaluators.keyvault import analyze_keyvault_hygiene
from app.datasec_evaluators.encryption import analyze_encryption_posture
from app.datasec_evaluators.data_access import analyze_data_access_controls
from app.datasec_evaluators.private_endpoints import analyze_private_endpoints
from app.datasec_evaluators.purview import analyze_purview_security
from app.datasec_evaluators.file_sync import analyze_file_sync_security
from app.datasec_evaluators.m365_dlp import analyze_m365_dlp
from app.datasec_evaluators.data_classification import analyze_data_classification_security
from app.datasec_evaluators.backup_dr import analyze_backup_dr
from app.datasec_evaluators.containers import analyze_container_security
from app.datasec_evaluators.network_segmentation import analyze_network_segmentation
from app.datasec_evaluators.data_residency import analyze_data_residency
from app.datasec_evaluators.threat_detection import analyze_threat_detection
from app.datasec_evaluators.sharepoint import analyze_sharepoint_governance
from app.datasec_evaluators.m365_lifecycle import analyze_m365_data_lifecycle
from app.datasec_evaluators.dlp_alerts import analyze_dlp_alert_effectiveness
from app.datasec_evaluators.redis import analyze_redis_security
from app.datasec_evaluators.messaging import analyze_messaging_security
from app.datasec_evaluators.ai_services import analyze_ai_services_security
from app.datasec_evaluators.data_factory import analyze_data_factory_security
from app.datasec_evaluators.managed_identity import analyze_managed_identity_deep
from app.datasec_evaluators.platform_services import (
    analyze_sql_mi_security,
    analyze_app_config_security,
    analyze_cert_lifecycle,
    analyze_databricks_security,
    analyze_apim_security,
    analyze_frontdoor_security,
    analyze_secret_sprawl,
    analyze_firewall_appgw_security,
    analyze_bastion_security,
    analyze_policy_compliance,
    analyze_defender_score,
)
from app.datasec_evaluators.identity_access import (
    analyze_stale_permissions,
    analyze_data_exfiltration,
    analyze_conditional_access_pim,
)
from app.datasec_evaluators.advanced_analytics import (
    analyze_blast_radius,
    analyze_data_flow,
    analyze_config_drift,
    analyze_supply_chain_risk,
)
from app.logger import log

async def run_data_security_assessment(
    creds: ComplianceCredentials,
    evidence: list[dict] | None = None,
    subscriptions: list[dict] | None = None,
) -> dict:
    """Run complete data-security assessment.

    Reuses evidence from a prior compliance assessment if provided;
    otherwise collects lightweight data via ARG + ARM enrichment.
    """
    if subscriptions is None:
        subscriptions = await creds.list_subscriptions()

    evidence_index: dict[str, list[dict]] = {}
    if evidence:
        for ev in evidence:
            etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
            if etype:
                evidence_index.setdefault(etype, []).append(ev)

    has_evidence = bool(evidence_index)
    if not has_evidence:
        log.info("No existing evidence — running lightweight ARG collection for data security")
        evidence_index = await _ds_lightweight_collect(creds, subscriptions)
        # Phase 1: deep ARM sub-resource enrichment
        log.info("Running ARM enrichment (SQL, VMs, PG/MySQL, Defender, diagnostics) …")
        await _ds_arm_enrich(creds, evidence_index)

    log.info("Running storage exposure analysis …")
    storage_findings = analyze_storage_exposure(evidence_index)

    log.info("Running database security analysis …")
    db_findings = analyze_database_security(evidence_index)

    log.info("Running Cosmos DB security analysis …")
    cosmos_findings = analyze_cosmosdb_security(evidence_index)

    log.info("Running PostgreSQL/MySQL security analysis …")
    pgmysql_findings = analyze_postgres_mysql_security(evidence_index)

    log.info("Running Key Vault hygiene analysis …")
    kv_findings = analyze_keyvault_hygiene(evidence_index)

    log.info("Running encryption posture analysis …")
    enc_findings = analyze_encryption_posture(evidence_index)

    log.info("Running data access controls analysis …")
    access_findings = analyze_data_access_controls(evidence_index)

    log.info("Running private endpoint analysis …")
    pe_findings = analyze_private_endpoints(evidence_index)

    log.info("Running Purview / Information Protection analysis …")
    purview_findings = analyze_purview_security(evidence_index)

    log.info("Running Azure File Sync security analysis …")
    filesync_findings = analyze_file_sync_security(evidence_index)

    log.info("Running M365 DLP policy analysis …")
    dlp_findings = analyze_m365_dlp(evidence_index)

    log.info("Running data classification & labeling analysis …")
    classification_findings = analyze_data_classification_security(evidence_index)

    log.info("Running backup & disaster recovery analysis …")
    backup_findings = analyze_backup_dr(evidence_index)

    log.info("Running container security analysis …")
    container_findings = analyze_container_security(evidence_index)

    log.info("Running network segmentation analysis …")
    network_findings = analyze_network_segmentation(evidence_index)

    log.info("Running data residency analysis …")
    residency_findings = analyze_data_residency(evidence_index)

    log.info("Running threat detection analysis …")
    threat_findings = analyze_threat_detection(evidence_index)

    log.info("Running SharePoint/OneDrive governance analysis …")
    spo_findings = analyze_sharepoint_governance(evidence_index)

    log.info("Running M365 data lifecycle analysis …")
    lifecycle_findings = analyze_m365_data_lifecycle(evidence_index)

    log.info("Running DLP alert effectiveness analysis …")
    dlp_alert_findings = analyze_dlp_alert_effectiveness(evidence_index)

    log.info("Running Redis security analysis …")
    redis_findings = analyze_redis_security(evidence_index)

    log.info("Running messaging security analysis …")
    messaging_findings = analyze_messaging_security(evidence_index)

    log.info("Running AI services security analysis …")
    ai_svc_findings = analyze_ai_services_security(evidence_index)

    log.info("Running data pipeline security analysis …")
    pipeline_findings = analyze_data_factory_security(evidence_index)

    log.info("Running managed identity deep audit …")
    mi_findings = analyze_managed_identity_deep(evidence_index)


    log.info("Running SQL MI security analysis …")
    sqlmi_findings = analyze_sql_mi_security(evidence_index)

    log.info("Running App Configuration security analysis …")
    appconfig_findings = analyze_app_config_security(evidence_index)

    log.info("Running certificate lifecycle analysis …")
    cert_findings = analyze_cert_lifecycle(evidence_index)

    log.info("Running Databricks security analysis …")
    databricks_findings = analyze_databricks_security(evidence_index)

    log.info("Running APIM security analysis …")
    apim_findings = analyze_apim_security(evidence_index)

    log.info("Running Front Door / WAF analysis …")
    frontdoor_findings = analyze_frontdoor_security(evidence_index)

    log.info("Running secret sprawl detection …")
    sprawl_findings = analyze_secret_sprawl(evidence_index)

    log.info("Running Firewall / App Gateway analysis …")
    fw_findings = analyze_firewall_appgw_security(evidence_index)

    log.info("Running Bastion security analysis …")
    bastion_findings = analyze_bastion_security(evidence_index)

    log.info("Running Azure Policy compliance analysis …")
    policy_findings = analyze_policy_compliance(evidence_index)

    log.info("Running Defender secure score analysis …")
    defender_findings = analyze_defender_score(evidence_index)


    log.info("Running stale permissions analysis …")
    stale_findings = analyze_stale_permissions(evidence_index)

    log.info("Running data exfiltration prevention analysis …")
    exfil_findings = analyze_data_exfiltration(evidence_index)

    log.info("Running Conditional Access / PIM analysis …")
    ca_findings = analyze_conditional_access_pim(evidence_index)


    log.info("Running Supply Chain Risk analysis …")
    supply_chain_findings = analyze_supply_chain_risk(evidence_index)

    # Build combined findings list once
    all_findings = (
        storage_findings + db_findings + cosmos_findings + pgmysql_findings
        + kv_findings + enc_findings + access_findings + pe_findings
        + purview_findings + filesync_findings + dlp_findings
        + classification_findings + backup_findings + container_findings
        + network_findings + residency_findings + threat_findings
        + spo_findings + lifecycle_findings + dlp_alert_findings
        + redis_findings + messaging_findings
        + ai_svc_findings + pipeline_findings + mi_findings
        + sqlmi_findings + appconfig_findings + cert_findings
        + databricks_findings + apim_findings + frontdoor_findings
        + sprawl_findings + fw_findings + bastion_findings
        + policy_findings + defender_findings
        + stale_findings + exfil_findings + ca_findings
        + supply_chain_findings
    )

    # Advanced analytics (non-finding-producing, attached to results)
    log.info("Computing blast radius \u2026")
    blast_radius = analyze_blast_radius(evidence_index, all_findings)

    log.info("Mapping data flows \u2026")
    data_flows = analyze_data_flow(evidence_index)

    # Enrich findings with compliance framework mapping
    enrich_compliance_mapping(all_findings)

    # Enrich per-resource risk details and remediation commands
    enrich_per_resource_details(all_findings)

    # Consolidate findings with overlapping resources within same category
    all_findings = consolidate_findings(all_findings)

    # ── Deterministic ordering ───────────────────────────────────────────
    # Sort findings by (Category, Subcategory, Severity) for stable output.
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            _sev_order.get(f.get("Severity", "medium").lower(), 9),
        )
    )
    # Sort AffectedResources within each finding by ResourceId for stability.
    for _f in all_findings:
        _f.get("AffectedResources", []).sort(
            key=lambda r: r.get("ResourceId", r.get("Name", ""))
        )
    log.info("Post-consolidation: %d findings (sorted)", len(all_findings))
    scores = compute_data_security_scores(all_findings)

    # Calculate remediation impact
    remediation_impact = compute_remediation_impact(all_findings, scores)

    # Tenant display name from Graph organization API
    _tenant_display = ""
    try:
        graph = creds.get_graph_client()
        org_resp = await graph.organization.get()
        orgs = getattr(org_resp, "value", []) or [] if org_resp else []
        if orgs:
            _tenant_display = getattr(orgs[0], "display_name", "") or ""
    except Exception:
        pass

    # Rebuild per-category index from consolidated findings
    _cat_index: dict[str, list[dict]] = {}
    for _f in all_findings:
        _cat_index.setdefault(_f.get("Category", "unknown"), []).append(_f)

    # Compute trend analysis (compare with previous if available)
    trend = compute_trend_analysis(scores, all_findings)

    return {
        "AssessmentId": str(uuid.uuid5(
            _DS_FINDING_NS,
            f"ds-assessment|{creds.tenant_id}|{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M')}",
        )),
        "AssessedAt": datetime.now(timezone.utc).isoformat(),
        "TenantId": creds.tenant_id,
        "TenantDisplayName": _tenant_display,
        "SubscriptionCount": len(subscriptions),
        "EvidenceSource": "existing_assessment" if has_evidence else "lightweight_collection",
        "EvidenceRecordCount": sum(len(v) for v in evidence_index.values()),
        "EvidenceSummary": {
            k: len(v) for k, v in sorted(evidence_index.items())
            if not k.startswith("_")
        },
        "DataSecurityScores": scores,
        "RemediationImpact": remediation_impact,
        "BlastRadius": blast_radius,
        "DataFlows": data_flows,
        "Findings": all_findings,
        "FindingCount": len(all_findings),
        "Categories": _cat_index,
        "CategoryCounts": {k: len(v) for k, v in _cat_index.items()},
        "TrendAnalysis": trend,
        "CollectionErrors": evidence_index.get("_collection_errors", []),
        "EnrichmentErrors": evidence_index.get("_enrichment_errors", []),
    }



def _normalize_evidence_record(data: dict) -> dict:
    """Ensure consistent field names across evidence from ARG, ARM, and Graph."""
    norm = dict(data)
    # Normalize common field name variations
    _FIELD_MAP = {
        "Id": "id",
        "Name": "name",
        "Type": "type",
        "Location": "location",
        "ResourceGroup": "resourceGroup",
        "SubscriptionId": "subscriptionId",
    }
    for src_key, dst_key in _FIELD_MAP.items():
        if src_key in norm and dst_key not in norm:
            norm[dst_key] = norm[src_key]
    # Ensure id field exists (common for Graph API results)
    if "id" not in norm:
        norm["id"] = norm.get("resourceId", norm.get("resource_id", ""))
    return norm


async def _ds_lightweight_collect(
    creds: ComplianceCredentials,
    subscriptions: list[dict],
) -> dict[str, list[dict]]:
    """Quick ARG-based collection for data-security analysis.
    Covers all 8 resource types + private endpoints + role assignments + containers.
    """
    from app.query_evaluators.arg_queries import query_resource_graph

    index: dict[str, list[dict]] = {}
    _collection_errors: list[dict] = []
    sub_ids = [s.get("subscription_id", s.get("subscriptionId", "")) for s in subscriptions]

    kql_queries = {
        "azure-resource": (
            "Resources | project id, name, type, location, resourceGroup, tags"
        ),
        "azure-storage-security": (
            "Resources | where type =~ 'microsoft.storage/storageaccounts' "
            "| project id, name, type, location, resourceGroup, "
            "properties.supportsHttpsTrafficOnly, "
            "properties.allowBlobPublicAccess, "
            "properties.networkAcls.defaultAction, "
            "properties.encryption.keySource, "
            "properties.minimumTlsVersion, "
            "properties.allowSharedKeyAccess, "
            "properties.encryption.requireInfrastructureEncryption, "
            "properties.privateEndpointConnections, "
            "properties.sasPolicy, "
            "properties.immutableStorageWithVersioning, "
            "properties.networkAcls.ipRules, "
            "properties.networkAcls.virtualNetworkRules, "
            "properties.networkAcls.bypass, "
            "sku"
        ),
        "azure-storage-containers": (
            "Resources | where type =~ 'microsoft.storage/storageaccounts/blobservices/containers' "
            "| project id, name, type, properties.publicAccess"
        ),
        "azure-sql-server": (
            "Resources | where type =~ 'microsoft.sql/servers' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.privateEndpointConnections"
        ),
        "azure-keyvault": (
            "Resources | where type =~ 'microsoft.keyvault/vaults' "
            "| project id, name, type, location, "
            "properties.enableRbacAuthorization, "
            "properties.enablePurgeProtection, "
            "properties.enableSoftDelete, "
            "properties.networkAcls, "
            "properties.privateEndpointConnections"
        ),
        "azure-compute-instance": (
            "Resources | where type =~ 'microsoft.compute/virtualmachines' "
            "| project id, name, type, location, resourceGroup"
        ),
        "azure-cosmosdb": (
            "Resources | where type =~ 'microsoft.documentdb/databaseaccounts' "
            "| project id, name, type, location, "
            "properties.publicNetworkAccess, "
            "properties.ipRules, "
            "properties.virtualNetworkRules, "
            "properties.disableLocalAuth, "
            "properties.backupPolicy, "
            "properties.keyVaultKeyUri, "
            "properties.privateEndpointConnections"
        ),
        "azure-dbforpostgresql": (
            "Resources | where type =~ 'microsoft.dbforpostgresql/flexibleservers' "
            "| project id, name, type, location, resourceGroup, "
            "properties.network.publicNetworkAccess, "
            "properties.backup.geoRedundantBackup, "
            "properties.highAvailability, "
            "properties.privateEndpointConnections"
        ),
        "azure-dbformysql": (
            "Resources | where type =~ 'microsoft.dbformysql/flexibleservers' "
            "| project id, name, type, location, resourceGroup, "
            "properties.network.publicNetworkAccess, "
            "properties.backup.geoRedundantBackup, "
            "properties.highAvailability, "
            "properties.privateEndpointConnections"
        ),
        "azure-private-endpoint-connections": (
            "Resources | where type =~ 'microsoft.network/privateendpoints' "
            "| mv-expand conn = properties.privateLinkServiceConnections "
            "| project id, name, privateLinkServiceId = tostring(conn.properties.privateLinkServiceId)"
        ),
        "azure-recovery-vault": (
            "Resources | where type =~ 'microsoft.recoveryservices/vaults' "
            "| project id, name, type, location, resourceGroup, "
            "properties.provisioningState, "
            "properties.publicNetworkAccess, "
            "properties.privateEndpointConnections, "
            "properties.redundancySettings"
        ),
        "azure-containerregistry": (
            "Resources | where type =~ 'microsoft.containerregistry/registries' "
            "| project id, name, type, location, resourceGroup, sku, "
            "properties.adminUserEnabled, "
            "properties.publicNetworkAccess, "
            "properties.networkRuleSet, "
            "properties.policies, "
            "properties.privateEndpointConnections"
        ),
        "azure-aks": (
            "Resources | where type =~ 'microsoft.containerservice/managedclusters' "
            "| project id, name, type, location, resourceGroup, sku, "
            "properties.enableRBAC, "
            "properties.aadProfile, "
            "properties.networkProfile.networkPolicy, "
            "properties.networkProfile.networkPlugin, "
            "properties.apiServerAccessProfile, "
            "properties.privateCluster"
        ),
        "azure-purview": (
            "Resources | where type =~ 'microsoft.purview/accounts' "
            "| project id, name, type, location, "
            "properties.publicNetworkAccess, "
            "properties.privateEndpointConnections, "
            "identity"
        ),
        "azure-storagesync": (
            "Resources | where type =~ 'microsoft.storagesync/storagesyncservices' "
            "| project id, name, type, location, "
            "properties.incomingTrafficPolicy, "
            "properties.privateEndpointConnections"
        ),
        "azure-nsg": (
            "Resources | where type =~ 'microsoft.network/networksecuritygroups' "
            "| project id, name, type, location, resourceGroup, "
            "properties.securityRules"
        ),
        "azure-vnet": (
            "Resources | where type =~ 'microsoft.network/virtualnetworks' "
            "| project id, name, type, location, resourceGroup, "
            "properties.enableDdosProtection, "
            "properties.subnets"
        ),
        "azure-managed-disk": (
            "Resources | where type =~ 'microsoft.compute/disks' "
            "| project id, name, type, location, resourceGroup, "
            "sku, properties.encryption, properties.diskSizeGB, "
            "properties.osType, managedBy"
        ),
        "azure-cognitive-account": (
            "Resources | where type =~ 'microsoft.cognitiveservices/accounts' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.networkAcls, "
            "properties.disableLocalAuth, "
            "properties.encryption, "
            "properties.privateEndpointConnections, "
            "identity"
        ),
        "azure-redis-cache": (
            "Resources | where type =~ 'microsoft.cache/redis' "
            "| project id, name, type, location, resourceGroup, "
            "properties.minimumTlsVersion, "
            "properties.enableNonSslPort, "
            "properties.publicNetworkAccess, "
            "properties.redisFirewallRules, "
            "properties.privateEndpointConnections, "
            "properties.patchSchedule, "
            "sku"
        ),
        "azure-eventhub-namespace": (
            "Resources | where type =~ 'microsoft.eventhub/namespaces' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.disableLocalAuth, "
            "properties.minimumTlsVersion, "
            "properties.privateEndpointConnections, "
            "sku"
        ),
        "azure-servicebus-namespace": (
            "Resources | where type =~ 'microsoft.servicebus/namespaces' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.disableLocalAuth, "
            "properties.minimumTlsVersion, "
            "properties.privateEndpointConnections, "
            "sku"
        ),
        "azure-data-factory": (
            "Resources | where type =~ 'microsoft.datafactory/factories' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.repoConfiguration, "
            "properties.globalParameters, "
            "properties.managedVirtualNetwork, "
            "identity"
        ),
        "azure-synapse-workspace": (
            "Resources | where type =~ 'microsoft.synapse/workspaces' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.managedVirtualNetwork, "
            "properties.managedVirtualNetworkSettings, "
            "properties.azureADOnlyAuthentication, "
            "properties.privateEndpointConnections, "
            "identity"
        ),
    }

    for etype, kql in kql_queries.items():
        try:
            # Append deterministic ordering to ensure stable results across runs
            _ordered_kql = kql if "| order by" in kql.lower() else kql + " | order by id asc"
            rows = await query_resource_graph(creds, _ordered_kql, sub_ids, top=1000)
            index[etype] = [
                {"EvidenceType": etype, "Data": _normalize_evidence_record(r), "ResourceId": r.get("id", "")}
                for r in rows
            ]
            if rows:
                log.info("  ARG [%s]: %d resources", etype, len(rows))
        except Exception as exc:
            log.warning("ARG query failed for %s: %s", etype, exc)
            _collection_errors.append({"query": etype, "error": str(exc)})

    # Collect role assignments for data-access analysis
    try:
        role_kql = (
            "AuthorizationResources "
            "| where type =~ 'microsoft.authorization/roleassignments' "
            "| extend roleDefId = tostring(properties.roleDefinitionId) "
            "| extend principalId = tostring(properties.principalId) "
            "| extend scope = tostring(properties.scope) "
            "| extend principalType = tostring(properties.principalType) "
            "| project id, roleDefId, principalId, scope, principalType "
            "| order by id asc"
        )
        role_rows = await query_resource_graph(creds, role_kql, sub_ids, top=5000)
        # We need role definition names — resolve via a second query
        roledef_kql = (
            "AuthorizationResources "
            "| where type =~ 'microsoft.authorization/roledefinitions' "
            "| project id, roleName = tostring(properties.roleName) "
            "| order by id asc"
        )
        roledef_rows = await query_resource_graph(creds, roledef_kql, sub_ids, top=500)
        roledef_map = {r.get("id", "").lower(): r.get("roleName", "") for r in roledef_rows}

        index["azure-role-assignments"] = []
        for r in role_rows:
            role_def_id = r.get("roleDefId", "").lower()
            role_name = roledef_map.get(role_def_id, "")
            index["azure-role-assignments"].append({
                "EvidenceType": "azure-role-assignments",
                "Data": {
                    "roleDefinitionName": role_name,
                    "scope": r.get("scope", ""),
                    "principalId": r.get("principalId", ""),
                    "principalType": r.get("principalType", ""),
                    "principalName": r.get("principalId", ""),  # we only have ID
                },
                "ResourceId": r.get("id", ""),
            })
        if role_rows:
            log.info("  ARG [role-assignments]: %d assignments, %d role definitions",
                     len(role_rows), len(roledef_rows))
    except Exception as exc:
        log.warning("Role-assignment ARG query failed: %s", exc)


    # ── Wave A+B+C ARG queries ───────────────────────────────────────────
    _new_queries = {
        "azure-sql-mi": (
            "Resources | where type =~ 'microsoft.sql/managedinstances' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicDataEndpointEnabled, "
            "properties.administrators.administratorType, "
            "properties.privateEndpointConnections"
        ),
        "azure-app-configuration": (
            "Resources | where type =~ 'microsoft.appconfiguration/configurationstores' "
            "| project id, name, type, location, resourceGroup, "
            "properties.publicNetworkAccess, "
            "properties.encryption, "
            "properties.softDeleteRetentionInDays, "
            "properties.enablePurgeProtection, "
            "properties.privateEndpointConnections"
        ),
        "azure-databricks": (
            "Resources | where type =~ 'microsoft.databricks/workspaces' "
            "| project id, name, type, location, resourceGroup, "
            "properties.parameters, "
            "properties.encryption, "
            "properties.publicNetworkAccess, "
            "properties.privateEndpointConnections"
        ),
        "azure-apim": (
            "Resources | where type =~ 'microsoft.apimanagement/service' "
            "| project id, name, type, location, resourceGroup, "
            "properties.virtualNetworkType, "
            "identity, "
            "properties.developerPortalStatus, "
            "properties.privateEndpointConnections"
        ),
        "azure-frontdoor": (
            "Resources | where type =~ 'microsoft.cdn/profiles' or type =~ 'microsoft.network/frontdoors' "
            "| project id, name, type, location, resourceGroup, "
            "properties.frontDoorWebApplicationFirewallPolicyLink, "
            "properties.minimumTlsVersion"
        ),
        "azure-webapp": (
            "Resources | where type =~ 'microsoft.web/sites' "
            "| project id, name, type, location, resourceGroup, kind, "
            "identity, "
            "properties.httpsOnly, "
            "properties.siteConfig"
        ),
        "azure-firewall": (
            "Resources | where type =~ 'microsoft.network/azurefirewalls' "
            "| project id, name, type, location, resourceGroup, "
            "properties.threatIntelMode, "
            "properties.sku"
        ),
        "azure-appgw": (
            "Resources | where type =~ 'microsoft.network/applicationgateways' "
            "| project id, name, type, location, resourceGroup, "
            "properties.sku.tier, "
            "properties.webApplicationFirewallConfiguration"
        ),
        "azure-bastion": (
            "Resources | where type =~ 'microsoft.network/bastionhosts' "
            "| project id, name, type, location, resourceGroup, "
            "properties.enableShareableLink, "
            "properties.enableTunneling"
        ),
        "azure-policy-states": (
            "PolicyResources | where type =~ 'microsoft.policyinsights/policystates' "
            "| where properties.complianceState =~ 'NonCompliant' "
            "| project id, name, "
            "properties.policyDefinitionName, "
            "properties.policyDefinitionDisplayName, "
            "properties.complianceState, "
            "properties.resourceId "
            "| take 500"
        ),
        "azure-security-recommendations": (
            "SecurityResources | where type =~ 'microsoft.security/assessments' "
            "| where properties.status.code =~ 'Unhealthy' "
            "| project id, name, "
            "properties.displayName, "
            "properties.status.code, "
            "properties.status.cause, "
            "properties.metadata.severity "
            "| take 500"
        ),
    }
    for qkey, qkql in _new_queries.items():
        try:
            _ordered_qkql = qkql if "| order by" in qkql.lower() or "| take" in qkql.lower() else qkql + " | order by id asc"
            rows = await query_resource_graph(creds, _ordered_qkql, sub_ids)
            index[qkey] = [
                {"EvidenceType": qkey, "Data": _normalize_evidence_record(r), "ResourceId": r.get("id", "")}
                for r in rows
            ]
            if rows:
                log.info("  ARG [%s]: %d resources", qkey, len(rows))
        except Exception as exc:
            log.warning("ARG query [%s] failed: %s", qkey, exc)
            _collection_errors.append({"query": qkey, "error": str(exc)})
            index.setdefault(qkey, [])


    # ── Wave D: Sign-in activity, Conditional Access, PIM ────────────────
    # Sign-in activity from Graph audit logs (if accessible)
    try:
        graph = creds.get_graph_client()
        # Attempt to get sign-in activity summary (requires AuditLog.Read.All)
        index.setdefault("azure-sign-in-activity", [])
        log.info("  Skipping sign-in activity collection (Graph sign-in API requires premium license)")
    except Exception:
        index.setdefault("azure-sign-in-activity", [])

    # Conditional Access policies (if accessible)
    try:
        from app.collectors.entra.conditional_access import collect_entra_conditional_access
        ca_evidence = await collect_entra_conditional_access(creds)
        index["azure-conditional-access"] = [
            {"EvidenceType": "azure-conditional-access",
             "Data": ev.get("Data", {}),
             "ResourceId": ev.get("ResourceId", "")}
            for ev in ca_evidence
        ]
        log.info("  Conditional Access: %d policies collected", len(ca_evidence))
    except Exception as exc:
        log.warning("  Conditional Access collection failed: %s", exc)
        index.setdefault("azure-conditional-access", [])

    # PIM roles (if accessible)
    index.setdefault("azure-pim-roles", [])

    index["_collection_errors"] = _collection_errors
    return index


# ── Deep ARM enrichment (Phase 1) ───────────────────────────────────────

async def _ds_arm_enrich(
    creds: ComplianceCredentials,
    index: dict[str, list[dict]],
) -> None:
    """Targeted ARM REST calls to fill in sub-resource properties that
    ARG does not expose: SQL firewall/TDE/auditing, VM encryption status,
    PG/MySQL firewall rules, Defender pricing plans, diagnostic settings.
    """
    import asyncio
    enrichment_tasks: list = []

    # Pre-warm the credential token so individual ARM calls don't race
    # on a cold DefaultAzureCredential, which causes intermittent timeouts.
    try:
        await creds.credential.get_token("https://management.azure.com/.default")
        log.info("ARM enrichment: credential token pre-cached")
    except Exception as exc:
        log.warning("ARM enrichment: credential pre-cache failed: %s", exc)

    # 1. SQL Server TDE / Auditing / Firewall / Threat Protection
    sql_servers = index.get("azure-sql-server", [])
    if sql_servers:
        enrichment_tasks.append(_enrich_sql_servers(creds, sql_servers))

    # 2. VM disk encryption status
    vms = index.get("azure-compute-instance", [])
    if vms:
        enrichment_tasks.append(_enrich_vm_encryption(creds, vms))

    # 3. PostgreSQL / MySQL firewall rules
    pg_servers = index.get("azure-dbforpostgresql", [])
    mysql_servers = index.get("azure-dbformysql", [])
    if pg_servers:
        enrichment_tasks.append(_enrich_pg_firewall(creds, pg_servers))
    if mysql_servers:
        enrichment_tasks.append(_enrich_mysql_firewall(creds, mysql_servers))

    # 4. Defender pricing plans
    subs = set()
    for etype in index.values():
        for ev in etype:
            rid = ev.get("ResourceId", ev.get("resource_id", ""))
            parts = rid.split("/")
            if len(parts) >= 3 and parts[1].lower() == "subscriptions":
                subs.add(parts[2])
    if subs:
        enrichment_tasks.append(_enrich_defender_plans(creds, list(subs), index))

    # 5. Diagnostic settings for data services
    enrichment_tasks.append(_enrich_diagnostic_settings(creds, index))

    # 6. SQL sensitivity labels & vulnerability assessment
    if sql_servers:
        enrichment_tasks.append(_enrich_sql_sensitivity(creds, sql_servers))

    # 7. Defender for Storage sensitive-data alerts (actual findings)
    if subs:
        enrichment_tasks.append(_enrich_defender_alerts(creds, list(subs), index))

    # 8. Purview scan run results
    purview_accounts = index.get("azure-purview", [])
    if purview_accounts:
        enrichment_tasks.append(_enrich_purview_scan_results(creds, purview_accounts, index))


    # ── Wave A+B+C ARM enrichment ────────────────────────────────────────
    # SQL MI — Advanced Threat Protection
    sql_mis = index.get("azure-sql-mi", [])
    if sql_mis:
        async def _enrich_sqlmi_atp(evs):
            for ev in evs:
                rid = ev.get("ResourceId", "")
                data = ev.get("Data", {})
                atp_url = f"https://management.azure.com{rid}/securityAlertPolicies/Default?api-version=2022-05-01-preview"
                atp_resp = await _arm_get_json(creds, atp_url)
                if atp_resp and isinstance(atp_resp, dict):
                    state = atp_resp.get("properties", {}).get("state", "").lower()
                    data["AdvancedThreatProtection"] = state == "enabled"
        enrichment_tasks.append(_enrich_sqlmi_atp(sql_mis))

    # Web Apps — fetch app settings for secret sprawl detection
    webapps = index.get("azure-webapp", [])
    if webapps:
        async def _enrich_webapp_settings(evs):
            for ev in evs:
                rid = ev.get("ResourceId", "")
                data = ev.get("Data", {})
                settings_url = f"https://management.azure.com{rid}/config/appsettings/list?api-version=2023-12-01"
                # This is a POST endpoint
                try:
                    import aiohttp
                    token = creds.get_arm_token()
                    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                    async with aiohttp.ClientSession() as session:
                        async with session.post(settings_url, headers=headers) as resp:
                            if resp.status == 200:
                                body = await resp.json()
                                props = body.get("properties", {})
                                data["appSettings"] = [{"name": k, "value": v} for k, v in props.items()]
                except Exception:
                    pass
        enrichment_tasks.append(_enrich_webapp_settings(webapps))

    # Azure Firewall — fetch policy for IDPS config
    firewalls = index.get("azure-firewall", [])
    if firewalls:
        async def _enrich_firewall_idps(evs):
            for ev in evs:
                rid = ev.get("ResourceId", "")
                data = ev.get("Data", {})
                fw_url = f"https://management.azure.com{rid}?api-version=2023-11-01"
                fw_resp = await _arm_get_json(creds, fw_url)
                if fw_resp and isinstance(fw_resp, dict):
                    fp_id = fw_resp.get("properties", {}).get("firewallPolicy", {}).get("id", "")
                    if fp_id:
                        pol_url = f"https://management.azure.com{fp_id}?api-version=2023-11-01"
                        pol_resp = await _arm_get_json(creds, pol_url)
                        if pol_resp and isinstance(pol_resp, dict):
                            idps = pol_resp.get("properties", {}).get("intrusionDetection", {})
                            data["intrusionDetection"] = idps
        enrichment_tasks.append(_enrich_firewall_idps(firewalls))

    # Key Vault — fetch certificates for lifecycle checks
    kvs = index.get("azure-keyvault", [])
    if kvs:
        async def _enrich_kv_certs(kv_evs):
            index.setdefault("azure-keyvault-certs", [])
            for ev in kv_evs:
                rid = ev.get("ResourceId", "")
                data = ev.get("Data", {})
                vault_name = data.get("name", "")
                vault_uri = f"https://{vault_name}.vault.azure.net"
                certs_url = f"{vault_uri}/certificates?api-version=7.4"
                try:
                    token = creds.get_keyvault_token()
                    import aiohttp
                    headers = {"Authorization": f"Bearer {token}"}
                    async with aiohttp.ClientSession() as session:
                        async with session.get(certs_url, headers=headers) as resp:
                            if resp.status == 200:
                                body = await resp.json()
                                for cert in body.get("value", []):
                                    cert_name = cert.get("id", "").rsplit("/", 1)[-1]
                                    attrs = cert.get("attributes", {})
                                    index["azure-keyvault-certs"].append({
                                        "EvidenceType": "azure-keyvault-certs",
                                        "Data": {
                                            "name": cert_name,
                                            "vaultName": vault_name,
                                            "expires": attrs.get("exp", ""),
                                            "enabled": attrs.get("enabled", True),
                                        },
                                        "ResourceId": f"{rid}/certificates/{cert_name}",
                                    })
                except Exception:
                    pass
        enrichment_tasks.append(_enrich_kv_certs(kvs))

    # Map task index → descriptive label for error reporting
    _task_labels = [
        "SQL Server TDE/Auditing/Firewall",
        "VM disk encryption",
        "PostgreSQL firewall",
        "MySQL firewall",
        "Defender pricing plans",
        "Diagnostic settings",
        "SQL sensitivity labels",
        "Defender alerts",
        "Purview scan results",
    ]
    # Extend labels for any wave A/B/C tasks appended above
    while len(_task_labels) < len(enrichment_tasks):
        _task_labels.append(f"ARM enrichment task #{len(_task_labels) + 1}")

    if enrichment_tasks:
        _enrich_errors: list[dict] = index.setdefault("_enrichment_errors", [])
        results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                label = _task_labels[i] if i < len(_task_labels) else f"task-{i}"
                log.warning("ARM enrichment task '%s' failed: %s", label, r)
                _enrich_errors.append({
                    "enrichment_step": label,
                    "error": str(r),
                    "impact": (
                        f"Findings for '{label}' may be incomplete. "
                        "A score of 0 for affected categories does not guarantee compliance."
                    ),
                })


# Semaphore to limit concurrent ARM REST calls and avoid Azure API throttling.
# Shared across all enrichment tasks within a single assessment run.
import asyncio as _asyncio
_ARM_CONCURRENCY = _asyncio.Semaphore(10)


async def _arm_get_json(
    creds: ComplianceCredentials,
    url: str,
    *,
    max_retries: int = 3,
    base_delay: float = 1.0,
    retry_on_empty_list: bool = False,
) -> dict | list | None:
    """ARM REST GET with retry + exponential backoff.

    Uses a shared semaphore to limit to 10 concurrent ARM calls, preventing
    thundering-herd throttling.  Retries on 429 (throttling), 500, 502,
    503, 504, and transient network errors.  When *retry_on_empty_list* is
    ``True``, also retries if the response is HTTP 200 but ``value`` is an
    empty list (Azure sometimes returns stale empty responses).
    Returns parsed JSON or ``None``.
    """
    import asyncio
    import aiohttp

    _RETRYABLE_STATUSES = {429, 500, 502, 503, 504}

    for attempt in range(max_retries):
        async with _ARM_CONCURRENCY:
            try:
                token = await creds.credential.get_token(
                    "https://management.azure.com/.default"
                )
                headers = {"Authorization": f"Bearer {token.token}"}
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status == 200:
                            body = await resp.json()
                            # Retry if caller expects a non-empty list but got empty
                            if (
                                retry_on_empty_list
                                and attempt < max_retries - 1
                                and isinstance(body, dict)
                                and isinstance(body.get("value"), list)
                                and len(body["value"]) == 0
                            ):
                                delay = base_delay * (2 ** attempt)
                                log.debug(
                                    "ARM GET %s → 200 but empty value[] "
                                    "(attempt %d/%d, retry in %.1fs)",
                                    url, attempt + 1, max_retries, delay,
                                )
                                await asyncio.sleep(delay)
                                continue
                            return body
                        if resp.status in (403, 401):
                            log.debug("ARM GET %s → %d (access denied)", url, resp.status)
                            return None  # not retryable
                        if resp.status == 404:
                            log.debug("ARM GET %s → 404 (not found)", url)
                            return None  # not retryable
                        if resp.status in _RETRYABLE_STATUSES:
                            delay = base_delay * (2 ** attempt)
                            if resp.status == 429:
                                retry_after = resp.headers.get("Retry-After")
                                if retry_after and retry_after.isdigit():
                                    delay = max(delay, int(retry_after))
                            log.warning(
                                "ARM GET %s → %d (attempt %d/%d, retry in %.1fs)",
                                url, resp.status, attempt + 1, max_retries, delay,
                            )
                            await asyncio.sleep(delay)
                            continue
                        log.debug("ARM GET %s → %d", url, resp.status)
                        return None
            except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as exc:
                delay = base_delay * (2 ** attempt)
                log.warning(
                    "ARM GET %s failed (attempt %d/%d): %s — retry in %.1fs",
                    url, attempt + 1, max_retries, exc, delay,
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(delay)
                continue
            except Exception as exc:
                log.debug("ARM GET %s failed (non-retryable): %s", url, exc)
                return None
    log.warning("ARM GET %s exhausted %d retries", url, max_retries)
    return None


async def _enrich_sql_servers(creds: ComplianceCredentials, sql_evidences: list[dict]) -> None:
    """Fetch firewall rules, TDE status, auditing, threat protection for each SQL server."""
    import asyncio
    base = "https://management.azure.com"
    api = "?api-version=2023-05-01-preview"

    async def enrich_one(ev: dict) -> None:
        rid = ev.get("ResourceId", ev.get("resource_id", ""))
        if not rid:
            return
        data = ev.get("Data", ev.get("data", {}))

        # Firewall rules
        fw_url = f"{base}{rid}/firewallRules{api}"
        fw_resp = await _arm_get_json(creds, fw_url)
        if fw_resp and isinstance(fw_resp, dict):
            rules = fw_resp.get("value", [])
            data["FirewallRules"] = [
                {
                    "Name": r.get("name", ""),
                    "StartIpAddress": r.get("properties", {}).get("startIpAddress", ""),
                    "EndIpAddress": r.get("properties", {}).get("endIpAddress", ""),
                }
                for r in rules
            ]

        # Auditing settings
        audit_url = f"{base}{rid}/auditingSettings/default{api}"
        audit_resp = await _arm_get_json(creds, audit_url)
        if audit_resp and isinstance(audit_resp, dict):
            state = audit_resp.get("properties", {}).get("state", "").lower()
            data["AuditingEnabled"] = state == "enabled"

        # Threat protection
        atp_url = f"{base}{rid}/securityAlertPolicies/Default{api}"
        atp_resp = await _arm_get_json(creds, atp_url)
        if atp_resp and isinstance(atp_resp, dict):
            state = atp_resp.get("properties", {}).get("state", "").lower()
            data["AdvancedThreatProtection"] = state == "enabled"

        # TDE — need to check databases
        db_url = f"{base}{rid}/databases{api}"
        db_resp = await _arm_get_json(creds, db_url)
        if db_resp and isinstance(db_resp, dict):
            dbs = db_resp.get("value", [])
            all_tde = True
            for db in dbs:
                db_name = db.get("name", "")
                if db_name.lower() == "master":
                    continue
                db_rid = db.get("id", "")
                tde_url = f"{base}{db_rid}/transparentDataEncryption/current{api}"
                tde_resp = await _arm_get_json(creds, tde_url)
                if tde_resp and isinstance(tde_resp, dict):
                    tde_state = tde_resp.get("properties", {}).get("state", "").lower()
                    if tde_state != "enabled":
                        all_tde = False
                        break
            data["TransparentDataEncryption"] = all_tde

    await asyncio.gather(*[enrich_one(ev) for ev in sql_evidences], return_exceptions=True)
    log.info("  ARM enrichment: %d SQL servers", len(sql_evidences))


async def _enrich_vm_encryption(creds: ComplianceCredentials, vm_evidences: list[dict]) -> None:
    """Check VM disk encryption status via instance view."""
    import asyncio
    base = "https://management.azure.com"
    api = "?api-version=2024-03-01&$expand=instanceView"

    async def enrich_one(ev: dict) -> None:
        rid = ev.get("ResourceId", ev.get("resource_id", ""))
        if not rid:
            return
        data = ev.get("Data", ev.get("data", {}))
        url = f"{base}{rid}{api}"
        resp = await _arm_get_json(creds, url)
        if resp and isinstance(resp, dict):
            props = resp.get("properties", {})
            # Check OS disk encryption settings
            os_disk = props.get("storageProfile", {}).get("osDisk", {})
            managed = os_disk.get("managedDisk", {})
            des_id = managed.get("diskEncryptionSet", {}).get("id") if isinstance(managed, dict) else None
            enc_at_host = props.get("securityProfile", {}).get("encryptionAtHost", False)
            # Also check Azure Disk Encryption via extensions
            ade_ext = False
            for ext in props.get("instanceView", {}).get("extensions", []):
                if "azurediskencryption" in ext.get("type", "").lower():
                    ade_ext = True
                    break
            data["DiskEncryptionEnabled"] = bool(des_id) or enc_at_host or ade_ext
            # Store granular encryption type for posture analysis
            if des_id:
                data["DiskEncryptionType"] = "CMK"
            elif ade_ext:
                data["DiskEncryptionType"] = "ADE"
            elif enc_at_host:
                data["DiskEncryptionType"] = "EncryptionAtHost"
            else:
                data["DiskEncryptionType"] = "PMK"  # platform-managed keys only

    await asyncio.gather(*[enrich_one(ev) for ev in vm_evidences], return_exceptions=True)
    log.info("  ARM enrichment: %d VMs", len(vm_evidences))


async def _enrich_pg_firewall(creds: ComplianceCredentials, pg_evidences: list[dict]) -> None:
    """Fetch PG Flexible Server firewall rules + SSL parameter."""
    import asyncio
    base = "https://management.azure.com"
    api = "?api-version=2023-06-01-preview"

    async def enrich_one(ev: dict) -> None:
        rid = ev.get("ResourceId", ev.get("resource_id", ""))
        if not rid:
            return
        data = ev.get("Data", ev.get("data", {}))
        fw_url = f"{base}{rid}/firewallRules{api}"
        fw_resp = await _arm_get_json(creds, fw_url)
        if fw_resp and isinstance(fw_resp, dict):
            data["FirewallRules"] = [
                {
                    "name": r.get("name", ""),
                    "startIpAddress": r.get("properties", {}).get("startIpAddress", ""),
                    "endIpAddress": r.get("properties", {}).get("endIpAddress", ""),
                }
                for r in fw_resp.get("value", [])
            ]
        # SSL
        ssl_url = f"{base}{rid}/configurations/require_secure_transport{api}"
        ssl_resp = await _arm_get_json(creds, ssl_url)
        if ssl_resp and isinstance(ssl_resp, dict):
            data["requireSecureTransport"] = ssl_resp.get("properties", {}).get("value", "on").lower()

    await asyncio.gather(*[enrich_one(ev) for ev in pg_evidences], return_exceptions=True)
    log.info("  ARM enrichment: %d PostgreSQL servers", len(pg_evidences))


async def _enrich_mysql_firewall(creds: ComplianceCredentials, mysql_evidences: list[dict]) -> None:
    """Fetch MySQL Flexible Server firewall rules + SSL parameter."""
    import asyncio
    base = "https://management.azure.com"
    api = "?api-version=2023-06-30"

    async def enrich_one(ev: dict) -> None:
        rid = ev.get("ResourceId", ev.get("resource_id", ""))
        if not rid:
            return
        data = ev.get("Data", ev.get("data", {}))
        fw_url = f"{base}{rid}/firewallRules{api}"
        fw_resp = await _arm_get_json(creds, fw_url)
        if fw_resp and isinstance(fw_resp, dict):
            data["FirewallRules"] = [
                {
                    "name": r.get("name", ""),
                    "startIpAddress": r.get("properties", {}).get("startIpAddress", ""),
                    "endIpAddress": r.get("properties", {}).get("endIpAddress", ""),
                }
                for r in fw_resp.get("value", [])
            ]
        ssl_url = f"{base}{rid}/configurations/require_secure_transport{api}"
        ssl_resp = await _arm_get_json(creds, ssl_url)
        if ssl_resp and isinstance(ssl_resp, dict):
            data["requireSecureTransport"] = ssl_resp.get("properties", {}).get("value", "ON").lower()

    await asyncio.gather(*[enrich_one(ev) for ev in mysql_evidences], return_exceptions=True)
    log.info("  ARM enrichment: %d MySQL servers", len(mysql_evidences))


async def _enrich_defender_plans(
    creds: ComplianceCredentials,
    subscription_ids: list[str],
    index: dict[str, list[dict]],
) -> None:
    """Fetch Defender for Cloud pricing plans for data-relevant services."""
    import asyncio
    base = "https://management.azure.com"
    api = "?api-version=2024-01-01"
    plans_of_interest = {"storageaccounts", "sqlservers", "keyvaults",
                         "opensourcerelationaldatabases", "sqlservervirtualmachines",
                         "cosmosdb"}
    index.setdefault("azure-defender-plans", [])

    async def fetch_sub(sub_id: str) -> None:
        url = f"{base}/subscriptions/{sub_id}/providers/Microsoft.Security/pricings{api}"
        resp = await _arm_get_json(creds, url, retry_on_empty_list=True)
        if resp and isinstance(resp, dict):
            for plan in resp.get("value", []):
                name = plan.get("name", "").lower()
                if name in plans_of_interest:
                    tier = plan.get("properties", {}).get("pricingTier", "Free")
                    extensions = plan.get("properties", {}).get("extensions", [])
                    ext_data = [
                        {"name": e.get("name", ""), "isEnabled": e.get("isEnabled", False)}
                        for e in (extensions if isinstance(extensions, list) else [])
                    ]
                    index["azure-defender-plans"].append({
                        "EvidenceType": "azure-defender-plans",
                        "Data": {
                            "name": plan.get("name", ""),
                            "pricingTier": tier,
                            "subscriptionId": sub_id,
                            "extensions": ext_data,
                        },
                        "ResourceId": plan.get("id", ""),
                    })

    await asyncio.gather(*[fetch_sub(sid) for sid in subscription_ids], return_exceptions=True)
    log.info("  ARM enrichment: Defender plans across %d subscriptions", len(subscription_ids))


async def _enrich_diagnostic_settings(
    creds: ComplianceCredentials,
    index: dict[str, list[dict]],
) -> None:
    """Check if data services have diagnostic settings configured."""
    import asyncio
    base = "https://management.azure.com"
    api = "?api-version=2021-05-01-preview"
    index.setdefault("azure-diagnostic-settings", [])

    data_services = (
        index.get("azure-storage-security", [])
        + index.get("azure-sql-server", [])
        + index.get("azure-keyvault", [])
        + index.get("azure-cosmosdb", [])
        + index.get("azure-dbforpostgresql", [])
        + index.get("azure-dbformysql", [])
    )

    async def check_one(ev: dict) -> None:
        rid = ev.get("ResourceId", ev.get("resource_id", ""))
        if not rid:
            return
        url = f"{base}{rid}/providers/Microsoft.Insights/diagnosticSettings{api}"
        resp = await _arm_get_json(creds, url)
        if resp and isinstance(resp, dict):
            settings = resp.get("value", [])
            if settings:
                index["azure-diagnostic-settings"].append({
                    "EvidenceType": "azure-diagnostic-settings",
                    "Data": {"resourceId": rid, "settingsCount": len(settings)},
                    "ResourceId": rid,
                })

    await asyncio.gather(*[check_one(ev) for ev in data_services], return_exceptions=True)
    log.info("  ARM enrichment: diagnostic settings for %d data services", len(data_services))


async def _enrich_sql_sensitivity(
    creds: ComplianceCredentials,
    sql_evidences: list[dict],
) -> None:
    """Fetch SQL sensitivity labels and vulnerability assessment status per database.

    Populates ``_databases`` list on each SQL server evidence with per-database
    sensitivity label info, and ``VulnerabilityAssessmentEnabled`` at server level.
    """
    import asyncio
    base = "https://management.azure.com"
    db_api = "?api-version=2023-05-01-preview"
    label_api = "?api-version=2020-11-01-preview"

    async def enrich_one(ev: dict) -> None:
        rid = ev.get("ResourceId", ev.get("resource_id", ""))
        if not rid:
            return
        data = ev.get("Data", ev.get("data", {}))

        # List databases
        db_url = f"{base}{rid}/databases{db_api}"
        db_resp = await _arm_get_json(creds, db_url)
        db_list: list[dict] = []
        if db_resp and isinstance(db_resp, dict):
            for db in db_resp.get("value", []):
                db_name = db.get("name", "")
                if db_name.lower() == "master":
                    continue
                db_rid = db.get("id", "")
                db_info: dict = {"name": db_name, "id": db_rid}

                # Recommended sensitivity labels (unclassified sensitive columns)
                rec_url = f"{base}{db_rid}/recommendedSensitivityLabels{label_api}"
                rec_resp = await _arm_get_json(creds, rec_url)
                if rec_resp and isinstance(rec_resp, dict):
                    db_info["RecommendedSensitivityLabels"] = [
                        {
                            "column": r.get("properties", {}).get("columnName", ""),
                            "table": r.get("properties", {}).get("tableName", ""),
                            "schema": r.get("properties", {}).get("schemaName", ""),
                            "labelName": r.get("properties", {}).get("sensitivityLabel", ""),
                            "informationType": r.get("properties", {}).get("informationType", ""),
                        }
                        for r in rec_resp.get("value", [])
                    ]
                else:
                    db_info["RecommendedSensitivityLabels"] = []

                # Current sensitivity labels (already classified columns)
                cur_url = f"{base}{db_rid}/currentSensitivityLabels{label_api}"
                cur_resp = await _arm_get_json(creds, cur_url)
                if cur_resp and isinstance(cur_resp, dict):
                    db_info["CurrentSensitivityLabels"] = [
                        {
                            "column": r.get("properties", {}).get("columnName", ""),
                            "table": r.get("properties", {}).get("tableName", ""),
                            "schema": r.get("properties", {}).get("schemaName", ""),
                            "labelName": r.get("properties", {}).get("sensitivityLabel", ""),
                            "informationType": r.get("properties", {}).get("informationType", ""),
                        }
                        for r in cur_resp.get("value", [])
                    ]
                else:
                    db_info["CurrentSensitivityLabels"] = []

                db_list.append(db_info)

        data["_databases"] = db_list

        # Vulnerability Assessment at server level
        va_url = f"{base}{rid}/vulnerabilityAssessments/default{db_api}"
        va_resp = await _arm_get_json(creds, va_url)
        if va_resp and isinstance(va_resp, dict):
            storage_path = va_resp.get("properties", {}).get("storageContainerPath", "")
            recurring = va_resp.get("properties", {}).get("recurringScans", {}).get("isEnabled", False)
            data["VulnerabilityAssessmentEnabled"] = bool(storage_path) or recurring
        else:
            data["VulnerabilityAssessmentEnabled"] = False

    await asyncio.gather(*[enrich_one(ev) for ev in sql_evidences], return_exceptions=True)
    log.info("  ARM enrichment: SQL sensitivity labels for %d servers", len(sql_evidences))


async def _enrich_defender_alerts(
    creds: ComplianceCredentials,
    subscription_ids: list[str],
    index: dict[str, list[dict]],
) -> None:
    """Fetch Defender for Cloud security alerts related to sensitive data.

    Queries ``Microsoft.Security/alerts`` per subscription and keeps alerts
    whose ``alertType`` indicates sensitive-data discovery results (e.g.
    ``Storage.Blob.SensitiveData.*``).
    """
    import asyncio
    base = "https://management.azure.com"
    api = "?api-version=2022-01-01"
    index.setdefault("azure-defender-alerts", [])

    async def fetch_sub(sub_id: str) -> None:
        url = f"{base}/subscriptions/{sub_id}/providers/Microsoft.Security/alerts{api}"
        resp = await _arm_get_json(creds, url)
        if resp and isinstance(resp, dict):
            for alert in resp.get("value", []):
                props = alert.get("properties", {})
                alert_type = props.get("alertType", "")
                if "sensitivedata" in alert_type.lower():
                    index["azure-defender-alerts"].append({
                        "EvidenceType": "azure-defender-alerts",
                        "Data": {
                            "alertType": alert_type,
                            "properties": props,
                            "subscriptionId": sub_id,
                        },
                        "ResourceId": alert.get("id", ""),
                    })

    await asyncio.gather(*[fetch_sub(sid) for sid in subscription_ids],
                          return_exceptions=True)
    log.info("  ARM enrichment: Defender alerts across %d subscriptions "
             "(%d sensitive-data alerts)",
             len(subscription_ids), len(index["azure-defender-alerts"]))


async def _purview_get_json(
    creds: ComplianceCredentials,
    url: str,
    *,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> dict | list | None:
    """GET helper for the Purview Data Map / Scanning API.

    Uses the ``https://purview.azure.net/.default`` token scope instead of the
    ARM management scope.  Retries on transient failures.
    """
    import asyncio
    import aiohttp
    for attempt in range(max_retries):
        try:
            token = await creds.credential.get_token("https://purview.azure.net/.default")
            headers = {"Authorization": f"Bearer {token.token}"}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    if resp.status in (403, 401):
                        log.debug("Purview GET %s → %d (access denied)", url, resp.status)
                        return None
                    if resp.status in (429, 500, 502, 503, 504):
                        delay = base_delay * (2 ** attempt)
                        log.debug("Purview GET %s → %d (attempt %d/%d, retry in %.1fs)",
                                  url, resp.status, attempt + 1, max_retries, delay)
                        await asyncio.sleep(delay)
                        continue
                    log.debug("Purview GET %s → %d", url, resp.status)
                    return None
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as exc:
            delay = base_delay * (2 ** attempt)
            log.debug("Purview GET %s failed (attempt %d/%d): %s", url, attempt + 1, max_retries, exc)
            if attempt < max_retries - 1:
                await asyncio.sleep(delay)
            continue
        except Exception as exc:
            log.debug("Purview GET %s failed: %s", url, exc)
            return None
    return None


async def _enrich_purview_scan_results(
    creds: ComplianceCredentials,
    purview_evidences: list[dict],
    index: dict[str, list[dict]],
) -> None:
    """Fetch scan run status from Purview Scanning API for each Purview account.

    For every registered data source in each Purview account, retrieves the
    list of scans and their latest run status.  Results are stored under
    ``azure-purview-scan-runs`` in the evidence index.
    """
    import asyncio
    api = "?api-version=2023-09-01"
    index.setdefault("azure-purview-scan-runs", [])

    async def process_account(ev: dict) -> None:
        data = ev.get("Data", ev.get("data", {}))
        acct_name = data.get("name", data.get("Name", ""))
        if not acct_name:
            return
        endpoint = f"https://{acct_name}.purview.azure.com"

        # List data sources
        ds_url = f"{endpoint}/scan/datasources{api}"
        ds_resp = await _purview_get_json(creds, ds_url)
        if not ds_resp:
            return
        sources = ds_resp.get("value", []) if isinstance(ds_resp, dict) else (
            ds_resp if isinstance(ds_resp, list) else []
        )

        for source in sources:
            src_name = source.get("name", "")
            if not src_name:
                continue

            # List scans for this source
            scans_url = f"{endpoint}/scan/datasources/{src_name}/scans{api}"
            scans_resp = await _purview_get_json(creds, scans_url)
            if not scans_resp:
                index["azure-purview-scan-runs"].append({
                    "EvidenceType": "azure-purview-scan-runs",
                    "Data": {
                        "sourceName": src_name,
                        "purviewAccount": acct_name,
                        "scanRunCount": 0,
                        "latestRunStatus": "",
                        "latestRunEnd": "",
                    },
                    "ResourceId": ev.get("ResourceId", ""),
                })
                continue

            scans_list = scans_resp.get("value", []) if isinstance(scans_resp, dict) else (
                scans_resp if isinstance(scans_resp, list) else []
            )
            if not scans_list:
                index["azure-purview-scan-runs"].append({
                    "EvidenceType": "azure-purview-scan-runs",
                    "Data": {
                        "sourceName": src_name,
                        "purviewAccount": acct_name,
                        "scanRunCount": 0,
                        "latestRunStatus": "",
                        "latestRunEnd": "",
                    },
                    "ResourceId": ev.get("ResourceId", ""),
                })
                continue

            # Get latest scan run across all scans for this source
            latest_status = ""
            latest_end = ""
            total_runs = 0
            for scan in scans_list:
                scan_name = scan.get("name", "")
                if not scan_name:
                    continue
                runs_url = (
                    f"{endpoint}/scan/datasources/{src_name}"
                    f"/scans/{scan_name}/runs{api}"
                )
                runs_resp = await _purview_get_json(creds, runs_url)
                if not runs_resp:
                    continue
                runs = runs_resp.get("value", []) if isinstance(runs_resp, dict) else (
                    runs_resp if isinstance(runs_resp, list) else []
                )
                total_runs += len(runs)
                for run in runs:
                    run_end = run.get("endTime", run.get("scanResultId", ""))
                    run_status = run.get("status", "")
                    if run_end and (not latest_end or run_end > latest_end):
                        latest_end = run_end
                        latest_status = run_status

            index["azure-purview-scan-runs"].append({
                "EvidenceType": "azure-purview-scan-runs",
                "Data": {
                    "sourceName": src_name,
                    "purviewAccount": acct_name,
                    "scanRunCount": total_runs,
                    "latestRunStatus": latest_status,
                    "latestRunEnd": latest_end,
                },
                "ResourceId": ev.get("ResourceId", ""),
            })

    await asyncio.gather(*[process_account(ev) for ev in purview_evidences],
                          return_exceptions=True)
    log.info("  Purview enrichment: scan runs for %d data sources across %d accounts",
             len(index["azure-purview-scan-runs"]), len(purview_evidences))
