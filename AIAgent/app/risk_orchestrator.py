"""
Risk Analysis Orchestrator.

Coordinates evidence collection, evaluator invocation, and result aggregation.
Mirrors the Data Security / PostureIQ orchestrator pattern.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.auth import ComplianceCredentials
from app.collectors.base import paginate_arm, AccessDeniedError
from app.risk_evaluators.identity import analyze_identity_risk
from app.risk_evaluators.network import analyze_network_risk
from app.risk_evaluators.defender import analyze_defender_posture
from app.risk_evaluators.config_drift import analyze_config_drift
from app.risk_evaluators.insider_risk import analyze_insider_risk
from app.risk_evaluators.scoring import compute_risk_scores
from app.risk_evaluators.enrichment import enrich_compliance_mapping

log = logging.getLogger(__name__)


async def run_risk_analysis(
    creds: ComplianceCredentials,
    evidence: list[dict] | None = None,
    subscriptions: list[dict] | None = None,
    thresholds: Any | None = None,
) -> dict:
    """Run complete risk analysis.

    If *evidence* is provided (from a prior assessment) it is reused;
    otherwise a lightweight ARG + Graph collection is performed.
    """
    if subscriptions is None:
        subscriptions = await creds.list_subscriptions()

    # Build evidence index
    evidence_index: dict[str, list[dict]] = {}
    if evidence:
        for ev in evidence:
            etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
            if etype:
                evidence_index.setdefault(etype, []).append(ev)

    has_evidence = bool(evidence_index)
    if not has_evidence:
        log.info("No existing evidence — running lightweight collection via ARG + Graph")
        evidence_index = await _lightweight_collect(creds, subscriptions)

    log.info("Running identity risk analysis …")
    identity_findings = analyze_identity_risk(evidence_index, thresholds)

    log.info("Running network risk analysis …")
    network_findings = analyze_network_risk(evidence_index)

    log.info("Running Defender posture analysis …")
    defender_findings = await analyze_defender_posture(creds, subscriptions, evidence_index)

    log.info("Running config drift analysis …")
    config_findings = analyze_config_drift(evidence_index)

    log.info("Running insider risk analysis …")
    insider_findings = analyze_insider_risk(evidence_index)

    all_findings = identity_findings + network_findings + defender_findings + config_findings + insider_findings
    enrich_compliance_mapping(all_findings)
    log.info("Computing risk scores (%d findings) …", len(all_findings))
    scores = compute_risk_scores(all_findings)

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

    return {
        "AnalysisId": str(uuid.uuid4()),
        "AnalyzedAt": datetime.now(timezone.utc).isoformat(),
        "TenantId": creds.tenant_id,
        "TenantDisplayName": _tenant_display,
        "SubscriptionCount": len(subscriptions),
        "EvidenceSource": "existing_assessment" if has_evidence else "lightweight_collection",
        "EvidenceRecordCount": sum(len(v) for v in evidence_index.values()),
        "RiskScores": scores,
        "Findings": all_findings,
        "FindingCount": len(all_findings),
        "Categories": {
            "identity": identity_findings,
            "network": network_findings,
            "defender": defender_findings,
            "config": config_findings,
            "insider_risk": insider_findings,
        },
        "CategoryCounts": {
            "identity": len(identity_findings),
            "network": len(network_findings),
            "defender": len(defender_findings),
            "config": len(config_findings),
            "insider_risk": len(insider_findings),
        },
    }


async def _lightweight_collect(
    creds: ComplianceCredentials,
    subscriptions: list[dict],
) -> dict[str, list[dict]]:
    """Quick evidence collection using ARG + Graph for standalone risk analysis."""
    from app.query_evaluators.arg_queries import query_resource_graph

    # --- Risk-specific KQL (inlined to avoid coupling to Cloud Explorer) ---
    _RISK_KQL_ALL_RESOURCES = """
        Resources
        | project name, type, location, resourceGroup, subscriptionId, tags
        | order by type, name
    """
    _RISK_KQL_NSG_OPEN_RULES = """
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
    """
    _RISK_KQL_PUBLIC_IPS = """
        Resources
        | where type =~ 'microsoft.network/publicipaddresses'
        | project name, resourceGroup, location, properties.ipAddress,
                  properties.publicIPAllocationMethod, subscriptionId
    """
    _RISK_KQL_STORAGE_PUBLIC_ACCESS = """
        Resources
        | where type =~ 'microsoft.storage/storageaccounts'
        | where properties.allowBlobPublicAccess == true
               or properties.publicNetworkAccess == 'Enabled'
        | project name, resourceGroup, location,
                  properties.allowBlobPublicAccess,
                  properties.publicNetworkAccess, subscriptionId
    """
    _RISK_KQL_SQL_SERVERS = """
        Resources
        | where type =~ 'microsoft.sql/servers'
        | project name, resourceGroup, location,
                  properties.administratorLogin,
                  properties.publicNetworkAccess, subscriptionId
    """

    index: dict[str, list[dict]] = {}
    sub_ids = [s.get("subscription_id", s.get("subscriptionId", "")) for s in subscriptions]

    # 1) All resources (used by config drift)
    try:
        results = await query_resource_graph(creds, _RISK_KQL_ALL_RESOURCES, sub_ids, top=1000)
        index["azure-resource"] = [
            {"EvidenceType": "azure-resource", "Data": r, "ResourceId": r.get("id", "")}
            for r in results
        ]
    except Exception as exc:
        log.warning("ARG all_resources failed: %s", exc)

    # 2) NSG open rules
    try:
        nsg_rows = await query_resource_graph(creds, _RISK_KQL_NSG_OPEN_RULES, sub_ids, top=1000)
        nsg_map: dict[str, dict] = {}
        for row in nsg_rows:
            nsg_name = row.get("nsgName", row.get("name", "Unknown"))
            rg = row.get("resourceGroup", "")
            port = str(row.get("destinationPort", ""))
            if nsg_name not in nsg_map:
                nsg_map[nsg_name] = {
                    "NsgName": nsg_name, "ResourceGroup": rg,
                    "RdpExposed": False, "SshExposed": False,
                }
            if port in ("3389", "*"):
                nsg_map[nsg_name]["RdpExposed"] = True
            if port in ("22", "*"):
                nsg_map[nsg_name]["SshExposed"] = True
        index["azure-network-security-nsg"] = [
            {"EvidenceType": "azure-network-security-nsg", "Data": v,
             "ResourceId": f"/subscriptions/nsg/{v['NsgName']}"}
            for v in nsg_map.values()
        ]
        log.info("Lightweight NSG: %d NSGs with open rules", len(nsg_map))
    except Exception as exc:
        log.warning("ARG nsg_open_rules failed: %s", exc)

    # 3) Public IPs (informational)
    try:
        results = await query_resource_graph(creds, _RISK_KQL_PUBLIC_IPS, sub_ids, top=1000)
        index["public-ips"] = [
            {"EvidenceType": "public-ips", "Data": r, "ResourceId": r.get("id", "")}
            for r in results
        ]
    except Exception as exc:
        log.warning("ARG public_ips failed: %s", exc)

    # 4) Storage public access
    try:
        storage_rows = await query_resource_graph(creds, _RISK_KQL_STORAGE_PUBLIC_ACCESS, sub_ids, top=1000)
        index["azure-storage-security"] = [
            {"EvidenceType": "azure-storage-security",
             "Data": {
                 "StorageAccountName": r.get("name", "Unknown"),
                 "AllowBlobPublicAccess": r.get("properties_allowBlobPublicAccess",
                                                 r.get("allowBlobPublicAccess", True)),
                 "ResourceGroup": r.get("resourceGroup", ""),
             },
             "ResourceId": r.get("id", "")}
            for r in storage_rows
        ]
        log.info("Lightweight storage: %d public accounts", len(storage_rows))
    except Exception as exc:
        log.warning("ARG storage_public_access failed: %s", exc)

    # 5) Web apps
    _webapp_kql = """
        Resources
        | where type =~ 'microsoft.web/sites'
        | project name, resourceGroup, location,
                  properties.httpsOnly, properties.siteConfig.minTlsVersion,
                  subscriptionId, id
    """
    try:
        webapp_rows = await query_resource_graph(creds, _webapp_kql, sub_ids, top=1000)
        index["azure-webapp-config"] = [
            {"EvidenceType": "azure-webapp-config",
             "Data": {
                 "Name": r.get("name", "Unknown"),
                 "HttpsOnly": r.get("properties_httpsOnly", r.get("httpsOnly")),
                 "MinTlsVersion": r.get("properties_siteConfig_minTlsVersion",
                                        r.get("minTlsVersion", "")),
                 "ResourceGroup": r.get("resourceGroup", ""),
             },
             "ResourceId": r.get("id", "")}
            for r in webapp_rows
        ]
        log.info("Lightweight webapps: %d apps", len(webapp_rows))
    except Exception as exc:
        log.warning("ARG webapp query failed: %s", exc)

    # 6) SQL servers with firewall rules via ARM
    try:
        sql_rows = await query_resource_graph(creds, _RISK_KQL_SQL_SERVERS, sub_ids, top=1000)
        for sr in sql_rows:
            sql_id = sr.get("id", "")
            fw_rules: list[dict] = []
            if sql_id:
                try:
                    fw_resp = await paginate_arm(
                        creds, f"{sql_id}/firewallRules", "2021-11-01"
                    )
                    fw_rules = [
                        {
                            "Name": fw.get("name", ""),
                            "StartIpAddress": fw.get("properties", {}).get("startIpAddress", ""),
                            "EndIpAddress": fw.get("properties", {}).get("endIpAddress", ""),
                        }
                        for fw in fw_resp
                    ]
                except (AccessDeniedError, Exception) as fw_exc:
                    log.debug("SQL firewall rules fetch failed for %s: %s", sql_id, fw_exc)
            index.setdefault("azure-sql-server", []).append({
                "EvidenceType": "azure-sql-server",
                "Data": {
                    "Name": sr.get("name", "Unknown"),
                    "ResourceGroup": sr.get("resourceGroup", ""),
                    "PublicNetworkAccess": sr.get("properties_publicNetworkAccess",
                                                   sr.get("publicNetworkAccess", "")),
                    "FirewallRules": fw_rules,
                },
                "ResourceId": sql_id,
            })
        log.info("Lightweight SQL: %d servers", len(sql_rows))
    except Exception as exc:
        log.warning("ARG sql_servers failed: %s", exc)

    # 7) Role assignments via ARM
    for sid in sub_ids:
        if not sid:
            continue
        try:
            ra_list = await paginate_arm(
                creds,
                f"/subscriptions/{sid}/providers/Microsoft.Authorization/roleAssignments",
                "2022-04-01",
            )
            for ra in ra_list:
                props = ra.get("properties", {})
                role_def_id = props.get("roleDefinitionId", "")
                role_name = ""
                if role_def_id:
                    try:
                        rd_resp = await paginate_arm(creds, role_def_id, "2022-04-01")
                        if isinstance(rd_resp, dict):
                            role_name = rd_resp.get("properties", {}).get("roleName", "")
                        elif isinstance(rd_resp, list) and rd_resp:
                            role_name = rd_resp[0].get("properties", {}).get("roleName", "")
                    except Exception:
                        pass
                index.setdefault("azure-role-assignment", []).append({
                    "EvidenceType": "azure-role-assignment",
                    "Data": {
                        "PrincipalId": props.get("principalId", ""),
                        "PrincipalType": props.get("principalType", ""),
                        "RoleName": role_name,
                        "Scope": props.get("scope", ""),
                    },
                    "ResourceId": ra.get("id", ""),
                })
            log.info("Lightweight role assignments for %s: %d", sid[:8], len(ra_list))
        except (AccessDeniedError, Exception) as exc:
            log.warning("Role assignments failed for %s: %s", sid[:8], exc)

    # 8) Entra user summary, MFA, roles, apps via Graph
    try:
        from app.collectors.graph.entra_collector import (
            collect_user_summary, collect_mfa_summary,
            collect_directory_role_members, collect_applications,
            collect_risky_users, collect_access_reviews,
        )
        graph_creds = creds

        user_summary = await collect_user_summary(graph_creds)
        if user_summary:
            index["entra-user-summary"] = [{"EvidenceType": "entra-user-summary", "Data": user_summary}]

        mfa_summary = await collect_mfa_summary(graph_creds)
        if mfa_summary:
            index["entra-mfa-summary"] = [{"EvidenceType": "entra-mfa-summary", "Data": mfa_summary}]

        role_members = await collect_directory_role_members(graph_creds)
        index["entra-directory-role-member"] = [
            {"EvidenceType": "entra-directory-role-member", "Data": rm}
            for rm in role_members
        ]

        apps = await collect_applications(graph_creds)
        index["entra-application"] = [
            {"EvidenceType": "entra-application", "Data": a}
            for a in apps
        ]

        risky = await collect_risky_users(graph_creds)
        index["entra-risky-user"] = [
            {"EvidenceType": "entra-risky-user", "Data": r}
            for r in risky
        ]

        reviews = await collect_access_reviews(graph_creds)
        index["entra-access-review"] = [
            {"EvidenceType": "entra-access-review", "Data": r}
            for r in reviews
        ]
    except ImportError:
        log.warning("Graph collectors not available for lightweight risk collection")
    except Exception as exc:
        log.warning("Lightweight Graph collection failed: %s", exc)

    return index
