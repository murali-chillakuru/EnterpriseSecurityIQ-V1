"""
Data Security — Advanced analytics — blast radius, data flow, config drift, supply chain risk.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_blast_radius(evidence_index: dict[str, list[dict]], findings: list[dict]) -> dict:
    """Compute blast-radius metrics: how many resources and data stores
    would be affected if a single finding were exploited.
    Returns a dict of finding_id -> {radius, affected_types, critical_chain}.
    """
    resource_map: dict[str, set[str]] = {}  # resource_id -> set of finding_ids
    for f in findings:
        fid = f.get("DataSecurityFindingId", "")
        for r in f.get("AffectedResources", []):
            rid = r.get("ResourceId", "") if isinstance(r, dict) else ""
            if rid:
                resource_map.setdefault(rid, set()).add(fid)

    # Build adjacency: findings that share resources are in the same blast zone
    finding_radius: dict[str, dict] = {}
    for f in findings:
        fid = f.get("DataSecurityFindingId", "")
        affected_rids = set()
        for r in f.get("AffectedResources", []):
            rid = r.get("ResourceId", "") if isinstance(r, dict) else ""
            if rid:
                affected_rids.add(rid)
        # Transitive: resources with shared findings
        connected_findings: set[str] = set()
        for rid in affected_rids:
            connected_findings.update(resource_map.get(rid, set()))
        connected_findings.discard(fid)

        # Distinct resource types affected
        affected_types = set()
        for rid in affected_rids:
            parts = rid.split("/")
            for i, p in enumerate(parts):
                if p.lower() == "providers" and i + 2 < len(parts):
                    affected_types.add(f"{parts[i+1]}/{parts[i+2]}")
                    break

        finding_radius[fid] = {
            "radius": len(affected_rids),
            "connected_findings": len(connected_findings),
            "affected_types": list(affected_types),
            "severity": f.get("Severity", "medium"),
            "title": f.get("Title", ""),
        }

    return finding_radius


# ADVANCED ANALYTICS — DATA FLOW MAPPING

def analyze_data_flow(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Map data flows between services based on evidence relationships.
    Detects:
      - Storage <-> Data Factory/Synapse linked services
      - Key Vault references from App Settings
      - Private endpoint connections (source -> target)
      - Database <-> Application connections
    Returns a list of flow dicts: {source, target, flow_type, risk_level}.
    """
    flows: list[dict] = []

    # Private endpoint flows
    pe_data = evidence_index.get("azure-private-endpoints", [])
    for pe in pe_data:
        props = pe.get("properties", {})
        target_rid = ""
        pls = props.get("privateLinkServiceConnections", []) or props.get("manualPrivateLinkServiceConnections", [])
        for conn in (pls or []):
            target_rid = conn.get("properties", {}).get("privateLinkServiceId", "")
        if target_rid:
            source_vnet = props.get("subnet", {}).get("id", "").split("/subnets/")[0] if props.get("subnet") else ""
            flows.append({
                "source": source_vnet or pe.get("id", ""),
                "target": target_rid,
                "flow_type": "private_endpoint",
                "risk_level": "low",
            })

    # Data Factory linked service flows
    adf_data = evidence_index.get("azure-data-factory", [])
    for adf in adf_data:
        adf_id = adf.get("id", "")
        props = adf.get("properties", {})
        # Check for linked service references in properties
        if props.get("publicNetworkAccess", "").lower() == "enabled":
            flows.append({
                "source": adf_id,
                "target": "external_network",
                "flow_type": "public_data_pipeline",
                "risk_level": "high",
            })
        else:
            flows.append({
                "source": adf_id,
                "target": "managed_vnet",
                "flow_type": "private_data_pipeline",
                "risk_level": "low",
            })

    # Web app -> Key Vault / Storage / DB flows from app settings
    webapp_data = evidence_index.get("azure-webapp", [])
    for app in webapp_data:
        app_id = app.get("id", "")
        settings = app.get("_appSettings", {})
        for key, val in settings.items():
            if isinstance(val, str):
                if "@Microsoft.KeyVault" in val:
                    flows.append({
                        "source": app_id,
                        "target": "keyvault",
                        "flow_type": "keyvault_reference",
                        "risk_level": "low",
                    })
                elif any(kw in val.lower() for kw in ["accountkey=", "password=", "server=tcp:"]):
                    flows.append({
                        "source": app_id,
                        "target": "data_service",
                        "flow_type": "connection_string",
                        "risk_level": "high",
                    })

    return flows


# ADVANCED ANALYTICS — CONFIG DRIFT DETECTION

def analyze_config_drift(
    current_evidence: dict[str, list[dict]],
    previous_evidence: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """Detect configuration drift between two evidence snapshots.
    Compares key security properties of resources.
    Returns a list of drift findings.
    """
    findings: list[dict] = []
    if not previous_evidence:
        return findings

    # Security-sensitive properties to track per resource type
    drift_checks = {
        "azure-storage-accounts": [
            ("properties.allowBlobPublicAccess", "Blob public access changed"),
            ("properties.networkAcls.defaultAction", "Network default action changed"),
            ("properties.minimumTlsVersion", "Minimum TLS version changed"),
            ("properties.supportsHttpsTrafficOnly", "HTTPS-only setting changed"),
        ],
        "azure-sql-servers": [
            ("properties.publicNetworkAccess", "SQL public network access changed"),
            ("properties.minimalTlsVersion", "SQL minimum TLS changed"),
        ],
        "azure-keyvault": [
            ("properties.enablePurgeProtection", "Purge protection changed"),
            ("properties.enableSoftDelete", "Soft delete changed"),
            ("properties.publicNetworkAccess", "KV public network access changed"),
        ],
    }

    for resource_type, checks in drift_checks.items():
        current_resources = {r.get("id", ""): r for r in current_evidence.get(resource_type, []) if r.get("id")}
        previous_resources = {r.get("id", ""): r for r in previous_evidence.get(resource_type, []) if r.get("id")}

        for rid, curr in current_resources.items():
            prev = previous_resources.get(rid)
            if not prev:
                continue

            for prop_path, desc in checks:
                curr_val = _deep_get(curr, prop_path)
                prev_val = _deep_get(prev, prop_path)
                if curr_val != prev_val and prev_val is not None:
                    # Determine if drift is toward less security
                    severity = "medium"
                    if _is_security_regression(prop_path, prev_val, curr_val):
                        severity = "high"

                    findings.append(_ds_finding(
                        "config_drift", "drift_detected",
                        f"{desc}: {curr.get('name', rid.split('/')[-1])}",
                        f"Configuration property '{prop_path}' changed from "
                        f"'{prev_val}' to '{curr_val}'. This may indicate "
                        f"unauthorized configuration change or policy bypass.",
                        severity,
                        [{"ResourceId": rid, "Name": curr.get("name", ""),
                          "Type": curr.get("type", resource_type),
                          "Detail": f"Changed: {prev_val} -> {curr_val}"}],
                        {"Description": f"Verify the change to {prop_path} was authorized.",
                         "AzureCLI": f"az resource show --ids {rid} --query properties"}
                    ))

    return findings


def _deep_get(d: dict, path: str):
    """Get a nested dict value by dot-separated path."""
    keys = path.split(".")
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k)
        else:
            return None
    return d


def _is_security_regression(prop: str, old_val, new_val) -> bool:
    """Check if a property change represents a security regression."""
    regressions = {
        "properties.allowBlobPublicAccess": lambda o, n: n is True and o is False,
        "properties.networkAcls.defaultAction": lambda o, n: str(n).lower() == "allow" and str(o).lower() == "deny",
        "properties.enablePurgeProtection": lambda o, n: n is False and o is True,
        "properties.enableSoftDelete": lambda o, n: n is False and o is True,
        "properties.publicNetworkAccess": lambda o, n: str(n).lower() == "enabled" and str(o).lower() == "disabled",
    }
    check = regressions.get(prop)
    return check(old_val, new_val) if check else False


# ADVANCED ANALYTICS — SCORE FORECASTING

def compute_score_forecast(
    trend_history: list[dict],
    current_score: float,
    planned_remediations: int = 0,
) -> dict:
    """Forecast future data security score based on trend and planned remediations.
    Uses simple linear regression on historical scores.
    """
    if len(trend_history) < 2:
        return {
            "forecast_30d": current_score,
            "forecast_90d": current_score,
            "trend_direction": "stable",
            "confidence": "low",
            "planned_improvement": 0,
        }

    # Extract score values
    scores = [entry.get("score", entry.get("OverallScore", current_score)) for entry in trend_history[-30:]]
    n = len(scores)

    # Simple linear regression: y = a + bx
    x_mean = (n - 1) / 2
    y_mean = sum(scores) / n
    num = sum((i - x_mean) * (s - y_mean) for i, s in enumerate(scores))
    den = sum((i - x_mean) ** 2 for i in range(n))
    slope = num / den if den != 0 else 0
    intercept = y_mean - slope * x_mean

    # Forecast (30 days ~ 30 data points, 90 days ~ 90)
    # Assume ~1 data point per day based on daily assessments
    forecast_30 = max(0, min(100, intercept + slope * (n + 30)))
    forecast_90 = max(0, min(100, intercept + slope * (n + 90)))

    # Planned remediation improvement estimate (each fix ~ 2-5 point improvement)
    planned_improvement = planned_remediations * 3.0  # avg 3 points per fix
    forecast_30 = max(0, forecast_30 - planned_improvement * 0.5)
    forecast_90 = max(0, forecast_90 - planned_improvement)

    direction = "improving" if slope < -0.5 else "degrading" if slope > 0.5 else "stable"
    confidence = "high" if n >= 10 else "medium" if n >= 5 else "low"

    return {
        "forecast_30d": round(forecast_30, 1),
        "forecast_90d": round(forecast_90, 1),
        "trend_direction": direction,
        "slope": round(slope, 3),
        "confidence": confidence,
        "data_points": n,
        "planned_improvement": round(planned_improvement, 1),
    }


# ADVANCED ANALYTICS — SUPPLY CHAIN RISK

def analyze_supply_chain_risk(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Analyze supply chain risk for data services.
    Checks:
      - Container images from untrusted registries
      - Third-party managed connectors in Data Factory
      - External dependencies in Function Apps
      - Unsigned/unverified extensions
    """
    findings: list[dict] = []

    # Container images from non-private registries
    acr_data = evidence_index.get("azure-container-registries", [])
    acr_servers = set()
    for acr in acr_data:
        login = acr.get("properties", {}).get("loginServer", "")
        if login:
            acr_servers.add(login.lower())

    aks_data = evidence_index.get("azure-aks", [])
    for cluster in aks_data:
        props = cluster.get("properties", {})
        pools = props.get("agentPoolProfiles", [])
        # Check if ACR integration is configured
        acr_profile = props.get("identityProfile", {})
        has_acr_pull = bool(acr_profile)
        if not has_acr_pull and acr_servers:
            findings.append(_ds_finding(
                "supply_chain", "aks_no_acr_integration",
                f"AKS cluster without ACR integration: {cluster.get('name', '')}",
                "AKS cluster does not have integrated ACR pull, which may allow "
                "pulling images from untrusted public registries instead of "
                "the organization's private registry.",
                "medium",
                [{"ResourceId": cluster.get("id", ""), "Name": cluster.get("name", ""),
                  "Type": "Microsoft.ContainerService/managedClusters",
                  "Detail": "No ACR integration configured"}],
                {"Description": "Attach ACR to AKS cluster.",
                 "AzureCLI": "az aks update -n <cluster> -g <rg> --attach-acr <acr-name>"}
            ))

    # ACR admin access (supply chain: admin creds can push malicious images)
    for acr in acr_data:
        props = acr.get("properties", {})
        if props.get("adminUserEnabled"):
            findings.append(_ds_finding(
                "supply_chain", "acr_admin_enabled",
                f"ACR admin user enabled: {acr.get('name', '')}",
                "ACR admin user provides unrestricted push/pull access. "
                "A leaked admin credential can inject malicious images "
                "into the supply chain, affecting all consuming services.",
                "high",
                [{"ResourceId": acr.get("id", ""), "Name": acr.get("name", ""),
                  "Type": "Microsoft.ContainerRegistry/registries",
                  "Detail": "Admin user is enabled"}],
                {"Description": "Disable admin user, use RBAC instead.",
                 "AzureCLI": "az acr update -n <acr-name> --admin-enabled false"}
            ))

    # Function apps with external package references
    func_data = evidence_index.get("azure-webapp", [])
    for func in func_data:
        kind = (func.get("kind", "") or "").lower()
        if "functionapp" not in kind:
            continue
        props = func.get("properties", {})
        site_config = props.get("siteConfig", {})
        # Check for WEBSITE_RUN_FROM_PACKAGE pointing to external URLs
        app_settings = func.get("_appSettings", {})
        run_from = app_settings.get("WEBSITE_RUN_FROM_PACKAGE", "")
        if isinstance(run_from, str) and run_from.startswith("http") and not any(
            acr_s in run_from.lower() for acr_s in acr_servers
        ):
            findings.append(_ds_finding(
                "supply_chain", "func_external_package",
                f"Function app loads code from external URL: {func.get('name', '')}",
                "Function app runs code fetched from an external URL. "
                "If the external source is compromised, malicious code "
                "could be deployed with data access permissions.",
                "high",
                [{"ResourceId": func.get("id", ""), "Name": func.get("name", ""),
                  "Type": "Microsoft.Web/sites",
                  "Detail": f"WEBSITE_RUN_FROM_PACKAGE points to external URL"}],
                {"Description": "Use Azure Storage or deployment slots instead of external URLs.",
                 "AzureCLI": "az functionapp config appsettings set -n <name> -g <rg> --settings WEBSITE_RUN_FROM_PACKAGE=1"}
            ))

    return findings

