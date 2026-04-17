"""
Data Security — Data Classification & Labeling evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_data_classification_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data classification, sensitivity labeling, and data-discovery posture.

    Checks whether sensitive data in SQL databases is properly classified and
    labelled, whether Purview scans are covering data stores, whether Defender
    sensitive-data discovery is enabled, whether data services exist without
    any classification or governance setup, whether Defender has detected
    actual sensitive data in storage, and whether Purview scans have run
    successfully.
    """
    findings: list[dict] = []
    findings.extend(_check_sql_sensitivity_labels(evidence_index))
    findings.extend(_check_sql_vulnerability_assessment(evidence_index))
    findings.extend(_check_defender_sensitive_data_discovery(evidence_index))
    findings.extend(_check_purview_classification_coverage(evidence_index))
    findings.extend(_check_unclassified_data_stores(evidence_index))
    findings.extend(_check_defender_sdd_alerts(evidence_index))
    findings.extend(_check_purview_scan_results(evidence_index))
    findings.extend(_check_auto_labeling_policies(evidence_index))
    return findings


def _check_auto_labeling_policies(idx: dict) -> list[dict]:
    """Flag if no auto-labeling policies exist for sensitivity labels."""
    labels = idx.get("m365-sensitivity-label-definition", [])
    if not labels:
        return []
    has_auto = False
    for ev in labels:
        data = ev.get("Data", ev.get("data", {}))
        auto_conditions = data.get("autoLabelingConditions",
                         data.get("AutoLabelingConditions"))
        auto_labeling = data.get("autoLabeling", data.get("AutoLabeling", {}))
        if auto_conditions or (isinstance(auto_labeling, dict) and
                               auto_labeling.get("isEnabled", False)):
            has_auto = True
            break
    if not has_auto:
        return [_ds_finding(
            "data_classification", "no_auto_labeling",
            "No auto-labeling policies configured for sensitivity labels",
            "Without auto-labeling, sensitivity labels must be applied manually "
            "by users. Auto-labeling automatically classifies content based on "
            "sensitive information types, ensuring consistent data protection.",
            "medium", [],
            {"Description": "Configure auto-labeling policies in Microsoft Purview.",
             "PortalSteps": [
                 "Go to compliance.microsoft.com > Information protection > Auto-labeling",
                 "Create auto-labeling policies for PII, financial, and health data",
                 "Test in simulation mode before activating",
             ]},
        )]
    return []


def _check_sql_sensitivity_labels(idx: dict) -> list[dict]:
    """Flag SQL databases with recommended sensitivity labels that have not been applied.

    ARM enrichment populates ``RecommendedSensitivityLabels`` (columns the engine
    has detected as potentially sensitive) and ``CurrentSensitivityLabels`` (columns
    already classified).  A gap means sensitive columns are unlabelled.
    """
    sql_servers = idx.get("azure-sql-server", [])
    flagged: list[dict] = []
    for ev in sql_servers:
        data = ev.get("Data", ev.get("data", {}))
        dbs = data.get("_databases", [])
        for db in dbs:
            recommended = db.get("RecommendedSensitivityLabels", [])
            current = db.get("CurrentSensitivityLabels", [])
            if recommended and len(recommended) > len(current):
                gap = len(recommended) - len(current)
                flagged.append({
                    "Type": "SQL Database",
                    "Name": f"{data.get('Name', data.get('name', 'Unknown'))}/{db.get('name', 'Unknown')}",
                    "ResourceId": db.get("id", ev.get("ResourceId", "")),
                    "RecommendedColumns": len(recommended),
                    "LabeledColumns": len(current),
                    "UnlabeledColumns": gap,
                })

    if flagged:
        total_gap = sum(r["UnlabeledColumns"] for r in flagged)
        return [_ds_finding(
            "data_classification", "sql_unlabeled_sensitive_columns",
            f"{total_gap} sensitive SQL columns lack classification labels across {len(flagged)} database(s)",
            "SQL Data Discovery has identified columns containing potentially sensitive data "
            "(PII, financial, health) that have not been assigned sensitivity labels. "
            "Unlabeled columns cannot be governed by DLP or access policies.",
            "high", flagged,
            {"Description": "Review and apply recommended sensitivity labels.",
             "PortalSteps": [
                 "Azure Portal \u2192 SQL database \u2192 Data Discovery & Classification",
                 "Review recommendations and accept/modify labels",
                 "Click \u2018Accept all\u2019 or label columns individually",
             ],
             "TSQL": "-- View recommended labels\nSELECT * FROM sys.sensitivity_classifications;"},
        )]
    return []


def _check_sql_vulnerability_assessment(idx: dict) -> list[dict]:
    """Flag SQL servers where Vulnerability Assessment (data discovery) is not configured."""
    sql_servers = idx.get("azure-sql-server", [])
    no_va: list[dict] = []
    for ev in sql_servers:
        data = ev.get("Data", ev.get("data", {}))
        va_state = data.get("VulnerabilityAssessmentEnabled")
        # Only flag if we have explicitly checked (enriched) and it's disabled
        if va_state is False:
            no_va.append({
                "Type": "SQL Server",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })

    if no_va:
        return [_ds_finding(
            "data_classification", "sql_va_disabled",
            f"{len(no_va)} SQL servers without Vulnerability Assessment / Data Discovery",
            "SQL Vulnerability Assessment includes data discovery & classification which "
            "automatically identifies columns containing sensitive data. Without it, "
            "sensitive data may go undetected and unlabeled.",
            "medium", no_va,
            {"Description": "Enable SQL Vulnerability Assessment with data discovery.",
             "AzureCLI": (
                 "az sql server va create -n <server> -g <rg> "
                 "--storage-account <sa> --storage-container-path <path>"
             ),
             "PortalSteps": [
                 "Azure Portal \u2192 SQL server \u2192 Microsoft Defender for SQL",
                 "Enable Vulnerability Assessment",
                 "Configure storage account for scan results",
             ]},
        )]
    return []


def _check_defender_sensitive_data_discovery(idx: dict) -> list[dict]:
    """Flag subscriptions where Defender for Storage's sensitive-data discovery is disabled."""
    plans = idx.get("azure-defender-plans", [])
    # Find StorageAccounts plans
    storage_plans: list[dict] = []
    for ev in plans:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("name", "").lower() == "storageaccounts":
            storage_plans.append(ev)

    if not storage_plans:
        return []  # No Defender plans collected at all

    no_sdd: list[dict] = []
    for ev in storage_plans:
        data = ev.get("Data", ev.get("data", {}))
        extensions = data.get("extensions", [])
        sdd_enabled = False
        for ext in extensions:
            if isinstance(ext, dict) and ext.get("name", "").lower() == "sensitivedatadiscovery":
                sdd_enabled = ext.get("isEnabled", "") in (True, "true", "True")
                break

        tier = data.get("pricingTier", "Free")
        if tier.lower() == "free" or not sdd_enabled:
            no_sdd.append({
                "Type": "Defender Plan",
                "Name": f"StorageAccounts ({data.get('subscriptionId', 'N/A')[:8]}…)",
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "PricingTier": tier,
                "SensitiveDataDiscovery": "Enabled" if sdd_enabled else "Disabled",
            })

    if no_sdd:
        return [_ds_finding(
            "data_classification", "defender_storage_sdd_disabled",
            f"Defender sensitive-data discovery disabled in {len(no_sdd)} subscription(s)",
            "Microsoft Defender for Storage can automatically discover blobs containing "
            "sensitive information (PII, financial data, secrets). Without this, sensitive "
            "files in storage accounts may go undetected.",
            "high", no_sdd,
            {"Description": "Enable Defender for Storage with sensitive-data discovery.",
             "AzureCLI": (
                 "az security pricing create -n StorageAccounts --tier Standard "
                 "--extensions name=SensitiveDataDiscovery isEnabled=true"
             ),
             "PortalSteps": [
                 "Azure Portal \u2192 Microsoft Defender for Cloud \u2192 Environment settings",
                 "Select subscription \u2192 Defender plans \u2192 Storage",
                 "Enable \u2018Sensitive data discovery\u2019 extension",
             ]},
        )]
    return []


def _check_purview_classification_coverage(idx: dict) -> list[dict]:
    """Flag data stores that are not registered as Purview data sources.

    If a Purview account exists but there are data services (SQL, Storage,
    Cosmos, PG, MySQL) with no evidence of Purview scanning, the organisation
    likely has a coverage gap.
    """
    purview = idx.get("azure-purview", [])
    if not purview:
        return []  # No Purview \u2192 handled by purview category

    # Count data services
    data_service_types = {
        "azure-storage-security": "Storage Account",
        "azure-sql-server": "SQL Server",
        "azure-cosmosdb": "Cosmos DB",
        "azure-dbforpostgresql": "PostgreSQL",
        "azure-dbformysql": "MySQL",
    }
    unregistered: list[dict] = []
    registered_sources = idx.get("azure-purview-datasources", [])
    registered_ids = {
        ev.get("ResourceId", ev.get("resource_id", "")).lower()
        for ev in registered_sources
    }

    for etype, label in data_service_types.items():
        for ev in idx.get(etype, []):
            rid = ev.get("ResourceId", ev.get("resource_id", "")).lower()
            if rid and rid not in registered_ids:
                data = ev.get("Data", ev.get("data", {}))
                unregistered.append({
                    "Type": label,
                    "Name": data.get("name", data.get("Name", "Unknown")),
                    "ResourceId": rid,
                })

    if unregistered:
        return [_ds_finding(
            "data_classification", "purview_scan_coverage_gap",
            f"{len(unregistered)} data service(s) not registered for Purview scanning",
            "Microsoft Purview is deployed but not all data services are registered as "
            "data sources. Unregistered sources are not scanned for sensitive data "
            "classification, leaving a governance blind spot.",
            "medium", unregistered,
            {"Description": "Register all data services as Purview data sources.",
             "PortalSteps": [
                 "Microsoft Purview governance portal \u2192 Data Map \u2192 Data Sources",
                 "Register each unregistered data service",
                 "Create and schedule scans with appropriate classification rules",
             ]},
        )]
    return []


def _check_unclassified_data_stores(idx: dict) -> list[dict]:
    """Flag data services that have no classification, labelling, or governance setup.

    A data store is considered \u2018unclassified\u2019 if:
      - No Purview account exists AND
      - No Defender sensitive-data discovery is enabled AND
      - (For SQL) no sensitivity labels exist
    """
    purview = idx.get("azure-purview", [])
    # Check if Defender SDD is enabled on any subscription
    defender_sdd_active = False
    for ev in idx.get("azure-defender-plans", []):
        data = ev.get("Data", ev.get("data", {}))
        if data.get("name", "").lower() == "storageaccounts":
            for ext in data.get("extensions", []):
                if isinstance(ext, dict) and ext.get("name", "").lower() == "sensitivedatadiscovery":
                    if ext.get("isEnabled", "") in (True, "true", "True"):
                        defender_sdd_active = True

    if purview or defender_sdd_active:
        return []  # At least one classification mechanism is in place

    # Count unclassified data stores
    data_service_types = {
        "azure-storage-security": "Storage Account",
        "azure-sql-server": "SQL Server",
        "azure-cosmosdb": "Cosmos DB",
        "azure-dbforpostgresql": "PostgreSQL",
        "azure-dbformysql": "MySQL",
    }
    unclassified: list[dict] = []
    for etype, label in data_service_types.items():
        for ev in idx.get(etype, []):
            data = ev.get("Data", ev.get("data", {}))
            unclassified.append({
                "Type": label,
                "Name": data.get("name", data.get("Name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })

    if unclassified:
        return [_ds_finding(
            "data_classification", "no_data_classification",
            f"{len(unclassified)} data service(s) have no classification or governance",
            "No Microsoft Purview account and no Defender sensitive-data discovery is "
            "enabled. Sensitive data across storage accounts, databases, and other data "
            "services cannot be automatically identified, classified, or labelled.",
            "high", unclassified,
            {"Description": "Deploy Microsoft Purview or enable Defender for Storage "
             "sensitive-data discovery to identify and classify sensitive data.",
             "PortalSteps": [
                 "Option A: Create a Microsoft Purview account and register data sources",
                 "Option B: Enable Defender for Storage with sensitive-data discovery",
                 "Option C: Manually classify SQL columns via Data Discovery & Classification",
             ]},
        )]
    return []


def _check_defender_sdd_alerts(idx: dict) -> list[dict]:
    """Surface actual Defender for Storage sensitive-data alerts.

    Unlike ``_check_defender_sensitive_data_discovery`` which checks whether the
    SDD *feature* is enabled, this check reports what Defender actually found —
    storage accounts that contain blobs flagged as holding PII, financial data,
    or other sensitive content.
    """
    alerts = idx.get("azure-defender-alerts", [])
    if not alerts:
        return []

    # Group alerts by target storage account
    by_account: dict[str, list[dict]] = {}
    for ev in alerts:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", {})
        alert_type = props.get("alertType", data.get("alertType", ""))
        # Defender for Storage SDD alerts use alertType prefix:
        #   Storage.Blob.SensitiveData.*
        if "sensitivedata" not in alert_type.lower():
            continue
        # Extract attacked resource (the storage account)
        entity_id = ""
        for entity in props.get("entities", []):
            rid = entity.get("resourceId", entity.get("id", ""))
            if "storageaccounts" in rid.lower():
                entity_id = rid
                break
        if not entity_id:
            entity_id = props.get("attackedResourceId",
                                  data.get("attackedResourceId", ""))
        acct_name = entity_id.rsplit("/", 1)[-1] if entity_id else alert_type
        by_account.setdefault(acct_name, []).append({
            "alertType": alert_type,
            "severity": props.get("severity", data.get("severity", "")),
            "status": props.get("status", data.get("status", "")),
            "description": props.get("description", data.get("description", ""))[:200],
            "resourceId": entity_id,
        })

    if not by_account:
        return []

    total_alerts = sum(len(v) for v in by_account.values())
    affected: list[dict] = []
    for acct, acct_alerts in by_account.items():
        severities = {a["severity"] for a in acct_alerts if a["severity"]}
        affected.append({
            "Type": "Storage Account",
            "Name": acct,
            "ResourceId": acct_alerts[0].get("resourceId", ""),
            "AlertCount": len(acct_alerts),
            "AlertSeverities": ", ".join(sorted(severities)) or "N/A",
            "SampleAlertTypes": ", ".join(sorted({a["alertType"] for a in acct_alerts[:3]})),
        })

    return [_ds_finding(
        "data_classification", "defender_sdd_sensitive_data_found",
        f"Defender detected sensitive data in {len(by_account)} storage account(s) "
        f"({total_alerts} alert(s))",
        "Microsoft Defender for Storage sensitive-data discovery has identified blobs "
        "containing potentially sensitive information (PII, financial data, credentials). "
        "Review the alerts and ensure proper access controls, encryption, and data "
        "governance are applied to the affected accounts.",
        "high", affected,
        {"Description": "Review Defender alerts and apply data governance controls.",
         "PortalSteps": [
             "Azure Portal → Microsoft Defender for Cloud → Security alerts",
             "Filter by alert type 'Storage.Blob.SensitiveData'",
             "Review affected blobs and apply sensitivity labels or access restrictions",
             "Consider moving sensitive data to dedicated, hardened storage accounts",
         ]},
    )]


def _check_purview_scan_results(idx: dict) -> list[dict]:
    """Flag Purview data sources with failed, stale, or never-executed scans.

    Enrichment populates ``azure-purview-scan-runs`` with per-source scan run
    status.  A source is flagged if its latest scan failed, never ran, or last
    succeeded more than 30 days ago.
    """
    scan_runs = idx.get("azure-purview-scan-runs", [])
    if not scan_runs:
        return []

    problem_sources: list[dict] = []
    for ev in scan_runs:
        data = ev.get("Data", ev.get("data", {}))
        source_name = data.get("sourceName", "Unknown")
        latest_status = data.get("latestRunStatus", "")
        latest_end = data.get("latestRunEnd", "")
        scan_count = data.get("scanRunCount", 0)

        issue = ""
        if scan_count == 0 or latest_status == "":
            issue = "Never scanned"
        elif latest_status.lower() in ("failed", "cancelled"):
            issue = f"Latest scan {latest_status.lower()}"
        elif latest_end:
            try:
                end_dt = datetime.fromisoformat(latest_end.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - end_dt).days
                if age_days > 30:
                    issue = f"Stale — last successful scan {age_days} days ago"
            except (ValueError, TypeError):
                pass

        if issue:
            problem_sources.append({
                "Type": "Purview Data Source",
                "Name": source_name,
                "ResourceId": ev.get("ResourceId", ""),
                "Issue": issue,
                "LatestStatus": latest_status or "N/A",
                "ScanRunCount": scan_count,
            })

    if not problem_sources:
        return []

    return [_ds_finding(
        "data_classification", "purview_scan_issues",
        f"{len(problem_sources)} Purview data source(s) have scan issues",
        "Microsoft Purview scans have either never run, failed, or are stale "
        "(>30 days since last successful run) for some registered data sources. "
        "Without up-to-date scans, data classification and governance coverage "
        "may be incomplete.",
        "medium", problem_sources,
        {"Description": "Fix or re-run Purview scans for affected data sources.",
         "PortalSteps": [
             "Microsoft Purview governance portal → Data Map → Data Sources",
             "Select each affected source → Scans → View run history",
             "Fix scan credentials or connectivity issues and re-trigger scans",
         ]},
    )]


