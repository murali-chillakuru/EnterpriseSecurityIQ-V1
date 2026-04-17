"""
Data Security — Data Residency & Sovereignty evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_data_residency(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data residency and sovereignty posture."""
    findings: list[dict] = []
    findings.extend(_check_resource_location_compliance(evidence_index))
    findings.extend(_check_geo_replication_cross_boundary(evidence_index))
    return findings


def _check_resource_location_compliance(idx: dict) -> list[dict]:
    """Flag data services deployed in unusual or non-standard regions."""
    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
        + idx.get("azure-keyvault", [])
        + idx.get("azure-cosmosdb", [])
        + idx.get("azure-dbforpostgresql", [])
        + idx.get("azure-dbformysql", [])
    )
    if not data_services:
        return []
    # Determine expected regions from frequency analysis
    region_counts: dict[str, int] = {}
    for ev in data_services:
        data = ev.get("Data", ev.get("data", {}))
        loc = data.get("location", "").lower()
        if loc:
            region_counts[loc] = region_counts.get(loc, 0) + 1
    if not region_counts:
        return []
    total = sum(region_counts.values())
    # Regions with < 10% of resources are considered outliers
    expected = {r for r, c in region_counts.items() if c / total >= 0.1}
    outliers: list[dict] = []
    for ev in data_services:
        data = ev.get("Data", ev.get("data", {}))
        loc = data.get("location", "").lower()
        if loc and loc not in expected:
            outliers.append({
                "Type": data.get("type", "DataService"),
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Location": loc,
                "ExpectedRegions": ", ".join(sorted(expected)),
            })
    if outliers:
        return [_ds_finding(
            "data_residency", "resource_location_outlier",
            f"{len(outliers)} data service(s) in unexpected regions",
            "Data services deployed in regions different from the organization's primary "
            "locations may violate data residency or sovereignty requirements.",
            "medium", outliers,
            {"Description": "Review data services in outlier regions for compliance.",
             "PortalSteps": [
                 "Verify each outlier resource is intentionally deployed in its region",
                 "Consider Azure Policy to restrict allowed regions",
             ]},
        )]
    return []


def _check_geo_replication_cross_boundary(idx: dict) -> list[dict]:
    """Flag storage accounts with geo-replication that may cross sovereignty boundaries."""
    storage = idx.get("azure-storage-security", [])
    geo_replicated: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        sku = data.get("sku", data.get("Sku", {})) or {}
        sku_name = sku.get("name", "") if isinstance(sku, dict) else str(sku)
        if any(geo in sku_name.lower() for geo in ("grs", "gzrs", "ragrs", "ragzrs")):
            geo_replicated.append({
                "Type": "StorageAccount",
                "Name": data.get("name", data.get("StorageAccountName", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "SkuName": sku_name,
                "PrimaryLocation": data.get("location", ""),
            })
    if geo_replicated:
        return [_ds_finding(
            "data_residency", "geo_replication_cross_boundary",
            f"{len(geo_replicated)} storage accounts with geo-replication",
            "Geo-replicated storage accounts replicate data to a paired region. "
            "Verify the secondary region meets data residency requirements.",
            "informational", geo_replicated,
            {"Description": "Review paired regions for data sovereignty compliance.",
             "PortalSteps": [
                 "Azure Portal > Storage account > Geo-replication",
                 "Verify secondary region is acceptable for data residency",
                 "Consider LRS/ZRS if cross-region replication is not permitted",
             ]},
        )]
    return []


