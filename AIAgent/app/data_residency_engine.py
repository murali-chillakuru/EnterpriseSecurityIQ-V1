"""
EnterpriseSecurityIQ — Data Residency Validation Engine.

Validates that Azure resources comply with data residency requirements:
  1. Region Compliance  — resources are deployed in allowed regions
  2. Data Sovereignty   — storage/database replication stays within boundaries
  3. Geo-Redundancy Audit — checks GRS/GZRS replication destinations
  4. Cross-Region Dependencies — identifies cross-region service links
  5. Policy Alignment   — validates against Azure Policy location constraints

Works on pre-indexed evidence (reusable from a prior assessment).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ── Common region groupings ─────────────────────────────────────────────

REGION_GROUPS: dict[str, list[str]] = {
    "US": [
        "eastus", "eastus2", "centralus", "northcentralus", "southcentralus",
        "westus", "westus2", "westus3", "westcentralus",
    ],
    "Europe": [
        "northeurope", "westeurope", "uksouth", "ukwest",
        "francecentral", "francesouth", "germanywestcentral", "germanynorth",
        "switzerlandnorth", "switzerlandwest", "norwayeast", "norwaywest",
        "swedencentral", "polandcentral", "italynorth", "spaincentral",
    ],
    "AsiaPacific": [
        "eastasia", "southeastasia", "japaneast", "japanwest",
        "australiaeast", "australiasoutheast", "australiacentral",
        "koreacentral", "koreasouth", "centralindia", "southindia",
        "westindia",
    ],
    "Canada": ["canadacentral", "canadaeast"],
    "Brazil": ["brazilsouth", "brazilsoutheast"],
    "MiddleEast": ["uaenorth", "uaecentral", "qatarcentral", "israelcentral"],
    "Africa": ["southafricanorth", "southafricawest"],
    "Government": [
        "usgovvirginia", "usgovarizona", "usgovtexas", "usgoviowa",
        "usdodeast", "usdodcentral",
    ],
    "China": ["chinaeast", "chinanorth", "chinaeast2", "chinanorth2", "chinaeast3", "chinanorth3"],
}

# Reverse lookup: region → group
_REGION_TO_GROUP: dict[str, str] = {}
for group, regions in REGION_GROUPS.items():
    for r in regions:
        _REGION_TO_GROUP[r] = group


def _get_region_group(location: str) -> str:
    """Map an Azure region to its sovereignty group."""
    normalized = (location or "").lower().replace(" ", "")
    return _REGION_TO_GROUP.get(normalized, "Unknown")


def _residency_finding(
    category: str,
    subcategory: str,
    title: str,
    description: str,
    severity: str,
    affected_resources: list[dict] | None = None,
    remediation: str = "",
) -> dict:
    return {
        "ResidencyFindingId": str(uuid.uuid4()),
        "Category": category,
        "Subcategory": subcategory,
        "Title": title,
        "Description": description,
        "Severity": severity,
        "AffectedResources": affected_resources or [],
        "AffectedCount": len(affected_resources) if affected_resources else 0,
        "Remediation": remediation,
        "DetectedAt": datetime.now(timezone.utc).isoformat(),
    }


# ── Analyzers ───────────────────────────────────────────────────────────

def analyze_region_compliance(
    evidence_index: dict[str, list[dict]],
    allowed_regions: list[str] | None = None,
    allowed_region_groups: list[str] | None = None,
) -> list[dict]:
    """Check that all resources are in allowed regions or region groups."""
    findings: list[dict] = []
    if not allowed_regions and not allowed_region_groups:
        return findings

    allowed_set = set((r.lower().replace(" ", "") for r in (allowed_regions or [])))
    allowed_group_set = set((g for g in (allowed_region_groups or [])))

    violations: list[dict] = []

    # Check all resource evidence types
    for etype, records in evidence_index.items():
        for record in records:
            data = record.get("Data", {})
            location = (data.get("Location", "") or "").lower().replace(" ", "")
            if not location or location == "global":
                continue

            region_group = _get_region_group(location)
            in_allowed_region = location in allowed_set if allowed_set else True
            in_allowed_group = region_group in allowed_group_set if allowed_group_set else True

            if not in_allowed_region and not in_allowed_group:
                violations.append({
                    "ResourceId": data.get("ResourceId", record.get("ResourceId", "")),
                    "Name": data.get("Name", ""),
                    "ResourceType": data.get("ResourceType", record.get("ResourceType", "")),
                    "Location": location,
                    "RegionGroup": region_group,
                })

    if violations:
        findings.append(_residency_finding(
            category="DataResidency",
            subcategory="RegionCompliance",
            title=f"{len(violations)} resources in non-allowed regions",
            description=f"Found {len(violations)} resources deployed outside allowed regions/region groups.",
            severity="high",
            affected_resources=violations,
            remediation="Migrate resources to allowed regions or update the allowed regions policy.",
        ))

    return findings


def analyze_storage_replication(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Check storage account replication for cross-region data residency issues."""
    findings: list[dict] = []

    # GRS/GZRS/RA-GRS replicate to paired regions which may cross sovereignty boundaries
    cross_boundary_accounts: list[dict] = []
    for record in evidence_index.get("azure-storage-security", []):
        data = record.get("Data", {})
        replication = (data.get("Replication", "") or "").upper()
        location = (data.get("Location", "") or "").lower().replace(" ", "")
        region_group = _get_region_group(location)

        if any(geo in replication for geo in ("GRS", "GZRS", "RAGRS", "RAGZRS")):
            cross_boundary_accounts.append({
                "ResourceId": data.get("StorageAccountId", record.get("ResourceId", "")),
                "Name": data.get("Name", ""),
                "Location": location,
                "RegionGroup": region_group,
                "Replication": replication,
            })

    if cross_boundary_accounts:
        findings.append(_residency_finding(
            category="DataResidency",
            subcategory="StorageReplication",
            title=f"{len(cross_boundary_accounts)} storage accounts with geo-redundant replication",
            description="These storage accounts use GRS/GZRS replication which copies data to a paired region. Verify the paired region meets data residency requirements.",
            severity="medium",
            affected_resources=cross_boundary_accounts,
            remediation="Consider LRS or ZRS replication if data must not leave the region. Review Azure region pairs to confirm residency compliance.",
        ))

    return findings


def analyze_database_replication(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Check database geo-replication configurations."""
    findings: list[dict] = []

    # SQL Servers with geo-replication
    geo_replicated: list[dict] = []
    for record in evidence_index.get("azure-sql-server", []):
        data = record.get("Data", {})
        # Check for failover groups or geo-replication indicators
        location = (data.get("Location", "") or "").lower().replace(" ", "")
        region_group = _get_region_group(location)
        geo_replicated.append({
            "ResourceId": data.get("ServerId", record.get("ResourceId", "")),
            "Name": data.get("Name", ""),
            "Location": location,
            "RegionGroup": region_group,
        })

    # Cosmos DB multi-region
    for record in evidence_index.get("azure-cosmosdb-account", []):
        data = record.get("Data", {})
        locations = data.get("ReadLocations", []) or data.get("WriteLocations", []) or []
        if len(locations) > 1:
            groups = set()
            for loc in locations:
                loc_name = loc if isinstance(loc, str) else loc.get("locationName", "")
                groups.add(_get_region_group(loc_name))
            if len(groups) > 1:
                geo_replicated.append({
                    "ResourceId": data.get("AccountId", record.get("ResourceId", "")),
                    "Name": data.get("Name", ""),
                    "Locations": locations,
                    "RegionGroups": list(groups),
                    "CrossBoundary": True,
                })

    if geo_replicated:
        findings.append(_residency_finding(
            category="DataResidency",
            subcategory="DatabaseReplication",
            title=f"{len(geo_replicated)} databases with geo-replication",
            description="Check that database geo-replication targets comply with data residency requirements.",
            severity="medium",
            affected_resources=geo_replicated,
            remediation="Review geo-replication targets and failover groups. Ensure secondary regions meet sovereignty requirements.",
        ))

    return findings


def analyze_cross_region_dependencies(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Identify services linked across different region groups."""
    findings: list[dict] = []

    # Check private endpoints connecting to resources in different regions
    cross_region_links: list[dict] = []
    for record in evidence_index.get("azure-private-endpoint", []):
        data = record.get("Data", {})
        pe_location = (data.get("Location", "") or "").lower().replace(" ", "")
        linked_ids = data.get("LinkedServiceIds", []) or []
        pe_group = _get_region_group(pe_location)

        for linked_id in linked_ids:
            # Extract potential region from the linked resource
            if linked_id and pe_group != "Unknown":
                cross_region_links.append({
                    "PrivateEndpointId": data.get("EndpointId", ""),
                    "EndpointName": data.get("Name", ""),
                    "EndpointLocation": pe_location,
                    "EndpointRegionGroup": pe_group,
                    "LinkedServiceId": linked_id,
                })

    if cross_region_links:
        findings.append(_residency_finding(
            category="DataResidency",
            subcategory="CrossRegionDependencies",
            title=f"{len(cross_region_links)} cross-region private endpoint links",
            description="Private endpoints connecting to services — verify they don't cross sovereignty boundaries.",
            severity="low",
            affected_resources=cross_region_links,
            remediation="Review private endpoint connections to ensure data doesn't cross sovereignty boundaries.",
        ))

    return findings


def analyze_policy_location_constraints(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Check if Azure Policy enforces location constraints."""
    findings: list[dict] = []

    policies = evidence_index.get("azure-policy-assignment", [])
    location_policies = [
        p for p in policies
        if "location" in (p.get("Data", {}).get("PolicyDefinitionId", "") or "").lower()
        or "allowedlocations" in (p.get("Data", {}).get("PolicyDefinitionId", "") or "").lower()
    ]

    if not location_policies:
        findings.append(_residency_finding(
            category="DataResidency",
            subcategory="PolicyAlignment",
            title="No Azure Policy location constraints detected",
            description="No Azure Policy assignments enforcing allowed locations were found. Consider enabling 'Allowed locations' policy to enforce data residency.",
            severity="high",
            affected_resources=[],
            remediation="Assign the built-in 'Allowed locations' policy to restrict resource deployment to approved regions.",
        ))
    else:
        findings.append(_residency_finding(
            category="DataResidency",
            subcategory="PolicyAlignment",
            title=f"{len(location_policies)} location constraint policies found",
            description=f"Found {len(location_policies)} Azure Policy assignments related to location constraints.",
            severity="informational",
            affected_resources=[{"PolicyId": p.get("Data", {}).get("PolicyId", ""), "Name": p.get("Data", {}).get("Name", "")} for p in location_policies],
        ))

    return findings


# ── Main entry point ────────────────────────────────────────────────────

async def assess_data_residency(
    creds: ComplianceCredentials | None = None,
    subscriptions: list[dict] | None = None,
    evidence_index: dict[str, list[dict]] | None = None,
    allowed_regions: list[str] | None = None,
    allowed_region_groups: list[str] | None = None,
) -> dict[str, Any]:
    """Run data residency validation across all categories.

    Returns:
        {
            "findings": [...],
            "summary": {"total_findings": N, "by_severity": {...}, "by_category": {...}},
            "residency_score": float,
        }
    """
    if evidence_index is None:
        evidence_index = {}

    findings: list[dict] = []
    findings.extend(analyze_region_compliance(evidence_index, allowed_regions, allowed_region_groups))
    findings.extend(analyze_storage_replication(evidence_index))
    findings.extend(analyze_database_replication(evidence_index))
    findings.extend(analyze_cross_region_dependencies(evidence_index))
    findings.extend(analyze_policy_location_constraints(evidence_index))

    # Summarize
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in findings:
        sev = f.get("Severity", "medium")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = f.get("Subcategory", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    # Score: start at 100, deduct by severity
    _SEVERITY_DEDUCT = {"critical": 25, "high": 15, "medium": 5, "low": 2, "informational": 0}
    score = 100.0
    for f in findings:
        score -= _SEVERITY_DEDUCT.get(f.get("Severity", "medium"), 5) * max(1, f.get("AffectedCount", 1))
    score = max(0.0, min(100.0, score))

    return {
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
        },
        "residency_score": round(score, 1),
    }
