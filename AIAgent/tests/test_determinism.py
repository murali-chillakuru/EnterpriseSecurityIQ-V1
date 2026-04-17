"""
Determinism validation test for the Data Security Assessment Engine.

Verifies that identical evidence inputs produce identical outputs across
multiple runs, excluding only the ``AssessedAt`` / ``DetectedAt`` timestamps.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.data_security_engine import (
    analyze_storage_exposure,
    analyze_database_security,
    analyze_keyvault_hygiene,
    analyze_encryption_posture,
    analyze_data_access_controls,
    analyze_private_endpoints,
    analyze_m365_dlp,
    analyze_data_classification_security,
    analyze_backup_dr,
    analyze_network_segmentation,
    analyze_threat_detection,
    analyze_ai_services_security,
    compute_data_security_scores,
    consolidate_findings,
    enrich_compliance_mapping,
    enrich_per_resource_details,
)


# ── Frozen evidence index ────────────────────────────────────────────

def _build_frozen_evidence() -> dict[str, list[dict]]:
    """Return a deterministic evidence index covering multiple categories."""
    return {
        "azure-storage-security": [
            {
                "EvidenceType": "azure-storage-security",
                "ResourceId": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/stor1",
                "Data": {
                    "StorageAccountName": "stor1",
                    "name": "stor1",
                    "AllowBlobPublicAccess": True,
                    "HttpsOnly": True,
                    "NetworkDefaultAction": "Allow",
                    "BlobSoftDeleteEnabled": True,
                    "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/stor1",
                    "type": "microsoft.storage/storageaccounts",
                },
            },
            {
                "EvidenceType": "azure-storage-security",
                "ResourceId": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/stor2",
                "Data": {
                    "StorageAccountName": "stor2",
                    "name": "stor2",
                    "AllowBlobPublicAccess": False,
                    "HttpsOnly": False,
                    "NetworkDefaultAction": "Deny",
                    "BlobSoftDeleteEnabled": False,
                    "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/stor2",
                    "type": "microsoft.storage/storageaccounts",
                },
            },
        ],
        "azure-sql-server": [
            {
                "EvidenceType": "azure-sql-server",
                "ResourceId": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sql1",
                "Data": {
                    "Name": "sql1",
                    "name": "sql1",
                    "TransparentDataEncryption": False,
                    "AuditingEnabled": False,
                    "AdvancedThreatProtection": False,
                    "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sql1",
                    "type": "microsoft.sql/servers",
                },
            },
        ],
        "azure-keyvault": [
            {
                "EvidenceType": "azure-keyvault",
                "ResourceId": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv1",
                "Data": {
                    "name": "kv1",
                    "PurgeProtectionEnabled": False,
                    "EnableRbacAuthorization": False,
                    "NetworkDefaultAction": "Allow",
                    "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv1",
                    "type": "microsoft.keyvault/vaults",
                },
            },
        ],
        "azure-compute-instance": [
            {
                "EvidenceType": "azure-compute-instance",
                "ResourceId": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/vm1",
                "Data": {
                    "Name": "vm1",
                    "name": "vm1",
                    "EncryptionAtHost": False,
                    "DiskEncryptionEnabled": False,
                    "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/vm1",
                    "type": "microsoft.compute/virtualmachines",
                },
            },
        ],
        "azure-managed-disk": [
            {
                "EvidenceType": "azure-managed-disk",
                "ResourceId": "/subscriptions/sub1/rg1/Microsoft.Compute/disks/disk1",
                "Data": {
                    "name": "disk1",
                    "EncryptionType": "EncryptionAtRestWithPlatformKey",
                    "id": "/subscriptions/sub1/rg1/Microsoft.Compute/disks/disk1",
                    "type": "microsoft.compute/disks",
                },
            },
        ],
        "azure-vnet": [
            {
                "EvidenceType": "azure-vnet",
                "ResourceId": "/subscriptions/sub1/rg1/Microsoft.Network/virtualNetworks/vnet1",
                "Data": {
                    "name": "vnet1",
                    "DdosProtectionEnabled": False,
                    "id": "/subscriptions/sub1/rg1/Microsoft.Network/virtualNetworks/vnet1",
                    "type": "microsoft.network/virtualnetworks",
                },
            },
        ],
        "azure-defender-plans": [],
        "azure-action-groups": [],
    }


def _strip_timestamps(obj):
    """Recursively strip timestamp fields for comparison."""
    if isinstance(obj, dict):
        return {
            k: _strip_timestamps(v) for k, v in obj.items()
            if k not in ("DetectedAt", "AssessedAt")
        }
    if isinstance(obj, list):
        return [_strip_timestamps(item) for item in obj]
    return obj


def _run_full_pipeline(evidence_index: dict) -> dict:
    """Run the full analyzer pipeline on the given evidence index."""
    all_findings: list[dict] = []
    analyzers = [
        analyze_storage_exposure,
        analyze_database_security,
        analyze_keyvault_hygiene,
        analyze_encryption_posture,
        analyze_data_access_controls,
        analyze_private_endpoints,
        analyze_m365_dlp,
        analyze_data_classification_security,
        analyze_backup_dr,
        analyze_network_segmentation,
        analyze_threat_detection,
        analyze_ai_services_security,
    ]
    for fn in analyzers:
        all_findings.extend(fn(evidence_index))

    enrich_compliance_mapping(all_findings)
    enrich_per_resource_details(all_findings)
    all_findings = consolidate_findings(all_findings)

    # Deterministic sort (same as engine)
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            _sev_order.get(f.get("Severity", "medium").lower(), 9),
        )
    )
    for f in all_findings:
        f.get("AffectedResources", []).sort(
            key=lambda r: r.get("ResourceId", r.get("Name", ""))
        )

    scores = compute_data_security_scores(all_findings)

    return {
        "Findings": all_findings,
        "FindingCount": len(all_findings),
        "DataSecurityScores": scores,
    }


# ── Tests ────────────────────────────────────────────────────────────

class TestDeterminism(unittest.TestCase):
    """Ensure identical evidence → identical output (excluding timestamps)."""

    def test_two_runs_produce_identical_output(self):
        """Run the pipeline twice with the same evidence and compare."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        clean_a = _strip_timestamps(result_a)
        clean_b = _strip_timestamps(result_b)

        self.assertEqual(
            json.dumps(clean_a, sort_keys=True, default=str),
            json.dumps(clean_b, sort_keys=True, default=str),
            "Two runs with identical evidence produced different output",
        )

    def test_finding_ids_are_deterministic(self):
        """Finding IDs should be stable uuid5 values, not random uuid4."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        ids_a = [f["DataSecurityFindingId"] for f in result_a["Findings"]]
        ids_b = [f["DataSecurityFindingId"] for f in result_b["Findings"]]

        self.assertEqual(ids_a, ids_b, "Finding IDs differ between runs")

    def test_finding_order_is_stable(self):
        """Findings should be sorted by (Category, Subcategory, Severity)."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))

        categories = [
            (f["Category"], f["Subcategory"], f["Severity"])
            for f in result["Findings"]
        ]
        sorted_categories = sorted(
            categories,
            key=lambda t: (
                t[0],
                t[1],
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(t[2].lower(), 9),
            ),
        )
        self.assertEqual(categories, sorted_categories, "Findings are not in deterministic order")

    def test_scores_are_identical(self):
        """Score values must match exactly across runs."""
        evidence = _build_frozen_evidence()
        scores_a = _run_full_pipeline(copy.deepcopy(evidence))["DataSecurityScores"]
        scores_b = _run_full_pipeline(copy.deepcopy(evidence))["DataSecurityScores"]

        self.assertEqual(scores_a["OverallScore"], scores_b["OverallScore"])
        self.assertEqual(scores_a["OverallLevel"], scores_b["OverallLevel"])
        self.assertEqual(scores_a["SeverityDistribution"], scores_b["SeverityDistribution"])
        self.assertEqual(
            json.dumps(scores_a["CategoryScores"], sort_keys=True),
            json.dumps(scores_b["CategoryScores"], sort_keys=True),
        )

    def test_affected_resources_are_sorted(self):
        """AffectedResources within each finding must be sorted by ResourceId."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))
        for f in result["Findings"]:
            resources = f.get("AffectedResources", [])
            ids = [r.get("ResourceId", r.get("Name", "")) for r in resources]
            self.assertEqual(ids, sorted(ids),
                             f"AffectedResources not sorted in finding: {f.get('Subcategory')}")

    def test_three_runs_all_match(self):
        """Triple-run consistency check mimicking the original validation."""
        evidence = _build_frozen_evidence()
        results = [
            _strip_timestamps(_run_full_pipeline(copy.deepcopy(evidence)))
            for _ in range(3)
        ]
        baseline = json.dumps(results[0], sort_keys=True, default=str)
        for i, r in enumerate(results[1:], 2):
            self.assertEqual(
                baseline,
                json.dumps(r, sort_keys=True, default=str),
                f"Run {i} differs from run 1",
            )


if __name__ == "__main__":
    unittest.main()
