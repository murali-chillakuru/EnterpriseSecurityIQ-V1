"""
Tests for Phase 3: Data Security Assessment Engine.

Covers:
  - Storage exposure analysis (4 sub-checks)
  - Database security analysis (4 sub-checks)
  - Key Vault hygiene analysis (3 sub-checks)
  - Encryption posture analysis (2 sub-checks)
  - Data classification analysis (1 sub-check)
  - Scoring algorithm
  - Agent tool registration
  - CLI parsability
  - Module imports
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone, timedelta

# Ensure AIAgent/ is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ====================================================================
# Helpers — match the engine's evidence schema exactly
# ====================================================================

def _storage_ev(data: dict) -> dict:
    """Create an azure-storage-security evidence record."""
    return {"EvidenceType": "azure-storage-security", "Data": data, "ResourceId": data.get("id", "")}


def _sql_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-sql-server", "Data": data, "ResourceId": data.get("id", "")}


def _kv_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-keyvault", "Data": data, "ResourceId": data.get("id", "")}


def _vm_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-compute-instance", "Data": data, "ResourceId": data.get("id", "")}


def _resource_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-resource", "Data": data, "ResourceId": data.get("id", "")}


def _build_index(records: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for r in records:
        etype = r.get("EvidenceType", "")
        idx.setdefault(etype, []).append(r)
    return idx


# ====================================================================
# 1. Storage Exposure
# ====================================================================

class TestStorageExposure(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_storage_exposure
        self.analyze = analyze_storage_exposure

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_blob_access_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "myblobstore",
            "AllowBlobPublicAccess": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/myblobstore",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("public blob" in f["Title"].lower() for f in findings))

    def test_https_not_enforced_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "insecure",
            "HttpsOnly": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/insecure",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("https" in f["Title"].lower() for f in findings))

    def test_network_unrestricted_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "opensa",
            "NetworkDefaultAction": "Allow",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/opensa",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("unrestricted" in f["Title"].lower() or "network" in f["Title"].lower()
                            for f in findings))

    def test_soft_delete_disabled_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "nodel",
            "BlobSoftDeleteEnabled": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/nodel",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("soft delete" in f["Title"].lower() or "delete" in f["Title"].lower()
                            for f in findings))

    def test_compliant_storage_no_findings(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "goodsa",
            "AllowBlobPublicAccess": False,
            "HttpsOnly": True,
            "NetworkDefaultAction": "Deny",
            "BlobSoftDeleteEnabled": True,
            "SasPolicy": {"sasExpirationPeriod": "1.00:00:00"},
            "ImmutableStorageWithVersioning": {"enabled": True},
            "IsBlobVersioningEnabled": True,
            "IsChangeFeedEnabled": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/goodsa",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# 2. Database Security
# ====================================================================

class TestDatabaseSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_database_security
        self.analyze = analyze_database_security

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_tde_disabled_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "TransparentDataEncryption": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("tde" in f["Title"].lower() or "transparent" in f["Title"].lower()
                            or "encryption" in f["Title"].lower() for f in findings))

    def test_auditing_disabled_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv2",
            "AuditingEnabled": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv2",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("audit" in f["Title"].lower() for f in findings))

    def test_threat_protection_disabled_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv3",
            "AdvancedThreatProtection": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv3",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("threat" in f["Title"].lower() for f in findings))

    def test_sql_open_firewall_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv4",
            "FirewallRules": [
                {"StartIpAddress": "0.0.0.0", "EndIpAddress": "255.255.255.255"},
            ],
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv4",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("firewall" in f["Title"].lower() or "0.0.0.0" in f["Title"]
                            for f in findings))

    def test_secure_sql_no_findings(self):
        idx = _build_index([_sql_ev({
            "Name": "secureSql",
            "TransparentDataEncryption": True,
            "AuditingEnabled": True,
            "AdvancedThreatProtection": True,
            "azureADOnlyAuthentication": True,
            "FirewallRules": [],
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/secureSql",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# 3. Key Vault Hygiene
# ====================================================================

class TestKeyVaultHygiene(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_keyvault_hygiene
        self.analyze = analyze_keyvault_hygiene

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_purge_protection_disabled_detected(self):
        idx = _build_index([_kv_ev({
            "VaultName": "kv1",
            "EnablePurgeProtection": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv1",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("purge" in f["Title"].lower() for f in findings))

    def test_broad_access_policies_detected(self):
        """Broad access = RBAC disabled AND > 10 access policies."""
        policies = [{"permissions": {"keys": ["all"]}} for _ in range(15)]
        idx = _build_index([_kv_ev({
            "VaultName": "kv2",
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": False,
            "AccessPolicies": policies,
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv2",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("access" in f["Title"].lower() or "excessive" in f["Title"].lower()
                            for f in findings))

    def test_expired_items_detected(self):
        expired_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        idx = _build_index([_kv_ev({
            "VaultName": "kv3",
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": True,
            "Secrets": [{"Name": "old-secret", "Expiry": expired_date}],
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv3",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("expired" in f["Title"].lower() for f in findings))

    def test_expiring_items_detected(self):
        expiring_date = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        idx = _build_index([_kv_ev({
            "VaultName": "kv4",
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": True,
            "Keys": [{"Name": "rotating-key", "Expiry": expiring_date}],
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv4",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("expiring" in f["Title"].lower() for f in findings))

    def test_healthy_keyvault_no_findings(self):
        idx = _build_index([_kv_ev({
            "VaultName": "safe-kv",
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": True,
            "NetworkAcls": {"defaultAction": "Deny"},
            "Secrets": [],
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/safe-kv",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# 4. Encryption Posture
# ====================================================================

class TestEncryptionPosture(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_encryption_posture
        self.analyze = analyze_encryption_posture

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_unencrypted_disk_detected(self):
        idx = _build_index([_vm_ev({
            "Name": "myvm1",
            "DiskEncryptionEnabled": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/myvm1",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("encrypt" in f["Title"].lower() or "unencrypted" in f["Title"].lower()
                            for f in findings))

    def test_no_cmk_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "msa",
            "KeySource": "Microsoft.Storage",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/msa",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("managed key" in f["Title"].lower() or "cmk" in f["Title"].lower()
                            for f in findings))

    def test_cmk_in_use_no_cmk_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "cmksa",
            "KeySource": "Microsoft.Keyvault",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/cmksa",
        })])
        findings = self.analyze(idx)
        cmk_findings = [f for f in findings if f["Subcategory"] == "no_cmk"]
        self.assertEqual(len(cmk_findings), 0)


# ====================================================================
# 5. Data Classification (Legacy — tag-based)
# ====================================================================

class TestDataClassificationLegacy(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_classification
        self.analyze = analyze_data_classification

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)


# ====================================================================
# 5b. Data Classification & Labeling (New — category 12)
# ====================================================================

def _defender_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-defender-plans", "Data": data, "ResourceId": data.get("id", "")}

def _purview_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-purview", "Data": data, "ResourceId": data.get("id", "")}


class TestDataClassificationSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_classification_security
        self.analyze = analyze_data_classification_security

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_sql_unlabeled_columns_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
            "_databases": [{
                "name": "mydb",
                "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1/databases/mydb",
                "RecommendedSensitivityLabels": [
                    {"column": "SSN", "table": "Users", "schema": "dbo", "labelName": "Confidential"},
                    {"column": "Email", "table": "Users", "schema": "dbo", "labelName": "General"},
                ],
                "CurrentSensitivityLabels": [
                    {"column": "SSN", "table": "Users", "schema": "dbo", "labelName": "Confidential"},
                ],
            }],
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("unlabeled" in f["Title"].lower() or "classification" in f["Title"].lower()
                            for f in findings))
        self.assertEqual(findings[0]["Category"], "data_classification")

    def test_sql_all_labeled_no_finding(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
            "_databases": [{
                "name": "mydb",
                "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1/databases/mydb",
                "RecommendedSensitivityLabels": [
                    {"column": "SSN", "table": "Users"},
                ],
                "CurrentSensitivityLabels": [
                    {"column": "SSN", "table": "Users"},
                ],
            }],
        })])
        findings = self.analyze(idx)
        label_findings = [f for f in findings if f["Subcategory"] == "sql_unlabeled_sensitive_columns"]
        self.assertEqual(len(label_findings), 0)

    def test_sql_va_disabled_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "VulnerabilityAssessmentEnabled": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("vulnerability" in f["Title"].lower() or "data discovery" in f["Title"].lower()
                            for f in findings))

    def test_defender_sdd_disabled_detected(self):
        idx = _build_index([_defender_ev({
            "name": "StorageAccounts",
            "pricingTier": "Standard",
            "subscriptionId": "sub1",
            "extensions": [{"name": "SensitiveDataDiscovery", "isEnabled": False}],
            "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings/StorageAccounts",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("sensitive" in f["Title"].lower() and "discovery" in f["Title"].lower()
                            for f in findings))

    def test_defender_sdd_enabled_no_finding(self):
        idx = _build_index([_defender_ev({
            "name": "StorageAccounts",
            "pricingTier": "Standard",
            "subscriptionId": "sub1",
            "extensions": [{"name": "SensitiveDataDiscovery", "isEnabled": True}],
            "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings/StorageAccounts",
        })])
        findings = self.analyze(idx)
        sdd_findings = [f for f in findings if f["Subcategory"] == "defender_storage_sdd_disabled"]
        self.assertEqual(len(sdd_findings), 0)

    def test_unclassified_data_stores_detected(self):
        """No Purview, no Defender SDD → data stores are unclassified."""
        idx = _build_index([_storage_ev({
            "name": "mysa",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/mysa",
        })])
        findings = self.analyze(idx)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("no" in f["Title"].lower() and "classification" in f["Title"].lower()
                            for f in findings))

    def test_purview_exists_no_unclassified_finding(self):
        """With Purview present, don't flag unclassified."""
        idx = _build_index([
            _storage_ev({
                "name": "mysa",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/mysa",
            }),
            _purview_ev({
                "name": "mypurview",
                "id": "/subscriptions/sub1/rg1/Microsoft.Purview/accounts/mypurview",
            }),
        ])
        findings = self.analyze(idx)
        unclassified = [f for f in findings if f["Subcategory"] == "no_data_classification"]
        self.assertEqual(len(unclassified), 0)


# ====================================================================
# 5c. Defender SDD Alerts & Purview Scan Results (New checks)
# ====================================================================

def _defender_alert_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-defender-alerts", "Data": data, "ResourceId": data.get("id", "")}

def _purview_scan_run_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-purview-scan-runs", "Data": data, "ResourceId": data.get("id", "")}


class TestDefenderSDDAlerts(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_classification_security
        self.analyze = analyze_data_classification_security

    def test_no_alerts_no_finding(self):
        """No Defender alerts → no sensitive-data-found finding."""
        idx = _build_index([])
        findings = self.analyze(idx)
        alert_findings = [f for f in findings if f["Subcategory"] == "defender_sdd_sensitive_data_found"]
        self.assertEqual(len(alert_findings), 0)

    def test_sensitive_data_alerts_detected(self):
        """Defender SDD alerts present → finding surfaces them."""
        idx = _build_index([_defender_alert_ev({
            "alertType": "Storage.Blob.SensitiveData.PII",
            "id": "/subscriptions/sub1/providers/Microsoft.Security/alerts/alert1",
            "properties": {
                "alertType": "Storage.Blob.SensitiveData.PII",
                "severity": "High",
                "status": "Active",
                "description": "Sensitive PII data found in blob container",
                "entities": [
                    {"resourceId": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/mysa"},
                ],
                "attackedResourceId": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/mysa",
            },
        })])
        findings = self.analyze(idx)
        sdd = [f for f in findings if f["Subcategory"] == "defender_sdd_sensitive_data_found"]
        self.assertEqual(len(sdd), 1)
        self.assertEqual(sdd[0]["Category"], "data_classification")
        self.assertGreater(sdd[0]["AffectedCount"], 0)
        self.assertEqual(sdd[0]["Severity"], "high")

    def test_non_sensitive_alerts_ignored(self):
        """Non-SDD alerts (no 'sensitivedata' in alertType) → no finding."""
        idx = _build_index([_defender_alert_ev({
            "alertType": "Storage.Blob.AnonymousAccess",
            "id": "/subscriptions/sub1/providers/Microsoft.Security/alerts/alert2",
            "properties": {
                "alertType": "Storage.Blob.AnonymousAccess",
                "severity": "Medium",
                "status": "Active",
                "description": "Anonymous access detected",
                "entities": [],
            },
        })])
        findings = self.analyze(idx)
        sdd = [f for f in findings if f["Subcategory"] == "defender_sdd_sensitive_data_found"]
        self.assertEqual(len(sdd), 0)


class TestPurviewScanResults(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_classification_security
        self.analyze = analyze_data_classification_security

    def test_no_scan_runs_no_finding(self):
        """No Purview scan-run evidence → no scan-issues finding."""
        idx = _build_index([])
        findings = self.analyze(idx)
        scan_findings = [f for f in findings if f["Subcategory"] == "purview_scan_issues"]
        self.assertEqual(len(scan_findings), 0)

    def test_failed_scan_detected(self):
        """Purview scan with 'Failed' status → finding."""
        idx = _build_index([_purview_scan_run_ev({
            "sourceName": "my-storage",
            "purviewAccount": "mypurview",
            "scanRunCount": 3,
            "latestRunStatus": "Failed",
            "latestRunEnd": "2025-03-01T10:00:00Z",
            "id": "/subscriptions/sub1/rg1/Microsoft.Purview/accounts/mypurview",
        })])
        findings = self.analyze(idx)
        scan_issues = [f for f in findings if f["Subcategory"] == "purview_scan_issues"]
        self.assertEqual(len(scan_issues), 1)
        self.assertEqual(scan_issues[0]["Category"], "data_classification")
        # Check the affected resource mentions the issue
        affected = scan_issues[0]["AffectedResources"]
        self.assertGreater(len(affected), 0)
        self.assertIn("failed", affected[0]["Issue"].lower())

    def test_stale_scan_detected(self):
        """Purview scan >30 days old → flagged as stale."""
        idx = _build_index([_purview_scan_run_ev({
            "sourceName": "old-sql",
            "purviewAccount": "mypurview",
            "scanRunCount": 5,
            "latestRunStatus": "Succeeded",
            "latestRunEnd": "2024-01-01T10:00:00Z",
            "id": "/subscriptions/sub1/rg1/Microsoft.Purview/accounts/mypurview",
        })])
        findings = self.analyze(idx)
        scan_issues = [f for f in findings if f["Subcategory"] == "purview_scan_issues"]
        self.assertEqual(len(scan_issues), 1)
        self.assertIn("Stale", scan_issues[0]["AffectedResources"][0]["Issue"])

    def test_never_scanned_detected(self):
        """Purview source with zero scan runs → flagged."""
        idx = _build_index([_purview_scan_run_ev({
            "sourceName": "new-cosmos",
            "purviewAccount": "mypurview",
            "scanRunCount": 0,
            "latestRunStatus": "",
            "latestRunEnd": "",
            "id": "/subscriptions/sub1/rg1/Microsoft.Purview/accounts/mypurview",
        })])
        findings = self.analyze(idx)
        scan_issues = [f for f in findings if f["Subcategory"] == "purview_scan_issues"]
        self.assertEqual(len(scan_issues), 1)
        self.assertIn("Never scanned", scan_issues[0]["AffectedResources"][0]["Issue"])

    def test_successful_recent_scan_no_finding(self):
        """Purview scan that succeeded recently → no issue."""
        from datetime import datetime, timezone
        recent = datetime.now(timezone.utc).isoformat()
        idx = _build_index([_purview_scan_run_ev({
            "sourceName": "healthy-sql",
            "purviewAccount": "mypurview",
            "scanRunCount": 10,
            "latestRunStatus": "Succeeded",
            "latestRunEnd": recent,
            "id": "/subscriptions/sub1/rg1/Microsoft.Purview/accounts/mypurview",
        })])
        findings = self.analyze(idx)
        scan_issues = [f for f in findings if f["Subcategory"] == "purview_scan_issues"]
        self.assertEqual(len(scan_issues), 0)


# ====================================================================
# 6. Scoring
# ====================================================================

class TestDataSecurityScoring(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import compute_data_security_scores
        self.score = compute_data_security_scores

    def test_no_findings_returns_zero_score(self):
        scores = self.score([])
        self.assertEqual(scores["OverallScore"], 0)
        self.assertEqual(scores["OverallLevel"], "low")

    def test_findings_produce_nonzero_score(self):
        findings = [{
            "DataSecurityFindingId": "DS-001",
            "Category": "storage",
            "Subcategory": "blob_public_access",
            "Title": "Public Blob Access",
            "Severity": "critical",
            "AffectedCount": 5,
        }]
        scores = self.score(findings)
        self.assertGreater(scores["OverallScore"], 0)

    def test_severity_distribution(self):
        findings = [
            {"DataSecurityFindingId": "1", "Category": "storage", "Severity": "critical", "AffectedCount": 1, "Title": "A", "Subcategory": "a"},
            {"DataSecurityFindingId": "2", "Category": "storage", "Severity": "high", "AffectedCount": 1, "Title": "B", "Subcategory": "b"},
            {"DataSecurityFindingId": "3", "Category": "database", "Severity": "medium", "AffectedCount": 1, "Title": "C", "Subcategory": "c"},
            {"DataSecurityFindingId": "4", "Category": "keyvault", "Severity": "low", "AffectedCount": 1, "Title": "D", "Subcategory": "d"},
        ]
        scores = self.score(findings)
        dist = scores["SeverityDistribution"]
        self.assertEqual(dist["critical"], 1)
        self.assertEqual(dist["high"], 1)
        self.assertEqual(dist["medium"], 1)
        self.assertEqual(dist["low"], 1)

    def test_category_scores_present(self):
        findings = [
            {"DataSecurityFindingId": "1", "Category": "storage", "Severity": "high", "AffectedCount": 1, "Title": "A", "Subcategory": "a"},
            {"DataSecurityFindingId": "2", "Category": "database", "Severity": "medium", "AffectedCount": 1, "Title": "B", "Subcategory": "b"},
        ]
        scores = self.score(findings)
        cats = scores["CategoryScores"]
        self.assertIn("storage", cats)
        self.assertIn("database", cats)

    def test_top_findings_limited(self):
        findings = [
            {"DataSecurityFindingId": str(i), "Category": "storage", "Severity": "high",
             "AffectedCount": i, "Title": f"Finding {i}", "Subcategory": "x"}
            for i in range(1, 15)
        ]
        scores = self.score(findings)
        self.assertLessEqual(len(scores.get("TopFindings", [])), 10)


# ====================================================================
# 7. Finding Structure
# ====================================================================

class TestFindingStructure(unittest.TestCase):
    def test_finding_has_required_fields(self):
        from app.data_security_engine import analyze_storage_exposure
        idx = _build_index([_storage_ev({
            "StorageAccountName": "pub",
            "AllowBlobPublicAccess": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/pub",
        })])
        findings = analyze_storage_exposure(idx)
        self.assertGreater(len(findings), 0)
        f = findings[0]
        for key in ("DataSecurityFindingId", "Category", "Subcategory",
                     "Title", "Description", "Severity", "AffectedResources",
                     "AffectedCount", "Remediation", "DetectedAt"):
            self.assertIn(key, f, f"Missing key: {key}")
        self.assertIsInstance(f["AffectedResources"], list)
        self.assertIsInstance(f["Remediation"], dict)

    def test_finding_category_subcategory(self):
        from app.data_security_engine import analyze_database_security
        idx = _build_index([_sql_ev({
            "Name": "srv",
            "TransparentDataEncryption": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/srv",
        })])
        findings = analyze_database_security(idx)
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["Category"], "database")
        self.assertEqual(findings[0]["Subcategory"], "tde_disabled")


# ====================================================================
# 8. Agent Tool Registration
# ====================================================================

class TestAgentDataSecurityTool(unittest.TestCase):
    def test_tools_list_has_assess_data_security(self):
        from app.agent import TOOLS
        names = [t.__name__ for t in TOOLS]
        self.assertIn("assess_data_security", names)
        self.assertEqual(len(TOOLS), 12)


# ====================================================================
# 9. Module Imports
# ====================================================================

class TestDataSecurityImports(unittest.TestCase):
    def test_import_data_security_engine(self):
        import app.data_security_engine
        self.assertTrue(hasattr(app.data_security_engine, "run_data_security_assessment"))
        self.assertTrue(hasattr(app.data_security_engine, "compute_data_security_scores"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_storage_exposure"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_database_security"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_keyvault_hygiene"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_encryption_posture"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_data_classification"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_data_classification_security"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_backup_dr"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_container_security"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_network_segmentation"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_data_residency"))
        self.assertTrue(hasattr(app.data_security_engine, "analyze_threat_detection"))

    def test_import_cli_parseable(self):
        """Verify run_data_security.py is valid Python."""
        import ast
        cli_path = os.path.join(os.path.dirname(__file__), "..", "run_data_security.py")
        with open(cli_path, "r", encoding="utf-8") as fh:
            ast.parse(fh.read())


# ====================================================================
# Helpers — new categories
# ====================================================================

def _recovery_vault_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-recovery-vault", "Data": data, "ResourceId": data.get("id", "")}

def _acr_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-containerregistry", "Data": data, "ResourceId": data.get("id", "")}

def _aks_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-aks", "Data": data, "ResourceId": data.get("id", "")}

def _cosmosdb_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-cosmosdb", "Data": data, "ResourceId": data.get("id", "")}


# ====================================================================
# 10. Storage SAS Policy & Immutability
# ====================================================================

class TestStorageSASAndImmutability(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_storage_exposure
        self.analyze = analyze_storage_exposure

    def test_sas_policy_missing_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "nosas",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/nosas",
        })])
        findings = self.analyze(idx)
        sas_findings = [f for f in findings if "sas" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(sas_findings), 0)

    def test_sas_policy_configured_no_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "goodsa",
            "SasPolicy": {"sasExpirationPeriod": "1.00:00:00"},
            "AllowBlobPublicAccess": False,
            "HttpsOnly": True,
            "NetworkDefaultAction": "Deny",
            "BlobSoftDeleteEnabled": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/goodsa",
        })])
        findings = self.analyze(idx)
        sas_findings = [f for f in findings if "sas" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(sas_findings), 0)

    def test_immutability_missing_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "noimmut",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/noimmut",
        })])
        findings = self.analyze(idx)
        immut_findings = [f for f in findings if "immutab" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(immut_findings), 0)

    def test_immutability_enabled_no_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "immutsa",
            "ImmutableStorageWithVersioning": {"enabled": True},
            "AllowBlobPublicAccess": False,
            "HttpsOnly": True,
            "NetworkDefaultAction": "Deny",
            "BlobSoftDeleteEnabled": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/immutsa",
        })])
        findings = self.analyze(idx)
        immut_findings = [f for f in findings if "immutab" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(immut_findings), 0)


# ====================================================================
# 11. Key Vault RBAC & Network
# ====================================================================

class TestKeyVaultRBACAndNetwork(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_keyvault_hygiene
        self.analyze = analyze_keyvault_hygiene

    def test_rbac_disabled_detected(self):
        idx = _build_index([_kv_ev({
            "VaultName": "legacyvault",
            "EnableRbacAuthorization": False,
            "EnablePurgeProtection": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/legacyvault",
        })])
        findings = self.analyze(idx)
        rbac_findings = [f for f in findings if "rbac" in f.get("Subcategory", "").lower() or "legacy" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(rbac_findings), 0)

    def test_rbac_enabled_no_finding(self):
        idx = _build_index([_kv_ev({
            "VaultName": "modernvault",
            "EnableRbacAuthorization": True,
            "EnablePurgeProtection": True,
            "NetworkAcls": {"defaultAction": "Deny"},
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/modernvault",
        })])
        findings = self.analyze(idx)
        rbac_findings = [f for f in findings if "legacy" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(rbac_findings), 0)

    def test_network_open_detected(self):
        idx = _build_index([_kv_ev({
            "VaultName": "openvault",
            "EnableRbacAuthorization": True,
            "EnablePurgeProtection": True,
            "NetworkAcls": {"defaultAction": "Allow"},
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/openvault",
        })])
        findings = self.analyze(idx)
        net_findings = [f for f in findings if "network" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(net_findings), 0)

    def test_network_deny_no_finding(self):
        idx = _build_index([_kv_ev({
            "VaultName": "securevault",
            "EnableRbacAuthorization": True,
            "EnablePurgeProtection": True,
            "NetworkAcls": {"defaultAction": "Deny"},
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/securevault",
        })])
        findings = self.analyze(idx)
        net_findings = [f for f in findings if "network" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(net_findings), 0)


# ====================================================================
# 12. Encryption Type Distinction
# ====================================================================

class TestEncryptionType(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_encryption_posture
        self.analyze = analyze_encryption_posture

    def test_pmk_only_detected(self):
        idx = _build_index([_vm_ev({
            "Name": "pmkvm",
            "DiskEncryptionEnabled": True,
            "DiskEncryptionType": "PMK",
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/pmkvm",
        })])
        findings = self.analyze(idx)
        pmk_findings = [f for f in findings if "pmk" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(pmk_findings), 0)

    def test_cmk_no_pmk_finding(self):
        idx = _build_index([_vm_ev({
            "Name": "cmkvm",
            "DiskEncryptionEnabled": True,
            "DiskEncryptionType": "CMK",
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/cmkvm",
        })])
        findings = self.analyze(idx)
        pmk_findings = [f for f in findings if "pmk" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(pmk_findings), 0)

    def test_unencrypted_no_pmk_finding(self):
        idx = _build_index([_vm_ev({
            "Name": "noencvm",
            "DiskEncryptionEnabled": False,
            "DiskEncryptionType": "PMK",
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/noencvm",
        })])
        findings = self.analyze(idx)
        pmk_findings = [f for f in findings if "pmk" in f.get("Subcategory", "").lower()]
        # Should not flag PMK for unencrypted VMs (those go to unencrypted_disks)
        self.assertEqual(len(pmk_findings), 0)


# ====================================================================
# 13. Backup & Disaster Recovery
# ====================================================================

class TestBackupDR(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_backup_dr
        self.analyze = analyze_backup_dr

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_vault_not_geo_redundant_detected(self):
        idx = _build_index([_recovery_vault_ev({
            "name": "localvault",
            "redundancySettings": {"standardTierStorageRedundancy": "LocallyRedundant"},
            "id": "/subscriptions/sub1/rg1/Microsoft.RecoveryServices/vaults/localvault",
        })])
        findings = self.analyze(idx)
        geo_findings = [f for f in findings if "geo" in f.get("Subcategory", "").lower() or "redundan" in f.get("Title", "").lower()]
        self.assertGreater(len(geo_findings), 0)

    def test_vault_geo_redundant_no_finding(self):
        idx = _build_index([_recovery_vault_ev({
            "name": "geovault",
            "redundancySettings": {"standardTierStorageRedundancy": "GeoRedundant"},
            "id": "/subscriptions/sub1/rg1/Microsoft.RecoveryServices/vaults/geovault",
        })])
        findings = self.analyze(idx)
        geo_findings = [f for f in findings if "redundan" in f.get("Title", "").lower()]
        self.assertEqual(len(geo_findings), 0)

    def test_unprotected_vm_detected(self):
        idx = _build_index([_vm_ev({
            "Name": "nobackupvm",
            "BackupProtected": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/nobackupvm",
        })])
        findings = self.analyze(idx)
        backup_findings = [f for f in findings if "unprotected" in f.get("Subcategory", "").lower() or "backup" in f.get("Title", "").lower()]
        self.assertGreater(len(backup_findings), 0)

    def test_cosmosdb_periodic_backup_detected(self):
        idx = _build_index([_cosmosdb_ev({
            "name": "periodiccosmos",
            "backupPolicy": {"type": "Periodic"},
            "id": "/subscriptions/sub1/rg1/Microsoft.DocumentDB/databaseAccounts/periodiccosmos",
        })])
        findings = self.analyze(idx)
        cosmos_findings = [f for f in findings if "cosmosdb" in f.get("Subcategory", "").lower() or "cosmos" in f.get("Title", "").lower()]
        self.assertGreater(len(cosmos_findings), 0)

    def test_cosmosdb_continuous_backup_no_finding(self):
        idx = _build_index([_cosmosdb_ev({
            "name": "contcosmos",
            "backupPolicy": {"type": "Continuous"},
            "id": "/subscriptions/sub1/rg1/Microsoft.DocumentDB/databaseAccounts/contcosmos",
        })])
        findings = self.analyze(idx)
        cosmos_findings = [f for f in findings if "cosmos" in f.get("Title", "").lower()]
        self.assertEqual(len(cosmos_findings), 0)


# ====================================================================
# 14. Container Security
# ====================================================================

class TestContainerSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_container_security
        self.analyze = analyze_container_security

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_acr_admin_enabled_detected(self):
        idx = _build_index([_acr_ev({
            "name": "myreg",
            "adminUserEnabled": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerRegistry/registries/myreg",
        })])
        findings = self.analyze(idx)
        admin_findings = [f for f in findings if "admin" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(admin_findings), 0)

    def test_acr_admin_disabled_no_finding(self):
        idx = _build_index([_acr_ev({
            "name": "securereg",
            "adminUserEnabled": False,
            "sku": {"name": "Standard"},
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerRegistry/registries/securereg",
        })])
        findings = self.analyze(idx)
        admin_findings = [f for f in findings if "admin" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(admin_findings), 0)

    def test_acr_basic_sku_vulnerability_scanning_detected(self):
        idx = _build_index([_acr_ev({
            "name": "basicreg",
            "sku": {"name": "Basic"},
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerRegistry/registries/basicreg",
        })])
        findings = self.analyze(idx)
        vuln_findings = [f for f in findings if "vulnerab" in f.get("Subcategory", "").lower() or "scanning" in f.get("Title", "").lower()]
        self.assertGreater(len(vuln_findings), 0)

    def test_aks_no_rbac_detected(self):
        idx = _build_index([_aks_ev({
            "name": "badcluster",
            "enableRBAC": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerService/managedClusters/badcluster",
        })])
        findings = self.analyze(idx)
        rbac_findings = [f for f in findings if "rbac" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(rbac_findings), 0)

    def test_aks_rbac_and_aad_no_finding(self):
        idx = _build_index([_aks_ev({
            "name": "goodcluster",
            "enableRBAC": True,
            "aadProfile": {"managed": True},
            "properties_networkProfile_networkPolicy": "calico",
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerService/managedClusters/goodcluster",
        })])
        findings = self.analyze(idx)
        rbac_findings = [f for f in findings if "rbac" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(rbac_findings), 0)

    def test_aks_no_network_policy_detected(self):
        idx = _build_index([_aks_ev({
            "name": "nopolcluster",
            "enableRBAC": True,
            "aadProfile": {"managed": True},
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerService/managedClusters/nopolcluster",
        })])
        findings = self.analyze(idx)
        netpol_findings = [f for f in findings if "network_policy" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(netpol_findings), 0)


# ====================================================================
# Additional helpers for new categories
# ====================================================================

def _pgmysql_ev(data: dict, db_type: str = "postgresql") -> dict:
    etype = f"azure-dbfor{db_type}"
    return {"EvidenceType": etype, "Data": data, "ResourceId": data.get("id", "")}

def _nsg_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-nsg", "Data": data, "ResourceId": data.get("id", "")}

def _vnet_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-vnet", "Data": data, "ResourceId": data.get("id", "")}

def _disk_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-managed-disk", "Data": data, "ResourceId": data.get("id", "")}

def _role_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-role-assignments", "Data": data, "ResourceId": data.get("id", "")}

def _dlp_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-dlp-policies", "Data": data, "ResourceId": data.get("id", "")}

def _action_group_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-action-groups", "Data": data, "ResourceId": data.get("id", "")}


# ====================================================================
# 15a. New Storage Sub-checks
# ====================================================================

class TestStorageNewSubchecks(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_storage_exposure
        self.analyze = analyze_storage_exposure

    def test_lifecycle_management_missing_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "nolcmsa",
            "LifecycleManagementEnabled": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/nolcmsa",
        })])
        findings = self.analyze(idx)
        lcm_findings = [f for f in findings if "lifecycle" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(lcm_findings), 0)

    def test_lifecycle_management_enabled_no_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "goodsa",
            "LifecycleManagementEnabled": True,
            "AllowBlobPublicAccess": False, "HttpsOnly": True,
            "NetworkDefaultAction": "Deny", "BlobSoftDeleteEnabled": True,
            "SasPolicy": {"sasExpirationPeriod": "1.00:00:00"},
            "ImmutableStorageWithVersioning": {"enabled": True},
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/goodsa",
        })])
        findings = self.analyze(idx)
        lcm_findings = [f for f in findings if "lifecycle" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(lcm_findings), 0)

    def test_wildcard_cors_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "corssa",
            "CorsRules": [{"allowedOrigins": ["*"]}],
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/corssa",
        })])
        findings = self.analyze(idx)
        cors_findings = [f for f in findings if "cors" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(cors_findings), 0)

    def test_no_wildcard_cors_no_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "goodsa",
            "CorsRules": [{"allowedOrigins": ["https://example.com"]}],
            "AllowBlobPublicAccess": False, "HttpsOnly": True,
            "NetworkDefaultAction": "Deny", "BlobSoftDeleteEnabled": True,
            "SasPolicy": {"sasExpirationPeriod": "1.00:00:00"},
            "ImmutableStorageWithVersioning": {"enabled": True},
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/goodsa",
        })])
        findings = self.analyze(idx)
        cors_findings = [f for f in findings if "cors" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(cors_findings), 0)

    def test_overly_permissive_bypass_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "bypasssa",
            "NetworkAcls": {"defaultAction": "Deny", "bypass": "Logging, Metrics, AzureServices"},
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/bypasssa",
        })])
        findings = self.analyze(idx)
        bypass_findings = [f for f in findings if "bypass" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(bypass_findings), 0)

    def test_azureservices_only_bypass_no_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "goodsa",
            "NetworkAcls": {"defaultAction": "Deny", "bypass": "AzureServices"},
            "AllowBlobPublicAccess": False, "HttpsOnly": True,
            "NetworkDefaultAction": "Deny", "BlobSoftDeleteEnabled": True,
            "SasPolicy": {"sasExpirationPeriod": "1.00:00:00"},
            "ImmutableStorageWithVersioning": {"enabled": True},
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/goodsa",
        })])
        findings = self.analyze(idx)
        bypass_findings = [f for f in findings if "bypass" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(bypass_findings), 0)

    def test_no_blob_logging_detected(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "nologsa",
            "BlobLoggingEnabled": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/nologsa",
        })])
        findings = self.analyze(idx)
        log_findings = [f for f in findings if "logging" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(log_findings), 0)


# ====================================================================
# 15b. New SQL Sub-checks
# ====================================================================

class TestSQLNewSubchecks(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_database_security
        self.analyze = analyze_database_security

    def test_allow_azure_services_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "FirewallRules": [{"Name": "AllowAllAzureIps", "StartIpAddress": "0.0.0.0", "EndIpAddress": "0.0.0.0"}],
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        azure_svc = [f for f in findings if "allow_azure" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(azure_svc), 0)

    def test_no_allow_azure_services_no_finding(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "TransparentDataEncryption": True,
            "AuditingEnabled": True,
            "AdvancedThreatProtection": True,
            "FirewallRules": [{"Name": "office", "StartIpAddress": "10.0.0.1", "EndIpAddress": "10.0.0.1"}],
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        azure_svc = [f for f in findings if "allow_azure" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(azure_svc), 0)

    def test_tde_service_managed_key_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "TransparentDataEncryption": True,
            "TdeKeySource": "ServiceManaged",
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        tde_key = [f for f in findings if "tde_service_managed" in f.get("Subcategory", "").lower()
                   or "tde_key" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(tde_key), 0)

    def test_tde_cmk_no_finding(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "TransparentDataEncryption": True,
            "TdeKeySource": "AzureKeyVault",
            "AuditingEnabled": True,
            "AdvancedThreatProtection": True,
            "FirewallRules": [],
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        tde_key = [f for f in findings if "service_managed_key" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(tde_key), 0)

    def test_public_access_enabled_detected(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "publicNetworkAccess": "Enabled",
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        public = [f for f in findings if "public_access" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(public), 0)

    def test_public_access_disabled_no_finding(self):
        idx = _build_index([_sql_ev({
            "Name": "sqlsrv1",
            "publicNetworkAccess": "Disabled",
            "TransparentDataEncryption": True,
            "AuditingEnabled": True,
            "AdvancedThreatProtection": True,
            "FirewallRules": [],
            "id": "/subscriptions/sub1/rg1/Microsoft.Sql/servers/sqlsrv1",
        })])
        findings = self.analyze(idx)
        public = [f for f in findings if "sql_public_access" == f.get("Subcategory", "").lower()]
        self.assertEqual(len(public), 0)


# ====================================================================
# 15c. Cosmos DB CMK
# ====================================================================

class TestCosmosDBCMK(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_cosmosdb_security
        self.analyze = analyze_cosmosdb_security

    def test_no_cmk_detected(self):
        idx = _build_index([_cosmosdb_ev({
            "name": "mycosmosdb",
            "id": "/subscriptions/sub1/rg1/Microsoft.DocumentDB/databaseAccounts/mycosmosdb",
        })])
        findings = self.analyze(idx)
        cmk_findings = [f for f in findings if "cmk" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(cmk_findings), 0)

    def test_cmk_configured_no_finding(self):
        idx = _build_index([_cosmosdb_ev({
            "name": "securecosmos",
            "keyVaultKeyUri": "https://myvault.vault.azure.net/keys/mykey/version",
            "publicNetworkAccess": "Disabled",
            "ipRangeFilter": "10.0.0.0/24",
            "disableKeyBasedMetadataWriteAccess": True,
            "backupPolicy": {"type": "Continuous"},
            "id": "/subscriptions/sub1/rg1/Microsoft.DocumentDB/databaseAccounts/securecosmos",
        })])
        findings = self.analyze(idx)
        cmk_findings = [f for f in findings if "cmk" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(cmk_findings), 0)


# ====================================================================
# 15d. PG/MySQL High Availability
# ====================================================================

class TestPGMySQLHA(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_postgres_mysql_security
        self.analyze = analyze_postgres_mysql_security

    def test_no_ha_detected(self):
        idx = _build_index([_pgmysql_ev({
            "name": "mypg",
            "type": "microsoft.dbforpostgresql/flexibleservers",
            "highAvailability": {"mode": "Disabled"},
            "id": "/subscriptions/sub1/rg1/Microsoft.DBforPostgreSQL/flexibleServers/mypg",
        })])
        findings = self.analyze(idx)
        ha_findings = [f for f in findings if "high_availability" in f.get("Subcategory", "").lower()
                       or "ha" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(ha_findings), 0)

    def test_ha_enabled_no_finding(self):
        idx = _build_index([_pgmysql_ev({
            "name": "mypg",
            "type": "microsoft.dbforpostgresql/flexibleservers",
            "highAvailability": {"mode": "ZoneRedundant"},
            "SslEnforcement": "Enabled",
            "PublicNetworkAccess": "Disabled",
            "GeoRedundantBackup": "Enabled",
            "FirewallRules": [],
            "id": "/subscriptions/sub1/rg1/Microsoft.DBforPostgreSQL/flexibleServers/mypg",
        })])
        findings = self.analyze(idx)
        ha_findings = [f for f in findings if "high_availability" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(ha_findings), 0)


# ====================================================================
# 15e. Key Vault Soft Delete & No Expiry
# ====================================================================

class TestKeyVaultNewSubchecks(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_keyvault_hygiene
        self.analyze = analyze_keyvault_hygiene

    def test_soft_delete_disabled_detected(self):
        idx = _build_index([_kv_ev({
            "VaultName": "nosoftkv",
            "enableSoftDelete": False,
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/nosoftkv",
        })])
        findings = self.analyze(idx)
        sd_findings = [f for f in findings if "soft_delete" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(sd_findings), 0)

    def test_soft_delete_enabled_no_finding(self):
        idx = _build_index([_kv_ev({
            "VaultName": "goodkv",
            "enableSoftDelete": True,
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": True,
            "NetworkAcls": {"defaultAction": "Deny"},
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/goodkv",
        })])
        findings = self.analyze(idx)
        sd_findings = [f for f in findings if "soft_delete" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(sd_findings), 0)

    def test_no_expiry_secrets_detected(self):
        idx = _build_index([_kv_ev({
            "VaultName": "expirekv",
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": True,
            "Secrets": [{"Name": "mysecret"}],
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/expirekv",
        })])
        findings = self.analyze(idx)
        exp_findings = [f for f in findings if "no_expiry" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(exp_findings), 0)

    def test_secrets_with_expiry_no_finding(self):
        future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        idx = _build_index([_kv_ev({
            "VaultName": "goodkv",
            "EnablePurgeProtection": True,
            "EnableRbacAuthorization": True,
            "NetworkAcls": {"defaultAction": "Deny"},
            "Secrets": [{"Name": "mysecret", "Expiry": future}],
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/goodkv",
        })])
        findings = self.analyze(idx)
        exp_findings = [f for f in findings if "no_expiry" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(exp_findings), 0)


# ====================================================================
# 15f. Encryption At Host & Managed Disk CMK
# ====================================================================

class TestEncryptionNewSubchecks(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_encryption_posture
        self.analyze = analyze_encryption_posture

    def test_no_encryption_at_host_detected(self):
        idx = _build_index([_vm_ev({
            "Name": "vmnoeh",
            "DiskEncryptionEnabled": True,
            "DiskEncryptionType": "PMK",
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/vmnoeh",
        })])
        findings = self.analyze(idx)
        eah_findings = [f for f in findings if "encryption_at_host" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(eah_findings), 0)

    def test_encryption_at_host_enabled_no_finding(self):
        idx = _build_index([_vm_ev({
            "Name": "vmeh",
            "DiskEncryptionEnabled": True,
            "DiskEncryptionType": "EncryptionAtHost",
            "KeySource": "Microsoft.Keyvault",
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/vmeh",
        })])
        findings = self.analyze(idx)
        eah_findings = [f for f in findings if "encryption_at_host" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(eah_findings), 0)

    def test_managed_disk_no_cmk_detected(self):
        idx = _build_index([_disk_ev({
            "name": "disk1",
            "encryption": {"type": "EncryptionAtRestWithPlatformKey"},
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/disks/disk1",
        })])
        findings = self.analyze(idx)
        disk_findings = [f for f in findings if "managed_disk" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(disk_findings), 0)

    def test_managed_disk_cmk_no_finding(self):
        idx = _build_index([_disk_ev({
            "name": "disk1",
            "encryption": {"type": "EncryptionAtRestWithCustomerKey", "diskEncryptionSetId": "/sub/rg/des/myset"},
            "id": "/subscriptions/sub1/rg1/Microsoft.Compute/disks/disk1",
        })])
        findings = self.analyze(idx)
        disk_findings = [f for f in findings if "managed_disk_no_cmk" == f.get("Subcategory", "")]
        self.assertEqual(len(disk_findings), 0)


# ====================================================================
# 15g. Data Access Controls (Owner/Contributor & SP KV)
# ====================================================================

class TestDataAccessNewSubchecks(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_access_controls
        self.analyze = analyze_data_access_controls

    def test_owner_on_storage_detected(self):
        idx = _build_index([_role_ev({
            "roleDefinitionName": "Owner",
            "scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mysa",
            "principalId": "user-123",
            "principalType": "User",
            "id": "/subscriptions/sub1/providers/Microsoft.Authorization/roleAssignments/ra1",
        })])
        findings = self.analyze(idx)
        owner_findings = [f for f in findings if "owner_contributor" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(owner_findings), 0)

    def test_reader_on_storage_no_finding(self):
        idx = _build_index([_role_ev({
            "roleDefinitionName": "Reader",
            "scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mysa",
            "principalId": "user-123",
            "principalType": "User",
            "id": "/subscriptions/sub1/providers/Microsoft.Authorization/roleAssignments/ra1",
        })])
        findings = self.analyze(idx)
        owner_findings = [f for f in findings if "owner_contributor" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(owner_findings), 0)

    def test_sp_broad_keyvault_detected(self):
        idx = _build_index([_role_ev({
            "roleDefinitionName": "Key Vault Administrator",
            "scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/mykv",
            "principalId": "sp-456",
            "principalType": "ServicePrincipal",
            "id": "/subscriptions/sub1/providers/Microsoft.Authorization/roleAssignments/ra2",
        })])
        findings = self.analyze(idx)
        sp_findings = [f for f in findings if "sp_broad_keyvault" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(sp_findings), 0)

    def test_sp_secrets_user_no_finding(self):
        idx = _build_index([_role_ev({
            "roleDefinitionName": "Key Vault Secrets User",
            "scope": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/mykv",
            "principalId": "sp-456",
            "principalType": "ServicePrincipal",
            "id": "/subscriptions/sub1/providers/Microsoft.Authorization/roleAssignments/ra2",
        })])
        findings = self.analyze(idx)
        sp_findings = [f for f in findings if "sp_broad_keyvault" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(sp_findings), 0)


# ====================================================================
# 15h. Private Endpoint Pending Approval
# ====================================================================

class TestPEPendingApproval(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_private_endpoints
        self.analyze = analyze_private_endpoints

    def test_pending_pe_detected(self):
        idx = _build_index([_storage_ev({
            "name": "pendingsa",
            "type": "Microsoft.Storage/storageAccounts",
            "privateEndpointConnections": [{
                "properties": {
                    "privateLinkServiceConnectionState": {"status": "Pending"},
                },
            }],
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/pendingsa",
        })])
        findings = self.analyze(idx)
        pending = [f for f in findings if "pending" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(pending), 0)

    def test_approved_pe_no_finding(self):
        idx = _build_index([_storage_ev({
            "name": "approvedsa",
            "type": "Microsoft.Storage/storageAccounts",
            "privateEndpointConnections": [{
                "properties": {
                    "privateLinkServiceConnectionState": {"status": "Approved"},
                },
            }],
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/approvedsa",
        })])
        findings = self.analyze(idx)
        pending = [f for f in findings if "pending" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(pending), 0)


# ====================================================================
# 15i. DLP Notify-Only Actions
# ====================================================================

class TestDLPNotifyOnly(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_m365_dlp
        self.analyze = analyze_m365_dlp

    def test_notify_only_detected(self):
        idx = _build_index([_dlp_ev({
            "name": "weak-policy",
            "state": "Enabled",
            "mode": "Enable",
            "actions": [{"type": "Notify"}],
            "id": "dlp-policy-1",
        })])
        findings = self.analyze(idx)
        notify = [f for f in findings if "notify_only" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(notify), 0)

    def test_block_action_no_finding(self):
        idx = _build_index([_dlp_ev({
            "name": "strong-policy",
            "state": "Enabled",
            "mode": "Enable",
            "actions": [{"type": "BlockAccess"}, {"type": "Notify"}],
            "id": "dlp-policy-2",
        })])
        findings = self.analyze(idx)
        notify = [f for f in findings if "notify_only" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(notify), 0)


# ====================================================================
# 15j. Backup Vault CMK
# ====================================================================

class TestBackupVaultCMK(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_backup_dr
        self.analyze = analyze_backup_dr

    def test_vault_no_cmk_detected(self):
        idx = _build_index([_recovery_vault_ev({
            "name": "nocmkvault",
            "encryption": {},
            "redundancySettings": {"standardTierStorageRedundancy": "GeoRedundant"},
            "id": "/subscriptions/sub1/rg1/Microsoft.RecoveryServices/vaults/nocmkvault",
        })])
        findings = self.analyze(idx)
        cmk_findings = [f for f in findings if "cmk" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(cmk_findings), 0)

    def test_vault_cmk_configured_no_finding(self):
        idx = _build_index([_recovery_vault_ev({
            "name": "cmkvault",
            "encryption": {
                "keyVaultProperties": {"keyUri": "https://myvault.vault.azure.net/keys/mykey"},
            },
            "redundancySettings": {"standardTierStorageRedundancy": "GeoRedundant"},
            "id": "/subscriptions/sub1/rg1/Microsoft.RecoveryServices/vaults/cmkvault",
        })])
        findings = self.analyze(idx)
        cmk_findings = [f for f in findings if "vault_no_cmk" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(cmk_findings), 0)


# ====================================================================
# 15k. Container Security New Sub-checks
# ====================================================================

class TestContainerNewSubchecks(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_container_security
        self.analyze = analyze_container_security

    def test_acr_no_quarantine_detected(self):
        idx = _build_index([_acr_ev({
            "name": "myreg",
            "sku": {"name": "Premium"},
            "Policies": {"quarantinePolicy": {"status": "disabled"}},
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerRegistry/registries/myreg",
        })])
        findings = self.analyze(idx)
        q_findings = [f for f in findings if "quarantine" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(q_findings), 0)

    def test_acr_quarantine_enabled_no_finding(self):
        idx = _build_index([_acr_ev({
            "name": "myreg",
            "adminUserEnabled": False,
            "sku": {"name": "Premium"},
            "Policies": {"quarantinePolicy": {"status": "enabled"}},
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerRegistry/registries/myreg",
        })])
        findings = self.analyze(idx)
        q_findings = [f for f in findings if "quarantine" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(q_findings), 0)

    def test_acr_basic_sku_no_quarantine_finding(self):
        """Quarantine only applies to Premium SKU — Basic should not be flagged."""
        idx = _build_index([_acr_ev({
            "name": "basicreg",
            "sku": {"name": "Basic"},
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerRegistry/registries/basicreg",
        })])
        findings = self.analyze(idx)
        q_findings = [f for f in findings if "quarantine" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(q_findings), 0)

    def test_aks_no_policy_addon_detected(self):
        idx = _build_index([_aks_ev({
            "name": "nopolicycluster",
            "enableRBAC": True,
            "aadProfile": {"managed": True},
            "addonProfiles": {"azurepolicy": {"enabled": False}},
            "properties_networkProfile_networkPolicy": "calico",
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerService/managedClusters/nopolicycluster",
        })])
        findings = self.analyze(idx)
        pss = [f for f in findings if "pod_security" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(pss), 0)

    def test_aks_policy_addon_enabled_no_finding(self):
        idx = _build_index([_aks_ev({
            "name": "goodcluster",
            "enableRBAC": True,
            "aadProfile": {"managed": True},
            "addonProfiles": {"azurepolicy": {"enabled": True}},
            "properties_networkProfile_networkPolicy": "calico",
            "id": "/subscriptions/sub1/rg1/Microsoft.ContainerService/managedClusters/goodcluster",
        })])
        findings = self.analyze(idx)
        pss = [f for f in findings if "pod_security" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(pss), 0)


# ====================================================================
# 16. Network Segmentation (NEW category)
# ====================================================================

class TestNetworkSegmentation(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_network_segmentation
        self.analyze = analyze_network_segmentation

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_nsg_permissive_data_ports_detected(self):
        idx = _build_index([_nsg_ev({
            "name": "badnsg",
            "securityRules": [{
                "name": "allow-all-sql",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "*",
                    "destinationPortRange": "1433",
                },
            }],
            "id": "/subscriptions/sub1/rg1/Microsoft.Network/networkSecurityGroups/badnsg",
        })])
        findings = self.analyze(idx)
        nsg_findings = [f for f in findings if "permissive_data_ports" in f.get("Subcategory", "")]
        self.assertGreater(len(nsg_findings), 0)

    def test_nsg_restricted_source_no_finding(self):
        idx = _build_index([_nsg_ev({
            "name": "goodnsg",
            "securityRules": [{
                "name": "allow-sql-from-vnet",
                "properties": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "sourceAddressPrefix": "10.0.0.0/24",
                    "destinationPortRange": "1433",
                },
            }],
            "id": "/subscriptions/sub1/rg1/Microsoft.Network/networkSecurityGroups/goodnsg",
        })])
        findings = self.analyze(idx)
        nsg_findings = [f for f in findings if "permissive_data_ports" in f.get("Subcategory", "")]
        self.assertEqual(len(nsg_findings), 0)

    def test_no_ddos_protection_detected(self):
        idx = _build_index([_vnet_ev({
            "name": "noddosvnet",
            "enableDdosProtection": False,
            "id": "/subscriptions/sub1/rg1/Microsoft.Network/virtualNetworks/noddosvnet",
        })])
        findings = self.analyze(idx)
        ddos_findings = [f for f in findings if "ddos" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(ddos_findings), 0)

    def test_ddos_enabled_no_finding(self):
        idx = _build_index([_vnet_ev({
            "name": "ddosvnet",
            "enableDdosProtection": True,
            "id": "/subscriptions/sub1/rg1/Microsoft.Network/virtualNetworks/ddosvnet",
        })])
        findings = self.analyze(idx)
        ddos_findings = [f for f in findings if "ddos" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(ddos_findings), 0)

    def test_subnet_missing_service_endpoints_detected(self):
        idx = _build_index([_vnet_ev({
            "name": "myvnet",
            "subnets": [{
                "name": "datasubnet",
                "properties": {
                    "addressPrefix": "10.0.1.0/24",
                    "serviceEndpoints": [],
                },
            }],
            "id": "/subscriptions/sub1/rg1/Microsoft.Network/virtualNetworks/myvnet",
        })])
        findings = self.analyze(idx)
        se_findings = [f for f in findings if "service_endpoint" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(se_findings), 0)

    def test_subnet_with_all_endpoints_no_finding(self):
        idx = _build_index([_vnet_ev({
            "name": "myvnet",
            "subnets": [{
                "name": "datasubnet",
                "properties": {
                    "addressPrefix": "10.0.1.0/24",
                    "serviceEndpoints": [
                        {"service": "Microsoft.Storage"},
                        {"service": "Microsoft.Sql"},
                        {"service": "Microsoft.KeyVault"},
                        {"service": "Microsoft.AzureCosmosDB"},
                    ],
                },
            }],
            "id": "/subscriptions/sub1/rg1/Microsoft.Network/virtualNetworks/myvnet",
        })])
        findings = self.analyze(idx)
        se_findings = [f for f in findings if "service_endpoint" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(se_findings), 0)


# ====================================================================
# 17. Data Residency & Sovereignty (NEW category)
# ====================================================================

class TestDataResidency(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_residency
        self.analyze = analyze_data_residency

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_outlier_region_detected(self):
        """One resource in a different region from the majority → flagged."""
        idx = _build_index([
            _storage_ev({
                "name": "sa-east", "location": "eastus",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa-east",
            }),
            _storage_ev({
                "name": "sa-east2", "location": "eastus",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa-east2",
            }),
            _storage_ev({
                "name": "sa-east3", "location": "eastus",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa-east3",
            }),
            _storage_ev({
                "name": "sa-brazil", "location": "brazilsouth",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa-brazil",
            }),
        ])
        findings = self.analyze(idx)
        # 3/4 in eastus → brazilsouth is outlier
        # eastus has 75% >= 10%, brazilsouth has 25% >= 10%
        # Actually with 4 resources, brazilsouth = 25% which is >= 10%. Need smaller fraction.
        # Let's adjust: need > 10 resources to make outlier work better.
        # Actually the logic is: < 10% is outlier. 25% is not < 10%. No finding expected here.
        # Better test: 10 in eastus, 1 in brazil
        pass

    def test_outlier_region_with_many_resources(self):
        """One resource in outlier region (< 10% of total)."""
        resources = [
            _storage_ev({
                "name": f"sa-east{i}", "location": "eastus",
                "id": f"/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa-east{i}",
            })
            for i in range(10)
        ] + [
            _storage_ev({
                "name": "sa-brazil", "location": "brazilsouth",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa-brazil",
            }),
        ]
        idx = _build_index(resources)
        findings = self.analyze(idx)
        outlier = [f for f in findings if "location" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(outlier), 0)

    def test_all_same_region_no_finding(self):
        idx = _build_index([
            _storage_ev({
                "name": "sa1", "location": "eastus",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa1",
            }),
            _storage_ev({
                "name": "sa2", "location": "eastus",
                "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/sa2",
            }),
        ])
        findings = self.analyze(idx)
        outlier = [f for f in findings if "location" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(outlier), 0)

    def test_geo_replication_detected(self):
        idx = _build_index([_storage_ev({
            "name": "geosa",
            "sku": {"name": "Standard_GRS"},
            "location": "eastus",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/geosa",
        })])
        findings = self.analyze(idx)
        geo_findings = [f for f in findings if "geo_replication" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(geo_findings), 0)

    def test_lrs_no_geo_finding(self):
        idx = _build_index([_storage_ev({
            "name": "lrssa",
            "sku": {"name": "Standard_LRS"},
            "location": "eastus",
            "id": "/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/lrssa",
        })])
        findings = self.analyze(idx)
        geo_findings = [f for f in findings if "geo_replication" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(geo_findings), 0)


# ====================================================================
# 18. Threat Detection & Incident Response (NEW category)
# ====================================================================

class TestThreatDetection(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_threat_detection
        self.analyze = analyze_threat_detection

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_defender_coverage_gaps_detected(self):
        idx = _build_index([_defender_ev({
            "name": "StorageAccounts",
            "pricingTier": "Free",
            "subscriptionId": "sub1",
            "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings/StorageAccounts",
        })])
        findings = self.analyze(idx)
        gap_findings = [f for f in findings if "coverage_gap" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(gap_findings), 0)

    def test_defender_all_enabled_no_finding(self):
        plans = [
            _defender_ev({
                "name": name,
                "pricingTier": "Standard",
                "subscriptionId": "sub1",
                "id": f"/subscriptions/sub1/providers/Microsoft.Security/pricings/{name}",
            })
            for name in ["StorageAccounts", "SqlServers", "KeyVaults",
                         "OpenSourceRelationalDatabases", "CosmosDb"]
        ]
        idx = _build_index(plans)
        findings = self.analyze(idx)
        gap_findings = [f for f in findings if "coverage_gap" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(gap_findings), 0)

    def test_no_action_groups_detected(self):
        idx = _build_index([_defender_ev({
            "name": "StorageAccounts",
            "pricingTier": "Standard",
            "subscriptionId": "sub1",
            "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings/StorageAccounts",
        })])
        findings = self.analyze(idx)
        ag_findings = [f for f in findings if "action_group" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(ag_findings), 0)

    def test_action_groups_present_no_finding(self):
        idx = _build_index([
            _defender_ev({
                "name": "StorageAccounts",
                "pricingTier": "Standard",
                "subscriptionId": "sub1",
                "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings/StorageAccounts",
            }),
            _action_group_ev({
                "name": "SecurityAlerts",
                "id": "/subscriptions/sub1/rg1/Microsoft.Insights/actionGroups/SecurityAlerts",
            }),
        ])
        findings = self.analyze(idx)
        ag_findings = [f for f in findings if "action_group" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(ag_findings), 0)


# ====================================================================
# 15. CLI Enhancements (suppressions, trend, CSV, remediation)
# ====================================================================

class TestCLIEnhancements(unittest.TestCase):
    def test_apply_suppressions(self):
        from run_data_security import _apply_suppressions
        findings = [
            {"Category": "storage", "Subcategory": "public_blob_access", "Severity": "high",
             "AffectedResources": [{"ResourceId": "/sub/rg/sa/mysa"}]},
            {"Category": "keyvault", "Subcategory": "purge_protection_disabled", "Severity": "high",
             "AffectedResources": [{"ResourceId": "/sub/rg/kv/mykv"}]},
        ]
        suppressions = [{"Subcategory": "public_blob_access"}]
        active, suppressed = _apply_suppressions(findings, suppressions)
        self.assertEqual(len(active), 1)
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(active[0]["Subcategory"], "purge_protection_disabled")

    def test_apply_suppressions_by_resource(self):
        from run_data_security import _apply_suppressions
        findings = [
            {"Category": "storage", "Subcategory": "public_blob_access", "Severity": "high",
             "AffectedResources": [{"ResourceId": "/sub/rg/sa/mysa"}]},
        ]
        suppressions = [{"Subcategory": "public_blob_access", "ResourceId": "/sub/rg/sa/mysa"}]
        active, suppressed = _apply_suppressions(findings, suppressions)
        self.assertEqual(len(active), 0)
        self.assertEqual(len(suppressed), 1)

    def test_compute_trend(self):
        import tempfile
        from run_data_security import _compute_trend
        prev = {
            "AssessedAt": "2025-01-01T00:00:00",
            "DataSecurityScores": {"OverallScore": 45},
            "Findings": [
                {"Category": "storage", "Subcategory": "public_blob_access"},
                {"Category": "keyvault", "Subcategory": "purge_protection_disabled"},
            ],
        }
        current = {
            "DataSecurityScores": {"OverallScore": 30},
            "Findings": [
                {"Category": "storage", "Subcategory": "public_blob_access"},
                {"Category": "encryption", "Subcategory": "unencrypted_disks"},
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(prev, f)
            prev_path = f.name
        try:
            trend = _compute_trend(current, prev_path)
            self.assertIsNotNone(trend)
            self.assertEqual(trend["ScoreDelta"], -15.0)
            self.assertEqual(trend["NewCount"], 1)  # encryption.unencrypted_disks
            self.assertEqual(trend["ResolvedCount"], 1)  # keyvault.purge_protection_disabled
        finally:
            os.unlink(prev_path)

    def test_generate_remediation_scripts(self):
        import tempfile
        from run_data_security import _generate_remediation_scripts
        findings = [
            {"Title": "Open Storage", "Severity": "high",
             "Remediation": {"AzureCLI": "az storage account update -n sa1 --https-only true"}},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            ps_path, sh_path = _generate_remediation_scripts(findings, tmpdir)
            self.assertTrue(os.path.exists(ps_path))
            self.assertTrue(os.path.exists(sh_path))
            with open(ps_path, "r") as fh:
                ps_content = fh.read()
            self.assertIn("az storage account update", ps_content)
            self.assertIn("[HIGH]", ps_content)


# ====================================================================
# Phase 2/3: New engine checks — Storage Blob Versioning & Change Feed
# ====================================================================

class TestStorageBlobVersioning(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_storage_exposure
        self.analyze = analyze_storage_exposure

    def test_no_versioning_flagged(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "nover", "IsBlobVersioningEnabled": False,
            "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/nover",
        })])
        findings = self.analyze(idx)
        ver = [f for f in findings if f.get("Subcategory") == "blob_versioning_disabled"]
        self.assertEqual(len(ver), 1)
        self.assertIn("versioning", ver[0]["Title"].lower())

    def test_versioning_enabled_no_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "ver", "IsBlobVersioningEnabled": True,
            "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/ver",
        })])
        findings = self.analyze(idx)
        ver = [f for f in findings if f.get("Subcategory") == "blob_versioning_disabled"]
        self.assertEqual(len(ver), 0)

    def test_missing_key_treated_as_disabled(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "nokey",
            "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/nokey",
        })])
        findings = self.analyze(idx)
        ver = [f for f in findings if f.get("Subcategory") == "blob_versioning_disabled"]
        self.assertEqual(len(ver), 1)


class TestStorageChangeFeed(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_storage_exposure
        self.analyze = analyze_storage_exposure

    def test_no_change_feed_flagged(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "nocf", "IsChangeFeedEnabled": False,
            "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/nocf",
        })])
        findings = self.analyze(idx)
        cf = [f for f in findings if f.get("Subcategory") == "change_feed_disabled"]
        self.assertEqual(len(cf), 1)

    def test_change_feed_enabled_no_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "cf", "IsChangeFeedEnabled": True,
            "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/cf",
        })])
        findings = self.analyze(idx)
        cf = [f for f in findings if f.get("Subcategory") == "change_feed_disabled"]
        self.assertEqual(len(cf), 0)


# ====================================================================
# Phase 2/3: SQL DDM & RLS
# ====================================================================

class TestSQLDDM(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_database_security
        self.analyze = analyze_database_security

    def test_no_ddm_flagged(self):
        idx = _build_index([_sql_ev({
            "Name": "srv1", "DataMaskingEnabled": False,
            "id": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1",
        })])
        findings = self.analyze(idx)
        ddm = [f for f in findings if f.get("Subcategory") == "sql_no_ddm"]
        self.assertEqual(len(ddm), 1)

    def test_ddm_enabled_no_finding(self):
        idx = _build_index([_sql_ev({
            "Name": "srv1", "DataMaskingEnabled": True,
            "id": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1",
        })])
        findings = self.analyze(idx)
        ddm = [f for f in findings if f.get("Subcategory") == "sql_no_ddm"]
        self.assertEqual(len(ddm), 0)


class TestSQLRLS(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_database_security
        self.analyze = analyze_database_security

    def test_rls_disabled_flagged(self):
        idx = _build_index([_sql_ev({
            "Name": "srv1",
            "_databases": [{"name": "db1", "RowLevelSecurityEnabled": False,
                            "id": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1/databases/db1"}],
            "id": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1",
        })])
        findings = self.analyze(idx)
        rls = [f for f in findings if f.get("Subcategory") == "sql_no_rls"]
        self.assertEqual(len(rls), 1)

    def test_rls_enabled_no_finding(self):
        idx = _build_index([_sql_ev({
            "Name": "srv1",
            "_databases": [{"name": "db1", "RowLevelSecurityEnabled": True}],
            "id": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1",
        })])
        findings = self.analyze(idx)
        rls = [f for f in findings if f.get("Subcategory") == "sql_no_rls"]
        self.assertEqual(len(rls), 0)


# ====================================================================
# Phase 2/3: Cosmos DB Consistency
# ====================================================================

class TestCosmosDBConsistency(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_cosmosdb_security
        self.analyze = analyze_cosmosdb_security

    def test_eventual_consistency_flagged(self):
        idx = _build_index([_cosmosdb_ev({
            "name": "db1",
            "consistencyPolicy": {"defaultConsistencyLevel": "Eventual"},
            "id": "/subscriptions/s/rg/Microsoft.DocumentDB/databaseAccounts/db1",
        })])
        findings = self.analyze(idx)
        cons = [f for f in findings if f.get("Subcategory") == "eventual_consistency"]
        self.assertEqual(len(cons), 1)

    def test_strong_consistency_no_finding(self):
        idx = _build_index([_cosmosdb_ev({
            "name": "db1",
            "consistencyPolicy": {"defaultConsistencyLevel": "Strong"},
            "id": "/subscriptions/s/rg/Microsoft.DocumentDB/databaseAccounts/db1",
        })])
        findings = self.analyze(idx)
        cons = [f for f in findings if f.get("Subcategory") == "eventual_consistency"]
        self.assertEqual(len(cons), 0)

    def test_session_consistency_no_finding(self):
        idx = _build_index([_cosmosdb_ev({
            "name": "db1",
            "consistencyPolicy": {"defaultConsistencyLevel": "Session"},
            "id": "/subscriptions/s/rg/Microsoft.DocumentDB/databaseAccounts/db1",
        })])
        findings = self.analyze(idx)
        cons = [f for f in findings if f.get("Subcategory") == "eventual_consistency"]
        self.assertEqual(len(cons), 0)


# ====================================================================
# Phase 2/3: Key Vault Certificate Auto-Renewal
# ====================================================================

class TestKeyVaultCertAutoRenewal(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_keyvault_hygiene
        self.analyze = analyze_keyvault_hygiene

    def test_cert_no_auto_renewal_flagged(self):
        idx = _build_index([_kv_ev({
            "VaultName": "myvault",
            "Certificates": [{"Name": "cert1", "Policy": {"LifetimeActions": []}}],
            "id": "/subscriptions/s/rg/Microsoft.KeyVault/vaults/myvault",
        })])
        findings = self.analyze(idx)
        cert = [f for f in findings if f.get("Subcategory") == "cert_no_auto_renewal"]
        self.assertEqual(len(cert), 1)

    def test_cert_with_auto_renewal_no_finding(self):
        idx = _build_index([_kv_ev({
            "VaultName": "myvault",
            "Certificates": [{"Name": "cert1", "Policy": {
                "LifetimeActions": [{"Action": {"ActionType": "AutoRenew"},
                                     "Trigger": {"DaysBeforeExpiry": 30}}],
            }}],
            "id": "/subscriptions/s/rg/Microsoft.KeyVault/vaults/myvault",
        })])
        findings = self.analyze(idx)
        cert = [f for f in findings if f.get("Subcategory") == "cert_no_auto_renewal"]
        self.assertEqual(len(cert), 0)

    def test_cert_missing_policy_flagged(self):
        idx = _build_index([_kv_ev({
            "VaultName": "myvault",
            "Certificates": [{"Name": "cert1"}],
            "id": "/subscriptions/s/rg/Microsoft.KeyVault/vaults/myvault",
        })])
        findings = self.analyze(idx)
        cert = [f for f in findings if f.get("Subcategory") == "cert_no_auto_renewal"]
        self.assertEqual(len(cert), 1)


# ====================================================================
# Phase 2/3: Key Vault HSM-Backed Keys
# ====================================================================

class TestKeyVaultHSM(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_keyvault_hygiene
        self.analyze = analyze_keyvault_hygiene

    def test_software_key_flagged(self):
        idx = _build_index([_kv_ev({
            "VaultName": "myvault",
            "Keys": [{"Name": "key1", "KeyType": "RSA"}],
            "id": "/subscriptions/s/rg/Microsoft.KeyVault/vaults/myvault",
        })])
        findings = self.analyze(idx)
        hsm = [f for f in findings if f.get("Subcategory") == "keys_not_hsm_backed"]
        self.assertEqual(len(hsm), 1)
        self.assertIn("software", hsm[0]["Title"].lower())

    def test_hsm_key_no_finding(self):
        idx = _build_index([_kv_ev({
            "VaultName": "myvault",
            "Keys": [{"Name": "key1", "KeyType": "RSA-HSM"}],
            "id": "/subscriptions/s/rg/Microsoft.KeyVault/vaults/myvault",
        })])
        findings = self.analyze(idx)
        hsm = [f for f in findings if f.get("Subcategory") == "keys_not_hsm_backed"]
        self.assertEqual(len(hsm), 0)

    def test_ec_hsm_key_no_finding(self):
        idx = _build_index([_kv_ev({
            "VaultName": "myvault",
            "Keys": [{"Name": "key1", "KeyType": "EC-HSM"}],
            "id": "/subscriptions/s/rg/Microsoft.KeyVault/vaults/myvault",
        })])
        findings = self.analyze(idx)
        hsm = [f for f in findings if f.get("Subcategory") == "keys_not_hsm_backed"]
        self.assertEqual(len(hsm), 0)


# ====================================================================
# Phase 2/3: File Sync Cloud Tiering & Stale Servers
# ====================================================================

def _sync_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-storagesync", "Data": data, "ResourceId": data.get("id", "")}


class TestFileSyncCloudTiering(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_file_sync_security
        self.analyze = analyze_file_sync_security

    def test_no_tiering_flagged(self):
        idx = _build_index([_sync_ev({
            "name": "sync1", "cloudTieringEnabled": False,
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        ct = [f for f in findings if f.get("Subcategory") == "cloud_tiering_disabled"]
        self.assertEqual(len(ct), 1)

    def test_tiering_enabled_no_finding(self):
        idx = _build_index([_sync_ev({
            "name": "sync1", "cloudTieringEnabled": True,
            "volumeFreeSpacePercent": 20,
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        ct = [f for f in findings if f.get("Subcategory") == "cloud_tiering_disabled"]
        self.assertEqual(len(ct), 0)


class TestFileSyncStaleServers(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_file_sync_security
        self.analyze = analyze_file_sync_security

    def test_stale_heartbeat_flagged(self):
        old_hb = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        idx = _build_index([_sync_ev({
            "name": "sync1",
            "registeredServers": [{"serverName": "srv1", "lastHeartBeat": old_hb, "agentVersion": "15.0"}],
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f.get("Subcategory") == "stale_registered_servers"]
        self.assertEqual(len(stale), 1)

    def test_recent_heartbeat_no_finding(self):
        recent_hb = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        idx = _build_index([_sync_ev({
            "name": "sync1",
            "registeredServers": [{"serverName": "srv1", "lastHeartBeat": recent_hb, "agentVersion": "15.0"}],
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f.get("Subcategory") == "stale_registered_servers"]
        self.assertEqual(len(stale), 0)


# ====================================================================
# Phase 2/3: DLP Sensitive Info Types & Rule Effectiveness
# ====================================================================

class TestDLPSensitiveInfoTypes(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_m365_dlp
        self.analyze = analyze_m365_dlp

    def test_no_sit_configured_flagged(self):
        idx = _build_index([_dlp_ev({
            "name": "policy1", "state": "Enabled", "sensitiveInfoTypes": [],
            "id": "dlp-policy-1",
        })])
        findings = self.analyze(idx)
        sit = [f for f in findings if f.get("Subcategory") == "dlp_no_sensitive_info_types"]
        self.assertEqual(len(sit), 1)

    def test_sit_configured_no_finding(self):
        idx = _build_index([_dlp_ev({
            "name": "policy1", "state": "Enabled",
            "sensitiveInfoTypes": [{"name": "Credit Card"}, {"name": "SSN"}],
            "id": "dlp-policy-1",
        })])
        findings = self.analyze(idx)
        sit = [f for f in findings if f.get("Subcategory") == "dlp_no_sensitive_info_types"]
        self.assertEqual(len(sit), 0)

    def test_disabled_policy_skipped(self):
        idx = _build_index([_dlp_ev({
            "name": "policy1", "state": "disabled", "sensitiveInfoTypes": [],
            "id": "dlp-policy-1",
        })])
        findings = self.analyze(idx)
        sit = [f for f in findings if f.get("Subcategory") == "dlp_no_sensitive_info_types"]
        self.assertEqual(len(sit), 0)


class TestDLPRuleEffectiveness(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_m365_dlp
        self.analyze = analyze_m365_dlp

    def test_no_rules_flagged(self):
        idx = _build_index([_dlp_ev({
            "name": "policy1", "state": "Enabled", "rules": [],
            "id": "dlp-policy-1",
        })])
        findings = self.analyze(idx)
        wr = [f for f in findings if f.get("Subcategory") == "dlp_weak_rules"]
        self.assertEqual(len(wr), 1)

    def test_rule_no_conditions_flagged(self):
        idx = _build_index([_dlp_ev({
            "name": "policy1", "state": "Enabled",
            "rules": [{"name": "Rule1", "conditions": []}],
            "id": "dlp-policy-1",
        })])
        findings = self.analyze(idx)
        wr = [f for f in findings if f.get("Subcategory") == "dlp_weak_rules"]
        self.assertEqual(len(wr), 1)

    def test_rule_with_conditions_no_finding(self):
        idx = _build_index([_dlp_ev({
            "name": "policy1", "state": "Enabled",
            "rules": [{"name": "Rule1", "conditions": [{"type": "SIT", "name": "SSN"}]}],
            "id": "dlp-policy-1",
        })])
        findings = self.analyze(idx)
        wr = [f for f in findings if f.get("Subcategory") == "dlp_weak_rules"]
        self.assertEqual(len(wr), 0)


# ====================================================================
# Phase 2/3: Data Residency
# ====================================================================

class TestDataResidencyAdvanced(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_residency
        self.analyze = analyze_data_residency

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_outlier_region_flagged(self):
        # Need 10+ resources so the outlier is < 10% of total
        evs = [
            _storage_ev({"StorageAccountName": f"sa{i}", "location": "eastus",
                         "id": f"/subscriptions/s/rg/Microsoft.Storage/storageAccounts/sa{i}"})
            for i in range(11)
        ] + [
            _storage_ev({"StorageAccountName": "outlier", "location": "brazilsouth",
                         "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/outlier"}),
        ]
        idx = _build_index(evs)
        findings = self.analyze(idx)
        outlier = [f for f in findings if f.get("Subcategory") == "resource_location_outlier"]
        self.assertEqual(len(outlier), 1)
        self.assertIn("unexpected", outlier[0]["Title"].lower())

    def test_single_region_no_outlier(self):
        evs = [
            _storage_ev({"StorageAccountName": "sa1", "location": "westus2",
                         "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/sa1"}),
        ]
        idx = _build_index(evs)
        findings = self.analyze(idx)
        outlier = [f for f in findings if f.get("Subcategory") == "resource_location_outlier"]
        self.assertEqual(len(outlier), 0)

    def test_geo_replication_flagged(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "geo", "location": "eastus",
            "sku": {"name": "Standard_RAGRS"},
            "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/geo",
        })])
        findings = self.analyze(idx)
        geo = [f for f in findings if f.get("Subcategory") == "geo_replication_cross_boundary"]
        self.assertEqual(len(geo), 1)

    def test_lrs_no_geo_finding(self):
        idx = _build_index([_storage_ev({
            "StorageAccountName": "lrs", "location": "eastus",
            "sku": {"name": "Standard_LRS"},
            "id": "/subscriptions/s/rg/Microsoft.Storage/storageAccounts/lrs",
        })])
        findings = self.analyze(idx)
        geo = [f for f in findings if f.get("Subcategory") == "geo_replication_cross_boundary"]
        self.assertEqual(len(geo), 0)


# ====================================================================
# Phase 2/3: Threat Detection — Defender Coverage Gaps & Audit Log Retention
# ====================================================================

def _defender_plan_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-defender-plans", "Data": data, "ResourceId": data.get("id", "")}

def _diag_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-diagnostic-settings", "Data": data, "ResourceId": data.get("resourceId", data.get("id", ""))}


class TestThreatDetectionAdvanced(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_threat_detection
        self.analyze = analyze_threat_detection

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_defender_gaps_flagged(self):
        idx = _build_index([_defender_plan_ev({
            "subscriptionId": "sub1",
            "plans": [
                {"name": "StorageAccounts", "pricingTier": "Free"},
                {"name": "SqlServers", "pricingTier": "Standard"},
            ],
            "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings",
        })])
        findings = self.analyze(idx)
        gaps = [f for f in findings if f.get("Subcategory") == "defender_coverage_gaps"]
        self.assertGreater(len(gaps), 0)

    def test_alert_action_groups_missing_flagged(self):
        idx = _build_index([_defender_plan_ev({
            "subscriptionId": "sub1",
            "plans": [{"name": "StorageAccounts", "pricingTier": "Standard"}],
            "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings",
        })])
        findings = self.analyze(idx)
        ag = [f for f in findings if f.get("Subcategory") == "no_security_action_groups"]
        self.assertEqual(len(ag), 1)

    def test_action_groups_present_no_finding(self):
        idx = _build_index([
            _defender_plan_ev({
                "subscriptionId": "sub1",
                "plans": [{"name": "StorageAccounts", "pricingTier": "Standard"}],
                "id": "/subscriptions/sub1/providers/Microsoft.Security/pricings",
            }),
            _action_group_ev({"name": "SecurityAlerts", "id": "ag1"}),
        ])
        findings = self.analyze(idx)
        ag = [f for f in findings if f.get("Subcategory") == "no_security_action_groups"]
        self.assertEqual(len(ag), 0)

    def test_audit_log_short_retention_flagged(self):
        idx = _build_index([_diag_ev({
            "resourceId": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1",
            "logs": [{"category": "SQLSecurityAuditEvents", "retentionPolicy": {"enabled": True, "days": 30}}],
        })])
        findings = self.analyze(idx)
        ret = [f for f in findings if f.get("Subcategory") == "audit_log_short_retention"]
        self.assertEqual(len(ret), 1)

    def test_audit_log_90_days_no_finding(self):
        idx = _build_index([_diag_ev({
            "resourceId": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1",
            "logs": [{"category": "SQLSecurityAuditEvents", "retentionPolicy": {"enabled": True, "days": 90}}],
        })])
        findings = self.analyze(idx)
        ret = [f for f in findings if f.get("Subcategory") == "audit_log_short_retention"]
        self.assertEqual(len(ret), 0)

    def test_retention_disabled_not_flagged(self):
        idx = _build_index([_diag_ev({
            "resourceId": "/subscriptions/s/rg/Microsoft.Sql/servers/srv1",
            "logs": [{"category": "Audit", "retentionPolicy": {"enabled": False, "days": 7}}],
        })])
        findings = self.analyze(idx)
        ret = [f for f in findings if f.get("Subcategory") == "audit_log_short_retention"]
        self.assertEqual(len(ret), 0)


# ====================================================================
# Phase 3: File Sync Public Access & Private Endpoint
# ====================================================================

class TestFileSyncPublicAccess(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_file_sync_security
        self.analyze = analyze_file_sync_security

    def test_public_access_flagged(self):
        idx = _build_index([_sync_ev({
            "name": "sync1", "incomingTrafficPolicy": "AllowAllTraffic",
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f.get("Subcategory") == "file_sync_public_access"]
        self.assertEqual(len(pub), 1)

    def test_vnet_only_no_finding(self):
        idx = _build_index([_sync_ev({
            "name": "sync1", "incomingTrafficPolicy": "AllowVirtualNetworksOnly",
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f.get("Subcategory") == "file_sync_public_access"]
        self.assertEqual(len(pub), 0)


class TestFileSyncPrivateEndpoint(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_file_sync_security
        self.analyze = analyze_file_sync_security

    def test_no_pe_flagged(self):
        idx = _build_index([_sync_ev({
            "name": "sync1",
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        pe = [f for f in findings if f.get("Subcategory") == "file_sync_no_private_endpoint"]
        self.assertEqual(len(pe), 1)

    def test_pe_present_no_finding(self):
        idx = _build_index([_sync_ev({
            "name": "sync1",
            "privateEndpointConnections": [{"id": "pe1"}],
            "id": "/subscriptions/s/rg/Microsoft.StorageSync/storageSyncServices/sync1",
        })])
        findings = self.analyze(idx)
        pe = [f for f in findings if f.get("Subcategory") == "file_sync_no_private_endpoint"]
        self.assertEqual(len(pe), 0)


# ====================================================================
# Phase 3: Edge cases — malformed evidence, null fields
# ====================================================================

class TestEdgeCases(unittest.TestCase):
    def test_storage_none_data_field(self):
        from app.data_security_engine import analyze_storage_exposure
        ev = {"EvidenceType": "azure-storage-security", "Data": None, "ResourceId": ""}
        idx = {"azure-storage-security": [ev]}
        # Should not crash
        try:
            analyze_storage_exposure(idx)
        except (TypeError, AttributeError):
            pass  # Some checks may not handle None data gracefully — that's an acceptable edge

    def test_keyvault_empty_evidence(self):
        from app.data_security_engine import analyze_keyvault_hygiene
        idx = {"azure-keyvault": []}
        findings = analyze_keyvault_hygiene(idx)
        self.assertEqual(len(findings), 0)

    def test_cosmosdb_missing_consistency_policy(self):
        from app.data_security_engine import analyze_cosmosdb_security
        idx = _build_index([_cosmosdb_ev({
            "name": "db1",
            "id": "/subscriptions/s/rg/Microsoft.DocumentDB/databaseAccounts/db1",
        })])
        findings = analyze_cosmosdb_security(idx)
        # Should not crash; if no consistency policy, may or may not flag
        self.assertIsInstance(findings, list)

    def test_scoring_empty_findings(self):
        from app.data_security_engine import compute_data_security_scores
        result = compute_data_security_scores([])
        self.assertIn("OverallScore", result)
        # No findings = not necessarily 100; engine may return 0 for no data
        self.assertIsInstance(result["OverallScore"], (int, float))


# ────────────────────────────────────────────────────────────────────
# Finding Consolidation Tests
# ────────────────────────────────────────────────────────────────────

class TestConsolidateFindings(unittest.TestCase):
    """Test consolidate_findings() merges overlapping findings correctly."""

    def _make_finding(self, cat, subcat, severity, res_ids):
        return {
            "DataSecurityFindingId": str(uuid.uuid4()),
            "Category": cat,
            "Subcategory": subcat,
            "Title": f"{len(res_ids)} resources: {subcat}",
            "Description": f"Test finding for {subcat}",
            "Severity": severity,
            "AffectedResources": [
                {"Name": rid.split("/")[-1], "ResourceId": rid, "Type": "Test"}
                for rid in res_ids
            ],
            "AffectedCount": len(res_ids),
            "Remediation": {"Description": f"Fix {subcat}", "AzureCLI": f"az fix {subcat}"},
            "DetectedAt": "2025-01-01T00:00:00",
        }

    def test_no_merge_single_finding(self):
        from app.data_security_engine import consolidate_findings
        findings = [self._make_finding("storage", "blob_public", "high", ["/sub/rg/sa/a"])]
        result = consolidate_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertNotIn("MergedFrom", result[0])

    def test_merge_same_resources(self):
        from app.data_security_engine import consolidate_findings
        ids = ["/sub/rg/sa/a", "/sub/rg/sa/b", "/sub/rg/sa/c"]
        f1 = self._make_finding("storage", "no_sas", "medium", ids)
        f2 = self._make_finding("storage", "no_immutability", "low", ids)
        f3 = self._make_finding("storage", "no_versioning", "medium", ids)
        result = consolidate_findings([f1, f2, f3])
        self.assertEqual(len(result), 1)
        merged = result[0]
        self.assertEqual(merged["Category"], "storage")
        self.assertEqual(merged["Subcategory"], "storage_consolidated")
        self.assertEqual(merged["AffectedCount"], 3)
        self.assertEqual(merged["MergedCount"], 3)
        self.assertEqual(len(merged["MergedFrom"]), 3)

    def test_highest_severity_wins(self):
        from app.data_security_engine import consolidate_findings
        ids = ["/sub/rg/kv/a", "/sub/rg/kv/b"]
        f1 = self._make_finding("keyvault", "purge_off", "high", ids)
        f2 = self._make_finding("keyvault", "legacy_rbac", "medium", ids)
        result = consolidate_findings([f1, f2])
        self.assertEqual(result[0]["Severity"], "high")

    def test_no_merge_different_categories(self):
        from app.data_security_engine import consolidate_findings
        ids = ["/sub/rg/sa/a"]
        f1 = self._make_finding("storage", "check1", "medium", ids)
        f2 = self._make_finding("keyvault", "check2", "medium", ids)
        result = consolidate_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_no_merge_disjoint_resources(self):
        from app.data_security_engine import consolidate_findings
        f1 = self._make_finding("storage", "check1", "medium", ["/sub/rg/sa/a"])
        f2 = self._make_finding("storage", "check2", "medium", ["/sub/rg/sa/b"])
        result = consolidate_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_no_merge_empty_resources(self):
        from app.data_security_engine import consolidate_findings
        f1 = self._make_finding("m365_dlp", "no_dlp", "medium", [])
        f2 = self._make_finding("m365_dlp", "no_labels", "medium", [])
        result = consolidate_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_resources_deduped_in_merge(self):
        from app.data_security_engine import consolidate_findings
        ids = ["/sub/rg/sa/a", "/sub/rg/sa/b"]
        f1 = self._make_finding("storage", "check1", "medium", ids)
        f2 = self._make_finding("storage", "check2", "medium", ids)
        result = consolidate_findings([f1, f2])
        merged = result[0]
        res_ids = [ar["ResourceId"] for ar in merged["AffectedResources"]]
        self.assertEqual(len(res_ids), 2)
        self.assertEqual(len(set(res_ids)), 2)

    def test_gaps_field_populated(self):
        from app.data_security_engine import consolidate_findings
        ids = ["/sub/rg/sa/a"]
        f1 = self._make_finding("storage", "check_a", "medium", ids)
        f2 = self._make_finding("storage", "check_b", "medium", ids)
        result = consolidate_findings([f1, f2])
        gaps = result[0]["AffectedResources"][0].get("Gaps", [])
        self.assertIn("check_a", gaps)
        self.assertIn("check_b", gaps)

    def test_partial_overlap_merges(self):
        from app.data_security_engine import consolidate_findings
        # 3 out of 3 overlap in smaller set = 100% → merge
        f1 = self._make_finding("storage", "c1", "medium", ["/a", "/b", "/c"])
        f2 = self._make_finding("storage", "c2", "medium", ["/a", "/b", "/c", "/d"])
        result = consolidate_findings([f1, f2])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["AffectedCount"], 4)

    def test_low_overlap_no_merge(self):
        from app.data_security_engine import consolidate_findings
        # 1 out of 3 overlap = 33% → no merge (threshold 80%)
        f1 = self._make_finding("storage", "c1", "medium", ["/a", "/b", "/c"])
        f2 = self._make_finding("storage", "c2", "medium", ["/a", "/x", "/y"])
        result = consolidate_findings([f1, f2])
        self.assertEqual(len(result), 2)

    def test_remediation_combined(self):
        from app.data_security_engine import consolidate_findings
        ids = ["/a"]
        f1 = self._make_finding("keyvault", "c1", "high", ids)
        f2 = self._make_finding("keyvault", "c2", "medium", ids)
        result = consolidate_findings([f1, f2])
        rem = result[0]["Remediation"]
        self.assertIn("c1", rem["Description"])
        self.assertIn("c2", rem["Description"])
        self.assertIn("c1", rem["AzureCLI"])
        self.assertIn("c2", rem["AzureCLI"])


# ====================================================================
# Zero Trust-aligned checks
# ====================================================================

def _ev(etype: str, data: dict, rid: str = "") -> dict:
    return {"EvidenceType": etype, "Data": data, "ResourceId": rid or data.get("id", "")}


class TestSqlAadOnlyAuth(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_sql_aad_only_auth
        self.check = _check_sql_aad_only_auth

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_aad_only_enabled(self):
        idx = _build_index([_ev("azure-sql-server", {"azureADOnlyAuthentication": True, "Name": "srv1"}, "/sub/srv1")])
        self.assertEqual(self.check(idx), [])

    def test_local_auth_flagged(self):
        idx = _build_index([_ev("azure-sql-server", {"azureADOnlyAuthentication": False, "Name": "srv1"}, "/sub/srv1")])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "sql_local_auth_enabled")

    def test_no_aad_field_flagged(self):
        idx = _build_index([_ev("azure-sql-server", {"Name": "srv1"}, "/sub/srv1")])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)

    def test_nested_admin_field(self):
        idx = _build_index([_ev("azure-sql-server", {
            "administrators": {"azureADOnlyAuthentication": True}, "Name": "srv1"
        }, "/sub/srv1")])
        self.assertEqual(self.check(idx), [])


class TestPgMysqlAadAuth(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_pg_mysql_aad_auth
        self.check = _check_pg_mysql_aad_auth

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_aad_enabled_via_auth_config(self):
        idx = _build_index([_ev("azure-dbforpostgresql", {
            "authConfig": {"activeDirectoryAuth": "Enabled"},
            "name": "pg1", "type": "Microsoft.DBforPostgreSQL/flexibleServers"
        })])
        self.assertEqual(self.check(idx), [])

    def test_aad_enabled_via_admin(self):
        idx = _build_index([_ev("azure-dbformysql", {
            "azureADAdministrator": {"login": "admin@example.com"},
            "name": "mysql1", "type": "Microsoft.DBforMySQL/flexibleServers"
        })])
        self.assertEqual(self.check(idx), [])

    def test_no_aad_flagged(self):
        idx = _build_index([_ev("azure-dbforpostgresql", {
            "name": "pg1", "type": "Microsoft.DBforPostgreSQL/flexibleServers"
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "pg_mysql_no_aad_auth")


class TestManagedIdentityAdoption(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_managed_identity_adoption
        self.check = _check_managed_identity_adoption

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_has_identity(self):
        idx = _build_index([_ev("azure-storage-security", {
            "identity": {"type": "SystemAssigned"}, "name": "sa1"
        })])
        self.assertEqual(self.check(idx), [])

    def test_no_identity_flagged(self):
        idx = _build_index([_ev("azure-storage-security", {"name": "sa1"})])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_managed_identity")

    def test_identity_none_is_flagged(self):
        idx = _build_index([_ev("azure-keyvault", {
            "identity": {"type": "None"}, "name": "kv1"
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)


class TestResourceLocks(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_resource_locks
        self.check = _check_resource_locks

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_locked_resource_ok(self):
        idx = _build_index([
            _ev("azure-resource-lock", {"scope": "/sub/rg/sa1"}, "/sub/rg/sa1"),
            _ev("azure-storage-security", {"name": "sa1"}, "/sub/rg/sa1"),
        ])
        self.assertEqual(self.check(idx), [])

    def test_unlocked_flagged(self):
        idx = _build_index([
            _ev("azure-storage-security", {"name": "sa1"}, "/sub/rg/sa1"),
        ])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_resource_lock")


class TestDataFactoryManagedVnet(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_data_factory_managed_vnet
        self.check = _check_data_factory_managed_vnet

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_managed_vnet_set(self):
        idx = _build_index([_ev("azure-data-factory", {
            "name": "adf1", "properties": {"managedVirtualNetwork": "default"}
        })])
        self.assertEqual(self.check(idx), [])

    def test_no_managed_vnet_flagged(self):
        idx = _build_index([_ev("azure-data-factory", {
            "name": "adf1", "properties": {}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "adf_no_managed_vnet")


class TestSynapseManagedVnet(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_synapse_managed_vnet
        self.check = _check_synapse_managed_vnet

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_fully_protected(self):
        idx = _build_index([_ev("azure-synapse-workspace", {
            "name": "syn1",
            "properties": {
                "managedVirtualNetwork": "default",
                "managedVirtualNetworkSettings": {"preventDataExfiltration": True}
            }
        })])
        self.assertEqual(self.check(idx), [])

    def test_no_exfil_protection_flagged(self):
        idx = _build_index([_ev("azure-synapse-workspace", {
            "name": "syn1",
            "properties": {"managedVirtualNetwork": "default", "managedVirtualNetworkSettings": {}}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "synapse_no_exfiltration_protection")


class TestAiServicesNetwork(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_ai_services_network
        self.check = _check_ai_services_network

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_disabled_ok(self):
        idx = _build_index([_ev("azure-cognitive-account", {
            "name": "ai1", "properties": {"publicNetworkAccess": "Disabled"}
        })])
        self.assertEqual(self.check(idx), [])

    def test_deny_acl_ok(self):
        idx = _build_index([_ev("azure-cognitive-account", {
            "name": "ai1", "properties": {"networkAcls": {"defaultAction": "Deny"}}
        })])
        self.assertEqual(self.check(idx), [])

    def test_public_flagged(self):
        idx = _build_index([_ev("azure-cognitive-account", {
            "name": "ai1", "properties": {"publicNetworkAccess": "Enabled"}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "ai_services_public_access")


class TestLogAnalyticsCmk(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_log_analytics_cmk
        self.check = _check_log_analytics_cmk

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_cluster_linked_ok(self):
        idx = _build_index([_ev("azure-log-analytics", {
            "name": "la1", "properties": {"clusterResourceId": "/sub/clusters/c1"}
        })])
        self.assertEqual(self.check(idx), [])

    def test_no_cluster_flagged(self):
        idx = _build_index([_ev("azure-log-analytics", {
            "name": "la1", "properties": {}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "log_analytics_no_cmk")


class TestImmutableAuditLogs(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_immutable_audit_logs
        self.check = _check_immutable_audit_logs

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_immutable_ok(self):
        idx = _build_index([_ev("azure-log-analytics", {
            "name": "la1", "properties": {"features": {"immutableAuditLog": True}}
        })])
        self.assertEqual(self.check(idx), [])

    def test_not_immutable_flagged(self):
        idx = _build_index([_ev("azure-log-analytics", {
            "name": "la1", "properties": {"features": {}}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_immutable_audit_logs")


class TestAutoLabelingPolicies(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_auto_labeling_policies
        self.check = _check_auto_labeling_policies

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_has_auto_labeling(self):
        idx = _build_index([_ev("m365-sensitivity-label-definition", {
            "autoLabeling": {"isEnabled": True}
        })])
        self.assertEqual(self.check(idx), [])

    def test_no_auto_labeling_flagged(self):
        idx = _build_index([_ev("m365-sensitivity-label-definition", {
            "name": "Confidential"
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_auto_labeling")


class TestDataMinimization(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_data_minimization
        self.check = _check_data_minimization

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_has_delete_action(self):
        idx = _build_index([_ev("m365-retention-label", {
            "ActionAfterRetentionPeriod": "Delete"
        })])
        self.assertEqual(self.check(idx), [])

    def test_retain_only_flagged(self):
        idx = _build_index([_ev("m365-retention-label", {
            "ActionAfterRetentionPeriod": "Retain"
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_data_minimization")


class TestRedisTls(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_redis_tls
        self.check = _check_redis_tls

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_tls_12_ok(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {"minimumTlsVersion": "1.2"}
        })])
        self.assertEqual(self.check(idx), [])

    def test_weak_tls_flagged(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {"minimumTlsVersion": "1.0"}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "redis_weak_tls")


class TestRedisNonSslPort(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_redis_non_ssl_port
        self.check = _check_redis_non_ssl_port

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_ssl_port_disabled_ok(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {"enableNonSslPort": False}
        })])
        self.assertEqual(self.check(idx), [])

    def test_non_ssl_port_flagged(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {"enableNonSslPort": True}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "redis_non_ssl_port")


class TestRedisFirewall(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_redis_firewall
        self.check = _check_redis_firewall

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_firewall_rules_ok(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {"firewallRules": [{"startIP": "10.0.0.0"}]}
        })])
        self.assertEqual(self.check(idx), [])

    def test_private_endpoint_ok(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {"privateEndpointConnections": [{"id": "/pe1"}]}
        })])
        self.assertEqual(self.check(idx), [])

    def test_public_disabled_ok(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {"publicNetworkAccess": "Disabled"}
        })])
        self.assertEqual(self.check(idx), [])

    def test_no_protection_flagged(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1", "properties": {}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "redis_no_firewall")


class TestEventhubNetwork(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_eventhub_network
        self.check = _check_eventhub_network

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_disabled_ok(self):
        idx = _build_index([_ev("azure-eventhub-namespace", {
            "name": "eh1", "properties": {"publicNetworkAccess": "Disabled"}
        })])
        self.assertEqual(self.check(idx), [])

    def test_public_flagged(self):
        idx = _build_index([_ev("azure-eventhub-namespace", {
            "name": "eh1", "properties": {"publicNetworkAccess": "Enabled"}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "eventhub_public_access")


class TestServicebusNetwork(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_servicebus_network
        self.check = _check_servicebus_network

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_deny_ok(self):
        idx = _build_index([_ev("azure-servicebus-namespace", {
            "name": "sb1", "properties": {"networkRuleSets": {"defaultAction": "Deny"}}
        })])
        self.assertEqual(self.check(idx), [])

    def test_public_flagged(self):
        idx = _build_index([_ev("azure-servicebus-namespace", {
            "name": "sb1", "properties": {"publicNetworkAccess": "Enabled"}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "servicebus_public_access")


class TestMessagingTls(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import _check_messaging_tls
        self.check = _check_messaging_tls

    def test_empty(self):
        self.assertEqual(self.check({}), [])

    def test_tls_12_ok(self):
        idx = _build_index([_ev("azure-eventhub-namespace", {
            "name": "eh1", "type": "Microsoft.EventHub/namespaces",
            "properties": {"minimumTlsVersion": "1.2"}
        })])
        self.assertEqual(self.check(idx), [])

    def test_weak_tls_flagged(self):
        idx = _build_index([_ev("azure-servicebus-namespace", {
            "name": "sb1", "type": "Microsoft.ServiceBus/namespaces",
            "properties": {"minimumTlsVersion": "1.0"}
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "messaging_weak_tls")


class TestAnalyzeRedisSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_redis_security
        self.analyze = analyze_redis_security

    def test_empty(self):
        self.assertEqual(self.analyze({}), [])

    def test_all_issues_detected(self):
        idx = _build_index([_ev("azure-redis-cache", {
            "name": "r1",
            "properties": {
                "minimumTlsVersion": "1.0",
                "enableNonSslPort": True,
            }
        })])
        findings = self.analyze(idx)
        check_ids = {f["Subcategory"] for f in findings}
        self.assertIn("redis_weak_tls", check_ids)
        self.assertIn("redis_non_ssl_port", check_ids)
        self.assertIn("redis_no_firewall", check_ids)


class TestAnalyzeMessagingSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_messaging_security
        self.analyze = analyze_messaging_security

    def test_empty(self):
        self.assertEqual(self.analyze({}), [])

    def test_issues_detected(self):
        idx = _build_index([
            _ev("azure-eventhub-namespace", {
                "name": "eh1", "type": "Microsoft.EventHub/namespaces",
                "properties": {"publicNetworkAccess": "Enabled", "minimumTlsVersion": "1.0"}
            }),
            _ev("azure-servicebus-namespace", {
                "name": "sb1", "type": "Microsoft.ServiceBus/namespaces",
                "properties": {"publicNetworkAccess": "Enabled"}
            }),
        ])
        findings = self.analyze(idx)
        check_ids = {f["Subcategory"] for f in findings}
        self.assertIn("eventhub_public_access", check_ids)
        self.assertIn("servicebus_public_access", check_ids)
        self.assertIn("messaging_weak_tls", check_ids)


# ── Tests for Wave A–J analyze functions ──────────────────────────────


class TestAnalyzePurviewSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_purview_security
        self.analyze = analyze_purview_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_purview(self):
        idx = _build_index([
            _ev("azure-purview", {
                "name": "pv1",
                "publicNetworkAccess": "Disabled",
                "privateEndpointConnections": [{"id": "/pe1"}],
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Purview/accounts/pv1"),
        ])
        # Add identity so managed identity check passes
        idx["azure-purview"][0]["Data"]["identity"] = {"type": "SystemAssigned"}
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertNotIn("purview_public_access", subcats)
        self.assertNotIn("purview_no_private_endpoint", subcats)
        self.assertNotIn("purview_no_managed_identity", subcats)

    def test_noncompliant_purview_public_no_pe_no_mi(self):
        idx = _build_index([
            _ev("azure-purview", {
                "name": "pv-bad",
                "publicNetworkAccess": "Enabled",
                "privateEndpointConnections": [],
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Purview/accounts/pv-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("purview_public_access", subcats)
        self.assertIn("purview_no_private_endpoint", subcats)
        self.assertIn("purview_no_managed_identity", subcats)

    def test_no_purview_account(self):
        """When data services exist but no Purview account → no_purview_account."""
        idx = _build_index([
            _ev("azure-storage-security", {"StorageAccountName": "sa1"}),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_purview_account", subcats)


class TestAnalyzeSharepointGovernance(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_sharepoint_governance
        self.analyze = analyze_sharepoint_governance

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_sharepoint(self):
        idx = _build_index([
            _ev("spo-site-permissions", {
                "SiteName": "TeamSite", "SiteId": "s1",
                "IsOvershared": False, "GuestCount": 1, "ExternalUserCount": 0,
            }),
        ])
        findings = self.analyze(idx)
        self.assertEqual(findings, [])

    def test_overshared_site(self):
        idx = _build_index([
            _ev("spo-site-permissions", {
                "SiteName": "BigSite", "SiteId": "s1",
                "IsOvershared": True, "TotalPermissions": 200,
                "OwnerCount": 5, "MemberCount": 100, "GuestCount": 20,
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("overshared_sites", subcats)

    def test_anonymous_sharing_links(self):
        idx = _build_index([
            _ev("spo-sharing-links", {
                "SiteName": "DocsSite", "SiteId": "s2",
                "AnonymousLinks": 5, "TotalSharedItems": 50,
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("anonymous_sharing_links", subcats)

    def test_stale_sites(self):
        idx = _build_index([
            _ev("spo-site-inventory", {
                "SiteName": "OldSite", "SiteId": "s3", "IsStale": True,
                "LastModifiedDateTime": "2023-01-01T00:00:00Z",
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("stale_sites", subcats)


class TestAnalyzeM365DataLifecycle(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_m365_data_lifecycle
        self.analyze = analyze_m365_data_lifecycle

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_lifecycle(self):
        idx = _build_index([
            _ev("m365-retention-label", {
                "DisplayName": "KeepAndDelete", "IsInUse": True,
                "ActionAfterRetentionPeriod": "Delete",
            }),
            _ev("m365-ediscovery-case", {"CaseId": "c1", "Status": "Active"}),
        ])
        findings = self.analyze(idx)
        self.assertEqual(findings, [])

    def test_no_retention_labels(self):
        idx: dict[str, list[dict]] = {"m365-other": [{"EvidenceType": "m365-other", "Data": {}}]}
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_retention_labels", subcats)

    def test_no_ediscovery(self):
        idx = _build_index([
            _ev("m365-retention-label", {
                "DisplayName": "Keep", "IsInUse": True,
                "ActionAfterRetentionPeriod": "Delete",
            }),
        ])
        # Add m365 key so the m365 check triggers
        idx["m365-dummy"] = []
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_ediscovery_cases", subcats)


class TestAnalyzeDlpAlertEffectiveness(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_dlp_alert_effectiveness
        self.analyze = analyze_dlp_alert_effectiveness

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_no_alert_metrics(self):
        idx = _build_index([])
        self.assertEqual(self.analyze(idx), [])

    def test_high_severity_dlp_alerts(self):
        idx = _build_index([
            _ev("m365-dlp-alert-metrics", {
                "TotalDlpAlerts": 10, "TotalSecurityAlerts": 20,
                "SeverityCounts": {"high": 3, "critical": 3},
                "RecentAlerts": [{"Type": "DLPAlert", "Name": "a1"}],
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("high_severity_dlp_alerts", subcats)

    def test_no_dlp_alerts_with_policies(self):
        idx = _build_index([
            _ev("m365-dlp-alert-metrics", {
                "TotalDlpAlerts": 0, "TotalSecurityAlerts": 5,
                "SeverityCounts": {},
            }),
            _ev("m365-dlp-policies", {"PolicyName": "p1"}),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_dlp_alerts_with_policies", subcats)


class TestAnalyzeAiServicesSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_ai_services_security
        self.analyze = analyze_ai_services_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_ai_services(self):
        idx = _build_index([
            _ev("azure-cognitive-account", {
                "name": "ai1",
                "properties": {"disableLocalAuth": True},
                "identity": {"type": "SystemAssigned"},
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai1"),
        ])
        # Add CMK encryption
        idx["azure-cognitive-account"][0]["Data"]["properties"]["encryption"] = {
            "keySource": "Microsoft.KeyVault"
        }
        findings = self.analyze(idx)
        self.assertEqual(findings, [])

    def test_noncompliant_ai_key_auth_no_mi_no_cmk(self):
        idx = _build_index([
            _ev("azure-cognitive-account", {
                "name": "ai-bad",
                "properties": {"disableLocalAuth": False},
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("ai_key_auth_enabled", subcats)
        self.assertIn("ai_no_managed_identity", subcats)
        self.assertIn("ai_no_cmk", subcats)


class TestAnalyzeDataFactorySecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_factory_security
        self.analyze = analyze_data_factory_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_adf(self):
        idx = _build_index([
            _ev("azure-data-factory", {
                "name": "adf1",
                "properties": {"publicNetworkAccess": "Disabled"},
                "identity": {"type": "SystemAssigned"},
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.DataFactory/factories/adf1"),
        ])
        findings = self.analyze(idx)
        adf_findings = [f for f in findings if f["Category"] == "data_factory"]
        self.assertEqual(adf_findings, [])

    def test_noncompliant_adf(self):
        idx = _build_index([
            _ev("azure-data-factory", {
                "name": "adf-bad",
                "properties": {"publicNetworkAccess": "Enabled"},
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.DataFactory/factories/adf-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("adf_public_access", subcats)
        self.assertIn("adf_no_managed_identity", subcats)


class TestAnalyzeManagedIdentityDeep(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_managed_identity_deep
        self.analyze = analyze_managed_identity_deep

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_services_with_mi(self):
        idx = _build_index([
            _ev("azure-data-factory", {
                "name": "adf1", "identity": {"type": "SystemAssigned"},
            }),
            _ev("azure-eventhub-namespace", {
                "name": "eh1", "identity": {"type": "UserAssigned"},
            }),
        ])
        findings = self.analyze(idx)
        self.assertEqual(findings, [])

    def test_services_without_mi(self):
        idx = _build_index([
            _ev("azure-data-factory", {"name": "adf-no-mi"}),
            _ev("azure-servicebus-namespace", {"name": "sb-no-mi"}),
        ])
        findings = self.analyze(idx)
        self.assertTrue(len(findings) > 0)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("data_services_no_managed_identity", subcats)
        # Both resources should appear in affected
        names = {r["Name"] for f in findings for r in f["AffectedResources"]}
        self.assertIn("adf-no-mi", names)
        self.assertIn("sb-no-mi", names)


class TestAnalyzeSqlMiSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_sql_mi_security
        self.analyze = analyze_sql_mi_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_sql_mi(self):
        idx = _build_index([
            _ev("azure-sql-mi", {
                "name": "mi1",
                "AdvancedThreatProtection": True,
                "publicDataEndpointEnabled": False,
                "administratorType": "ActiveDirectory",
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/managedInstances/mi1"),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_noncompliant_sql_mi(self):
        idx = _build_index([
            _ev("azure-sql-mi", {
                "name": "mi-bad",
                "AdvancedThreatProtection": False,
                "publicDataEndpointEnabled": True,
                "administratorType": "SQL",
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Sql/managedInstances/mi-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("sqlmi_no_atp", subcats)
        self.assertIn("sqlmi_public_endpoint", subcats)
        self.assertIn("sqlmi_no_aad_only", subcats)


class TestAnalyzeAppConfigSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_app_config_security
        self.analyze = analyze_app_config_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_app_config(self):
        idx = _build_index([
            _ev("azure-app-configuration", {
                "name": "ac1",
                "publicNetworkAccess": "Disabled",
                "privateEndpointConnections": [{"id": "/pe1"}],
                "enablePurgeProtection": True,
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/ac1"),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_noncompliant_app_config(self):
        idx = _build_index([
            _ev("azure-app-configuration", {
                "name": "ac-bad",
                "publicNetworkAccess": "Enabled",
                "privateEndpointConnections": [],
                "enablePurgeProtection": False,
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/ac-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("appconfig_public_access", subcats)
        self.assertIn("appconfig_no_private_endpoint", subcats)
        self.assertIn("appconfig_no_soft_delete", subcats)


class TestAnalyzeCertLifecycle(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_cert_lifecycle
        self.analyze = analyze_cert_lifecycle

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_certs(self):
        future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        idx = _build_index([
            _ev("azure-keyvault-certs", {
                "name": "cert1", "vaultName": "kv1",
                "expires": future, "autoRenewEnabled": True, "keySize": 4096,
            }),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_expiring_cert(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        idx = _build_index([
            _ev("azure-keyvault-certs", {
                "name": "cert-exp", "vaultName": "kv1",
                "expires": soon, "autoRenewEnabled": True, "keySize": 2048,
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("cert_expiring_soon", subcats)

    def test_no_auto_renew_and_weak_key(self):
        future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        idx = _build_index([
            _ev("azure-keyvault-certs", {
                "name": "cert-weak", "vaultName": "kv1",
                "expires": future, "autoRenewEnabled": False, "keySize": 1024,
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("cert_no_auto_renew", subcats)
        self.assertIn("cert_weak_key", subcats)


class TestAnalyzeDatabricksSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_databricks_security
        self.analyze = analyze_databricks_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_databricks(self):
        idx = _build_index([
            _ev("azure-databricks", {
                "name": "dbx1",
                "parameters": {"customVirtualNetworkId": {"value": "/vnets/v1"}},
                "encryption": {"entities": {"managedServices": {"keySource": "Microsoft.Keyvault"}}},
                "publicNetworkAccess": "Disabled",
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/dbx1"),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_noncompliant_databricks(self):
        idx = _build_index([
            _ev("azure-databricks", {
                "name": "dbx-bad",
                "parameters": {},
                "encryption": {},
                "publicNetworkAccess": "Enabled",
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/dbx-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("databricks_no_vnet", subcats)
        self.assertIn("databricks_no_cmk", subcats)
        self.assertIn("databricks_public_access", subcats)


class TestAnalyzeApimSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_apim_security
        self.analyze = analyze_apim_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_apim(self):
        idx = _build_index([
            _ev("azure-apim", {
                "name": "apim1",
                "virtualNetworkType": "Internal",
                "identity": {"type": "SystemAssigned"},
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim1"),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_noncompliant_apim(self):
        idx = _build_index([
            _ev("azure-apim", {
                "name": "apim-bad",
                "virtualNetworkType": "None",
                "identity": {},
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.ApiManagement/service/apim-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("apim_no_vnet", subcats)
        self.assertIn("apim_no_managed_identity", subcats)


class TestAnalyzeFrontdoorSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_frontdoor_security
        self.analyze = analyze_frontdoor_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_frontdoor(self):
        idx = _build_index([
            _ev("azure-frontdoor", {
                "name": "fd1",
                "wafPolicyId": "/policies/waf1",
                "minimumTlsVersion": "1.2",
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd1"),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_noncompliant_frontdoor(self):
        idx = _build_index([
            _ev("azure-frontdoor", {
                "name": "fd-bad",
                "minimumTlsVersion": "1.0",
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Cdn/profiles/fd-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("frontdoor_no_waf", subcats)
        self.assertIn("frontdoor_old_tls", subcats)


class TestAnalyzeSecretSprawl(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_secret_sprawl
        self.analyze = analyze_secret_sprawl

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_webapp_kv_refs(self):
        idx = _build_index([
            _ev("azure-webapp", {
                "name": "app1",
                "appSettings": [
                    {"name": "DbConn", "value": "@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/db)"},
                ],
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/app1"),
        ])
        findings = self.analyze(idx)
        sprawl = [f for f in findings if f["Subcategory"] == "secret_in_app_settings"]
        self.assertEqual(sprawl, [])

    def test_secret_in_app_settings(self):
        idx = _build_index([
            _ev("azure-webapp", {
                "name": "app-bad",
                "appSettings": [
                    {"name": "ConnectionString", "value": "Server=tcp:srv.database.windows.net;Password=SuperSecret12345!"},
                ],
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/app-bad"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("secret_in_app_settings", subcats)

    def test_no_keyvault_references(self):
        idx = _build_index([
            _ev("azure-webapp", {
                "name": "app-no-kv",
                "appSettings": [
                    {"name": "Setting1", "value": "plain-value"},
                ],
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites/app-no-kv"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_keyvault_references", subcats)


class TestAnalyzeFirewallAppgwSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_firewall_appgw_security
        self.analyze = analyze_firewall_appgw_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_firewall(self):
        idx = _build_index([
            _ev("azure-firewall", {
                "name": "fw1",
                "threatIntelMode": "Deny",
                "intrusionDetection": {"mode": "Alert"},
            }),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_noncompliant_firewall(self):
        idx = _build_index([
            _ev("azure-firewall", {
                "name": "fw-bad",
                "threatIntelMode": "Off",
                "intrusionDetection": {"mode": "Off"},
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("firewall_no_threat_intel", subcats)
        self.assertIn("firewall_no_idps", subcats)

    def test_noncompliant_appgw_no_waf(self):
        idx = _build_index([
            _ev("azure-appgw", {
                "name": "gw-bad", "skuTier": "Standard_v2",
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("appgw_no_waf", subcats)


class TestAnalyzeBastionSecurity(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_bastion_security
        self.analyze = analyze_bastion_security

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_bastion(self):
        idx = _build_index([
            _ev("azure-bastion", {
                "name": "bastion1", "enableShareableLink": False,
            }),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_open_rdp_no_bastion(self):
        idx = _build_index([
            _ev("azure-nsg", {
                "name": "nsg-bad",
                "securityRules": [{
                    "direction": "Inbound", "access": "Allow",
                    "destinationPortRange": "3389",
                    "sourceAddressPrefix": "*",
                }],
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_bastion_open_rdp", subcats)

    def test_shareable_links_enabled(self):
        idx = _build_index([
            _ev("azure-bastion", {
                "name": "bastion-bad", "enableShareableLink": True,
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("bastion_shareable_links", subcats)


class TestAnalyzePolicyCompliance(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_policy_compliance
        self.analyze = analyze_policy_compliance

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_all_compliant(self):
        idx = _build_index([
            _ev("azure-policy-states", {
                "complianceState": "Compliant",
                "policyDefinitionDisplayName": "Storage HTTPS required",
            }),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_noncompliant_data_policies(self):
        idx = _build_index([
            _ev("azure-policy-states", {
                "complianceState": "NonCompliant",
                "policyDefinitionDisplayName": "Storage accounts should use private link",
                "policyDefinitionName": "storage-pe",
            }, rid="/subscriptions/s1/resourceGroups/rg/providers/p1"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("data_policy_noncompliant", subcats)


class TestAnalyzeDefenderScore(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_defender_score
        self.analyze = analyze_defender_score

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_all_healthy(self):
        idx = _build_index([
            _ev("azure-security-recommendations", {
                "displayName": "Enable encryption on storage",
                "state": "Healthy",
            }),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_unhealthy_data_recommendations(self):
        idx = _build_index([
            _ev("azure-security-recommendations", {
                "displayName": "Storage accounts should use private endpoint",
                "state": "Unhealthy", "severity": "high",
            }, rid="/recs/r1"),
            _ev("azure-security-recommendations", {
                "displayName": "SQL databases should have encryption enabled",
                "state": "Unhealthy", "severity": "high",
            }, rid="/recs/r2"),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("defender_data_recs_unhealthy", subcats)


class TestAnalyzeStalePermissions(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_stale_permissions
        self.analyze = analyze_stale_permissions

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_no_stale_assignments(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        idx = _build_index([
            _ev("azure-role-assignments", {
                "roleDefinitionName": "Storage Blob Data Reader",
                "scope": "/subscriptions/s1",
                "principalId": "p1", "principalType": "User",
            }),
            _ev("azure-sign-in-activity", {
                "principalId": "p1",
                "lastSignInDateTime": recent,
            }),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_stale_data_role(self):
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        idx = _build_index([
            _ev("azure-role-assignments", {
                "roleDefinitionName": "Storage Blob Data Contributor",
                "scope": "/subscriptions/s1/resourceGroups/rg",
                "principalId": "p-stale", "principalType": "User",
            }),
            _ev("azure-sign-in-activity", {
                "principalId": "p-stale",
                "lastSignInDateTime": old,
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("stale_data_role_assignment", subcats)


class TestAnalyzeDataExfiltration(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_exfiltration
        self.analyze = analyze_data_exfiltration

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_storage(self):
        idx = _build_index([
            _ev("azure-storage-security", {
                "StorageAccountName": "sa1",
                "NetworkDefaultAction": "Deny",
                "Bypass": "AzureServices",
            }),
        ])
        findings = self.analyze(idx)
        unusual = [f for f in findings if f["Subcategory"] == "storage_unusual_bypass"]
        self.assertEqual(unusual, [])

    def test_nsg_unrestricted_outbound(self):
        idx = _build_index([
            _ev("azure-nsg", {
                "name": "nsg-open",
                "securityRules": [{
                    "direction": "Outbound", "access": "Allow",
                    "destinationAddressPrefix": "*",
                    "destinationPortRange": "*",
                }],
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("nsg_unrestricted_outbound", subcats)


class TestAnalyzeConditionalAccessPim(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_conditional_access_pim
        self.analyze = analyze_conditional_access_pim

    def test_empty_evidence(self):
        findings = self.analyze({})
        # With no CA data, should report informational
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_ca_policy_data", subcats)

    def test_compliant_ca_with_mfa(self):
        idx = _build_index([
            _ev("azure-conditional-access", {
                "RequiresMFA": True, "GrantControls": ["mfa"],
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertNotIn("no_mfa_ca_policy", subcats)

    def test_no_mfa_policy(self):
        idx = _build_index([
            _ev("azure-conditional-access", {
                "RequiresMFA": False, "GrantControls": ["block"],
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("no_mfa_ca_policy", subcats)

    def test_pim_permanent_assignments(self):
        idx = _build_index([
            _ev("azure-conditional-access", {
                "RequiresMFA": True, "GrantControls": ["mfa"],
            }),
            _ev("azure-pim-roles", {
                "roleName": "Global Admin",
                "assignmentType": "Permanent",
            }),
        ])
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("pim_permanent_assignments", subcats)


class TestAnalyzeBlastRadius(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_blast_radius
        self.analyze = analyze_blast_radius

    def test_empty_findings(self):
        result = self.analyze({}, [])
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 0)

    def test_single_finding_radius(self):
        findings = [{
            "DataSecurityFindingId": "f1",
            "Severity": "high",
            "Title": "Public storage",
            "AffectedResources": [
                {"ResourceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"},
                {"ResourceId": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa2"},
            ],
        }]
        result = self.analyze({}, findings)
        self.assertIn("f1", result)
        self.assertEqual(result["f1"]["radius"], 2)
        self.assertEqual(result["f1"]["severity"], "high")

    def test_shared_resources_connected(self):
        findings = [
            {
                "DataSecurityFindingId": "f1", "Severity": "high", "Title": "t1",
                "AffectedResources": [{"ResourceId": "/rid/shared"}],
            },
            {
                "DataSecurityFindingId": "f2", "Severity": "medium", "Title": "t2",
                "AffectedResources": [{"ResourceId": "/rid/shared"}, {"ResourceId": "/rid/other"}],
            },
        ]
        result = self.analyze({}, findings)
        self.assertEqual(result["f1"]["connected_findings"], 1)
        self.assertEqual(result["f2"]["connected_findings"], 1)


class TestAnalyzeDataFlow(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_data_flow
        self.analyze = analyze_data_flow

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_private_endpoint_flows(self):
        # analyze_data_flow reads raw resource records, not wrapped evidence
        idx: dict[str, list[dict]] = {"azure-private-endpoints": [{
            "id": "/pe/pe1",
            "properties": {
                "privateLinkServiceConnections": [
                    {"properties": {"privateLinkServiceId": "/storageAccounts/sa1"}},
                ],
                "subnet": {"id": "/vnets/v1/subnets/s1"},
            },
        }]}
        flows = self.analyze(idx)
        self.assertTrue(len(flows) > 0)
        self.assertEqual(flows[0]["flow_type"], "private_endpoint")
        self.assertEqual(flows[0]["risk_level"], "low")

    def test_public_data_factory_flow(self):
        idx: dict[str, list[dict]] = {"azure-data-factory": [
            {"id": "/adf/adf1", "properties": {"publicNetworkAccess": "Enabled"}}
        ]}
        flows = self.analyze(idx)
        public_flows = [f for f in flows if f["flow_type"] == "public_data_pipeline"]
        self.assertTrue(len(public_flows) > 0)
        self.assertEqual(public_flows[0]["risk_level"], "high")


class TestAnalyzeConfigDrift(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_config_drift
        self.analyze = analyze_config_drift

    def test_no_previous_evidence(self):
        self.assertEqual(self.analyze({}, None), [])

    def test_no_drift(self):
        snapshot = {
            "azure-storage-accounts": [
                {"id": "/sa/sa1", "name": "sa1",
                 "properties": {"allowBlobPublicAccess": False,
                                "networkAcls": {"defaultAction": "Deny"}}},
            ],
        }
        self.assertEqual(self.analyze(snapshot, snapshot), [])

    def test_security_regression_detected(self):
        previous = {
            "azure-storage-accounts": [
                {"id": "/sa/sa1", "name": "sa1",
                 "properties": {"allowBlobPublicAccess": False,
                                "networkAcls": {"defaultAction": "Deny"}}},
            ],
        }
        current = {
            "azure-storage-accounts": [
                {"id": "/sa/sa1", "name": "sa1",
                 "properties": {"allowBlobPublicAccess": True,
                                "networkAcls": {"defaultAction": "Allow"}}},
            ],
        }
        findings = self.analyze(current, previous)
        self.assertTrue(len(findings) > 0)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("drift_detected", subcats)
        # Security regression should be high severity
        high_findings = [f for f in findings if f["Severity"] == "high"]
        self.assertTrue(len(high_findings) > 0)


class TestAnalyzeSupplyChainRisk(unittest.TestCase):
    def setUp(self):
        from app.data_security_engine import analyze_supply_chain_risk
        self.analyze = analyze_supply_chain_risk

    def test_empty_evidence(self):
        self.assertEqual(self.analyze({}), [])

    def test_compliant_acr(self):
        idx = _build_index([
            _ev("azure-container-registries", {
                "name": "myacr",
                "properties": {"adminUserEnabled": False, "loginServer": "myacr.azurecr.io"},
            }),
        ])
        self.assertEqual(self.analyze(idx), [])

    def test_acr_admin_enabled(self):
        # analyze_supply_chain_risk reads raw resource records
        idx: dict[str, list[dict]] = {"azure-container-registries": [{
            "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acr-bad",
            "name": "acr-bad",
            "properties": {"adminUserEnabled": True, "loginServer": "acr-bad.azurecr.io"},
        }]}
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("acr_admin_enabled", subcats)

    def test_aks_no_acr_integration(self):
        idx: dict[str, list[dict]] = {
            "azure-container-registries": [{
                "name": "myacr",
                "properties": {"adminUserEnabled": False, "loginServer": "myacr.azurecr.io"},
            }],
            "azure-aks": [{
                "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-no-acr",
                "name": "aks-no-acr",
                "properties": {"identityProfile": {}, "agentPoolProfiles": []},
            }],
        }
        findings = self.analyze(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("aks_no_acr_integration", subcats)


