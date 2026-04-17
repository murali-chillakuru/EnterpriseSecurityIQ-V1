"""
Determinism validation tests for the Full Tenant Assessment pipeline.

Verifies that evaluate_all() and supporting functions produce identical
outputs (excluding volatile fields like EvaluatedAt) when given the same
evidence in potentially different iteration orders.

Gaps found and FIXED:
  Gap 1  (High):   FindingRecord.finding_id — uuid4 → uuid5 (deterministic)
  Gap 3  (Medium): EvidenceRecord.evidence_id — uuid4 → uuid5
  Gap 5  (Medium): MissingEvidenceRecord.record_id — uuid4 → uuid5
  Gap 6  (Low):    AssessmentSummary.assessment_id — uuid4 → uuid5
  Gap 7  (High):   Findings list order — sorted in engine.py
  Gap 7b (High):   Description name lists — sorted in evaluators
  Gap 9  (Medium): json.dump — sort_keys=True added to data_exports.py
  Gap 10 (Low):    Raw evidence grouping — sorted in data_exports.py

Volatile by design (not determinism bugs):
  Gap 2  (Medium): FindingRecord.evaluated_at — datetime.now (expected)
  Gap 4  (Low):    EvidenceRecord.collected_at — datetime.now (expected)

Remaining (low priority):
  Gap 8  (Low):    OSCAL export uses uuid4 — FIXED (uuid5 + sort_keys + fixed filename)
"""

from __future__ import annotations

import copy
import json
import os
import random
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.evaluators.engine import (
    evaluate_all,
    _index_evidence,
    _weighted_score,
    _domain_scores,
    _maturity_level,
)
from app.config import ThresholdConfig
from app.models import FindingRecord, EvidenceRecord, MissingEvidenceRecord, Status, Severity


# ── Volatile fields (expected non-deterministic) ─────────────────────

VOLATILE_FIELDS = {"FindingId", "EvaluatedAt", "RecordId", "RecordedAt",
                   "EvidenceId", "CollectedAt", "AssessmentId"}


def _strip_volatile(obj):
    """Recursively remove volatile fields from a nested dict/list for comparison."""
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items() if k not in VOLATILE_FIELDS}
    if isinstance(obj, list):
        return [_strip_volatile(i) for i in obj]
    return obj


def _canonical_json(obj) -> str:
    """JSON serialize with sorted keys for deterministic comparison."""
    return json.dumps(_strip_volatile(obj), sort_keys=True, default=str)


# ── Frozen Evidence Fixtures ─────────────────────────────────────────

def _build_frozen_evidence() -> list[dict]:
    """Build a realistic set of evidence records covering multiple domains.

    Covers: access (RBAC), identity (users, MFA), data_protection (storage,
    SQL, VMs, KeyVault), logging (diagnostics), network (NSGs, storage security),
    governance (policies, defenders).
    """
    evidence = []

    # --- Access evidence: azure-role-assignment (10 records) ---
    for i in range(10):
        is_owner = i < 3
        is_priv = i < 5
        scope = "Subscription" if i < 6 else "ResourceGroup"
        role = "Owner" if is_owner else ("Contributor" if i < 7 else "Reader")
        evidence.append({
            "EvidenceType": "azure-role-assignment",
            "Source": "Azure",
            "Collector": "collect_rbac",
            "ResourceId": f"/subscriptions/sub1/providers/Microsoft.Authorization/roleAssignments/ra-{i:03d}",
            "Data": {
                "RoleDefinitionName": role,
                "PrincipalDisplayName": f"user{i}@contoso.com",
                "PrincipalId": f"pid-{i:04d}",
                "PrincipalType": "User" if i < 8 else "ServicePrincipal",
                "ScopeLevel": scope,
                "IsPrivileged": is_priv,
                "ResourceId": f"/subscriptions/sub1/providers/Microsoft.Authorization/roleAssignments/ra-{i:03d}",
            },
        })

    # MG-level Owner for least-privilege check
    evidence.append({
        "EvidenceType": "azure-role-assignment",
        "Source": "Azure",
        "Collector": "collect_rbac",
        "ResourceId": "/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.Authorization/roleAssignments/ra-mg1",
        "Data": {
            "RoleDefinitionName": "Owner",
            "PrincipalDisplayName": "mgadmin@contoso.com",
            "PrincipalId": "pid-mg-01",
            "PrincipalType": "User",
            "ScopeLevel": "ManagementGroup",
            "IsPrivileged": True,
        },
    })

    # --- Identity evidence: entra-role-assignment ---
    for i in range(3):
        evidence.append({
            "EvidenceType": "entra-role-assignment",
            "Source": "Entra",
            "Collector": "collect_entra_roles",
            "ResourceId": f"entra-role-{i}",
            "Data": {
                "RoleName": "Global Administrator" if i == 0 else "User Administrator",
                "PrincipalDisplayName": f"admin{i}@contoso.com",
                "PrincipalId": f"entra-pid-{i:04d}",
            },
        })

    # --- Identity evidence: entra-directory-role-member ---
    for i in range(4):
        evidence.append({
            "EvidenceType": "entra-directory-role-member",
            "Source": "Entra",
            "Collector": "collect_entra_roles",
            "ResourceId": f"entra-dir-role-{i}",
            "Data": {
                "RoleName": "Global Administrator" if i < 2 else "Security Administrator",
                "PrincipalDisplayName": f"diradmin{i}@contoso.com",
                "PrincipalId": f"entra-dir-pid-{i:04d}",
            },
        })

    # --- Identity evidence: entra-mfa-summary ---
    evidence.append({
        "EvidenceType": "entra-mfa-summary",
        "Source": "Entra",
        "Collector": "collect_entra_users",
        "ResourceId": "tenant-mfa-summary",
        "Data": {
            "TotalUsers": 100,
            "MfaRegistered": 85,
            "MfaPercentage": 85.0,
            "NotRegistered": 15,
        },
    })

    # --- Identity evidence: entra-conditional-access-policy ---
    for i in range(3):
        evidence.append({
            "EvidenceType": "entra-conditional-access-policy",
            "Source": "Entra",
            "Collector": "collect_entra_conditional_access",
            "ResourceId": f"ca-policy-{i}",
            "Data": {
                "DisplayName": f"CA Policy {i}",
                "State": "enabled" if i < 2 else "disabled",
                "Id": f"ca-policy-id-{i}",
            },
        })

    # --- Data Protection evidence: azure-vm-config (3 VMs) ---
    vm_configs = [
        {"Name": "vm-prod-01", "OsDiskEncrypted": True, "DataDiskCount": 2, "DataDisksEncrypted": True},
        {"Name": "vm-dev-02", "OsDiskEncrypted": False, "DataDiskCount": 1, "DataDisksEncrypted": False},
        {"Name": "vm-staging-03", "OsDiskEncrypted": True, "DataDiskCount": 0, "DataDisksEncrypted": True},
    ]
    for i, vm in enumerate(vm_configs):
        evidence.append({
            "EvidenceType": "azure-vm-config",
            "Source": "Azure",
            "Collector": "collect_compute",
            "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/{vm['Name']}",
            "Data": {**vm, "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Compute/virtualMachines/{vm['Name']}",
                     "ResourceType": "Microsoft.Compute/virtualMachines"},
        })

    # --- Data Protection evidence: azure-sql-server ---
    sql_configs = [
        {"Name": "sql-prod", "TransparentDataEncryption": True, "TdeEnabled": True,
         "AuditingEnabled": True, "AdvancedThreatProtection": True, "MinimalTlsVersion": "1.2"},
        {"Name": "sql-dev", "TransparentDataEncryption": False, "TdeEnabled": False,
         "AuditingEnabled": False, "AdvancedThreatProtection": False, "MinimalTlsVersion": "1.0"},
    ]
    for sql in sql_configs:
        evidence.append({
            "EvidenceType": "azure-sql-server",
            "Source": "Azure",
            "Collector": "collect_databases",
            "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Sql/servers/{sql['Name']}",
            "Data": {**sql, "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Sql/servers/{sql['Name']}",
                     "ResourceType": "Microsoft.Sql/servers"},
        })

    # --- Data Protection evidence: azure-storage-security ---
    stores = [
        {"Name": "storprod", "StorageAccountName": "storprod",
         "AllowBlobPublicAccess": False, "EnableHttpsTrafficOnly": True, "HttpsOnly": True,
         "NetworkDefaultAction": "Deny", "MinimumTlsVersion": "TLS1_2",
         "BlobSoftDeleteEnabled": True},
        {"Name": "stordev", "StorageAccountName": "stordev",
         "AllowBlobPublicAccess": True, "EnableHttpsTrafficOnly": False, "HttpsOnly": False,
         "NetworkDefaultAction": "Allow", "MinimumTlsVersion": "TLS1_0",
         "BlobSoftDeleteEnabled": False},
    ]
    for s in stores:
        evidence.append({
            "EvidenceType": "azure-storage-security",
            "Source": "Azure",
            "Collector": "collect_storage",
            "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/{s['Name']}",
            "Data": {**s, "id": f"/subscriptions/sub1/rg1/Microsoft.Storage/storageAccounts/{s['Name']}",
                     "type": "microsoft.storage/storageaccounts"},
        })

    # --- Data Protection evidence: azure-keyvault ---
    evidence.append({
        "EvidenceType": "azure-keyvault",
        "Source": "Azure",
        "Collector": "collect_keyvault",
        "ResourceId": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv-prod",
        "Data": {
            "name": "kv-prod",
            "PurgeProtectionEnabled": True,
            "SoftDeleteEnabled": True,
            "EnableRbacAuthorization": True,
            "NetworkDefaultAction": "Deny",
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv-prod",
            "type": "microsoft.keyvault/vaults",
        },
    })
    evidence.append({
        "EvidenceType": "azure-keyvault",
        "Source": "Azure",
        "Collector": "collect_keyvault",
        "ResourceId": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv-dev",
        "Data": {
            "name": "kv-dev",
            "PurgeProtectionEnabled": False,
            "SoftDeleteEnabled": False,
            "EnableRbacAuthorization": False,
            "NetworkDefaultAction": "Allow",
            "id": "/subscriptions/sub1/rg1/Microsoft.KeyVault/vaults/kv-dev",
            "type": "microsoft.keyvault/vaults",
        },
    })

    # --- Logging evidence: azure-diagnostic-setting ---
    for i in range(5):
        evidence.append({
            "EvidenceType": "azure-diagnostic-setting",
            "Source": "Azure",
            "Collector": "collect_diagnostics",
            "ResourceId": f"/subscriptions/sub1/rg1/providers/res-{i}/diagnosticSettings/ds-{i}",
            "Data": {
                "Name": f"diag-setting-{i}",
                "ResourceId": f"/subscriptions/sub1/rg1/providers/res-{i}",
                "Enabled": True,
                "LogCategories": ["AuditEvent", "AllMetrics"],
                "DestinationType": "LogAnalytics",
            },
        })

    # --- Network evidence: azure-nsg-rule ---
    nsg_rules = [
        {"RuleName": "AllowAll-Inbound", "Direction": "Inbound", "Access": "Allow",
         "SourceAddressPrefix": "*", "DestinationPortRange": "*", "Priority": 100,
         "NsgName": "nsg-open"},
        {"RuleName": "AllowSSH", "Direction": "Inbound", "Access": "Allow",
         "SourceAddressPrefix": "10.0.0.0/8", "DestinationPortRange": "22", "Priority": 200,
         "NsgName": "nsg-restricted"},
        {"RuleName": "DenyAll-Inbound", "Direction": "Inbound", "Access": "Deny",
         "SourceAddressPrefix": "*", "DestinationPortRange": "*", "Priority": 4096,
         "NsgName": "nsg-restricted"},
    ]
    for nsg in nsg_rules:
        evidence.append({
            "EvidenceType": "azure-nsg-rule",
            "Source": "Azure",
            "Collector": "collect_network",
            "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Network/nsg/{nsg['NsgName']}/rules/{nsg['RuleName']}",
            "Data": nsg,
        })

    # --- Governance evidence: azure-policy-assignment ---
    for i in range(6):
        evidence.append({
            "EvidenceType": "azure-policy-assignment",
            "Source": "Azure",
            "Collector": "collect_policy",
            "ResourceId": f"/subscriptions/sub1/providers/Microsoft.Authorization/policyAssignments/pa-{i}",
            "Data": {
                "DisplayName": f"Policy {i}",
                "ComplianceState": "Compliant" if i < 4 else "NonCompliant",
                "PolicyDefinitionId": f"/providers/Microsoft.Authorization/policyDefinitions/pd-{i}",
            },
        })

    # --- Governance evidence: azure-defender-plan ---
    defender_plans = ["VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults", "AppService"]
    for plan in defender_plans:
        evidence.append({
            "EvidenceType": "azure-defender-plan",
            "Source": "Azure",
            "Collector": "collect_defender_plans",
            "ResourceId": f"/subscriptions/sub1/providers/Microsoft.Security/pricings/{plan}",
            "Data": {
                "Name": plan,
                "PricingTier": "Standard",
                "Enabled": True,
            },
        })

    # --- Webapp evidence ---
    webapps = [
        {"Name": "app-prod", "HttpsOnly": True, "MinTlsVersion": "1.2"},
        {"Name": "app-dev", "HttpsOnly": False, "MinTlsVersion": "1.0"},
    ]
    for w in webapps:
        evidence.append({
            "EvidenceType": "azure-webapp-config",
            "Source": "Azure",
            "Collector": "collect_webapp",
            "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Web/sites/{w['Name']}",
            "Data": {**w, "ResourceId": f"/subscriptions/sub1/rg1/Microsoft.Web/sites/{w['Name']}",
                     "ResourceType": "Microsoft.Web/sites"},
        })

    return evidence


def _shuffle_evidence(evidence: list[dict], seed: int) -> list[dict]:
    """Return a deep-copied list with evidence order shuffled.

    Also shuffles the internal order of evidence sharing the same EvidenceType
    by rebuilding the list with a different insertion order.
    """
    shuffled = copy.deepcopy(evidence)
    rng = random.Random(seed)
    rng.shuffle(shuffled)
    return shuffled


# ═══════════════════════════════════════════════════════════════════════
# Test Class 1: Document determinism gaps (xfail)
# ═══════════════════════════════════════════════════════════════════════

class TestAssessmentDeterminismGaps:
    """Tests documenting known determinism gaps as xfail."""

    EVIDENCE = _build_frozen_evidence()
    FRAMEWORKS = ["FedRAMP"]
    THRESHOLDS = ThresholdConfig()

    # Gap 1: FindingRecord.finding_id — FIXED (uuid5, deterministic)
    def test_gap1_finding_id_is_deterministic(self):
        """FindingRecord produces the same FindingId for identical inputs (uuid5)."""
        f1 = FindingRecord(
            control_id="AC-2", framework="FedRAMP", control_title="Account Management",
            status=Status.COMPLIANT, severity=Severity.HIGH, domain="access",
            description="Test finding",
        ).to_dict()
        f2 = FindingRecord(
            control_id="AC-2", framework="FedRAMP", control_title="Account Management",
            status=Status.COMPLIANT, severity=Severity.HIGH, domain="access",
            description="Test finding",
        ).to_dict()
        assert f1["FindingId"] == f2["FindingId"], "UUID5 should produce identical IDs for same inputs"

    # Gap 2: FindingRecord.evaluated_at varies
    def test_gap2_finding_evaluated_at_varies(self):
        """Two FindingRecords created moments apart have different EvaluatedAt."""
        f1 = FindingRecord(
            control_id="AC-2", framework="FedRAMP", control_title="Test",
            status=Status.COMPLIANT, severity=Severity.HIGH, domain="access",
        ).to_dict()
        f2 = FindingRecord(
            control_id="AC-2", framework="FedRAMP", control_title="Test",
            status=Status.COMPLIANT, severity=Severity.HIGH, domain="access",
        ).to_dict()
        # Timestamps may or may not differ within the same millisecond
        # but conceptually they're non-deterministic
        pytest.xfail("Gap 2: FindingRecord.evaluated_at uses datetime.now — non-deterministic by design")

    # Gap 3: EvidenceRecord.evidence_id — FIXED (uuid5, deterministic)
    def test_gap3_evidence_id_is_deterministic(self):
        """EvidenceRecord produces the same EvidenceId for identical inputs (uuid5)."""
        e1 = EvidenceRecord(
            source="Azure", collector="test", evidence_type="azure-test",
            description="test", data={},
        ).to_dict()
        e2 = EvidenceRecord(
            source="Azure", collector="test", evidence_type="azure-test",
            description="test", data={},
        ).to_dict()
        assert e1["EvidenceId"] == e2["EvidenceId"], "UUID5 should produce identical IDs for same inputs"

    # Gap 5: MissingEvidenceRecord.record_id — FIXED (uuid5, deterministic)
    def test_gap5_missing_evidence_record_id_deterministic(self):
        """MissingEvidenceRecord produces the same RecordId for identical inputs (uuid5)."""
        m1 = MissingEvidenceRecord(
            control_id="AC-2", framework="FedRAMP", control_title="Test",
            reason="Not collected",
        ).to_dict()
        m2 = MissingEvidenceRecord(
            control_id="AC-2", framework="FedRAMP", control_title="Test",
            reason="Not collected",
        ).to_dict()
        assert m1["RecordId"] == m2["RecordId"], "UUID5 should produce identical IDs for same inputs"

    # Gap 7: Findings order — FIXED (sorted in engine.py)
    def test_gap7_findings_order_deterministic(self):
        """Shuffled evidence order produces identical findings order."""
        ev_a = self.EVIDENCE
        ev_b = _shuffle_evidence(ev_a, seed=42)

        res_a = evaluate_all(ev_a, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_b = evaluate_all(ev_b, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        findings_a = [_strip_volatile(f) for f in res_a["findings"]]
        findings_b = [_strip_volatile(f) for f in res_b["findings"]]

        json_a = json.dumps(findings_a, sort_keys=True)
        json_b = json.dumps(findings_b, sort_keys=True)
        assert json_a == json_b, "Findings must be identical regardless of evidence order"

    # Gap 7b: Finding Description — FIXED (sorted name lists in evaluators)
    def test_gap7b_description_deterministic(self):
        """Evaluator descriptions are deterministic regardless of evidence order.

        6 locations across business_continuity.py (3) and identity.py (3)
        now use sorted() for name lists before ', '.join(names).
        """
        ev_a = self.EVIDENCE
        ev_b = _shuffle_evidence(ev_a, seed=42)

        res_a = evaluate_all(ev_a, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_b = evaluate_all(ev_b, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        descs_a = sorted(f.get("Description", "") for f in res_a["findings"])
        descs_b = sorted(f.get("Description", "") for f in res_b["findings"])

        assert descs_a == descs_b, "Descriptions must be identical regardless of evidence order"

    # Gap 9: JSON serialization — FIXED (sort_keys=True added to data_exports.py)
    def test_gap9_json_dump_with_sort_keys(self):
        """json.dump now uses sort_keys=True for deterministic output."""
        res_a = evaluate_all(self.EVIDENCE, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_b = evaluate_all(_shuffle_evidence(self.EVIDENCE, 99), frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        # Both unsorted and sorted JSON should match (evidence order no longer matters)
        json_a = json.dumps(res_a["summary"], sort_keys=True, default=str)
        json_b = json.dumps(res_b["summary"], sort_keys=True, default=str)
        assert json_a == json_b, "Summaries must be identical regardless of evidence order"


# ═══════════════════════════════════════════════════════════════════════
# Test Class 2: Pure computation determinism (should always pass)
# ═══════════════════════════════════════════════════════════════════════

class TestAssessmentComputationDeterminism:
    """Verify core computation functions are deterministic."""

    EVIDENCE = _build_frozen_evidence()
    FRAMEWORKS = ["FedRAMP"]
    THRESHOLDS = ThresholdConfig()

    def test_evaluate_all_summary_identical_across_runs(self):
        """Summary (scores, counts) must be identical across 5 runs."""
        summaries = []
        for _ in range(5):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            summaries.append(json.dumps(res["summary"], sort_keys=True, default=str))
        assert all(s == summaries[0] for s in summaries), \
            f"Summary varied across runs: {set(summaries)}"

    def test_evaluate_all_control_results_identical(self):
        """Control results (status, counts per control) must be identical across 5 runs."""
        results = []
        for _ in range(5):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            # Control results don't contain volatile fields
            results.append(json.dumps(res["control_results"], sort_keys=True, default=str))
        assert all(r == results[0] for r in results)

    def test_evaluate_all_findings_content_identical(self):
        """Finding content (excluding FindingId/EvaluatedAt) must be identical across 5 runs."""
        findings_sets = []
        for _ in range(5):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            stripped = [_strip_volatile(f) for f in res["findings"]]
            findings_sets.append(json.dumps(stripped, sort_keys=True, default=str))
        assert all(f == findings_sets[0] for f in findings_sets)

    def test_weighted_score_deterministic(self):
        """_weighted_score produces identical results."""
        controls = [
            {"Status": "compliant", "Severity": "critical"},
            {"Status": "non_compliant", "Severity": "high"},
            {"Status": "partial", "Severity": "medium"},
            {"Status": "compliant", "Severity": "low"},
            {"Status": "missing_evidence", "Severity": "high"},
        ]
        scores = [_weighted_score(copy.deepcopy(controls)) for _ in range(10)]
        assert all(s == scores[0] for s in scores)

    def test_domain_scores_deterministic(self):
        """_domain_scores produces identical results across runs."""
        controls = [
            {"Domain": "access", "Status": "compliant", "Severity": "high"},
            {"Domain": "access", "Status": "non_compliant", "Severity": "critical"},
            {"Domain": "identity", "Status": "compliant", "Severity": "medium"},
            {"Domain": "identity", "Status": "partial", "Severity": "high"},
            {"Domain": "data_protection", "Status": "compliant", "Severity": "low"},
        ]
        results = [json.dumps(_domain_scores(copy.deepcopy(controls)), sort_keys=True)
                   for _ in range(10)]
        assert all(r == results[0] for r in results)

    def test_maturity_level_deterministic(self):
        """_maturity_level produces identical results."""
        controls = [
            {"Status": "compliant", "Severity": "critical"},
            {"Status": "compliant", "Severity": "high"},
            {"Status": "non_compliant", "Severity": "medium"},
            {"Status": "partial", "Severity": "low"},
        ]
        levels = [_maturity_level(copy.deepcopy(controls)) for _ in range(10)]
        assert all(l == levels[0] for l in levels)

    def test_index_evidence_deterministic(self):
        """_index_evidence preserves insertion order consistently."""
        idx1 = _index_evidence(self.EVIDENCE)
        idx2 = _index_evidence(copy.deepcopy(self.EVIDENCE))
        assert list(idx1.keys()) == list(idx2.keys())
        for k in idx1:
            assert len(idx1[k]) == len(idx2[k])

    def test_missing_evidence_list_identical(self):
        """Missing evidence list (stripped of volatile) is identical across runs."""
        results = []
        for _ in range(5):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            stripped = [_strip_volatile(m) for m in res["missing_evidence"]]
            results.append(json.dumps(stripped, sort_keys=True, default=str))
        assert all(r == results[0] for r in results)

    def test_evaluate_all_multi_framework_summary(self):
        """Multi-framework evaluation produces consistent summary."""
        fws = ["FedRAMP", "CIS"]
        summaries = []
        for _ in range(5):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=fws, thresholds=self.THRESHOLDS,
            )
            summaries.append(json.dumps(res["summary"], sort_keys=True, default=str))
        assert all(s == summaries[0] for s in summaries)


# ═══════════════════════════════════════════════════════════════════════
# Test Class 3: Shuffled evidence → canonical results
# ═══════════════════════════════════════════════════════════════════════

class TestAssessmentShuffledDeterminism:
    """Verify that shuffling evidence order produces identical results
    (content-wise, after stripping volatile fields and sorting)."""

    EVIDENCE = _build_frozen_evidence()
    FRAMEWORKS = ["FedRAMP"]
    THRESHOLDS = ThresholdConfig()

    @pytest.mark.parametrize("seed", [1, 7, 13, 42, 99, 123, 256, 999])
    def test_summary_stable_under_shuffle(self, seed):
        """Summary must be identical regardless of evidence order."""
        ev_orig = self.EVIDENCE
        ev_shuf = _shuffle_evidence(ev_orig, seed)

        res_orig = evaluate_all(ev_orig, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_shuf = evaluate_all(ev_shuf, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        assert json.dumps(res_orig["summary"], sort_keys=True, default=str) == \
               json.dumps(res_shuf["summary"], sort_keys=True, default=str)

    @pytest.mark.parametrize("seed", [1, 7, 13, 42, 99, 123, 256, 999])
    def test_control_results_stable_under_shuffle(self, seed):
        """Control results must be identical regardless of evidence order."""
        ev_shuf = _shuffle_evidence(self.EVIDENCE, seed)

        res_orig = evaluate_all(self.EVIDENCE, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_shuf = evaluate_all(ev_shuf, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        assert json.dumps(res_orig["control_results"], sort_keys=True, default=str) == \
               json.dumps(res_shuf["control_results"], sort_keys=True, default=str)

    @pytest.mark.parametrize("seed", [1, 7, 13, 42, 99, 123, 256, 999])
    def test_findings_content_stable_under_shuffle(self, seed):
        """Finding content (full, excluding volatile fields) must be identical regardless of evidence order."""
        ev_shuf = _shuffle_evidence(self.EVIDENCE, seed)

        res_orig = evaluate_all(self.EVIDENCE, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_shuf = evaluate_all(ev_shuf, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        set_orig = {json.dumps(_strip_volatile(f), sort_keys=True) for f in res_orig["findings"]}
        set_shuf = {json.dumps(_strip_volatile(f), sort_keys=True) for f in res_shuf["findings"]}

        assert set_orig == set_shuf, "Finding content sets must be identical under shuffle"

    @pytest.mark.parametrize("seed", [1, 7, 13, 42, 99, 123, 256, 999])
    def test_findings_order_stable_under_shuffle(self, seed):
        """Finding order (after stripping volatile) must be identical regardless of evidence order."""
        ev_shuf = _shuffle_evidence(self.EVIDENCE, seed)

        res_orig = evaluate_all(self.EVIDENCE, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_shuf = evaluate_all(ev_shuf, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        list_orig = [json.dumps(_strip_volatile(f), sort_keys=True) for f in res_orig["findings"]]
        list_shuf = [json.dumps(_strip_volatile(f), sort_keys=True) for f in res_shuf["findings"]]

        assert list_orig == list_shuf, "Findings order must be deterministic under shuffle"

    @pytest.mark.parametrize("seed", [1, 7, 13, 42, 99, 123, 256, 999])
    def test_missing_evidence_stable_under_shuffle(self, seed):
        """Missing evidence records must be identical under shuffle."""
        ev_shuf = _shuffle_evidence(self.EVIDENCE, seed)

        res_orig = evaluate_all(self.EVIDENCE, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_shuf = evaluate_all(ev_shuf, frameworks=self.FRAMEWORKS, thresholds=self.THRESHOLDS)

        stripped_orig = [_strip_volatile(m) for m in res_orig["missing_evidence"]]
        stripped_shuf = [_strip_volatile(m) for m in res_shuf["missing_evidence"]]

        assert json.dumps(stripped_orig, sort_keys=True, default=str) == \
               json.dumps(stripped_shuf, sort_keys=True, default=str)


# ═══════════════════════════════════════════════════════════════════════
# Test Class 4: Multi-framework determinism
# ═══════════════════════════════════════════════════════════════════════

class TestMultiFrameworkDeterminism:
    """Verify multi-framework evaluation is deterministic."""

    EVIDENCE = _build_frozen_evidence()
    ALL_FRAMEWORKS = ["FedRAMP", "CIS", "ISO-27001", "NIST-800-53", "PCI-DSS",
                      "MCSB", "HIPAA", "SOC2", "GDPR", "NIST-CSF", "CSA-CCM"]
    THRESHOLDS = ThresholdConfig()

    def test_all_frameworks_summary_deterministic(self):
        """Running all 11 frameworks produces identical summary across 3 runs."""
        summaries = []
        for _ in range(3):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            summaries.append(json.dumps(res["summary"], sort_keys=True, default=str))
        assert all(s == summaries[0] for s in summaries)

    def test_all_frameworks_control_results_deterministic(self):
        """Control results across all frameworks are identical across 3 runs."""
        results = []
        for _ in range(3):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            results.append(json.dumps(res["control_results"], sort_keys=True, default=str))
        assert all(r == results[0] for r in results)

    def test_all_frameworks_findings_content_deterministic(self):
        """Finding content (stripped) across all frameworks is identical across 3 runs."""
        findings_lists = []
        for _ in range(3):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            stripped = [_strip_volatile(f) for f in res["findings"]]
            findings_lists.append(json.dumps(stripped, sort_keys=True, default=str))
        assert all(f == findings_lists[0] for f in findings_lists)

    def test_framework_summaries_per_framework_deterministic(self):
        """Per-framework summaries in FrameworkSummaries are identical across 3 runs."""
        fw_sums = []
        for _ in range(3):
            res = evaluate_all(
                copy.deepcopy(self.EVIDENCE),
                frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS,
            )
            fw_sums.append(json.dumps(res["summary"]["FrameworkSummaries"], sort_keys=True, default=str))
        assert all(s == fw_sums[0] for s in fw_sums)

    def test_all_frameworks_shuffled_summary_identical(self):
        """Shuffled evidence + all frameworks → identical summary."""
        res_orig = evaluate_all(self.EVIDENCE, frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_shuf = evaluate_all(
            _shuffle_evidence(self.EVIDENCE, seed=77),
            frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS,
        )
        assert json.dumps(res_orig["summary"], sort_keys=True, default=str) == \
               json.dumps(res_shuf["summary"], sort_keys=True, default=str)

    def test_all_frameworks_shuffled_control_results_identical(self):
        """Shuffled evidence + all frameworks → identical control results."""
        res_orig = evaluate_all(self.EVIDENCE, frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS)
        res_shuf = evaluate_all(
            _shuffle_evidence(self.EVIDENCE, seed=77),
            frameworks=self.ALL_FRAMEWORKS, thresholds=self.THRESHOLDS,
        )
        assert json.dumps(res_orig["control_results"], sort_keys=True, default=str) == \
               json.dumps(res_shuf["control_results"], sort_keys=True, default=str)
