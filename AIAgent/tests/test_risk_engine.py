"""
Tests for Phase 2 — Security Risk Gap Analysis Engine (app/risk_engine.py).

Covers:
  • Identity analyzers (7 sub-checks)
  • Network analyzers (4 sub-checks)
  • Defender analyzer (coverage check)
  • Config drift analyzers (3 sub-checks)
  • Risk scoring algorithm
  • Master orchestrator wiring
  • Agent tool registration
"""

from __future__ import annotations

import sys
import os
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.risk_engine import (
    _risk_finding,
    analyze_identity_risk,
    analyze_network_risk,
    analyze_config_drift,
    compute_risk_scores,
    _score_to_level,
    _check_dormant_accounts,
    _check_overpermissioned_sps,
    _check_app_credential_hygiene,
    _check_mfa_gaps,
    _check_admin_proliferation,
    _check_guest_risks,
    _check_risky_users,
    _check_open_management_ports,
    _check_public_storage,
    _check_webapp_security,
    _check_sql_exposure,
    _check_defender_coverage,
    _check_diagnostic_coverage,
    _check_policy_noncompliance,
    _check_tag_governance,
)


# ── Sample evidence factories ──────────────────────────────────────────

def _ev(etype: str, data: dict, resource_id: str = "") -> dict:
    return {"EvidenceType": etype, "Data": data, "ResourceId": resource_id}


# ====================================================================
# Identity Analyzer Tests
# ====================================================================

class TestDormantAccounts(unittest.TestCase):
    def test_triggers_on_high_stale_percent(self):
        idx = {"entra-user-summary": [
            _ev("entra-user-summary", {"TotalUsers": 100, "StaleUsers": 30, "StalePercent": 30}),
        ]}
        findings = _check_dormant_accounts(idx, None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "dormant_accounts")
        self.assertEqual(findings[0]["Severity"], "medium")

    def test_high_severity_many_stale(self):
        idx = {"entra-user-summary": [
            _ev("entra-user-summary", {"TotalUsers": 500, "StaleUsers": 100, "StalePercent": 25}),
        ]}
        findings = _check_dormant_accounts(idx, None)
        self.assertEqual(findings[0]["Severity"], "high")

    def test_no_trigger_below_threshold(self):
        idx = {"entra-user-summary": [
            _ev("entra-user-summary", {"TotalUsers": 100, "StaleUsers": 5, "StalePercent": 5}),
        ]}
        self.assertEqual(len(_check_dormant_accounts(idx, None)), 0)


class TestOverpermissionedSPs(unittest.TestCase):
    def test_flags_contributor_at_sub_scope(self):
        idx = {"azure-role-assignment": [
            _ev("azure-role-assignment", {
                "PrincipalType": "ServicePrincipal",
                "RoleName": "Contributor",
                "Scope": "/subscriptions/abc",
                "PrincipalId": "sp-1",
                "PrincipalName": "MyApp",
            }),
        ]}
        findings = _check_overpermissioned_sps(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["AffectedCount"], 1)

    def test_ignores_rg_scoped(self):
        idx = {"azure-role-assignment": [
            _ev("azure-role-assignment", {
                "PrincipalType": "ServicePrincipal",
                "RoleName": "Owner",
                "Scope": "/subscriptions/abc/resourceGroups/rg1",
            }),
        ]}
        self.assertEqual(len(_check_overpermissioned_sps(idx)), 0)

    def test_ignores_user_type(self):
        idx = {"azure-role-assignment": [
            _ev("azure-role-assignment", {
                "PrincipalType": "User",
                "RoleName": "Owner",
                "Scope": "/subscriptions/abc",
            }),
        ]}
        self.assertEqual(len(_check_overpermissioned_sps(idx)), 0)


class TestAppCredentialHygiene(unittest.TestCase):
    def test_detects_expired_cred(self):
        past = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        idx = {"entra-application": [
            _ev("entra-application", {
                "DisplayName": "OldApp", "AppId": "a1",
                "PasswordCredentials": [{"EndDateTime": past}],
            }),
        ]}
        findings = _check_app_credential_hygiene(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "expired_credentials")

    def test_detects_expiring_soon(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        idx = {"entra-application": [
            _ev("entra-application", {
                "DisplayName": "SoonApp", "AppId": "a2",
                "PasswordCredentials": [{"EndDateTime": soon}],
            }),
        ]}
        findings = _check_app_credential_hygiene(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "expiring_credentials")

    def test_no_issue_when_far_future(self):
        future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        idx = {"entra-application": [
            _ev("entra-application", {
                "DisplayName": "GoodApp", "AppId": "a3",
                "PasswordCredentials": [{"EndDateTime": future}],
            }),
        ]}
        self.assertEqual(len(_check_app_credential_hygiene(idx)), 0)


class TestMFAGaps(unittest.TestCase):
    def test_triggers_critical_below_50(self):
        idx = {"entra-mfa-summary": [
            _ev("entra-mfa-summary", {"RegisteredCount": 10, "TotalUsers": 100}),
        ]}
        findings = _check_mfa_gaps(idx, None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "critical")

    def test_triggers_high_above_50(self):
        idx = {"entra-mfa-summary": [
            _ev("entra-mfa-summary", {"RegisteredCount": 70, "TotalUsers": 100}),
        ]}
        findings = _check_mfa_gaps(idx, None)
        self.assertEqual(findings[0]["Severity"], "high")

    def test_no_trigger_above_threshold(self):
        idx = {"entra-mfa-summary": [
            _ev("entra-mfa-summary", {"RegisteredCount": 95, "TotalUsers": 100}),
        ]}
        self.assertEqual(len(_check_mfa_gaps(idx, None)), 0)


class TestAdminProliferation(unittest.TestCase):
    def test_flags_excess_global_admins(self):
        idx = {"entra-directory-role-member": [
            _ev("entra-directory-role-member", {"RoleName": "Global Administrator", "MemberId": f"u{i}", "MemberName": f"Admin{i}"})
            for i in range(8)
        ]}
        findings = _check_admin_proliferation(idx, None)
        self.assertEqual(len(findings), 1)
        self.assertIn("8", findings[0]["Title"])

    def test_critical_when_double_threshold(self):
        idx = {"entra-directory-role-member": [
            _ev("entra-directory-role-member", {"RoleName": "Global Administrator", "MemberId": f"u{i}", "MemberName": f"A{i}"})
            for i in range(12)
        ]}
        findings = _check_admin_proliferation(idx, None)
        self.assertEqual(findings[0]["Severity"], "critical")

    def test_ok_within_threshold(self):
        idx = {"entra-directory-role-member": [
            _ev("entra-directory-role-member", {"RoleName": "Global Administrator", "MemberId": f"u{i}", "MemberName": f"A{i}"})
            for i in range(3)
        ]}
        self.assertEqual(len(_check_admin_proliferation(idx, None)), 0)


class TestGuestRisks(unittest.TestCase):
    def test_high_guest_ratio(self):
        idx = {
            "entra-user-summary": [_ev("entra-user-summary", {"TotalUsers": 100, "GuestUsers": 30})],
            "entra-access-review": [],
        }
        findings = _check_guest_risks(idx)
        self.assertTrue(any(f["Subcategory"] == "guest_user_risk" for f in findings))

    def test_missing_guest_review(self):
        idx = {
            "entra-user-summary": [_ev("entra-user-summary", {"TotalUsers": 100, "GuestUsers": 15})],
            "entra-access-review": [],
        }
        findings = _check_guest_risks(idx)
        self.assertTrue(any(f["Subcategory"] == "missing_guest_review" for f in findings))


class TestRiskyUsers(unittest.TestCase):
    def test_high_risk_users(self):
        idx = {"entra-risky-user": [
            _ev("entra-risky-user", {"RiskLevel": "high", "RiskState": "atRisk",
                                      "UserId": "u1", "UserPrincipalName": "user@co.com"}),
        ]}
        findings = _check_risky_users(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "critical")

    def test_dismissed_ignored(self):
        idx = {"entra-risky-user": [
            _ev("entra-risky-user", {"RiskLevel": "high", "RiskState": "dismissed"}),
        ]}
        self.assertEqual(len(_check_risky_users(idx)), 0)


# ====================================================================
# Network Analyzer Tests
# ====================================================================

class TestOpenManagementPorts(unittest.TestCase):
    def test_rdp_exposed(self):
        idx = {"azure-network-security-nsg": [
            _ev("azure-network-security-nsg", {"RdpExposed": True, "NsgName": "nsg-1"}, "/sub/nsg-1"),
        ]}
        findings = _check_open_management_ports(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "critical")

    def test_no_exposure(self):
        idx = {"azure-network-security-nsg": [
            _ev("azure-network-security-nsg", {"RdpExposed": False, "SshExposed": False}),
        ]}
        self.assertEqual(len(_check_open_management_ports(idx)), 0)


class TestPublicStorage(unittest.TestCase):
    def test_public_blob_access(self):
        idx = {"azure-storage-security": [
            _ev("azure-storage-security", {"AllowBlobPublicAccess": True, "StorageAccountName": "sa1"}, "/sub/sa1"),
        ]}
        findings = _check_public_storage(idx)
        self.assertEqual(len(findings), 1)

    def test_private_storage(self):
        idx = {"azure-storage-security": [
            _ev("azure-storage-security", {"AllowBlobPublicAccess": False}),
        ]}
        self.assertEqual(len(_check_public_storage(idx)), 0)


class TestWebAppSecurity(unittest.TestCase):
    def test_no_https(self):
        idx = {"azure-webapp-config": [
            _ev("azure-webapp-config", {"HttpsOnly": False, "Name": "app1"}),
        ]}
        findings = _check_webapp_security(idx)
        self.assertEqual(len(findings), 1)
        self.assertIn("HTTPS", findings[0]["AffectedResources"][0]["Issues"][0])

    def test_old_tls(self):
        idx = {"azure-webapp-config": [
            _ev("azure-webapp-config", {"HttpsOnly": True, "MinTlsVersion": "1.0", "Name": "app2"}),
        ]}
        findings = _check_webapp_security(idx)
        self.assertEqual(len(findings), 1)


class TestSQLExposure(unittest.TestCase):
    def test_allow_all_rule(self):
        idx = {"azure-sql-server": [
            _ev("azure-sql-server", {
                "Name": "sql1",
                "FirewallRules": [{"StartIpAddress": "0.0.0.0", "EndIpAddress": "255.255.255.255", "Name": "AllowAll"}],
            }),
        ]}
        findings = _check_sql_exposure(idx)
        self.assertEqual(len(findings), 1)

    def test_restricted_rule(self):
        idx = {"azure-sql-server": [
            _ev("azure-sql-server", {
                "Name": "sql1",
                "FirewallRules": [{"StartIpAddress": "10.0.0.1", "EndIpAddress": "10.0.0.1"}],
            }),
        ]}
        self.assertEqual(len(_check_sql_exposure(idx)), 0)


# ====================================================================
# Defender Posture Tests
# ====================================================================

class TestDefenderCoverage(unittest.TestCase):
    def test_free_plans_flagged(self):
        idx = {"azure-defender-plan": [
            _ev("azure-defender-plan", {"PricingTier": "Free", "PlanName": "VirtualMachines"}),
            _ev("azure-defender-plan", {"PricingTier": "Free", "PlanName": "SqlServers"}),
        ]}
        findings = _check_defender_coverage(idx)
        self.assertEqual(len(findings), 1)
        self.assertIn("2", findings[0]["Title"])

    def test_standard_ok(self):
        idx = {"azure-defender-plan": [
            _ev("azure-defender-plan", {"PricingTier": "Standard", "PlanName": "VirtualMachines"}),
        ]}
        self.assertEqual(len(_check_defender_coverage(idx)), 0)


# ====================================================================
# Config Drift Tests
# ====================================================================

class TestDiagnosticCoverage(unittest.TestCase):
    def test_missing_diagnostics(self):
        idx = {
            "azure-resource": [
                _ev("azure-resource", {"ResourceType": "microsoft.compute/virtualmachines", "Name": "vm1"},
                    "/subscriptions/abc/resourceGroups/rg/providers/microsoft.compute/virtualmachines/vm1"),
            ],
            "azure-diagnostic-setting": [],
        }
        findings = _check_diagnostic_coverage(idx)
        self.assertEqual(len(findings), 1)

    def test_with_diagnostics(self):
        rid = "/subscriptions/abc/resourceGroups/rg/providers/microsoft.compute/virtualmachines/vm1"
        idx = {
            "azure-resource": [
                _ev("azure-resource", {"ResourceType": "microsoft.compute/virtualmachines", "Name": "vm1"}, rid),
            ],
            "azure-diagnostic-setting": [
                _ev("azure-diagnostic-setting", {}, f"{rid}/providers/microsoft.insights/diagnosticSettings/diag1"),
            ],
        }
        self.assertEqual(len(_check_diagnostic_coverage(idx)), 0)


class TestPolicyNoncompliance(unittest.TestCase):
    def test_noncompliant_flagged(self):
        idx = {"azure-policy-compliance": [
            _ev("azure-policy-compliance", {"ComplianceState": "NonCompliant", "PolicyDefinitionName": "p1"}),
        ]}
        findings = _check_policy_noncompliance(idx)
        self.assertEqual(len(findings), 1)

    def test_compliant_ok(self):
        idx = {"azure-policy-compliance": [
            _ev("azure-policy-compliance", {"ComplianceState": "Compliant"}),
        ]}
        self.assertEqual(len(_check_policy_noncompliance(idx)), 0)


class TestTagGovernance(unittest.TestCase):
    def test_many_untagged(self):
        idx = {"azure-resource": [
            _ev("azure-resource", {"ResourceType": "microsoft.compute/virtualmachines", "Name": f"vm{i}", "Tags": None})
            for i in range(15)
        ]}
        findings = _check_tag_governance(idx)
        self.assertEqual(len(findings), 1)

    def test_few_untagged_ok(self):
        idx = {"azure-resource": [
            _ev("azure-resource", {"ResourceType": "microsoft.compute/virtualmachines", "Name": "vm1", "Tags": None}),
        ]}
        self.assertEqual(len(_check_tag_governance(idx)), 0)


# ====================================================================
# Risk Scoring Tests
# ====================================================================

class TestRiskScoring(unittest.TestCase):
    def test_empty_findings(self):
        scores = compute_risk_scores([])
        self.assertEqual(scores["OverallRiskScore"], 0)
        self.assertEqual(scores["OverallRiskLevel"], "low")
        self.assertEqual(scores["TopRisks"], [])

    def test_single_critical(self):
        findings = [_risk_finding("identity", "test", "Test", "Desc", "critical")]
        scores = compute_risk_scores(findings)
        self.assertGreater(scores["OverallRiskScore"], 0)
        self.assertEqual(scores["SeverityDistribution"]["critical"], 1)
        self.assertIn("identity", scores["CategoryScores"])

    def test_mixed_severities(self):
        findings = [
            _risk_finding("identity", "a", "A", "D", "critical"),
            _risk_finding("network", "b", "B", "D", "medium"),
            _risk_finding("config", "c", "C", "D", "low"),
        ]
        scores = compute_risk_scores(findings)
        self.assertEqual(len(scores["CategoryScores"]), 3)
        self.assertEqual(scores["SeverityDistribution"]["critical"], 1)
        self.assertEqual(scores["SeverityDistribution"]["medium"], 1)
        self.assertEqual(scores["SeverityDistribution"]["low"], 1)

    def test_top_risks_limited_to_10(self):
        findings = [_risk_finding("identity", f"s{i}", f"T{i}", "D", "high") for i in range(20)]
        scores = compute_risk_scores(findings)
        self.assertLessEqual(len(scores["TopRisks"]), 10)


class TestScoreToLevel(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(_score_to_level(80), "critical")

    def test_high(self):
        self.assertEqual(_score_to_level(60), "high")

    def test_medium(self):
        self.assertEqual(_score_to_level(30), "medium")

    def test_low(self):
        self.assertEqual(_score_to_level(10), "low")


# ====================================================================
# Integration-level Tests
# ====================================================================

class TestFullAnalyzers(unittest.TestCase):
    """Test that the top-level analyzer functions aggregate sub-checks."""

    def test_identity_risk_aggregates(self):
        idx = {
            "entra-user-summary": [_ev("entra-user-summary", {"TotalUsers": 100, "StaleUsers": 30, "StalePercent": 30, "GuestUsers": 25})],
            "entra-mfa-summary": [_ev("entra-mfa-summary", {"RegisteredCount": 40, "TotalUsers": 100})],
            "entra-directory-role-member": [
                _ev("entra-directory-role-member", {"RoleName": "Global Administrator", "MemberId": f"u{i}", "MemberName": f"A{i}"})
                for i in range(8)
            ],
            "azure-role-assignment": [],
            "entra-application": [],
            "entra-access-review": [],
            "entra-risky-user": [],
        }
        findings = analyze_identity_risk(idx)
        # Should have findings from: dormant, mfa_gaps, admin_proliferation, guest
        self.assertGreaterEqual(len(findings), 3)
        categories = {f["Subcategory"] for f in findings}
        self.assertIn("dormant_accounts", categories)
        self.assertIn("mfa_gaps", categories)
        self.assertIn("admin_proliferation", categories)

    def test_network_risk_aggregates(self):
        idx = {
            "azure-network-security-nsg": [_ev("azure-network-security-nsg", {"RdpExposed": True, "NsgName": "nsg1"})],
            "azure-storage-security": [_ev("azure-storage-security", {"AllowBlobPublicAccess": True, "StorageAccountName": "sa1"})],
            "azure-webapp-config": [],
            "azure-sql-server": [],
        }
        findings = analyze_network_risk(idx)
        self.assertGreaterEqual(len(findings), 2)

    def test_config_drift_aggregates(self):
        idx = {
            "azure-resource": [
                _ev("azure-resource", {"ResourceType": "microsoft.compute/virtualmachines", "Name": f"vm{i}", "Tags": None},
                    f"/sub/rg/providers/microsoft.compute/virtualmachines/vm{i}")
                for i in range(15)
            ],
            "azure-diagnostic-setting": [],
            "azure-policy-compliance": [
                _ev("azure-policy-compliance", {"ComplianceState": "NonCompliant", "PolicyDefinitionName": "p1"}),
            ],
        }
        findings = analyze_config_drift(idx)
        subcats = {f["Subcategory"] for f in findings}
        self.assertIn("missing_diagnostics", subcats)
        self.assertIn("policy_noncompliance", subcats)
        self.assertIn("missing_tags", subcats)


class TestRiskFindingStructure(unittest.TestCase):
    def test_has_required_keys(self):
        f = _risk_finding("identity", "test", "Title", "Desc", "high",
                          affected_resources=[{"Type": "Test"}],
                          remediation={"Description": "Fix it"})
        for key in ("RiskFindingId", "Category", "Subcategory", "Title",
                     "Description", "Severity", "AffectedResources",
                     "AffectedCount", "Remediation", "DetectedAt"):
            self.assertIn(key, f)
        self.assertEqual(f["AffectedCount"], 1)


# ====================================================================
# Agent Tool Registration
# ====================================================================

class TestAgentToolRegistration(unittest.TestCase):
    def test_tools_list_has_analyze_risk(self):
        from app.agent import TOOLS
        names = [t.__name__ for t in TOOLS]
        self.assertIn("analyze_risk", names)
        self.assertEqual(len(TOOLS), 12)


class TestRunRiskAnalysisImport(unittest.TestCase):
    def test_import_risk_engine(self):
        import app.risk_engine
        self.assertTrue(hasattr(app.risk_engine, "run_risk_analysis"))
        self.assertTrue(hasattr(app.risk_engine, "compute_risk_scores"))

    def test_import_run_risk_analysis_cli(self):
        """Verify run_risk_analysis.py is parseable."""
        import ast
        cli_path = os.path.join(os.path.dirname(__file__), "..", "run_risk_analysis.py")
        with open(cli_path, "r", encoding="utf-8") as fh:
            ast.parse(fh.read())


if __name__ == "__main__":
    unittest.main()
