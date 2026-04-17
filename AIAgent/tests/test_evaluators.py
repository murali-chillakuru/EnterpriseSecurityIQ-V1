"""
EnterpriseSecurityIQ Agent Tests
Unit tests for evaluator field alignment, evaluator logic, and config parsing.
"""

from __future__ import annotations
import json
import sys
import os
import pathlib
import unittest

# Ensure the AIAgent directory is on sys.path
agent_dir = pathlib.Path(__file__).resolve().parent.parent
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from app.models import Status, Severity, EvidenceRecord, FindingRecord


# ---- Helpers ----

def _evidence(evidence_type: str, data: dict) -> dict:
    return EvidenceRecord(
        source="Azure", collector="TestCollector",
        evidence_type=evidence_type,
        description="test", data=data,
    ).to_dict()


def _index(records: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for r in records:
        et = r.get("EvidenceType", "")
        idx.setdefault(et, []).append(r)
    return idx


def _ctrl(domain: str, eval_logic: str, severity: str = "high") -> dict:
    return {
        "control_id": "TEST-01",
        "domain": domain,
        "severity": severity,
        "title": "Test Control",
        "evaluation_logic": eval_logic,
        "recommendation": "Fix it.",
        "_framework": "FedRAMP",
    }


# ==============================================================================
# Test evaluator-collector field alignment
# ==============================================================================

class TestDataProtectionFieldAlignment(unittest.TestCase):
    """Verify data_protection evaluator reads the exact fields collectors produce."""

    def test_storage_https_field(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-storage-security", {
            "Name": "mystorage", "EnableHttpsTrafficOnly": True,
            "MinimumTlsVersion": "TLS1_2",
        })]
        ctrl = _ctrl("data_protection", "check_data_in_transit_encryption")
        results = evaluate_data_protection("SC-8", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_storage_https_noncompliant(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-storage-security", {
            "Name": "badstorage", "EnableHttpsTrafficOnly": False,
            "MinimumTlsVersion": "TLS1_0",
        })]
        ctrl = _ctrl("data_protection", "check_data_in_transit_encryption")
        results = evaluate_data_protection("SC-8", ctrl, ev, _index(ev))
        nc = [r for r in results if r["Status"] == "non_compliant"]
        self.assertTrue(len(nc) >= 1)

    def test_vm_fields_compliant(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-vm-config", {
            "Name": "vm1", "OsDiskEncrypted": True, "DataDiskCount": 1,
            "DataDisksEncrypted": True, "IdentityType": "SystemAssigned",
            "HasMDEExtension": True, "BootDiagnosticsEnabled": True,
        })]
        ctrl = _ctrl("data_protection", "check_vm_security")
        results = evaluate_data_protection("SC-28", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_vm_fields_noncompliant(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-vm-config", {
            "Name": "badvm", "OsDiskEncrypted": False, "DataDiskCount": 2,
            "DataDisksEncrypted": False, "IdentityType": "None",
            "HasMDEExtension": False, "BootDiagnosticsEnabled": False,
        })]
        ctrl = _ctrl("data_protection", "check_vm_security")
        results = evaluate_data_protection("SC-28", ctrl, ev, _index(ev))
        nc = [r for r in results if r["Status"] == "non_compliant"]
        # Should flag: OS disk, data disks, identity, MDE, boot diag
        self.assertGreaterEqual(len(nc), 4)

    def test_keyvault_fields(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-keyvault", {
            "Name": "mykv", "EnableSoftDelete": True,
            "EnablePurgeProtection": True, "EnableRbacAuthorization": True,
            "NetworkAclsDefaultAction": "Deny",
        })]
        ctrl = _ctrl("data_protection", "check_keyvault_security")
        results = evaluate_data_protection("SC-12", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_keyvault_network_noncompliant(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-keyvault", {
            "Name": "openkv", "EnableSoftDelete": False,
            "EnablePurgeProtection": False, "EnableRbacAuthorization": False,
            "NetworkAclsDefaultAction": "Allow",
        })]
        ctrl = _ctrl("data_protection", "check_keyvault_security")
        results = evaluate_data_protection("SC-12", ctrl, ev, _index(ev))
        nc = [r for r in results if r["Status"] == "non_compliant"]
        self.assertGreaterEqual(len(nc), 3)

    def test_sql_fields(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-sql-server", {
            "Name": "sqlsrv", "AdAdminConfigured": True,
            "AuditingEnabled": True, "TdeEnabled": True,
            "PublicNetworkAccess": "Disabled", "MinimalTlsVersion": "1.2",
        })]
        ctrl = _ctrl("data_protection", "check_sql_security")
        results = evaluate_data_protection("SC-28", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_webapp_fields(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-webapp-config", {
            "Name": "myapp", "HttpsOnly": True, "MinTlsVersion": "1.2",
            "FtpsState": "Disabled", "RemoteDebuggingEnabled": False,
            "ManagedIdentityType": "SystemAssigned",
        })]
        ctrl = _ctrl("data_protection", "check_webapp_security")
        results = evaluate_data_protection("SC-8", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)


class TestNetworkFieldAlignment(unittest.TestCase):
    """Verify network evaluator reads the exact fields collectors produce."""

    def test_nsg_flat_model_rdp_exposed(self):
        from app.evaluators.network import evaluate_network
        ev = [_evidence("azure-nsg-rule", {
            "NsgName": "nsg1", "RuleName": "AllowRDP",
            "Direction": "Inbound", "Access": "Allow",
            "SourceAddressPrefix": "*", "SourceAddressPrefixes": [],
            "DestinationPortRange": "3389", "DestinationPortRanges": [],
        })]
        ctrl = _ctrl("network", "check_nsg_rules")
        results = evaluate_network("SC-7", ctrl, ev, _index(ev))
        nc = [r for r in results if r["Status"] == "non_compliant"]
        self.assertTrue(any("RDP" in r["Description"] for r in nc))

    def test_nsg_flat_model_safe(self):
        from app.evaluators.network import evaluate_network
        ev = [_evidence("azure-nsg-rule", {
            "NsgName": "nsg1", "RuleName": "AllowInternal",
            "Direction": "Inbound", "Access": "Allow",
            "SourceAddressPrefix": "10.0.0.0/8", "SourceAddressPrefixes": [],
            "DestinationPortRange": "443", "DestinationPortRanges": [],
        })]
        ctrl = _ctrl("network", "check_nsg_rules")
        results = evaluate_network("SC-7", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_storage_security_fields(self):
        from app.evaluators.network import evaluate_network
        ev = [_evidence("azure-storage-security", {
            "Name": "stor1", "EnableHttpsTrafficOnly": True,
            "MinimumTlsVersion": "TLS1_2", "AllowBlobPublicAccess": False,
            "AllowSharedKeyAccess": False, "NetworkDefaultAction": "Deny",
        })]
        ctrl = _ctrl("network", "check_storage_security")
        results = evaluate_network("SC-7", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_firewall_rule_count_fields(self):
        from app.evaluators.network import evaluate_network
        ev = [_evidence("azure-firewall", {
            "Name": "fw1", "ThreatIntelMode": "Deny",
            "NetworkRuleCollectionCount": 2,
            "ApplicationRuleCollectionCount": 1,
            "NatRuleCollectionCount": 1,
            "SkuTier": "Standard",
        })]
        ctrl = _ctrl("network", "check_firewall_protection")
        results = evaluate_network("SC-7", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_route_table_fields(self):
        from app.evaluators.network import evaluate_network
        ev = [_evidence("azure-route-table", {
            "Name": "rt1", "HasDefaultRouteToNVA": True,
            "DisableBgpRoutePropagation": True,
        })]
        ctrl = _ctrl("network", "check_route_table_security")
        results = evaluate_network("SC-7", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)


class TestGovernanceFieldAlignment(unittest.TestCase):
    """Verify governance evaluator reads the exact fields collectors produce."""

    def test_defender_plan_name_field(self):
        from app.evaluators.governance import evaluate_governance
        ev = []
        for plan in ["VirtualMachines", "SqlServers", "AppServices",
                      "StorageAccounts", "KeyVaults", "Arm", "Containers"]:
            ev.append(_evidence("azure-defender-pricing", {
                "PlanName": plan, "PricingTier": "Standard",
            }))
        ctrl = _ctrl("governance", "check_defender_enabled")
        results = evaluate_governance("SI-4", ctrl, ev, _index(ev))
        statuses = [r["Status"] for r in results]
        self.assertIn("compliant", statuses)

    def test_defender_missing_plan(self):
        from app.evaluators.governance import evaluate_governance
        ev = [_evidence("azure-defender-pricing", {
            "PlanName": "VirtualMachines", "PricingTier": "Standard",
        })]
        ctrl = _ctrl("governance", "check_defender_enabled")
        results = evaluate_governance("SI-4", ctrl, ev, _index(ev))
        nc = [r for r in results if r["Status"] == "non_compliant"]
        self.assertTrue(len(nc) >= 1, "Should flag missing critical defender plans")

    def test_security_contact_alert_field(self):
        from app.evaluators.governance import evaluate_governance
        ev_def = [_evidence("azure-defender-pricing", {
            "PlanName": "VirtualMachines", "PricingTier": "Standard",
        })]
        ev_contact = [_evidence("azure-security-contact", {
            "AlertNotifications": "On", "Email": "sec@test.com",
        })]
        ev_auto = [_evidence("azure-auto-provisioning", {
            "AutoProvision": "On",
        })]
        all_ev = ev_def + ev_contact + ev_auto
        ctrl = _ctrl("governance", "check_defender_plans")
        results = evaluate_governance("CA-7", ctrl, all_ev, _index(all_ev))
        # Should not flag contacts since AlertNotifications=On
        contact_findings = [r for r in results
                           if "No security contacts" in r.get("Description", "")]
        self.assertEqual(len(contact_findings), 0)


class TestDefaultHandlersNotAssessed(unittest.TestCase):
    """Verify _default handlers return NOT_ASSESSED, not COMPLIANT."""

    def test_data_protection_default(self):
        from app.evaluators.data_protection import evaluate_data_protection
        ev = [_evidence("azure-storage-security", {"Name": "x"})]
        ctrl = _ctrl("data_protection", "nonexistent_check")
        results = evaluate_data_protection("XX-1", ctrl, ev, _index(ev))
        self.assertEqual(results[0]["Status"], "not_assessed")

    def test_network_default(self):
        from app.evaluators.network import evaluate_network
        ev = [_evidence("azure-nsg-rule", {"Name": "x"})]
        ctrl = _ctrl("network", "nonexistent_check")
        results = evaluate_network("XX-1", ctrl, ev, _index(ev))
        self.assertEqual(results[0]["Status"], "not_assessed")

    def test_governance_default(self):
        from app.evaluators.governance import evaluate_governance
        ev = [_evidence("azure-defender-pricing", {"Name": "x"})]
        ctrl = _ctrl("governance", "nonexistent_check")
        results = evaluate_governance("XX-1", ctrl, ev, _index(ev))
        self.assertEqual(results[0]["Status"], "not_assessed")

    def test_identity_default(self):
        from app.evaluators.identity import evaluate_identity
        ev = [_evidence("entra-user-detail", {"Name": "x"})]
        ctrl = _ctrl("identity", "nonexistent_check")
        results = evaluate_identity("XX-1", ctrl, ev, _index(ev))
        self.assertEqual(results[0]["Status"], "not_assessed")

    def test_access_default(self):
        from app.evaluators.access import evaluate_access
        ev = [_evidence("azure-role-assignment", {"Name": "x"})]
        ctrl = _ctrl("access", "nonexistent_check")
        results = evaluate_access("XX-1", ctrl, ev, _index(ev))
        self.assertEqual(results[0]["Status"], "not_assessed")

    def test_logging_default(self):
        from app.evaluators.logging_eval import evaluate_logging
        ev = [_evidence("azure-diagnostic-setting", {"Name": "x"})]
        ctrl = _ctrl("logging", "nonexistent_check")
        results = evaluate_logging("XX-1", ctrl, ev, _index(ev))
        self.assertEqual(results[0]["Status"], "not_assessed")


# ==============================================================================
# Test engine domain filtering
# ==============================================================================

class TestEngineDomainFiltering(unittest.TestCase):
    """Verify evaluate_all respects the domains filter."""

    def test_domain_filter_limits_results(self):
        from app.evaluators.engine import evaluate_all
        # Create minimal evidence
        ev = [
            _evidence("azure-role-assignment", {"IsPrivileged": False, "ScopeLevel": "ResourceGroup", "RoleDefinitionName": "Reader"}),
            _evidence("azure-storage-security", {"Name": "s1", "EnableHttpsTrafficOnly": True, "MinimumTlsVersion": "TLS1_2"}),
        ]
        # Run for just access domain
        results_access = evaluate_all(ev, frameworks=["FedRAMP"], domains=["access"])
        # Run for all domains
        results_all = evaluate_all(ev, frameworks=["FedRAMP"])

        access_controls = [c for c in results_access["control_results"]
                          if c.get("Domain") == "access"]
        all_domains = {c.get("Domain") for c in results_all["control_results"]}

        # Filtered results should only have access domain
        filtered_domains = {c.get("Domain") for c in results_access["control_results"]}
        self.assertEqual(filtered_domains, {"access"})
        # Unfiltered should have multiple domains
        self.assertTrue(len(all_domains) > 1)


# ==============================================================================
# Test config parsing
# ==============================================================================

class TestConfigParsing(unittest.TestCase):
    """Verify AssessmentConfig loads correctly."""

    def test_default_config(self):
        from app.config import AssessmentConfig
        cfg = AssessmentConfig()
        self.assertTrue(cfg.collectors.azure_enabled)
        self.assertTrue(cfg.collectors.entra_enabled)
        self.assertEqual(cfg.frameworks, ["FedRAMP"])
        self.assertIn("json", cfg.output_formats)

    def test_config_from_dict(self):
        from app.config import AssessmentConfig
        cfg = AssessmentConfig()
        cfg.collectors.azure_enabled = False
        cfg.frameworks = ["CIS", "ISO-27001"]
        self.assertFalse(cfg.collectors.azure_enabled)
        self.assertEqual(len(cfg.frameworks), 2)

    def test_no_graph_scopes_in_config(self):
        """graph_scopes removed — config should not have them."""
        from app.config import AuthConfig
        cfg = AuthConfig()
        self.assertFalse(hasattr(cfg, "graph_scopes"))


# ==============================================================================
# Test access-denied handling
# ==============================================================================

class TestAccessDeniedHandling(unittest.TestCase):
    """Verify AccessDeniedError is raised and handled correctly."""

    def test_access_denied_error(self):
        from app.collectors.base import AccessDeniedError
        err = AccessDeniedError(api="Graph API", status=403, message="Forbidden")
        self.assertEqual(err.api, "Graph API")
        self.assertEqual(err.status, 403)
        self.assertIn("Forbidden", str(err))

    def test_extract_status_from_403_string(self):
        from app.collectors.base import _extract_status
        err = Exception("Request failed with status 403 Forbidden")
        self.assertEqual(_extract_status(err), 403)

    def test_extract_status_from_401_string(self):
        from app.collectors.base import _extract_status
        err = Exception("401 Unauthorized: token expired")
        self.assertEqual(_extract_status(err), 401)

    def test_extract_status_from_attribute(self):
        from app.collectors.base import _extract_status
        err = Exception("test")
        err.response_status_code = 403
        self.assertEqual(_extract_status(err), 403)

    def test_extract_status_returns_none(self):
        from app.collectors.base import _extract_status
        err = Exception("Something else went wrong")
        self.assertIsNone(_extract_status(err))

    def test_collector_result_access_denied_fields(self):
        from app.models import CollectorResult
        r = CollectorResult(
            collector="TestCollector", source="Azure", success=True,
            access_denied=True, access_denied_apis=["Graph API"],
        )
        self.assertTrue(r.access_denied)
        self.assertEqual(r.access_denied_apis, ["Graph API"])
        d = r.to_dict()
        self.assertTrue(d["AccessDenied"])
        self.assertEqual(d["AccessDeniedApis"], ["Graph API"])

    def test_run_collector_catches_access_denied(self):
        import asyncio
        from app.collectors.base import run_collector, AccessDeniedError

        async def _failing_collector():
            raise AccessDeniedError(api="identity.conditionalAccess", status=403)

        result = asyncio.run(run_collector("TestCollector", "Entra", _failing_collector))
        self.assertTrue(result.access_denied)
        self.assertEqual(result.access_denied_apis, ["identity.conditionalAccess"])
        self.assertTrue(result.success)  # access denied is NOT a failure
        self.assertEqual(result.record_count, 0)
        # Should contain an access-denied evidence marker
        self.assertEqual(len(result.data), 1)
        self.assertEqual(result.data[0]["EvidenceType"], "access-denied")

    def test_run_collector_catches_403_exception(self):
        import asyncio
        from app.collectors.base import run_collector

        async def _failing_collector():
            exc = Exception("403 Forbidden: Insufficient privileges")
            raise exc

        result = asyncio.run(run_collector("TestCollector", "Azure", _failing_collector))
        self.assertTrue(result.access_denied)
        self.assertTrue(result.success)


class TestAuthSimplified(unittest.TestCase):
    """Verify auth module no longer has DeviceCodeCredential."""

    def test_no_device_code_import(self):
        import app.auth as auth_module
        import inspect
        source = inspect.getsource(auth_module)
        self.assertNotIn("DeviceCodeCredential", source)


if __name__ == "__main__":
    unittest.main()
