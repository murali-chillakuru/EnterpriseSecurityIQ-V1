"""
Tests for the 10-Enhancement batch:
  #1  App registration fallback auth mode
  #2  M365 data lifecycle + DLP alert analysis in data_security_engine
  #3  Insider risk signals in risk_engine
  #4  Cross-run comparison tool (compare_runs)
  #5  Sensitive data exposure search tool (search_exposure)
  #6  System prompt tool chaining guidance
  #7  Streaming progress log calls
  #8  Scoped subscription parameter on analyze_risk / assess_data_security
  #9  5 M365 compliance collectors
  #10 Permission check tool (check_permissions)
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Shared helpers ──────────────────────────────────────────────────────

def _ev(etype: str, data: dict, resource_id: str = "") -> dict:
    return {"EvidenceType": etype, "Data": data, "ResourceId": resource_id}


def _build_index(records: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for r in records:
        idx.setdefault(r.get("EvidenceType", ""), []).append(r)
    return idx


# ====================================================================
# Enhancement #1 — App Registration fallback in auth.py
# ====================================================================

class TestAppRegistrationAuthMode(unittest.TestCase):
    """Verify the 'appregistration' auth mode is accepted and works."""

    def test_appregistration_mode_creates_client_secret_credential(self):
        from app.auth import ComplianceCredentials

        os.environ["ENTERPRISESECURITYIQ_APP_CLIENT_ID"] = "test-client-id"
        os.environ["ENTERPRISESECURITYIQ_APP_CLIENT_SECRET"] = "test-secret"
        os.environ["AZURE_TENANT_ID"] = "test-tenant"
        try:
            creds = ComplianceCredentials(auth_mode="appregistration")
            credential = creds.credential
            # Should be a ClientSecretCredential
            self.assertEqual(type(credential).__name__, "ClientSecretCredential")
        finally:
            os.environ.pop("ENTERPRISESECURITYIQ_APP_CLIENT_ID", None)
            os.environ.pop("ENTERPRISESECURITYIQ_APP_CLIENT_SECRET", None)
            os.environ.pop("AZURE_TENANT_ID", None)

    def test_appregistration_mode_raises_without_env(self):
        from app.auth import ComplianceCredentials

        os.environ.pop("ENTERPRISESECURITYIQ_APP_CLIENT_ID", None)
        os.environ.pop("ENTERPRISESECURITYIQ_APP_CLIENT_SECRET", None)
        os.environ.pop("AZURE_CLIENT_ID", None)
        os.environ.pop("AZURE_CLIENT_SECRET", None)

        creds = ComplianceCredentials(auth_mode="appregistration")
        with self.assertRaises(ValueError):
            _ = creds.credential


# ====================================================================
# Enhancement #2 — M365 Data Lifecycle + DLP Alerts in data_security_engine
# ====================================================================

class TestRetentionLabelsCheck(unittest.TestCase):
    """_check_retention_labels_exist from data_security_engine."""

    def test_no_retention_labels_flags_finding(self):
        from app.data_security_engine import _check_retention_labels_exist
        # Need some m365- key so has_m365 guard passes
        idx = _build_index([_ev("m365-label-analytics", {"Total": 0})])
        findings = _check_retention_labels_exist(idx)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["Subcategory"], "no_retention_labels")

    def test_unused_retention_labels(self):
        from app.data_security_engine import _check_retention_labels_exist
        idx = _build_index([
            _ev("m365-retention-summary", {"TotalLabels": 3, "InUseLabels": 0}),
            _ev("m365-retention-label", {"DisplayName": "Keep5Years", "IsInUse": False}),
        ])
        findings = _check_retention_labels_exist(idx)
        subs = [f["Subcategory"] for f in findings]
        self.assertIn("retention_labels_unused", subs)

    def test_active_retention_labels_clean(self):
        from app.data_security_engine import _check_retention_labels_exist
        idx = _build_index([
            _ev("m365-retention-summary", {"TotalLabels": 3, "InUseLabels": 2}),
            _ev("m365-retention-label", {"DisplayName": "Keep5Years", "IsInUse": True}),
        ])
        findings = _check_retention_labels_exist(idx)
        self.assertEqual(len(findings), 0)


class TestEdiscoveryReadinessCheck(unittest.TestCase):
    def test_no_ediscovery_flags_finding(self):
        from app.data_security_engine import _check_ediscovery_readiness
        # Need m365- key so has_m365 guard passes
        idx = _build_index([_ev("m365-label-analytics", {"Total": 0})])
        findings = _check_ediscovery_readiness(idx)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["Subcategory"], "no_ediscovery_cases")

    def test_ediscovery_present_clean(self):
        from app.data_security_engine import _check_ediscovery_readiness
        # Provide an actual case record so has_cases is True
        idx = _build_index([
            _ev("m365-ediscovery-case", {"DisplayName": "Case1", "Status": "active"}),
        ])
        findings = _check_ediscovery_readiness(idx)
        self.assertEqual(len(findings), 0)


class TestDlpAlertVolume(unittest.TestCase):
    def test_high_severity_dlp_alerts_flagged(self):
        from app.data_security_engine import _check_dlp_alert_volume
        idx = _build_index([
            _ev("m365-dlp-alert-metrics", {
                "TotalDlpAlerts": 15,
                "TotalSecurityAlerts": 20,
                "SeverityCounts": {"high": 3, "critical": 3, "medium": 5, "low": 4},
                "RecentAlerts": [],
            }),
        ])
        findings = _check_dlp_alert_volume(idx)
        subs = [f["Subcategory"] for f in findings]
        self.assertIn("high_severity_dlp_alerts", subs)

    def test_no_dlp_alerts_with_policies(self):
        from app.data_security_engine import _check_dlp_alert_volume
        idx = _build_index([
            _ev("m365-dlp-alert-metrics", {
                "TotalDlpAlerts": 0,
                "TotalSecurityAlerts": 5,
                "SeverityCounts": {},
            }),
            _ev("m365-dlp-policies", {"PolicyCount": 2}),
        ])
        findings = _check_dlp_alert_volume(idx)
        subs = [f["Subcategory"] for f in findings]
        self.assertIn("no_dlp_alerts_with_policies", subs)


class TestDataLifecycleOrchestrator(unittest.TestCase):
    def test_analyze_m365_data_lifecycle_returns_list(self):
        from app.data_security_engine import analyze_m365_data_lifecycle
        idx = _build_index([])
        result = analyze_m365_data_lifecycle(idx)
        self.assertIsInstance(result, list)

    def test_analyze_dlp_alert_effectiveness_returns_list(self):
        from app.data_security_engine import analyze_dlp_alert_effectiveness
        idx = _build_index([])
        result = analyze_dlp_alert_effectiveness(idx)
        self.assertIsInstance(result, list)


# ====================================================================
# Enhancement #3 — Insider Risk signals in risk_engine
# ====================================================================

class TestIrmPolicyExistence(unittest.TestCase):
    def test_no_irm_evidence_flags_not_assessed(self):
        from app.risk_engine import _check_irm_policy_existence
        # Need entra- or m365- key so has_m365 guard passes
        idx = _build_index([_ev("entra-user-summary", {"TotalUsers": 10})])
        findings = _check_irm_policy_existence(idx)
        self.assertTrue(len(findings) >= 1)

    def test_irm_with_alerts_clean(self):
        from app.risk_engine import _check_irm_policy_existence
        idx = _build_index([
            _ev("m365-irm-status", {"HasIrmAlerts": True, "IrmAlertsFound": 2}),
            _ev("m365-irm-settings", {"Configured": True}),
        ])
        findings = _check_irm_policy_existence(idx)
        self.assertEqual(len(findings), 0)


class TestIrmActiveAlerts(unittest.TestCase):
    def test_active_alerts_flagged(self):
        from app.risk_engine import _check_irm_active_alerts
        idx = _build_index([
            _ev("m365-irm-status", {
                "HasIrmAlerts": True,
                "IrmAlertsFound": 3,
                "SampleAlerts": [
                    {"Title": "Suspicious download", "Severity": "high", "Status": "active"},
                ],
            }),
        ])
        findings = _check_irm_active_alerts(idx)
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["Subcategory"], "active_irm_alerts")

    def test_no_active_alerts_clean(self):
        from app.risk_engine import _check_irm_active_alerts
        idx = _build_index([
            _ev("m365-irm-status", {"HasIrmAlerts": False, "IrmAlertsFound": 0}),
        ])
        findings = _check_irm_active_alerts(idx)
        self.assertEqual(len(findings), 0)


class TestInsiderRiskOrchestrator(unittest.TestCase):
    def test_analyze_insider_risk_returns_list(self):
        from app.risk_engine import analyze_insider_risk
        idx = _build_index([])
        result = analyze_insider_risk(idx)
        self.assertIsInstance(result, list)


# ====================================================================
# Enhancement #4 — Cross-run comparison (delta_report)
# ====================================================================

class TestDeltaReport(unittest.TestCase):
    def test_compute_delta_new_findings(self):
        from app.reports.delta_report import compute_delta
        current = {
            "control_results": [],
            "findings": [{"control_id": "AC-1", "resource": "r1", "check": "c1", "detail": "x"}],
            "summary": {},
        }
        previous = {"control_results": [], "findings": [], "summary": {}}
        delta = compute_delta(current, previous)
        self.assertEqual(len(delta["new_findings"]), 1)
        self.assertEqual(len(delta["resolved_findings"]), 0)

    def test_compute_delta_resolved_findings(self):
        from app.reports.delta_report import compute_delta
        current = {"control_results": [], "findings": [], "summary": {}}
        previous = {
            "control_results": [],
            "findings": [{"control_id": "AC-1", "resource": "r1", "check": "c1", "detail": "x"}],
            "summary": {},
        }
        delta = compute_delta(current, previous)
        self.assertEqual(len(delta["resolved_findings"]), 1)
        self.assertEqual(len(delta["new_findings"]), 0)

    def test_compute_delta_status_change(self):
        from app.reports.delta_report import compute_delta
        current = {
            "control_results": [{"framework": "MCSB", "control_id": "AC-1", "status": "COMPLIANT", "title": "T"}],
            "findings": [],
            "summary": {},
        }
        previous = {
            "control_results": [{"framework": "MCSB", "control_id": "AC-1", "status": "NON_COMPLIANT", "title": "T"}],
            "findings": [],
            "summary": {},
        }
        delta = compute_delta(current, previous)
        self.assertEqual(len(delta["status_changes"]), 1)
        self.assertEqual(delta["status_changes"][0]["new_status"], "COMPLIANT")

    def test_generate_delta_section_markdown(self):
        from app.reports.delta_report import generate_delta_section
        delta = {
            "summary": "1 new, 0 resolved, 0 improved, 0 regressed.",
            "score_change": {},
            "new_findings": [],
            "resolved_findings": [],
            "status_changes": [],
        }
        md = generate_delta_section(delta)
        self.assertIn("Delta from Previous Assessment", md)

    def test_find_previous_results_empty_dir(self):
        import tempfile
        from app.reports.delta_report import find_previous_results
        with tempfile.TemporaryDirectory() as td:
            result = find_previous_results(td)
            self.assertIsNone(result)


# ====================================================================
# Enhancement #5 — Exposure search (search_exposure)
# ====================================================================

class TestSearchExposureTool(unittest.TestCase):
    def test_exposure_queries_cover_all_categories(self):
        """The tool defines 5 exposure categories, each mapping to an ARG template."""
        from app.query_engine import ARG_TEMPLATES
        expected = ["storage_public_access", "nsg_open_rules",
                     "vms_without_disk_encryption", "unattached_disks", "public_ips"]
        for key in expected:
            self.assertIn(key, ARG_TEMPLATES, f"ARG template '{key}' is missing")


# ====================================================================
# Enhancement #6 — System prompt tool chaining
# ====================================================================

class TestSystemPromptUpdates(unittest.TestCase):
    def test_system_prompt_mentions_tool_chaining(self):
        from app.agent import SYSTEM_PROMPT
        self.assertIn("Tool Chaining Guidance", SYSTEM_PROMPT)

    def test_system_prompt_lists_new_capabilities(self):
        from app.agent import SYSTEM_PROMPT
        self.assertIn("Check Permissions", SYSTEM_PROMPT)
        self.assertIn("Compare Runs", SYSTEM_PROMPT)
        self.assertIn("Search Exposure", SYSTEM_PROMPT)

    def test_system_prompt_updated_risk_categories(self):
        from app.agent import SYSTEM_PROMPT
        self.assertIn("insider_risk", SYSTEM_PROMPT)

    def test_system_prompt_updated_data_security_categories(self):
        from app.agent import SYSTEM_PROMPT
        self.assertIn("data_lifecycle", SYSTEM_PROMPT)
        self.assertIn("dlp_alerts", SYSTEM_PROMPT)


# ====================================================================
# Enhancement #7 — Streaming progress (log calls present)
# ====================================================================

class TestStreamingProgressLogs(unittest.TestCase):
    """Verify that tool functions contain progress log.info calls."""

    def test_agent_tools_have_log_calls(self):
        import inspect
        from app import agent
        tools_to_check = [
            "run_assessment", "search_tenant", "analyze_risk",
            "assess_data_security", "assess_copilot_readiness",
            "assess_ai_agent_security", "check_permissions",
            "compare_runs", "search_exposure",
        ]
        for name in tools_to_check:
            fn = getattr(agent, name)
            source = inspect.getsource(fn)
            self.assertIn("log.info", source, f"{name} is missing log.info streaming call")


# ====================================================================
# Enhancement #8 — Scoped subscription parameter
# ====================================================================

class TestScopedSubscriptionParameter(unittest.TestCase):
    def test_analyze_risk_has_subscriptions_param(self):
        import inspect
        from app.agent import analyze_risk
        sig = inspect.signature(analyze_risk)
        self.assertIn("subscriptions", sig.parameters)

    def test_assess_data_security_has_subscriptions_param(self):
        import inspect
        from app.agent import assess_data_security
        sig = inspect.signature(assess_data_security)
        self.assertIn("subscriptions", sig.parameters)


# ====================================================================
# Enhancement #9 — M365 compliance collectors
# ====================================================================

class TestM365CollectorsExist(unittest.TestCase):
    """Verify the 5 new M365 evidence collector functions exist."""

    def test_collectors_importable(self):
        from app.collectors.azure.m365_compliance import (
            collect_m365_retention,
            collect_m365_insider_risk,
            collect_m365_ediscovery,
            collect_m365_dlp_alerts,
            collect_m365_label_analytics,
        )
        # All should be callable
        self.assertTrue(callable(collect_m365_retention))
        self.assertTrue(callable(collect_m365_insider_risk))
        self.assertTrue(callable(collect_m365_ediscovery))
        self.assertTrue(callable(collect_m365_dlp_alerts))
        self.assertTrue(callable(collect_m365_label_analytics))

    def test_error_handler_importable(self):
        from app.collectors.azure.m365_compliance import _handle_m365_error
        self.assertTrue(callable(_handle_m365_error))


# ====================================================================
# Enhancement #10 — Permission check tool
# ====================================================================

class TestCheckPermissionsTool(unittest.TestCase):
    def test_check_permissions_in_tools_list(self):
        from app.agent import TOOLS, check_permissions
        self.assertIn(check_permissions, TOOLS)

    def test_compare_runs_in_tools_list(self):
        from app.agent import TOOLS, compare_runs
        self.assertIn(compare_runs, TOOLS)

    def test_search_exposure_in_tools_list(self):
        from app.agent import TOOLS, search_exposure
        self.assertIn(search_exposure, TOOLS)


# ====================================================================
# TOOLS list — verify all 12 tools are registered
# ====================================================================

class TestToolsList(unittest.TestCase):
    def test_tools_list_has_12_entries(self):
        from app.agent import TOOLS
        self.assertEqual(len(TOOLS), 12)

    def test_all_tools_are_callable(self):
        from app.agent import TOOLS
        for tool in TOOLS:
            self.assertTrue(callable(tool), f"{tool} is not callable")

    def test_tool_names(self):
        from app.agent import TOOLS
        names = [t.__name__ for t in TOOLS]
        expected = [
            "run_assessment", "query_results", "search_tenant",
            "analyze_risk", "assess_data_security", "generate_rbac_report",
            "generate_report", "assess_copilot_readiness", "assess_ai_agent_security",
            "check_permissions", "compare_runs", "search_exposure",
        ]
        self.assertEqual(names, expected)


if __name__ == "__main__":
    unittest.main()
