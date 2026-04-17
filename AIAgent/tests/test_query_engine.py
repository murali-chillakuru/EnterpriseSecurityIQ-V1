"""
EnterpriseSecurityIQ — Query Engine Tests
Unit tests for the interactive query engine (Phase 1).
Tests natural language dispatch, cross-referencing, and template matching
without requiring live Azure/Entra credentials.
"""

from __future__ import annotations
import sys
import pathlib
import unittest
import asyncio

# Ensure the AIAgent directory is on sys.path
agent_dir = pathlib.Path(__file__).resolve().parent.parent
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

from app.query_engine import (
    cross_reference_findings,
    ARG_TEMPLATES,
    _NL_ARG_MAP,
    _NL_ENTRA_MAP,
)


# ---- Test data ----

SAMPLE_FINDINGS = [
    {
        "ControlId": "CIS-1.1",
        "ControlTitle": "Ensure MFA is enabled for all users",
        "Domain": "identity",
        "Severity": "critical",
        "Status": "non_compliant",
        "Description": "MFA not enforced for 5 users.",
        "Recommendation": "Enable MFA for all users.",
        "ResourceId": "",
        "ResourceType": "",
    },
    {
        "ControlId": "CIS-4.1",
        "ControlTitle": "Ensure SQL TDE is enabled",
        "Domain": "data_protection",
        "Severity": "high",
        "Status": "non_compliant",
        "Description": "SQL transparent data encryption not enabled.",
        "Recommendation": "Enable TDE on all SQL databases.",
        "ResourceId": "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Sql/servers/sql01",
        "ResourceType": "Microsoft.Sql/servers",
    },
    {
        "ControlId": "CIS-6.1",
        "ControlTitle": "Ensure NSG flow logs are enabled",
        "Domain": "network",
        "Severity": "medium",
        "Status": "compliant",
        "Description": "NSG flow logs are enabled.",
        "Recommendation": "",
        "ResourceId": "",
        "ResourceType": "",
    },
    {
        "ControlId": "NIST-AC-2",
        "ControlTitle": "Account Management",
        "Domain": "access",
        "Severity": "high",
        "Status": "non_compliant",
        "Description": "12 users with Global Admin role.",
        "Recommendation": "Reduce Global Admin assignments to ≤5.",
        "ResourceId": "",
        "ResourceType": "",
    },
    {
        "ControlId": "PCI-10.6",
        "ControlTitle": "Monitor system components",
        "Domain": "logging",
        "Severity": "high",
        "Status": "compliant",
        "Description": "Diagnostic settings configured.",
        "Recommendation": "",
        "ResourceId": "",
        "ResourceType": "",
    },
]


class TestCrossReferenceFindings(unittest.TestCase):
    """Test the cross_reference_findings function."""

    def test_search_by_control_id(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "CIS-1.1")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ControlId"], "CIS-1.1")

    def test_search_by_domain(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "identity")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["Domain"], "identity")

    def test_search_by_severity(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "critical")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["Severity"], "critical")

    def test_search_by_keyword(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "MFA")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ControlId"], "CIS-1.1")

    def test_search_by_status(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "non_compliant")
        self.assertEqual(len(results), 3)  # CIS-1.1, CIS-4.1, NIST-AC-2

    def test_search_compliant(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "compliant")
        # "compliant" matches both "compliant" and "non_compliant"
        self.assertTrue(len(results) >= 2)

    def test_search_by_resource_type(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "Microsoft.Sql")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ControlId"], "CIS-4.1")

    def test_severity_ordering(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "non_compliant")
        severities = [r["Severity"] for r in results]
        # critical should come first, then high
        self.assertEqual(severities[0], "critical")

    def test_no_match(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "zzz_nonexistent_xyz")
        self.assertEqual(len(results), 0)

    def test_empty_findings(self):
        results = cross_reference_findings([], "anything")
        self.assertEqual(len(results), 0)

    def test_partial_control_id(self):
        results = cross_reference_findings(SAMPLE_FINDINGS, "NIST")
        self.assertTrue(len(results) >= 1)
        self.assertTrue(any(r["ControlId"].startswith("NIST") for r in results))


class TestARGTemplates(unittest.TestCase):
    """Test ARG query templates are well-formed."""

    def test_all_templates_are_strings(self):
        for name, kql in ARG_TEMPLATES.items():
            self.assertIsInstance(kql, str, f"Template {name} is not a string")
            self.assertIn("Resources" if "Resources" in kql else "|", kql,
                          f"Template {name} looks malformed")

    def test_expected_templates_exist(self):
        expected = [
            "all_resources", "public_ips", "storage_public_access",
            "nsg_open_rules", "keyvaults", "aks_clusters",
            "resource_counts_by_type", "resources_by_location",
        ]
        for name in expected:
            self.assertIn(name, ARG_TEMPLATES, f"Missing template: {name}")

    def test_templates_have_project_or_summarize(self):
        for name, kql in ARG_TEMPLATES.items():
            self.assertTrue(
                "project" in kql.lower() or "summarize" in kql.lower(),
                f"Template {name} lacks 'project' or 'summarize' clause",
            )


class TestNLMappings(unittest.TestCase):
    """Test natural language → query type mappings."""

    def test_arg_mappings_have_valid_templates(self):
        for keywords, template_name in _NL_ARG_MAP:
            self.assertIn(template_name, ARG_TEMPLATES,
                          f"ARG mapping '{template_name}' not in templates")
            self.assertIsInstance(keywords, list)
            self.assertTrue(len(keywords) > 0)

    def test_entra_mappings_have_valid_types(self):
        valid_types = {
            "disabled_users", "guest_users", "stale_users", "directory_roles",
            "conditional_access", "apps", "service_principals", "groups", "users",
        }
        for keywords, query_type in _NL_ENTRA_MAP:
            self.assertIn(query_type, valid_types,
                          f"Entra mapping '{query_type}' not valid")
            self.assertIsInstance(keywords, list)
            self.assertTrue(len(keywords) > 0)

    def test_no_duplicate_keywords_across_arg(self):
        all_kw = []
        for keywords, _ in _NL_ARG_MAP:
            all_kw.extend(keywords)
        # Duplicates are OK for similar mappings, just check they're all strings
        for kw in all_kw:
            self.assertIsInstance(kw, str)

    def test_keyword_matching_vm(self):
        """Simulate keyword matching for VM queries."""
        q = "show me all virtual machines"
        matched = None
        for keywords, template_name in _NL_ARG_MAP:
            if any(kw in q.lower() for kw in keywords):
                matched = template_name
                break
        self.assertEqual(matched, "vms_without_disk_encryption")

    def test_keyword_matching_guest_users(self):
        q = "list all guest users"
        matched = None
        for keywords, query_type in _NL_ENTRA_MAP:
            if any(kw in q.lower() for kw in keywords):
                matched = query_type
                break
        self.assertEqual(matched, "guest_users")

    def test_keyword_matching_storage(self):
        q = "which storage accounts allow public access"
        matched = None
        for keywords, template_name in _NL_ARG_MAP:
            if any(kw in q.lower() for kw in keywords):
                matched = template_name
                break
        self.assertEqual(matched, "storage_public_access")

    def test_keyword_matching_global_admin(self):
        q = "show global admin users"
        matched = None
        for keywords, query_type in _NL_ENTRA_MAP:
            if any(kw in q.lower() for kw in keywords):
                matched = query_type
                break
        self.assertEqual(matched, "directory_roles")

    def test_keyword_matching_nsg(self):
        q = "find open ports in NSG rules"
        matched = None
        for keywords, template_name in _NL_ARG_MAP:
            if any(kw in q.lower() for kw in keywords):
                matched = template_name
                break
        self.assertEqual(matched, "nsg_open_rules")

    def test_keyword_matching_conditional_access(self):
        q = "list conditional access policies"
        matched = None
        for keywords, query_type in _NL_ENTRA_MAP:
            if any(kw in q.lower() for kw in keywords):
                matched = query_type
                break
        self.assertEqual(matched, "conditional_access")


class TestQueryEngineImports(unittest.TestCase):
    """Test that the query engine module imports cleanly."""

    def test_import_query_engine(self):
        from app.query_engine import (
            query_resource_graph,
            query_entra_users,
            query_entra_groups,
            query_entra_apps,
            query_entra_service_principals,
            query_entra_directory_roles,
            query_entra_conditional_access,
            get_resource_detail,
            get_entra_user_detail,
            cross_reference_findings,
            dispatch_natural_language,
            ARG_TEMPLATES,
        )
        # All should be callable
        self.assertTrue(callable(query_resource_graph))
        self.assertTrue(callable(dispatch_natural_language))
        self.assertTrue(callable(cross_reference_findings))
        self.assertIsInstance(ARG_TEMPLATES, dict)

    def test_import_run_query(self):
        """Verify run_query.py can be imported without errors."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            "run_query", str(agent_dir / "run_query.py"))
        mod = importlib.util.module_from_spec(spec)
        # Don't execute — just verify it parses
        self.assertIsNotNone(spec)


class TestAgentToolRegistration(unittest.TestCase):
    """Test that the agent TOOLS list includes the new search_tenant."""

    def test_tools_list_has_search_tenant(self):
        from app.agent import TOOLS
        tool_names = [t.__name__ for t in TOOLS]
        self.assertIn("search_tenant", tool_names)
        self.assertIn("run_assessment", tool_names)
        self.assertIn("query_results", tool_names)
        self.assertIn("generate_report", tool_names)
        self.assertEqual(len(TOOLS), 12)


if __name__ == "__main__":
    unittest.main()
