"""Tests for the new report generators and data exports."""
import json
import os
import tempfile
import pytest

from app.reports.inventory import extract_inventory, get_environment_summary
from app.reports.compliance_report_html import generate_compliance_report_html
from app.reports.compliance_report_md import generate_compliance_report_md
from app.reports.executive_summary import generate_executive_summary_html, generate_executive_summary_md
from app.reports.gaps_report import generate_gaps_report_html, generate_gaps_report_md
from app.reports.data_exports import export_data_files, save_raw_evidence


# ── Shared fixtures ──────────────────────────────────────────────────────

def _sample_evidence() -> list[dict]:
    return [
        {"EvidenceType": "azure-subscription", "Source": "Azure",
         "Data": {"SubscriptionId": "sub-001", "SubscriptionName": "Prod", "State": "Enabled"}},
        {"EvidenceType": "azure-resource-group", "Source": "Azure",
         "Data": {"ResourceGroup": "rg-prod", "SubscriptionName": "Prod", "Location": "eastus"}},
        {"EvidenceType": "azure-resource", "Source": "Azure",
         "Data": {"ResourceType": "Microsoft.Storage/storageAccounts", "Name": "st1",
                  "ResourceGroup": "rg-prod", "SubscriptionName": "Prod"}},
        {"EvidenceType": "azure-resource", "Source": "Azure",
         "Data": {"ResourceType": "Microsoft.Compute/virtualMachines", "Name": "vm1",
                  "ResourceGroup": "rg-prod", "SubscriptionName": "Prod"}},
        {"EvidenceType": "azure-role-assignment", "Source": "Azure",
         "Data": {"RoleName": "Owner", "PrincipalName": "admin@contoso.com",
                  "PrincipalType": "User", "Scope": "/subscriptions/sub-001"}},
        {"EvidenceType": "azure-policy-assignment", "Source": "Azure",
         "Data": {"DisplayName": "Require Tags", "Scope": "/subscriptions/sub-001",
                  "EnforcementMode": "Default"}},
        {"EvidenceType": "entra-tenant", "Source": "Entra",
         "Data": {"TenantId": "t-001", "DisplayName": "Contoso"}},
        {"EvidenceType": "entra-directory-role", "Source": "Entra",
         "Data": {"DisplayName": "Global Administrator", "IsBuiltIn": True,
                  "Description": "Full admin role"}},
        {"EvidenceType": "entra-conditional-access-policy", "Source": "Entra",
         "Data": {"DisplayName": "Require MFA", "State": "enabled",
                  "GrantControls": {"BuiltInControls": ["mfa"]}}},
        {"EvidenceType": "entra-user-summary", "Source": "Entra",
         "Data": {"TotalUsers": 100, "GuestUsers": 10, "MemberUsers": 90,
                  "EnabledUsers": 85, "DisabledUsers": 15}},
        {"EvidenceType": "entra-mfa-summary", "Source": "Entra",
         "Data": {"MfaRegistered": 70, "TotalUsers": 100}},
    ]


def _sample_results() -> dict:
    return {
        "summary": {
            "ComplianceScore": 45.0,
            "TotalControls": 20,
            "Compliant": 9,
            "NonCompliant": 7,
            "Partial": 2,
            "MissingEvidence": 2,
            "TotalEvidence": 11,
            "CriticalFindings": 2,
            "HighFindings": 3,
            "MediumFindings": 2,
            "Frameworks": ["FedRAMP"],
            "DomainScores": {
                "access": {"Score": 50, "Compliant": 2, "Total": 4},
                "identity": {"Score": 30, "Compliant": 1, "Total": 3},
            },
        },
        "control_results": [
            {"ControlId": "AC-1", "ControlTitle": "Access Control Policy",
             "Framework": "FedRAMP", "Domain": "access", "Severity": "high",
             "Status": "non_compliant", "FindingCount": 1},
            {"ControlId": "AC-2", "ControlTitle": "Account Mgmt",
             "Framework": "FedRAMP", "Domain": "access", "Severity": "medium",
             "Status": "compliant", "FindingCount": 0},
        ],
        "findings": [
            {"ControlId": "AC-1", "ControlTitle": "Access Control Policy",
             "Framework": "FedRAMP", "Domain": "access", "Severity": "high",
             "Status": "non_compliant",
             "Description": "No access control policy documented.",
             "Recommendation": "Define and implement an access control policy."},
            {"ControlId": "IA-2", "ControlTitle": "MFA Enforcement",
             "Framework": "FedRAMP", "Domain": "identity", "Severity": "critical",
             "Status": "non_compliant",
             "Description": "MFA not enforced for all users.",
             "Recommendation": "Enable MFA via Conditional Access."},
        ],
        "missing_evidence": [
            {"ControlId": "AU-6", "Severity": "medium", "MissingTypes": ["azure-log-analytics"]},
        ],
    }


def _tenant_info():
    return {"TenantId": "t-001", "DisplayName": "Contoso Test"}


# ── Inventory tests ──────────────────────────────────────────────────────

class TestInventory:
    def test_extract_inventory_subs(self):
        inv = extract_inventory(_sample_evidence())
        assert len(inv["subscriptions"]) == 1
        assert inv["subscriptions"][0]["SubscriptionId"] == "sub-001"

    def test_extract_inventory_resources(self):
        inv = extract_inventory(_sample_evidence())
        assert len(inv["resources"]) == 2
        assert "Microsoft.Storage/storageAccounts" in inv["resource_type_counts"]
        assert "Microsoft.Compute/virtualMachines" in inv["resource_type_counts"]

    def test_extract_inventory_rbac(self):
        inv = extract_inventory(_sample_evidence())
        assert len(inv["rbac_assignments"]) == 1
        # Owner → privileged
        assert len(inv["privileged_assignments"]) == 1
        assert len(inv["owner_assignments"]) == 1

    def test_extract_inventory_entra(self):
        inv = extract_inventory(_sample_evidence())
        assert inv["entra_tenant"]["TenantId"] == "t-001"
        assert len(inv["entra_roles"]) == 1
        assert len(inv["entra_ca_policies"]) == 1

    def test_get_environment_summary(self):
        inv = extract_inventory(_sample_evidence())
        env = get_environment_summary(inv)
        assert env["Azure Subscriptions"] == 1
        assert env["Azure Resources"] == 2
        assert env["Azure Role Assignments"] == 1

    def test_empty_evidence(self):
        inv = extract_inventory([])
        env = get_environment_summary(inv)
        assert env["Azure Subscriptions"] == 0
        assert inv["resources"] == []


# ── Compliance Report HTML tests ─────────────────────────────────────────

class TestComplianceReportHtml:
    def test_generates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_compliance_report_html(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            assert os.path.isfile(path)
            assert path.endswith("compliance-report.html")

    def test_contains_key_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_compliance_report_html(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            html = open(path, encoding="utf-8").read()
            assert "Document Control" in html
            assert "Executive Summary" in html
            assert "Azure Resource Inventory" in html
            assert "Entra ID" in html
            assert "Compliance Results" in html
            assert "Findings" in html
            assert "Remediation Plan" in html
            assert "Evidence Gaps" in html

    def test_contains_resource_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_compliance_report_html(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            html = open(path, encoding="utf-8").read()
            assert "sub-001" in html
            assert "rg-prod" in html
            assert "Owner" in html
            assert "Require MFA" in html


# ── Compliance Report MD tests ───────────────────────────────────────────

class TestComplianceReportMd:
    def test_generates_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_compliance_report_md(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            assert os.path.isfile(path)
            assert path.endswith("compliance-report.md")

    def test_contains_key_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_compliance_report_md(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            md = open(path, encoding="utf-8").read()
            assert "Document Control" in md
            assert "Executive Summary" in md
            assert "Azure Resource Inventory" in md
            assert "Entra ID" in md
            assert "Control Results" in md
            assert "Detailed Findings" in md


# ── Executive Summary tests ──────────────────────────────────────────────

class TestExecutiveSummary:
    def test_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_executive_summary_html(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            assert os.path.isfile(path)
            html = open(path, encoding="utf-8").read()
            assert "Executive Summary" in html
            assert "Top 10 Risks" in html

    def test_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_executive_summary_md(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            assert os.path.isfile(path)
            md = open(path, encoding="utf-8").read()
            assert "Executive Summary" in md
            assert "Top 10 Risks" in md
            assert "45.0%" in md


# ── Gaps Report tests ────────────────────────────────────────────────────

class TestGapsReport:
    def test_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_gaps_report_html(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            assert os.path.isfile(path)
            html = open(path, encoding="utf-8").read()
            assert "Gaps" in html
            assert "AC-1" in html

    def test_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = generate_gaps_report_md(
                _sample_results(), _sample_evidence(), _tenant_info(), tmp)
            assert os.path.isfile(path)
            md = open(path, encoding="utf-8").read()
            assert "Gaps" in md
            assert "IA-2" in md


# ── Data Export tests ────────────────────────────────────────────────────

class TestDataExports:
    def test_creates_compliance_data_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = export_data_files(_sample_results(), _sample_evidence(), tmp)
            json_count = sum(1 for p in paths if p.endswith(".json"))
            assert json_count >= 1
            assert any("compliance-data.json" in p for p in paths)

    def test_raw_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw_dir = save_raw_evidence(_sample_evidence(), tmp)
            raw_files = os.listdir(raw_dir)
            # Expect files grouped by evidence type
            assert any("azure-subscription" in f for f in raw_files)
            assert any("entra-tenant" in f for f in raw_files)


# ── Runner framework selection test ──────────────────────────────────────

class TestRunnerFrameworkSelection:
    def test_available_frameworks_imported(self):
        from app.evaluators.engine import AVAILABLE_FRAMEWORKS
        assert "FedRAMP" in AVAILABLE_FRAMEWORKS
        assert "CIS" in AVAILABLE_FRAMEWORKS
        assert len(AVAILABLE_FRAMEWORKS) >= 6
