"""
Tests for M365 Copilot Readiness Assessment Engine.

Covers:
  - Oversharing risk analysis (4 sub-checks)
  - Label coverage analysis (4 sub-checks)
  - DLP readiness analysis (3 sub-checks)
  - Restricted SharePoint Search analysis (1 sub-check)
  - Access governance analysis (2 sub-checks)
  - Content lifecycle analysis (2 sub-checks)
  - Audit & monitoring analysis (2 sub-checks)
  - Scoring algorithm
  - Finding structure
  - Agent tool registration
  - CLI parsability
  - Module imports
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ====================================================================
# Helpers — build evidence records matching collector shapes
# ====================================================================

def _spo_site_ev(data: dict) -> dict:
    return {"EvidenceType": "spo-site-inventory", "Data": data, "ResourceId": data.get("id", "")}

def _spo_perms_ev(data: dict) -> dict:
    return {"EvidenceType": "spo-site-permissions", "Data": data, "ResourceId": data.get("SiteId", "")}

def _spo_sharing_ev(data: dict) -> dict:
    return {"EvidenceType": "spo-sharing-links", "Data": data, "ResourceId": data.get("SiteId", "")}

def _spo_tenant_ev(data: dict) -> dict:
    return {"EvidenceType": "spo-tenant-sharing-config", "Data": data, "ResourceId": "tenant"}

def _spo_label_ev(data: dict) -> dict:
    return {"EvidenceType": "spo-label-summary", "Data": data, "ResourceId": "tenant"}

def _label_summary_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-label-summary", "Data": data, "ResourceId": "tenant"}

def _label_policy_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-label-policy-summary", "Data": data, "ResourceId": "tenant"}

def _dlp_label_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-dlp-label-integration", "Data": data, "ResourceId": "tenant"}

def _dlp_policy_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-dlp-policies", "Data": data, "ResourceId": "tenant"}

def _copilot_settings_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-copilot-settings", "Data": data, "ResourceId": "tenant"}

def _audit_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-audit-config", "Data": data, "ResourceId": "tenant"}

def _ca_policy_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-conditional-access-policy", "Data": data, "ResourceId": data.get("id", "")}

def _label_warning_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-label-collection-warning", "Data": data, "ResourceId": "m365-label-api-warning"}

def _subscribed_sku_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-subscribed-skus", "Data": data, "ResourceId": data.get("SkuId", "")}

def _access_review_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-access-review-definitions", "Data": data, "ResourceId": data.get("ReviewId", "")}

def _copilot_settings_warning_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-copilot-settings-warning", "Data": data, "ResourceId": "m365-copilot-settings-warning"}

def _spo_scope_warning_ev(data: dict) -> dict:
    return {"EvidenceType": "spo-scope-warning", "Data": data, "ResourceId": "spo-scope-warning"}

def _build_index(records: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for r in records:
        etype = r.get("EvidenceType", "")
        idx.setdefault(etype, []).append(r)
    return idx


# ====================================================================
# 1. Oversharing Risk
# ====================================================================

class TestOversharing(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_oversharing_risk
        self.analyze = analyze_oversharing_risk

    def test_no_evidence_returns_unable_to_assess(self):
        findings = self.analyze({})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "unable_to_assess")

    def test_broad_site_membership_detected(self):
        """TotalPermissions > 100 triggers broad_site_membership."""
        idx = _build_index([_spo_perms_ev({
            "SiteId": "site-1", "SiteName": "Wide Open",
            "TotalPermissions": 150,
        })])
        findings = self.analyze(idx)
        broad = [f for f in findings if f["Subcategory"] == "broad_site_membership"]
        self.assertGreater(len(broad), 0)

    def test_everyone_permissions_detected(self):
        """MemberCount > 200 triggers everyone_permissions heuristic."""
        idx = _build_index([_spo_perms_ev({
            "SiteId": "site-2", "SiteName": "Public Docs",
            "MemberCount": 300, "TotalPermissions": 10,
        })])
        findings = self.analyze(idx)
        everyone = [f for f in findings if f["Subcategory"] == "everyone_permissions"]
        self.assertGreater(len(everyone), 0)

    def test_anonymous_link_exposure_detected(self):
        """AnonymousLinks > 0 triggers anonymous_link_exposure."""
        idx = _build_index([
            _spo_site_ev({"SiteId": "site-3", "SiteName": "Marketing"}),
            _spo_sharing_ev({
                "SiteId": "site-3", "SiteName": "Marketing",
                "AnonymousLinks": 5,
            }),
        ])
        findings = self.analyze(idx)
        anon = [f for f in findings if f["Subcategory"] == "anonymous_link_exposure"]
        self.assertGreater(len(anon), 0)

    def test_external_sharing_open_detected(self):
        """IsAnonymousSharingEnabled triggers external_sharing_posture."""
        idx = _build_index([
            _spo_site_ev({"SiteId": "site-x", "SiteName": "Any Site"}),
            _spo_tenant_ev({
                "IsAnonymousSharingEnabled": True,
                "SharingCapability": "ExternalUserAndGuestSharing",
            }),
        ])
        findings = self.analyze(idx)
        ext = [f for f in findings if f["Subcategory"] == "external_sharing_posture"]
        self.assertGreater(len(ext), 0)

    def test_no_anonymous_links_no_finding(self):
        idx = _build_index([
            _spo_site_ev({"SiteId": "site-4", "SiteName": "Clean Site"}),
            _spo_sharing_ev({
                "SiteId": "site-4", "SiteName": "Clean Site",
                "AnonymousLinks": 0,
            }),
        ])
        findings = self.analyze(idx)
        anon = [f for f in findings if f["Subcategory"] == "anonymous_link_exposure"]
        self.assertEqual(len(anon), 0)

    def test_partial_site_discovery_from_scope_warning(self):
        """When spo-scope-warning present + sites exist, partial_site_discovery fires."""
        idx = _build_index([
            _spo_site_ev({"SiteId": "root-site", "SiteName": "Root", "DiscoveryMethod": "fallback"}),
            _spo_scope_warning_ev({
                "Warning": "SitesReadAllScopeMissing",
                "DiscoveryMethod": "fallback",
                "SitesDiscovered": 3,
            }),
        ])
        findings = self.analyze(idx)
        partial = [f for f in findings if f["Subcategory"] == "partial_site_discovery"]
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0]["Severity"], "medium")
        self.assertIn("Sites.Read.All", partial[0]["Title"])

    def test_full_discovery_no_partial_warning(self):
        """When sites discovered via search, no partial_site_discovery finding."""
        idx = _build_index([
            _spo_site_ev({"SiteId": "site-1", "SiteName": "Site 1", "DiscoveryMethod": "search"}),
            _spo_site_ev({"SiteId": "site-2", "SiteName": "Site 2", "DiscoveryMethod": "search"}),
        ])
        findings = self.analyze(idx)
        partial = [f for f in findings if f["Subcategory"] == "partial_site_discovery"]
        self.assertEqual(len(partial), 0)


# ====================================================================
# 2. Label Coverage
# ====================================================================

class TestLabelCoverage(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_label_coverage
        self.analyze = analyze_label_coverage

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_label_api_inaccessible_guard(self):
        """m365-label-collection-warning triggers unable-to-assess instead of false findings."""
        idx = _build_index([_label_warning_ev({
            "Warning": "LabelAPIInaccessible",
            "Impact": "Cannot determine whether sensitivity labels are defined.",
            "Recommendation": "Assign Information Protection Reader role.",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "label_api_inaccessible")
        self.assertEqual(findings[0]["Severity"], "high")

    def test_label_warning_overrides_real_labels(self):
        """Even with label summary present, the warning takes priority."""
        idx = _build_index([
            _label_warning_ev({"Warning": "LabelAPIInaccessible", "Impact": "n/a", "Recommendation": ""}),
            _label_summary_ev({"TotalLabels": 5, "ActiveLabels": 5}),
        ])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "label_api_inaccessible")

    def test_no_labels_defined_detected(self):
        """TotalLabels == 0 triggers no_labels_defined or similar."""
        idx = _build_index([_label_summary_ev({
            "TotalLabels": 0, "ActiveLabels": 0,
        })])
        findings = self.analyze(idx)
        label_findings = [f for f in findings if "label" in f["Subcategory"].lower()]
        self.assertGreater(len(label_findings), 0)

    def test_mandatory_labeling_disabled_detected(self):
        """HasMandatoryLabeling == False triggers finding."""
        idx = _build_index([_label_policy_ev({
            "TotalPolicies": 1, "HasMandatoryLabeling": False,
            "HasAutoLabeling": True,
        })])
        findings = self.analyze(idx)
        mandatory = [f for f in findings if "mandatory" in f["Subcategory"].lower()]
        self.assertGreater(len(mandatory), 0)

    def test_auto_labeling_absent_detected(self):
        """HasAutoLabeling == False triggers finding."""
        idx = _build_index([_label_policy_ev({
            "TotalPolicies": 1, "HasMandatoryLabeling": True,
            "HasAutoLabeling": False,
        })])
        findings = self.analyze(idx)
        auto = [f for f in findings if "auto" in f["Subcategory"].lower()]
        self.assertGreater(len(auto), 0)

    def test_low_site_label_coverage_detected(self):
        """LabelCoverage < 80 with UnlabeledSites > 0 triggers finding."""
        idx = _build_index([_spo_label_ev({
            "LabelCoverage": 30.0, "UnlabeledSites": 70,
        })])
        findings = self.analyze(idx)
        coverage = [f for f in findings if "label_coverage" in f["Subcategory"].lower()
                     or "site_label" in f["Subcategory"].lower()]
        self.assertGreater(len(coverage), 0)

    def test_good_label_coverage_no_finding(self):
        idx = _build_index([_spo_label_ev({
            "LabelCoverage": 90.0, "UnlabeledSites": 0,
        })])
        findings = self.analyze(idx)
        coverage = [f for f in findings if "label_coverage" in f["Subcategory"].lower()
                     or "site_label" in f["Subcategory"].lower()]
        self.assertEqual(len(coverage), 0)

    def test_labels_defined_no_finding(self):
        idx = _build_index([_label_summary_ev({
            "TotalLabels": 5, "ActiveLabels": 5,
        })])
        findings = self.analyze(idx)
        no_labels = [f for f in findings if "no_labels" in f.get("Subcategory", "")]
        self.assertEqual(len(no_labels), 0)


# ====================================================================
# 3. DLP Readiness
# ====================================================================

class TestDLPReadiness(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_dlp_readiness
        self.analyze = analyze_dlp_readiness

    def test_no_evidence_no_dlp_detected(self):
        """Empty evidence triggers no_dlp_policies finding."""
        findings = self.analyze({})
        no_dlp = [f for f in findings if "dlp" in f.get("Subcategory", "").lower()
                   or "dlp" in f.get("Title", "").lower()]
        self.assertGreater(len(no_dlp), 0)

    def test_dlp_no_label_integration_detected(self):
        """HasLabelBasedDLP == False triggers finding."""
        idx = _build_index([_dlp_label_ev({
            "HasLabelBasedDLP": False,
        })])
        findings = self.analyze(idx)
        label_int = [f for f in findings if "label" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(label_int), 0)

    def test_dlp_missing_workloads_detected(self):
        """DLP policies missing Exchange/Teams/SharePoint triggers finding."""
        idx = _build_index([_dlp_policy_ev({
            "Workloads": ["Exchange"],
        })])
        findings = self.analyze(idx)
        workload = [f for f in findings if "workload" in f.get("Subcategory", "").lower()
                     or "coverage" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(workload), 0)


# ====================================================================
# 4. Restricted SharePoint Search
# ====================================================================

class TestRestrictedSearch(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_restricted_search
        self.analyze = analyze_restricted_search

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_large_tenant_rss_not_configured_detected(self):
        """Tenant with >100 sites triggers RSS recommendation."""
        sites = [_spo_site_ev({
            "id": f"site-{i}", "SiteName": f"Site {i}", "IsStale": False,
        }) for i in range(110)]
        idx = _build_index(sites)
        findings = self.analyze(idx)
        rss = [f for f in findings if "rss" in f.get("Subcategory", "").lower()
                or "restricted" in f.get("Title", "").lower()]
        self.assertGreater(len(rss), 0)


# ====================================================================
# 5. Access Governance
# ====================================================================

class TestAccessGovernance(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_no_evidence_returns_ca_guard(self):
        """No CA policies -> ca_unable_to_assess guard fires."""
        findings = self.analyze({})
        ca_guard = [f for f in findings if f["Subcategory"] == "ca_unable_to_assess"]
        self.assertGreater(len(ca_guard), 0)
        self.assertEqual(ca_guard[0]["Severity"], "high")

    def test_no_copilot_in_ca_detected(self):
        """CA policies exist but don't cover Copilot."""
        idx = _build_index([_ca_policy_ev({
            "id": "ca-1", "displayName": "Block risky sign-ins",
            "IncludedApplications": ["Office365"],
        })])
        findings = self.analyze(idx)
        ca = [f for f in findings if "ca" in f.get("Subcategory", "").lower()
               or "conditional" in f.get("Title", "").lower()]
        self.assertGreater(len(ca), 0)

    def test_no_copilot_settings_detected(self):
        """Missing m365-copilot-settings triggers informational."""
        # Need at least one CA policy so the CA guard doesn't fire instead
        idx = _build_index([_ca_policy_ev({
            "id": "ca-x", "displayName": "Test Policy",
            "IncludedApplications": ["All"],
        })])
        findings = self.analyze(idx)
        deploy = [f for f in findings if "deployment" in f.get("Subcategory", "").lower()
                    or "copilot" in f.get("Title", "").lower()]
        self.assertGreater(len(deploy), 0)

    def test_copilot_settings_scope_denied_detected(self):
        """403 warning evidence triggers scope_denied finding with explanation."""
        idx = _build_index([
            _ca_policy_ev({"id": "ca-x", "displayName": "CA", "IncludedApplications": ["All"]}),
            _copilot_settings_warning_ev({
                "Error": "403 Forbidden",
                "RequiredScope": "OrgSettings.Read.All",
                "Reason": "Test reason",
                "Workaround": "Use a custom app registration.",
            }),
        ])
        findings = self.analyze(idx)
        scope = [f for f in findings if f["Subcategory"] == "copilot_deployment_scope_denied"]
        self.assertEqual(len(scope), 1)
        self.assertIn("OrgSettings.Read.All", scope[0]["Title"])
        self.assertEqual(scope[0]["Severity"], "informational")

    def test_copilot_settings_present_no_finding(self):
        """When m365-copilot-settings exists, no deployment finding."""
        idx = _build_index([
            _ca_policy_ev({"id": "ca-x", "displayName": "CA", "IncludedApplications": ["All"]}),
            _copilot_settings_ev({"UpdateChannel": "Current"}),
        ])
        findings = self.analyze(idx)
        deploy = [f for f in findings if "deployment" in f.get("Subcategory", "").lower()
                    or "scope_denied" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(deploy), 0)

    def test_no_copilot_license_detected(self):
        """Subscribed SKUs exist but no Copilot SKU triggers finding."""
        idx = _build_index([
            _ca_policy_ev({"id": "ca-1", "displayName": "CA", "IncludedApplications": ["All"]}),
            _copilot_settings_ev({"UpdateChannel": "Current"}),
            _subscribed_sku_ev({"SkuId": "sku-1", "SkuPartNumber": "ENTERPRISEPACK", "DisplayName": "Office 365 E3"}),
        ])
        findings = self.analyze(idx)
        lic = [f for f in findings if f["Subcategory"] == "no_copilot_license"]
        self.assertGreater(len(lic), 0)

    def test_copilot_license_present_no_finding(self):
        """Copilot SKU present means no license finding."""
        idx = _build_index([
            _ca_policy_ev({"id": "ca-1", "displayName": "CA", "IncludedApplications": ["All"]}),
            _copilot_settings_ev({"UpdateChannel": "Current"}),
            _subscribed_sku_ev({"SkuId": "sku-c", "SkuPartNumber": "Microsoft_365_Copilot", "DisplayName": "Microsoft 365 Copilot"}),
        ])
        findings = self.analyze(idx)
        lic = [f for f in findings if f["Subcategory"] == "no_copilot_license"]
        self.assertEqual(len(lic), 0)

    def test_no_access_reviews_detected(self):
        """No access review definitions triggers finding."""
        idx = _build_index([
            _ca_policy_ev({"id": "ca-1", "displayName": "CA", "IncludedApplications": ["All"]}),
        ])
        findings = self.analyze(idx)
        reviews = [f for f in findings if f["Subcategory"] == "no_access_reviews"]
        self.assertGreater(len(reviews), 0)

    def test_access_reviews_present_no_finding(self):
        """Access review definitions present means no finding."""
        idx = _build_index([
            _ca_policy_ev({"id": "ca-1", "displayName": "CA", "IncludedApplications": ["All"]}),
            _access_review_ev({"ReviewId": "rev-1", "DisplayName": "Quarterly Review", "Status": "InProgress"}),
        ])
        findings = self.analyze(idx)
        reviews = [f for f in findings if f["Subcategory"] == "no_access_reviews"]
        self.assertEqual(len(reviews), 0)


# ====================================================================
# 6. Content Lifecycle
# ====================================================================

class TestContentLifecycle(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_content_lifecycle
        self.analyze = analyze_content_lifecycle

    def test_no_evidence_produces_findings(self):
        """No evidence triggers retention_assessment_needed (informational)."""
        findings = self.analyze({})
        self.assertIsInstance(findings, list)

    def test_stale_content_detected(self):
        """IsStale == True triggers stale_content_exposure."""
        idx = _build_index([_spo_site_ev({
            "id": "site-old", "SiteName": "Stale Docs", "SiteId": "site-old",
            "IsStale": True,
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if "stale" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(stale), 0)

    def test_fresh_content_no_stale_finding(self):
        idx = _build_index([_spo_site_ev({
            "id": "site-new", "SiteName": "Fresh Docs", "SiteId": "site-new",
            "IsStale": False,
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if "stale" in f.get("Subcategory", "").lower()]
        self.assertEqual(len(stale), 0)


# ====================================================================
# 7. Audit & Monitoring
# ====================================================================

class TestAuditMonitoring(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_audit_monitoring
        self.analyze = analyze_audit_monitoring

    def test_no_evidence_triggers_audit_finding(self):
        """No m365-audit-config evidence triggers audit_logging_unknown."""
        findings = self.analyze({})
        self.assertGreater(len(findings), 0)

    def test_audit_logging_present_still_has_informational(self):
        """Audit evidence present, still gets copilot_interaction_audit (informational)."""
        idx = _build_index([_audit_ev({
            "UnifiedAuditLogEnabled": True,
        })])
        findings = self.analyze(idx)
        # Should always have the informational copilot_interaction_audit
        interaction = [f for f in findings if "copilot" in f.get("Subcategory", "").lower()
                        or "interaction" in f.get("Subcategory", "").lower()]
        self.assertGreater(len(interaction), 0)


# ====================================================================
# 8. Scoring
# ====================================================================

class TestCopilotReadinessScoring(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import compute_copilot_readiness_scores
        self.score = compute_copilot_readiness_scores

    def test_no_findings_returns_ready(self):
        scores = self.score([])
        self.assertEqual(scores["OverallScore"], 100.0)
        self.assertEqual(scores["ReadinessStatus"], "READY")

    def test_findings_reduce_readiness(self):
        findings = [{
            "CopilotReadinessFindingId": "CR-001",
            "Category": "oversharing_risk",
            "Subcategory": "broad_site_membership",
            "Title": "Broad Site Membership",
            "Severity": "high",
            "ComplianceStatus": "gap",
            "AffectedCount": 5,
        }]
        scores = self.score(findings)
        self.assertGreater(scores["OverallScore"], 0)

    def test_severity_distribution(self):
        findings = [
            {"CopilotReadinessFindingId": "1", "Category": "oversharing_risk", "Severity": "critical", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "A", "Subcategory": "a"},
            {"CopilotReadinessFindingId": "2", "Category": "label_coverage", "Severity": "high", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "B", "Subcategory": "b"},
            {"CopilotReadinessFindingId": "3", "Category": "dlp_readiness", "Severity": "medium", "ComplianceStatus": "partial", "AffectedCount": 1, "Title": "C", "Subcategory": "c"},
            {"CopilotReadinessFindingId": "4", "Category": "restricted_search", "Severity": "low", "ComplianceStatus": "compliant", "AffectedCount": 1, "Title": "D", "Subcategory": "d"},
        ]
        scores = self.score(findings)
        dist = scores["SeverityDistribution"]
        self.assertEqual(dist["critical"], 1)
        self.assertEqual(dist["high"], 1)
        self.assertEqual(dist["medium"], 1)
        self.assertEqual(dist["low"], 1)

    def test_readiness_status_not_ready_on_critical(self):
        findings = [
            {"CopilotReadinessFindingId": "1", "Category": "oversharing_risk", "Severity": "critical", "ComplianceStatus": "gap", "AffectedCount": 3, "Title": "A", "Subcategory": "a"},
        ]
        scores = self.score(findings)
        self.assertEqual(scores["ReadinessStatus"], "NOT READY")

    def test_compliance_breakdown(self):
        findings = [
            {"CopilotReadinessFindingId": "1", "Category": "oversharing_risk", "Severity": "high", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "A", "Subcategory": "a"},
            {"CopilotReadinessFindingId": "2", "Category": "label_coverage", "Severity": "medium", "ComplianceStatus": "partial", "AffectedCount": 1, "Title": "B", "Subcategory": "b"},
            {"CopilotReadinessFindingId": "3", "Category": "dlp_readiness", "Severity": "low", "ComplianceStatus": "compliant", "AffectedCount": 1, "Title": "C", "Subcategory": "c"},
        ]
        scores = self.score(findings)
        breakdown = scores.get("ComplianceBreakdown", {})
        self.assertEqual(breakdown.get("gap", 0), 1)
        self.assertEqual(breakdown.get("partial", 0), 1)
        self.assertEqual(breakdown.get("compliant", 0), 1)

    def test_category_scores_present(self):
        findings = [
            {"CopilotReadinessFindingId": "1", "Category": "oversharing_risk", "Severity": "high", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "A", "Subcategory": "a"},
            {"CopilotReadinessFindingId": "2", "Category": "dlp_readiness", "Severity": "medium", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "B", "Subcategory": "b"},
        ]
        scores = self.score(findings)
        cats = scores["CategoryScores"]
        self.assertIn("oversharing_risk", cats)
        self.assertIn("dlp_readiness", cats)


# ====================================================================
# 9. Finding Structure
# ====================================================================

class TestCRFindingStructure(unittest.TestCase):
    def test_finding_has_required_fields(self):
        from app.copilot_readiness_engine import analyze_oversharing_risk
        idx = _build_index([_spo_perms_ev({
            "SiteId": "site-1", "SiteName": "Wide Open",
            "TotalPermissions": 150,
        })])
        findings = analyze_oversharing_risk(idx)
        self.assertGreater(len(findings), 0)
        f = findings[0]
        for key in ("CopilotReadinessFindingId", "Category", "Subcategory",
                     "Title", "Description", "Severity", "ComplianceStatus",
                     "AffectedResources", "AffectedCount", "Remediation", "DetectedAt"):
            self.assertIn(key, f, f"Missing key: {key}")
        self.assertIsInstance(f["AffectedResources"], list)
        self.assertIsInstance(f["Remediation"], dict)
        self.assertIn(f["ComplianceStatus"], ("compliant", "gap", "partial"))


# ====================================================================
# 10. Agent Tool Registration
# ====================================================================

class TestAgentCopilotReadinessTool(unittest.TestCase):
    def test_tools_list_has_assess_copilot_readiness(self):
        from app.agent import TOOLS
        names = [t.__name__ for t in TOOLS]
        self.assertIn("assess_copilot_readiness", names)

    def test_tools_list_has_expected_count(self):
        from app.agent import TOOLS
        self.assertEqual(len(TOOLS), 12)


# ====================================================================
# 11. Module Imports
# ====================================================================

class TestCopilotReadinessImports(unittest.TestCase):
    def test_import_engine(self):
        import app.copilot_readiness_engine
        self.assertTrue(hasattr(app.copilot_readiness_engine, "run_copilot_readiness_assessment"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "compute_copilot_readiness_scores"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "analyze_oversharing_risk"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "analyze_label_coverage"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "analyze_dlp_readiness"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "analyze_restricted_search"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "analyze_access_governance"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "analyze_content_lifecycle"))
        self.assertTrue(hasattr(app.copilot_readiness_engine, "analyze_audit_monitoring"))

    def test_import_report(self):
        import app.reports.copilot_readiness_report
        self.assertTrue(hasattr(app.reports.copilot_readiness_report, "generate_copilot_readiness_report"))

    def test_cli_parseable(self):
        import ast
        cli_path = os.path.join(os.path.dirname(__file__), "..", "run_copilot_readiness.py")
        with open(cli_path, "r", encoding="utf-8") as fh:
            ast.parse(fh.read())


# ====================================================================
# Inventory Builders
# ====================================================================

class TestInventoryBuilders(unittest.TestCase):

    def test_license_inventory_sorted_by_consumed(self):
        from app.copilot_readiness_engine import _build_license_inventory
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "EnabledUnits": 100, "ConsumedUnits": 50, "SkuId": "a"}),
            _subscribed_sku_ev({"SkuPartNumber": "MICROSOFT_365_COPILOT", "EnabledUnits": 20, "ConsumedUnits": 18, "SkuId": "b"}),
        ])
        inv = _build_license_inventory(idx)
        self.assertEqual(len(inv), 2)
        self.assertEqual(inv[0]["SkuPartNumber"], "SPE_E5")  # higher consumed first
        self.assertEqual(inv[1]["ConsumedUnits"], 18)

    def test_license_inventory_empty(self):
        from app.copilot_readiness_engine import _build_license_inventory
        self.assertEqual(_build_license_inventory({}), [])

    def test_label_inventory_sorted_by_priority(self):
        from app.copilot_readiness_engine import _build_label_inventory
        idx = {
            "m365-sensitivity-label-definition": [
                {"EvidenceType": "m365-sensitivity-label-definition", "Data": {"Name": "Public", "Priority": 0, "IsActive": True, "ParentId": "", "ContentType": "file", "Color": "#00FF00"}},
                {"EvidenceType": "m365-sensitivity-label-definition", "Data": {"Name": "Confidential", "Priority": 2, "IsActive": True, "ParentId": "", "ContentType": "file", "Color": "#FF0000"}},
                {"EvidenceType": "m365-sensitivity-label-definition", "Data": {"Name": "Internal", "Priority": 1, "IsActive": True, "ParentId": "", "ContentType": "file", "Color": ""}},
            ]
        }
        inv = _build_label_inventory(idx)
        self.assertEqual(len(inv), 3)
        self.assertEqual(inv[0]["Name"], "Public")
        self.assertEqual(inv[2]["Name"], "Confidential")

    def test_label_inventory_empty(self):
        from app.copilot_readiness_engine import _build_label_inventory
        self.assertEqual(_build_label_inventory({}), [])

    def test_ca_policy_inventory(self):
        from app.copilot_readiness_engine import _build_ca_policy_inventory
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "DisplayName": "Block legacy", "State": "disabled", "RequiresMFA": False, "RequiresCompliantDevice": False, "TargetsAllUsers": False, "BlocksLegacyAuth": True, "HasLocationCondition": False, "GrantControls": ["block"]}),
            _ca_policy_ev({"id": "p2", "DisplayName": "Require MFA", "State": "enabled", "RequiresMFA": True, "RequiresCompliantDevice": False, "TargetsAllUsers": True, "BlocksLegacyAuth": False, "HasLocationCondition": False, "GrantControls": ["mfa"]}),
        ])
        inv = _build_ca_policy_inventory(idx)
        self.assertEqual(len(inv), 2)
        self.assertEqual(inv[0]["DisplayName"], "Require MFA")  # enabled first
        self.assertTrue(inv[0]["RequiresMFA"])

    def test_groups_inventory(self):
        from app.copilot_readiness_engine import _build_groups_inventory
        idx = {
            "m365-groups": [
                {"EvidenceType": "m365-groups", "Data": {"GroupId": "g1", "DisplayName": "Sales Team", "IsTeam": True, "Visibility": "Private", "MailEnabled": True, "SecurityEnabled": False, "Mail": "sales@contoso.com", "CreatedDate": "2025-01-01"}},
                {"EvidenceType": "m365-groups", "Data": {"GroupId": "g2", "DisplayName": "Execs", "IsTeam": False, "Visibility": "Public", "MailEnabled": True, "SecurityEnabled": False, "Mail": "execs@contoso.com", "CreatedDate": "2024-06-01"}},
            ]
        }
        inv = _build_groups_inventory(idx)
        self.assertEqual(len(inv), 2)
        self.assertTrue(inv[0]["IsTeam"])  # Teams sorted first
        self.assertEqual(inv[1]["DisplayName"], "Execs")

    def test_groups_inventory_empty(self):
        from app.copilot_readiness_engine import _build_groups_inventory
        self.assertEqual(_build_groups_inventory({}), [])

    def test_dlp_inventory(self):
        from app.copilot_readiness_engine import _build_dlp_inventory
        idx = _build_index([
            _dlp_policy_ev({"name": "PII", "state": "enabled", "locations": [{"workload": "Exchange"}, {"workload": "SharePoint"}]}),
        ])
        inv = _build_dlp_inventory(idx)
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["PolicyName"], "PII")
        self.assertIn("Exchange", inv[0]["Workloads"])

    def test_dlp_inventory_empty(self):
        from app.copilot_readiness_engine import _build_dlp_inventory
        self.assertEqual(_build_dlp_inventory({}), [])

    def test_entra_apps_inventory(self):
        from app.copilot_readiness_engine import _build_entra_apps_inventory
        idx = {
            "entra-applications": [
                {"EvidenceType": "entra-applications", "Data": {
                    "AppId": "app-1", "DisplayName": "My App", "CreatedDate": "2025-01-01",
                    "SignInAudience": "AzureADMyOrg", "HasGraphAccess": True,
                    "DelegatedPermissions": 3, "ApplicationPermissions": 1,
                    "CertificateCount": 0, "SecretCount": 1,
                }},
                {"EvidenceType": "entra-applications", "Data": {
                    "AppId": "app-2", "DisplayName": "Another App", "CreatedDate": "2025-02-01",
                    "SignInAudience": "AzureADMultipleOrgs", "HasGraphAccess": False,
                    "DelegatedPermissions": 0, "ApplicationPermissions": 0,
                    "CertificateCount": 1, "SecretCount": 0,
                }},
            ]
        }
        inv = _build_entra_apps_inventory(idx)
        self.assertEqual(len(inv), 2)
        # Sorted by TotalPermissions desc — app-1 has 4, app-2 has 0
        self.assertEqual(inv[0]["DisplayName"], "My App")
        self.assertTrue(inv[0]["HasGraphAccess"])
        self.assertEqual(inv[1]["DisplayName"], "Another App")

    def test_entra_apps_inventory_empty(self):
        from app.copilot_readiness_engine import _build_entra_apps_inventory
        self.assertEqual(_build_entra_apps_inventory({}), [])

    def test_service_principal_inventory(self):
        from app.copilot_readiness_engine import _build_service_principal_inventory
        idx = {
            "entra-service-principals": [
                {"EvidenceType": "entra-service-principals", "Data": {
                    "SPId": "sp-1", "AppId": "app-1", "DisplayName": "Enterprise App",
                    "ServicePrincipalType": "Application", "AccountEnabled": True,
                    "IsEnterprise": True, "AppRoleAssignmentCount": 3,
                }},
                {"EvidenceType": "entra-service-principals", "Data": {
                    "SPId": "sp-2", "AppId": "app-2", "DisplayName": "Non-Enterprise",
                    "ServicePrincipalType": "Application", "AccountEnabled": False,
                    "IsEnterprise": False, "AppRoleAssignmentCount": 0,
                }},
            ]
        }
        inv = _build_service_principal_inventory(idx)
        self.assertEqual(len(inv), 2)
        # Enterprise sorted first
        self.assertTrue(inv[0]["IsEnterprise"])
        self.assertEqual(inv[0]["DisplayName"], "Enterprise App")

    def test_service_principal_inventory_empty(self):
        from app.copilot_readiness_engine import _build_service_principal_inventory
        self.assertEqual(_build_service_principal_inventory({}), [])


# ====================================================================
# MS Reference URLs & Effort Tags
# ====================================================================

class TestMSReferenceAndEffort(unittest.TestCase):

    def test_controls_have_ms_reference_url(self):
        from app.copilot_readiness_engine import build_security_controls_matrix, analyze_oversharing_risk
        idx = _build_index([_spo_perms_ev({
            "SiteId": "site-1", "SiteName": "Test",
            "TotalPermissions": 10,
        })])
        findings = analyze_oversharing_risk(idx)
        controls = build_security_controls_matrix(findings)
        # All controls should have MicrosoftReferenceUrl key
        for c in controls:
            self.assertIn("MicrosoftReferenceUrl", c)
        # At least some should have a non-empty URL
        urls = [c["MicrosoftReferenceUrl"] for c in controls if c["MicrosoftReferenceUrl"]]
        self.assertGreater(len(urls), 0, "Expected at least one control with an MS Reference URL")

    def test_findings_have_effort_tag(self):
        from app.copilot_readiness_engine import analyze_oversharing_risk
        idx = _build_index([_spo_perms_ev({
            "SiteId": "site-1", "SiteName": "Wide Open",
            "TotalPermissions": 150,
        })])
        findings = analyze_oversharing_risk(idx)
        self.assertGreater(len(findings), 0)
        # Effort is added during the main assessment, so check the subcategory mapping exists
        from app.copilot_readiness_engine import _EFFORT_MAP
        for f in findings:
            subcat = f.get("Subcategory", "")
            if subcat in _EFFORT_MAP:
                self.assertIn(_EFFORT_MAP[subcat], ("quick_win", "moderate", "major"))


# ====================================================================
# Report rendering — new helper functions
# ====================================================================

class TestReportHelperFunctions(unittest.TestCase):

    def test_ms_ref_link_with_url(self):
        from app.reports.copilot_readiness_report import _ms_ref_link
        html = _ms_ref_link("MS Purview — DLP", "https://learn.microsoft.com/purview/dlp-learn-about-dlp")
        # External links removed — renders inline guidance text
        self.assertNotIn("href=", html)
        self.assertIn("MS Purview", html)
        self.assertIn("font-weight:600", html)  # bold label
        self.assertIn("text-secondary", html)  # explanation text

    def test_ms_ref_link_without_url(self):
        from app.reports.copilot_readiness_report import _ms_ref_link
        html = _ms_ref_link("MS Purview — DLP", "")
        self.assertNotIn("href=", html)
        self.assertIn("MS Purview", html)
        self.assertIn("font-weight:600", html)  # bold label
        self.assertIn("text-secondary", html)  # explanation text

    def test_ms_ref_link_empty(self):
        from app.reports.copilot_readiness_report import _ms_ref_link
        html = _ms_ref_link("", "")
        self.assertIn("—", html)

    def test_effort_badge(self):
        from app.reports.copilot_readiness_report import _effort_badge
        html = _effort_badge("quick_win")
        self.assertIn("Quick Win", html)
        self.assertIn("#107C10", html)  # green

        html = _effort_badge("moderate")
        self.assertIn("Moderate", html)

        html = _effort_badge("major")
        self.assertIn("Major", html)
        self.assertIn("#D13438", html)  # red

    def test_render_finding_row(self):
        from app.reports.copilot_readiness_report import _render_finding_row
        f = {
            "Severity": "high",
            "Category": "oversharing_risk",
            "Subcategory": "everyone_access",
            "Effort": "quick_win",
            "Title": "Everyone Except External Has Access",
            "Description": "Broad access detected.",
            "AffectedCount": 3,
            "AffectedResources": [{"Name": "Site A", "Type": "SharePoint", "ResourceId": "s1"}],
            "Remediation": {"Description": "Remove the Everyone group."},
        }
        html = _render_finding_row(1, f)
        self.assertIn("finding-summary-row", html)
        self.assertIn("finding-detail-row", html)
        self.assertIn("Everyone Except External", html)
        self.assertIn("Quick Win", html)
        self.assertIn("toggleFindingDetail", html)
        self.assertIn("Site A", html)
        self.assertIn("Remove the Everyone group", html)


# ====================================================================
# Report rendering — inventory tabs
# ====================================================================

class TestReportInventoryRendering(unittest.TestCase):

    def test_license_render(self):
        from app.reports.copilot_readiness_report import _render_license_inventory
        html = _render_license_inventory([
            {"SkuPartNumber": "MICROSOFT_365_COPILOT", "EnabledUnits": 10, "ConsumedUnits": 8},
        ])
        self.assertIn("MICROSOFT_365_COPILOT", html)
        self.assertIn("SKUs", html)

    def test_license_render_empty(self):
        from app.reports.copilot_readiness_report import _render_license_inventory
        html = _render_license_inventory([])
        self.assertIn("No license data", html)

    def test_label_render(self):
        from app.reports.copilot_readiness_report import _render_label_inventory
        html = _render_label_inventory([
            {"Name": "Confidential", "Priority": 1, "IsActive": True, "ParentId": "", "ContentType": "file", "Color": "#FF0000"},
        ])
        self.assertIn("Confidential", html)
        self.assertIn("Active", html)

    def test_ca_render(self):
        from app.reports.copilot_readiness_report import _render_ca_inventory
        html = _render_ca_inventory([
            {"DisplayName": "MFA Policy", "State": "enabled", "RequiresMFA": True, "RequiresCompliantDevice": False, "TargetsAllUsers": True, "BlocksLegacyAuth": False, "HasLocationCondition": False, "GrantControls": "mfa"},
        ])
        self.assertIn("MFA Policy", html)
        self.assertIn("Enabled", html)
        self.assertIn("MFA", html)

    def test_groups_render(self):
        from app.reports.copilot_readiness_report import _render_groups_inventory
        html = _render_groups_inventory([
            {"DisplayName": "Engineering", "IsTeam": True, "Visibility": "Private", "MailEnabled": True, "SecurityEnabled": False, "Mail": "eng@contoso.com", "CreatedDate": "2025-01-01"},
        ])
        self.assertIn("Engineering", html)
        self.assertIn("Team", html)
        self.assertIn("Groups", html)

    def test_groups_render_empty(self):
        from app.reports.copilot_readiness_report import _render_groups_inventory
        html = _render_groups_inventory([])
        self.assertIn("No M365 Groups", html)

    def test_dlp_render(self):
        from app.reports.copilot_readiness_report import _render_dlp_inventory
        html = _render_dlp_inventory([
            {"PolicyName": "PII Detection", "State": "enabled", "Workloads": "Exchange, SharePoint"},
        ])
        self.assertIn("PII Detection", html)
        self.assertIn("Enabled", html)

    def test_dlp_render_empty(self):
        from app.reports.copilot_readiness_report import _render_dlp_inventory
        html = _render_dlp_inventory([])
        self.assertIn("DLP policy data", html)

    def test_entra_apps_render(self):
        from app.reports.copilot_readiness_report import _render_entra_apps_inventory
        html = _render_entra_apps_inventory([
            {"AppId": "app-1", "DisplayName": "My App", "SignInAudience": "AzureADMyOrg",
             "HasGraphAccess": True, "DelegatedPermissions": 3, "ApplicationPermissions": 1,
             "CertificateCount": 0, "SecretCount": 1, "CreatedDate": "2025-01-01"},
        ])
        self.assertIn("My App", html)
        self.assertIn("Graph", html)
        self.assertIn("Apps", html)

    def test_entra_apps_render_empty(self):
        from app.reports.copilot_readiness_report import _render_entra_apps_inventory
        html = _render_entra_apps_inventory([])
        self.assertIn("No Entra", html)

    def test_sp_render(self):
        from app.reports.copilot_readiness_report import _render_service_principal_inventory
        html = _render_service_principal_inventory([
            {"SPId": "sp-1", "AppId": "app-1", "DisplayName": "Enterprise App",
             "ServicePrincipalType": "Application", "AccountEnabled": True,
             "IsEnterprise": True, "AppRoleAssignmentCount": 3},
        ])
        self.assertIn("Enterprise App", html)
        self.assertIn("Enterprise", html)

    def test_sp_render_empty(self):
        from app.reports.copilot_readiness_report import _render_service_principal_inventory
        html = _render_service_principal_inventory([])
        self.assertIn("No service principal", html)


# ====================================================================
# New checks: DSPM for AI
# ====================================================================

class TestDSPMForAI(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_copilot_security
        self.analyze = analyze_copilot_security

    def test_no_dspm_evidence_emits_finding(self):
        idx = _build_index([])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_dspm_for_ai", subcats)

    def test_dspm_enabled_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-dspm-for-ai", "Data": {"Enabled": True}, "ResourceId": "dspm"},
            _copilot_settings_ev({"Enabled": True}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_dspm_for_ai", subcats)

    def test_e5_without_dspm_emits_oversharing_review(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "SkuId": "e5-sku"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("dspm_oversharing_not_reviewed", subcats)


# ====================================================================
# New checks: SAM feature checks
# ====================================================================

class TestSAMFeatures(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_oversharing_risk
        self.analyze = analyze_oversharing_risk

    def test_sam_present_emits_rac_finding(self):
        """SAM licensed but no restricted access control evidence → finding."""
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "SkuId": "e5-sku"}),
            _spo_site_ev({"id": "s1", "webUrl": "https://contoso.sharepoint.com/sites/hr"}),
            _spo_perms_ev({"SiteId": "s1"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_sam_restricted_access_control", subcats)

    def test_sam_present_emits_lifecycle_finding(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "SkuId": "e5-sku"}),
            _spo_site_ev({"id": "s1", "webUrl": "https://contoso.sharepoint.com/sites/hr"}),
            _spo_perms_ev({"SiteId": "s1"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_sam_site_lifecycle_policy", subcats)

    def test_sam_present_emits_dag_finding(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "SkuId": "e5-sku"}),
            _spo_site_ev({"id": "s1", "webUrl": "https://contoso.sharepoint.com/sites/hr"}),
            _spo_perms_ev({"SiteId": "s1"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_sam_dag_reports", subcats)

    def test_no_sam_license_no_feature_findings(self):
        """Without SAM license, feature-level checks should not fire."""
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "ENTERPRISEPACK", "SkuId": "e3-sku"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_sam_restricted_access_control", subcats)
        self.assertNotIn("no_sam_site_lifecycle_policy", subcats)
        self.assertNotIn("no_sam_dag_reports", subcats)

    def test_rac_configured_no_finding(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "SkuId": "e5-sku"}),
            {"EvidenceType": "spo-restricted-access-control",
             "Data": {"Enabled": True}, "ResourceId": "rac"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_sam_restricted_access_control", subcats)

    def test_lifecycle_configured_no_finding(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "SkuId": "e5-sku"}),
            {"EvidenceType": "spo-site-lifecycle-policy",
             "Data": {"Enabled": True}, "ResourceId": "lifecycle"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_sam_site_lifecycle_policy", subcats)

    def test_dag_reports_present_no_finding(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "SPE_E5", "SkuId": "e5-sku"}),
            {"EvidenceType": "spo-data-access-governance",
             "Data": {"ReportCount": 3, "HasReports": True}, "ResourceId": "dag"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_sam_dag_reports", subcats)


# ====================================================================
# New checks: Copilot license assignment
# ====================================================================

class TestCopilotLicenseAssignment(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_copilot_licenses_unassigned(self):
        idx = _build_index([
            _subscribed_sku_ev({
                "SkuPartNumber": "Microsoft_365_Copilot",
                "SkuId": "copilot-sku",
                "PrepaidUnits": {"Enabled": 100},
                "ConsumedUnits": 0,
            }),
            _ca_policy_ev({"id": "p1", "State": "enabled", "IncludesCopilot": True}),
            _copilot_settings_ev({"Enabled": True}),
            _access_review_ev({"ReviewId": "r1"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("copilot_licenses_unassigned", subcats)

    def test_low_copilot_utilization(self):
        idx = _build_index([
            _subscribed_sku_ev({
                "SkuPartNumber": "Microsoft_365_Copilot",
                "SkuId": "copilot-sku",
                "PrepaidUnits": {"Enabled": 200},
                "ConsumedUnits": 50,
            }),
            _ca_policy_ev({"id": "p1", "State": "enabled", "IncludesCopilot": True}),
            _copilot_settings_ev({"Enabled": True}),
            _access_review_ev({"ReviewId": "r1"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("low_copilot_license_utilization", subcats)

    def test_copilot_fully_utilized_no_finding(self):
        idx = _build_index([
            _subscribed_sku_ev({
                "SkuPartNumber": "Microsoft_365_Copilot",
                "SkuId": "copilot-sku",
                "PrepaidUnits": {"Enabled": 100},
                "ConsumedUnits": 80,
            }),
            _ca_policy_ev({"id": "p1", "State": "enabled", "IncludesCopilot": True}),
            _copilot_settings_ev({"Enabled": True}),
            _access_review_ev({"ReviewId": "r1"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("copilot_licenses_unassigned", subcats)
        self.assertNotIn("low_copilot_license_utilization", subcats)


# ====================================================================
# New checks: M365 Backup
# ====================================================================

class TestM365Backup(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_content_lifecycle
        self.analyze = analyze_content_lifecycle

    def test_no_backup_evidence_emits_finding(self):
        idx = _build_index([])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_m365_backup", subcats)

    def test_backup_enabled_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-backup-config",
             "Data": {"Enabled": True, "Status": "active"}, "ResourceId": "backup"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_m365_backup", subcats)

    def test_backup_disabled_emits_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-backup-config",
             "Data": {"Enabled": False, "Status": "disabled"}, "ResourceId": "backup"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_m365_backup", subcats)


# ====================================================================
# Phase 1: Identity & Licensing Enhancements
# ====================================================================

def _user_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-user-details", "Data": data, "ResourceId": data.get("UserId", "")}

def _role_member_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-directory-role-members", "Data": data, "ResourceId": data.get("MemberId", "")}


class TestStaleAccounts(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_stale_account_detected(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _user_ev({"UserId": "u1", "DisplayName": "Old User", "UserPrincipalName": "old@contoso.com",
                       "LastSignInDateTime": old_date, "AccountEnabled": True}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("stale_accounts_detected", subcats)

    def test_recent_signin_no_stale_finding(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _user_ev({"UserId": "u1", "DisplayName": "Active User", "UserPrincipalName": "active@contoso.com",
                       "LastSignInDateTime": recent, "AccountEnabled": True}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("stale_accounts_detected", subcats)


class TestExcessiveGlobalAdmins(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_excessive_admins_detected(self):
        roles = [_role_member_ev({"RoleName": "Global Administrator",
                                   "MemberDisplayName": f"Admin {i}", "MemberId": f"m{i}",
                                   "MemberUPN": f"admin{i}@contoso.com"}) for i in range(8)]
        idx = _build_index([_ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]})] + roles)
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("excessive_global_admins", subcats)

    def test_five_admins_no_finding(self):
        roles = [_role_member_ev({"RoleName": "Global Administrator",
                                   "MemberDisplayName": f"Admin {i}", "MemberId": f"m{i}"}) for i in range(5)]
        idx = _build_index([_ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]})] + roles)
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("excessive_global_admins", subcats)


class TestSharedAccounts(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_shared_mailbox_type_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _user_ev({"UserId": "u1", "DisplayName": "Team Inbox", "UserPrincipalName": "team@contoso.com",
                       "MailboxType": "shared"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("shared_accounts_detected", subcats)

    def test_naming_pattern_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _user_ev({"UserId": "u2", "DisplayName": "Shared Admin", "UserPrincipalName": "shared.admin@contoso.com"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("shared_accounts_detected", subcats)

    def test_normal_account_no_finding(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _user_ev({"UserId": "u3", "DisplayName": "John Doe", "UserPrincipalName": "john.doe@contoso.com"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("shared_accounts_detected", subcats)


class TestGroupBasedLicensing(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_direct_only_licensing_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _subscribed_sku_ev({"SkuPartNumber": "Microsoft_365_Copilot", "SkuId": "cop-sku"}),
            _user_ev({"UserId": "u1", "DisplayName": "User 1", "HasCopilotLicense": True,
                       "LicenseAssignmentType": "direct"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_group_based_licensing", subcats)

    def test_group_assigned_no_finding(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _subscribed_sku_ev({"SkuPartNumber": "Microsoft_365_Copilot", "SkuId": "cop-sku"}),
            _user_ev({"UserId": "u1", "DisplayName": "User 1", "HasCopilotLicense": True,
                       "LicenseAssignmentType": "group"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_group_based_licensing", subcats)


class TestSessionControls(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_no_session_controls_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "State": "enabled", "IncludedApplications": ["All"],
                            "SessionControls": {}}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_session_signin_frequency", subcats)
        self.assertIn("no_persistent_browser_control", subcats)

    def test_signin_frequency_present_no_finding(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "State": "enabled", "IncludedApplications": ["All"],
                            "SessionControls": {"SignInFrequency": True, "PersistentBrowser": True}}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_session_signin_frequency", subcats)
        self.assertNotIn("no_persistent_browser_control", subcats)


# ====================================================================
# Phase 2: Exchange & Agent Governance Enhancements
# ====================================================================

def _delegation_ev(data: dict) -> dict:
    return {"EvidenceType": "exchange-mailbox-delegations", "Data": data, "ResourceId": data.get("MailboxId", "")}

def _shared_mbox_ev(data: dict) -> dict:
    return {"EvidenceType": "exchange-shared-mailboxes", "Data": data, "ResourceId": data.get("MailboxId", "")}


class TestMailboxDelegation(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_fullaccess_delegation_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _delegation_ev({"MailboxId": "m1", "MailboxDisplayName": "CEO Mailbox",
                             "DelegateDisplayName": "EA", "AccessRights": "FullAccess"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("mailbox_delegation_fullaccess", subcats)

    def test_sendas_delegation_no_finding(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _delegation_ev({"MailboxId": "m1", "MailboxDisplayName": "Team",
                             "DelegateDisplayName": "User", "AccessRights": "SendAs"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("mailbox_delegation_fullaccess", subcats)


class TestSharedMailboxPermissions(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_overdelegated_shared_mailbox_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _shared_mbox_ev({"MailboxId": "sm1", "DisplayName": "All Company", "MemberCount": 50}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("shared_mailbox_over_delegated", subcats)

    def test_small_shared_mailbox_no_finding(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _shared_mbox_ev({"MailboxId": "sm1", "DisplayName": "Finance Team", "MemberCount": 5}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("shared_mailbox_over_delegated", subcats)


class TestIBEnforcementDetail(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_ib_no_segments_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            {"EvidenceType": "m365-information-barriers", "Data": {"Enabled": True}, "ResourceId": "ib"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("ib_segments_not_assigned", subcats)

    def test_ib_with_segments_no_finding(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            {"EvidenceType": "m365-information-barriers", "Data": {"Enabled": True}, "ResourceId": "ib"},
            {"EvidenceType": "m365-ib-segments", "Data": {"SegmentId": "s1", "Name": "Finance"}, "ResourceId": "s1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("ib_segments_not_assigned", subcats)


class TestLicenseOffboarding(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_disabled_with_copilot_license_detected(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _user_ev({"UserId": "u1", "DisplayName": "Departed User", "UserPrincipalName": "departed@contoso.com",
                       "AccountEnabled": False, "HasCopilotLicense": True}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("disabled_users_with_copilot_license", subcats)

    def test_active_user_no_finding(self):
        idx = _build_index([
            _ca_policy_ev({"id": "p1", "IncludedApplications": ["All"]}),
            _user_ev({"UserId": "u1", "DisplayName": "Active User", "AccountEnabled": True, "HasCopilotLicense": True}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("disabled_users_with_copilot_license", subcats)


# ====================================================================
# Phase 2: Label Coverage Enhancement
# ====================================================================

class TestMandatoryLabelingScope(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_label_coverage
        self.analyze = analyze_label_coverage

    def test_incomplete_scope_detected(self):
        idx = _build_index([_label_policy_ev({
            "TotalPolicies": 1, "HasMandatoryLabeling": True, "HasAutoLabeling": True,
            "MandatoryLabeling": True, "MandatoryLabelingWorkloads": ["Exchange"],
        })])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("mandatory_labeling_incomplete_scope", subcats)

    def test_all_workloads_covered_no_finding(self):
        idx = _build_index([_label_policy_ev({
            "TotalPolicies": 1, "HasMandatoryLabeling": True, "HasAutoLabeling": True,
            "MandatoryLabeling": True,
            "MandatoryLabelingWorkloads": ["Word", "Excel", "PowerPoint", "Outlook", "Teams", "SharePoint"],
        })])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("mandatory_labeling_incomplete_scope", subcats)


# ====================================================================
# Phase 3/4: Oversharing Risk Enhancements
# ====================================================================

class TestPermissionBlastRadius(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_oversharing_risk
        self.analyze = analyze_oversharing_risk

    def test_high_blast_radius_detected(self):
        idx = _build_index([
            _spo_site_ev({"SiteId": "s1", "SiteName": "Wide Open Site"}),
            _spo_perms_ev({"SiteId": "s1", "SiteName": "Wide Open Site",
                            "TotalPermissions": 200, "MemberCount": 300,
                            "GuestCount": 50, "ExternalSharingCount": 30}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("high_permission_blast_radius", subcats)

    def test_low_blast_radius_no_finding(self):
        idx = _build_index([
            _spo_site_ev({"SiteId": "s1", "SiteName": "Private Site"}),
            _spo_perms_ev({"SiteId": "s1", "SiteName": "Private Site",
                            "TotalPermissions": 5, "MemberCount": 3,
                            "GuestCount": 0, "ExternalSharingCount": 0}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("high_permission_blast_radius", subcats)


class TestExternalSharingScorecard(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_oversharing_risk
        self.analyze = analyze_oversharing_risk

    def test_high_sharing_risk_detected(self):
        idx = _build_index([
            _spo_site_ev({"SiteId": "s1", "SiteName": "Shared Site"}),
            _spo_sharing_ev({"SiteId": "s1", "SiteName": "Shared Site",
                              "AnonymousLinks": 10, "ExternalLinks": 20, "OrgWideLinks": 5}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("external_sharing_risk_score", subcats)

    def test_no_sharing_links_no_finding(self):
        idx = _build_index([
            _spo_site_ev({"SiteId": "s1", "SiteName": "Internal Site"}),
            _spo_sharing_ev({"SiteId": "s1", "SiteName": "Internal Site",
                              "AnonymousLinks": 0, "ExternalLinks": 0, "OrgWideLinks": 0}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("external_sharing_risk_score", subcats)


# ====================================================================
# Phase 3: Audit & Monitoring Enhancements
# ====================================================================

class TestCopilotUsageAnalytics(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_audit_monitoring
        self.analyze = analyze_audit_monitoring

    def test_no_usage_reports_with_copilot_license(self):
        idx = _build_index([
            _audit_ev({"UnifiedAuditLogEnabled": True}),
            _subscribed_sku_ev({"SkuPartNumber": "Microsoft_365_Copilot", "SkuId": "cop"}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_copilot_usage_analytics", subcats)

    def test_usage_reports_present_no_finding(self):
        idx = _build_index([
            _audit_ev({"UnifiedAuditLogEnabled": True}),
            _subscribed_sku_ev({"SkuPartNumber": "Microsoft_365_Copilot", "SkuId": "cop"}),
            {"EvidenceType": "m365-copilot-usage-reports", "Data": {"ActiveUsers": 50}, "ResourceId": "usage"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_copilot_usage_analytics", subcats)


class TestCopilotAuditLogAnalysis(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_audit_monitoring
        self.analyze = analyze_audit_monitoring

    def test_no_audit_events_detected(self):
        idx = _build_index([
            _audit_ev({"UnifiedAuditLogEnabled": True}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("copilot_audit_events_not_analyzed", subcats)

    def test_audit_events_present_no_finding(self):
        idx = _build_index([
            _audit_ev({"UnifiedAuditLogEnabled": True}),
            {"EvidenceType": "m365-copilot-audit-events", "Data": {"EventCount": 100}, "ResourceId": "audit"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("copilot_audit_events_not_analyzed", subcats)


class TestPromptPatterns(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_audit_monitoring
        self.analyze = analyze_audit_monitoring

    def test_no_prompt_monitoring_detected(self):
        idx = _build_index([
            _audit_ev({"UnifiedAuditLogEnabled": True}),
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_prompt_pattern_monitoring", subcats)

    def test_prompt_monitoring_present_no_finding(self):
        idx = _build_index([
            _audit_ev({"UnifiedAuditLogEnabled": True}),
            {"EvidenceType": "m365-copilot-prompt-monitoring", "Data": {"Enabled": True}, "ResourceId": "pm"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_prompt_pattern_monitoring", subcats)


# ====================================================================
# Phase 2/3: Copilot Security Enhancements
# ====================================================================

class TestCopilotAgentInventory(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_copilot_security
        self.analyze = analyze_copilot_security

    def test_unmanaged_agents_detected(self):
        idx = _build_index([
            {"EvidenceType": "copilot-studio-bots", "Data": {
                "BotId": "b1", "DisplayName": "HR Bot", "IsPublished": True, "Owner": ""
            }, "ResourceId": "b1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("unmanaged_copilot_agents", subcats)

    def test_managed_agents_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "copilot-studio-bots", "Data": {
                "BotId": "b1", "DisplayName": "HR Bot", "IsPublished": True, "Owner": "admin@contoso.com"
            }, "ResourceId": "b1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("unmanaged_copilot_agents", subcats)


class TestAgentPermissionBoundary(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_copilot_security
        self.analyze = analyze_copilot_security

    def test_over_permissioned_agent_detected(self):
        idx = _build_index([
            {"EvidenceType": "copilot-studio-bots", "Data": {
                "BotId": "b1", "DisplayName": "Data Bot", "AppId": "app-1", "IsPublished": True, "Owner": "admin"
            }, "ResourceId": "b1"},
            {"EvidenceType": "entra-applications", "Data": {
                "AppId": "app-1", "DisplayName": "Data Bot App", "ApplicationPermissions": 10
            }, "ResourceId": "app-1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("agent_over_permissioned", subcats)

    def test_minimal_permissions_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "copilot-studio-bots", "Data": {
                "BotId": "b1", "DisplayName": "Simple Bot", "AppId": "app-2", "IsPublished": True, "Owner": "admin"
            }, "ResourceId": "b1"},
            {"EvidenceType": "entra-applications", "Data": {
                "AppId": "app-2", "DisplayName": "Simple Bot App", "ApplicationPermissions": 2
            }, "ResourceId": "app-2"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("agent_over_permissioned", subcats)


class TestRegulatoryMapping(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_copilot_security
        self.analyze = analyze_copilot_security

    def test_no_assessments_detected(self):
        idx = _build_index([])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_regulatory_framework_mapping", subcats)

    def test_assessments_present_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-compliance-manager-assessments", "Data": {
                "AssessmentId": "a1", "Framework": "ISO 27001"
            }, "ResourceId": "a1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_regulatory_framework_mapping", subcats)


class TestDataResidencyDeep(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_copilot_security
        self.analyze = analyze_copilot_security

    def test_multi_geo_detected(self):
        idx = _build_index([
            {"EvidenceType": "m365-organization-info", "Data": {
                "CountryLetterCode": "US", "PreferredDataLocation": "NAM"
            }, "ResourceId": "org"},
            {"EvidenceType": "m365-multi-geo-config", "Data": {"Location": "NAM"}, "ResourceId": "geo-1"},
            {"EvidenceType": "m365-multi-geo-config", "Data": {"Location": "EUR"}, "ResourceId": "geo-2"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("multi_geo_copilot_residency", subcats)

    def test_single_geo_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-organization-info", "Data": {
                "CountryLetterCode": "US", "PreferredDataLocation": "NAM"
            }, "ResourceId": "org"},
            {"EvidenceType": "m365-multi-geo-config", "Data": {"Location": "NAM"}, "ResourceId": "geo-1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("multi_geo_copilot_residency", subcats)


class TestRAIPolicy(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_copilot_security
        self.analyze = analyze_copilot_security

    def test_no_rai_policy_detected(self):
        idx = _build_index([])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_rai_policy", subcats)

    def test_rai_policy_present_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-rai-policies", "Data": {"PolicyId": "rai1", "Name": "AI Ethics"}, "ResourceId": "rai1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_rai_policy", subcats)

    def test_rai_label_counts_as_policy(self):
        idx = _build_index([
            {"EvidenceType": "m365-sensitivity-label-definition", "Data": {
                "Name": "Responsible AI - Review Required", "Priority": 5, "IsActive": True
            }, "ResourceId": "lbl-rai"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_rai_policy", subcats)


# ====================================================================
# Content Lifecycle Enhancement
# ====================================================================

class TestLegalHoldCompatibility(unittest.TestCase):
    def setUp(self):
        from app.copilot_readiness_engine import analyze_content_lifecycle
        self.analyze = analyze_content_lifecycle

    def test_no_legal_hold_detected(self):
        idx = _build_index([])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertIn("no_legal_hold_configured", subcats)

    def test_ediscovery_case_present_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-ediscovery-cases", "Data": {"CaseId": "c1", "Name": "Litigation Hold"}, "ResourceId": "c1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_legal_hold_configured", subcats)

    def test_legal_hold_present_no_finding(self):
        idx = _build_index([
            {"EvidenceType": "m365-legal-holds", "Data": {"HoldId": "h1", "Name": "Regulatory Hold"}, "ResourceId": "h1"},
        ])
        findings = self.analyze(idx)
        subcats = [f["Subcategory"] for f in findings]
        self.assertNotIn("no_legal_hold_configured", subcats)


# ====================================================================
# New Control Tuples in _COPILOT_SECURITY_CONTROLS
# ====================================================================

class TestNewControlTuples(unittest.TestCase):
    def test_all_new_controls_registered(self):
        from app.copilot_readiness_engine import _COPILOT_SECURITY_CONTROLS
        ctrl_ids = [c[0] for c in _COPILOT_SECURITY_CONTROLS]
        expected_new = [
            "CTRL-GOV-011", "CTRL-GOV-012", "CTRL-GOV-013", "CTRL-GOV-014",
            "CTRL-GOV-015", "CTRL-GOV-016", "CTRL-GOV-017", "CTRL-GOV-018",
            "CTRL-GOV-019", "CTRL-GOV-020",
            "CTRL-LBL-006",
            "CTRL-OVR-010", "CTRL-OVR-011",
            "CTRL-CLM-004",
            "CTRL-AUD-005", "CTRL-AUD-006", "CTRL-AUD-007",
            "CTRL-CPS-009", "CTRL-CPS-010", "CTRL-CPS-011",
            "CTRL-CPS-012", "CTRL-CPS-013",
        ]
        for ctrl_id in expected_new:
            self.assertIn(ctrl_id, ctrl_ids, f"Missing control: {ctrl_id}")

    def test_new_controls_have_valid_categories(self):
        from app.copilot_readiness_engine import _COPILOT_SECURITY_CONTROLS, _ALL_CATEGORIES
        for ctrl in _COPILOT_SECURITY_CONTROLS:
            self.assertIn(ctrl[2], _ALL_CATEGORIES, f"Control {ctrl[0]} has invalid category '{ctrl[2]}'")


# ====================================================================
# Effort map and MS reference URLs for new subcategories
# ====================================================================

class TestNewEffortAndReferences(unittest.TestCase):
    def test_new_subcategories_in_effort_map(self):
        from app.copilot_readiness_engine import _EFFORT_MAP
        new_subcats = [
            "stale_accounts_detected", "excessive_global_admins", "shared_accounts_detected",
            "no_group_based_licensing", "no_session_signin_frequency", "no_persistent_browser_control",
            "mailbox_delegation_fullaccess", "shared_mailbox_over_delegated",
            "ib_segments_not_assigned", "disabled_users_with_copilot_license",
            "mandatory_labeling_incomplete_scope",
            "high_permission_blast_radius", "external_sharing_risk_score",
            "no_legal_hold_configured",
            "no_copilot_usage_analytics", "copilot_audit_events_not_analyzed",
            "no_prompt_pattern_monitoring",
            "unmanaged_copilot_agents", "agent_over_permissioned",
            "no_regulatory_framework_mapping", "multi_geo_copilot_residency", "no_rai_policy",
        ]
        for subcat in new_subcats:
            self.assertIn(subcat, _EFFORT_MAP, f"Missing effort map entry: {subcat}")

    def test_new_ms_reference_urls(self):
        from app.copilot_readiness_engine import _MS_REFERENCE_URLS
        expected_refs = [
            "MS Entra — User Sign-In Activity",
            "MS Entra — Global Admin Best Practices",
            "MS Entra — Session Controls",
            "MS Exchange — Mailbox Permissions",
            "MS Purview — Compliance Manager",
            "MS Copilot Studio — Agent Governance",
            "MS Responsible AI",
        ]
        for ref in expected_refs:
            self.assertIn(ref, _MS_REFERENCE_URLS, f"Missing MS reference URL: {ref}")


# ====================================================================
# Phase 5: RCD, App Protection, Label Encryption
# ====================================================================

def _label_def_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-sensitivity-label-definition", "Data": data, "ResourceId": data.get("Id", "")}

def _app_protection_ev(data: dict) -> dict:
    return {"EvidenceType": "intune-app-protection-policies", "Data": data, "ResourceId": data.get("PolicyId", "")}


class TestRCD(unittest.TestCase):
    """Tests for Restricted Content Discoverability (RCD) check."""

    def setUp(self):
        from app.copilot_readiness_engine import analyze_restricted_search
        self.analyze = analyze_restricted_search

    def test_rcd_not_configured_large_tenant(self):
        """Large tenant without RCD triggers rcd_not_configured."""
        sites = [_spo_site_ev({"id": f"site-{i}", "SiteName": f"Site {i}"}) for i in range(50)]
        idx = _build_index(sites)
        findings = self.analyze(idx)
        rcd = [f for f in findings if f.get("Subcategory") == "rcd_not_configured"]
        self.assertGreater(len(rcd), 0)

    def test_rcd_configured_no_finding(self):
        """Large tenant with RCD enabled should not trigger finding."""
        sites = [_spo_site_ev({"id": f"site-{i}", "SiteName": f"Site {i}"}) for i in range(50)]
        config = [_spo_tenant_ev({"IsRestrictedContentDiscoverabilityEnabled": True})]
        idx = _build_index(sites + config)
        findings = self.analyze(idx)
        rcd = [f for f in findings if f.get("Subcategory") == "rcd_not_configured"]
        self.assertEqual(len(rcd), 0)

    def test_small_tenant_no_rcd_finding(self):
        """Small tenant (<= 20 sites) should not trigger RCD finding."""
        sites = [_spo_site_ev({"id": f"site-{i}", "SiteName": f"Site {i}"}) for i in range(10)]
        idx = _build_index(sites)
        findings = self.analyze(idx)
        rcd = [f for f in findings if f.get("Subcategory") == "rcd_not_configured"]
        self.assertEqual(len(rcd), 0)


class TestAppProtectionPolicies(unittest.TestCase):
    """Tests for App Protection Policy (MAM) check."""

    def setUp(self):
        from app.copilot_readiness_engine import analyze_access_governance
        self.analyze = analyze_access_governance

    def test_no_mam_policies_detected(self):
        """No app protection policies triggers no_app_protection_policies."""
        idx = _build_index([])
        findings = self.analyze(idx)
        mam = [f for f in findings if f.get("Subcategory") == "no_app_protection_policies"]
        self.assertGreater(len(mam), 0)

    def test_mam_policies_present_no_finding(self):
        """Having active policies for both platforms should not trigger finding."""
        policies = [
            _app_protection_ev({"PolicyName": "iOS Policy", "Platform": "ios", "IsActive": True}),
            _app_protection_ev({"PolicyName": "Android Policy", "Platform": "android", "IsActive": True}),
        ]
        idx = _build_index(policies)
        findings = self.analyze(idx)
        mam = [f for f in findings if f.get("Subcategory") == "no_app_protection_policies"]
        self.assertEqual(len(mam), 0)
        gap = [f for f in findings if f.get("Subcategory") == "app_protection_platform_gaps"]
        self.assertEqual(len(gap), 0)

    def test_mam_platform_gap_detected(self):
        """Only iOS policy should trigger platform gap for Android."""
        policies = [
            _app_protection_ev({"PolicyName": "iOS Only", "Platform": "ios", "IsActive": True}),
        ]
        idx = _build_index(policies)
        findings = self.analyze(idx)
        gap = [f for f in findings if f.get("Subcategory") == "app_protection_platform_gaps"]
        self.assertGreater(len(gap), 0)


class TestLabelEncryptionGaps(unittest.TestCase):
    """Tests for label encryption and site/group settings check."""

    def setUp(self):
        from app.copilot_readiness_engine import analyze_label_coverage
        self.analyze = analyze_label_coverage

    def test_labels_without_encryption_detected(self):
        """Active labels without encryption trigger labels_without_encryption."""
        labels = [
            _label_def_ev({"Name": "Confidential", "IsActive": True, "IsEncryptionEnabled": False, "Priority": 1}),
            _label_def_ev({"Name": "Public", "IsActive": True, "IsEncryptionEnabled": False, "Priority": 0}),
        ]
        summary = [_label_summary_ev({"TotalLabels": 2, "ActiveLabels": 2})]
        idx = _build_index(labels + summary)
        findings = self.analyze(idx)
        enc = [f for f in findings if f.get("Subcategory") == "labels_without_encryption"]
        self.assertGreater(len(enc), 0)

    def test_encrypted_labels_no_finding(self):
        """All labels with encryption should not trigger finding."""
        labels = [
            _label_def_ev({"Name": "Confidential", "IsActive": True, "IsEncryptionEnabled": True, "Priority": 1}),
        ]
        summary = [_label_summary_ev({"TotalLabels": 1, "ActiveLabels": 1})]
        idx = _build_index(labels + summary)
        findings = self.analyze(idx)
        enc = [f for f in findings if f.get("Subcategory") == "labels_without_encryption"]
        self.assertEqual(len(enc), 0)

    def test_labels_without_site_group_settings_detected(self):
        """Labels without site/group settings trigger finding."""
        labels = [
            _label_def_ev({"Name": "Internal", "IsActive": True, "HasSiteAndGroupSettings": False, "IsEncryptionEnabled": True, "Priority": 1}),
        ]
        summary = [_label_summary_ev({"TotalLabels": 1, "ActiveLabels": 1})]
        idx = _build_index(labels + summary)
        findings = self.analyze(idx)
        sg = [f for f in findings if f.get("Subcategory") == "labels_without_site_group_settings"]
        self.assertGreater(len(sg), 0)

    def test_no_labels_no_encryption_finding(self):
        """No label definitions should not trigger encryption check."""
        idx = _build_index([_label_summary_ev({"TotalLabels": 0})])
        findings = self.analyze(idx)
        enc = [f for f in findings if f.get("Subcategory") == "labels_without_encryption"]
        self.assertEqual(len(enc), 0)


class TestPhase5EffortAndReferences(unittest.TestCase):
    """Verify effort map entries, MS reference URLs, and controls for Phase 5."""

    def test_phase5_effort_map_entries(self):
        from app.copilot_readiness_engine import _EFFORT_MAP
        subcats = [
            "no_app_protection_policies", "app_protection_platform_gaps",
            "labels_without_encryption", "labels_without_site_group_settings",
            "rcd_not_configured",
        ]
        for sc in subcats:
            self.assertIn(sc, _EFFORT_MAP, f"Missing effort map entry: {sc}")

    def test_phase5_ms_reference_urls(self):
        from app.copilot_readiness_engine import _MS_REFERENCE_URLS
        refs = [
            "MS Intune — App Protection Policies",
            "MS Purview — Label Encryption",
            "MS Purview — Label Site & Group Settings",
            "MS SharePoint — Restricted Content Discoverability",
        ]
        for ref in refs:
            self.assertIn(ref, _MS_REFERENCE_URLS, f"Missing MS reference URL: {ref}")

    def test_phase5_security_controls(self):
        from app.copilot_readiness_engine import _COPILOT_SECURITY_CONTROLS
        ctrl_ids = [c[0] for c in _COPILOT_SECURITY_CONTROLS]
        self.assertIn("CTRL-GOV-021", ctrl_ids)
        self.assertIn("CTRL-LBL-007", ctrl_ids)
        self.assertIn("CTRL-RSS-002", ctrl_ids)

    def test_app_protection_inventory_builder(self):
        from app.copilot_readiness_engine import _build_app_protection_inventory
        policies = [
            _app_protection_ev({"PolicyName": "iOS MAM", "Platform": "ios", "IsActive": True, "AssignedApps": 5}),
            _app_protection_ev({"PolicyName": "Android MAM", "Platform": "android", "IsActive": True, "AssignedApps": 3}),
        ]
        idx = _build_index(policies)
        inv = _build_app_protection_inventory(idx)
        self.assertEqual(len(inv), 2)
        self.assertEqual(inv[0]["Platform"], "android")  # sorted by platform
        self.assertEqual(inv[1]["Platform"], "ios")

    def test_label_inventory_includes_encryption_fields(self):
        from app.copilot_readiness_engine import _build_label_inventory
        labels = [
            _label_def_ev({"Name": "Confidential", "Priority": 1, "IsActive": True,
                           "IsEncryptionEnabled": True, "HasSiteAndGroupSettings": True}),
        ]
        idx = _build_index(labels)
        inv = _build_label_inventory(idx)
        self.assertEqual(len(inv), 1)
        self.assertTrue(inv[0]["IsEncryptionEnabled"])
        self.assertTrue(inv[0]["HasSiteAndGroupSettings"])


# ====================================================================
# Phase 6: Checklist Gap Closure Tests
# ====================================================================

def _cross_tenant_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-cross-tenant-access", "Data": data, "ResourceId": "cross-tenant"}

def _user_details_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-user-details", "Data": data, "ResourceId": data.get("UserId", "")}

def _group_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-groups", "Data": data, "ResourceId": data.get("GroupId", "")}

def _graph_connector_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-graph-connectors", "Data": data, "ResourceId": data.get("ConnectorId", "")}

def _defender_incident_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-defender-copilot-incidents", "Data": data, "ResourceId": data.get("IncidentId", "")}


class TestCrossTenantAccess(unittest.TestCase):
    """Tests for _check_cross_tenant_access."""

    def setUp(self):
        from app.copilot_readiness_engine import _check_cross_tenant_access
        self.check = _check_cross_tenant_access

    def test_no_evidence_fires_not_assessed(self):
        findings = self.check({})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "cross_tenant_access_not_assessed")

    def test_permissive_default_fires(self):
        idx = _build_index([_cross_tenant_ev({
            "PolicyId": "default", "IsDefault": True,
            "InboundAllowed": True, "OutboundAllowed": True,
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "cross_tenant_access_permissive")

    def test_restricted_default_no_finding(self):
        idx = _build_index([_cross_tenant_ev({
            "PolicyId": "default", "IsDefault": True,
            "InboundAllowed": False, "OutboundAllowed": True,
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 0)


class TestHybridIdentity(unittest.TestCase):
    """Tests for _check_hybrid_identity_accounts."""

    def setUp(self):
        from app.copilot_readiness_engine import _check_hybrid_identity_accounts
        self.check = _check_hybrid_identity_accounts

    def test_no_users_no_finding(self):
        findings = self.check({})
        self.assertEqual(len(findings), 0)

    def test_stale_sync_detected(self):
        idx = _build_index([_user_details_ev({
            "UserId": "u1", "UserPrincipalName": "user@contoso.com",
            "AccountEnabled": True,
            "OnPremisesSyncEnabled": True,
            "OnPremisesDistinguishedName": "CN=user,OU=users",
            "OnPremisesLastSyncDateTime": "",  # stale — empty sync time
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "hybrid_accounts_stale_sync")

    def test_healthy_sync_no_finding(self):
        idx = _build_index([_user_details_ev({
            "UserId": "u1", "UserPrincipalName": "user@contoso.com",
            "AccountEnabled": True,
            "OnPremisesSyncEnabled": True,
            "OnPremisesLastSyncDateTime": "2026-04-01T10:00:00Z",
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 0)

    def test_disabled_account_ignored(self):
        idx = _build_index([_user_details_ev({
            "UserId": "u1", "UserPrincipalName": "disabled@contoso.com",
            "AccountEnabled": False,
            "OnPremisesSyncEnabled": True,
            "OnPremisesLastSyncDateTime": "",
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 0)


class TestCopilotLicenseSegmentation(unittest.TestCase):
    """Tests for _check_copilot_license_segmentation."""

    def setUp(self):
        from app.copilot_readiness_engine import _check_copilot_license_segmentation
        self.check = _check_copilot_license_segmentation

    def test_no_copilot_skus_no_finding(self):
        idx = _build_index([_subscribed_sku_ev({"SkuPartNumber": "ENTERPRISEPACK", "SkuId": "s1"})])
        findings = self.check(idx)
        self.assertEqual(len(findings), 0)

    def test_missing_segmentation_fires(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "Microsoft_Copilot", "SkuId": "cop1"}),
            _group_ev({"GroupId": "g1", "DisplayName": "All Users"}),
        ])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_copilot_license_segmentation")

    def test_segmented_groups_no_finding(self):
        idx = _build_index([
            _subscribed_sku_ev({"SkuPartNumber": "Microsoft_Copilot", "SkuId": "cop1"}),
            _group_ev({"GroupId": "g1", "DisplayName": "Copilot-Pilot"}),
            _group_ev({"GroupId": "g2", "DisplayName": "Copilot-Production"}),
        ])
        findings = self.check(idx)
        self.assertEqual(len(findings), 0)


class TestAgentApprovalWorkflow(unittest.TestCase):
    """Tests for _check_agent_approval_workflow."""

    def setUp(self):
        from app.copilot_readiness_engine import _check_agent_approval_workflow
        self.check = _check_agent_approval_workflow

    def test_no_settings_no_finding(self):
        findings = self.check({})
        self.assertEqual(len(findings), 0)

    def test_no_approval_fires(self):
        idx = _build_index([_copilot_settings_ev({
            "AllowUsersToCreateAgents": True,
            "AgentApprovalRequired": False,
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_agent_approval_workflow")

    def test_approval_required_no_finding(self):
        idx = _build_index([_copilot_settings_ev({
            "AllowUsersToCreateAgents": True,
            "AgentApprovalRequired": True,
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 0)


class TestExternalConnectorGovernance(unittest.TestCase):
    """Tests for _check_external_connector_governance."""

    def setUp(self):
        from app.copilot_readiness_engine import _check_external_connector_governance
        self.check = _check_external_connector_governance

    def test_ungoverned_connectors_fires(self):
        idx = _build_index([_graph_connector_ev({
            "ConnectorId": "c1", "Name": "HR Data",
            "HasOwner": False,
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "ungoverned_external_connectors")

    def test_high_perm_apps_fallback(self):
        apps = [{"EvidenceType": "entra-applications", "Data": {
            "AppId": "a1", "DisplayName": "DataBot",
            "ApplicationPermissions": 8,
        }, "ResourceId": "a1"}]
        idx = _build_index(apps)
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "external_connector_review_needed")

    def test_no_connectors_no_apps_no_finding(self):
        findings = self.check({})
        self.assertEqual(len(findings), 0)


class TestDefenderCopilotIncidents(unittest.TestCase):
    """Tests for _check_defender_copilot_incidents."""

    def setUp(self):
        from app.copilot_readiness_engine import _check_defender_copilot_incidents
        self.check = _check_defender_copilot_incidents

    def test_high_severity_incident_fires(self):
        idx = _build_index([_defender_incident_ev({
            "IncidentId": "inc1", "Title": "Copilot data exfiltration attempt",
            "Severity": "High", "Status": "Active",
        })])
        # Also need alert evidence present
        idx["m365-alert-policies"] = [{"EvidenceType": "m365-alert-policies", "Data": {"AlertCount": 1}}]
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "copilot_security_incidents_detected")

    def test_no_incidents_no_finding(self):
        findings = self.check({})
        self.assertEqual(len(findings), 0)


class TestPromptGuardrails(unittest.TestCase):
    """Tests for _check_prompt_guardrails."""

    def setUp(self):
        from app.copilot_readiness_engine import _check_prompt_guardrails
        self.check = _check_prompt_guardrails

    def test_no_settings_no_finding(self):
        findings = self.check({})
        self.assertEqual(len(findings), 0)

    def test_wide_open_fires(self):
        idx = _build_index([_copilot_settings_ev({
            "WebSearchEnabled": True,
            "PromptRestrictions": None,
            "ContentFilterEnabled": None,
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Subcategory"], "no_prompt_guardrails")

    def test_filters_enabled_no_finding(self):
        idx = _build_index([_copilot_settings_ev({
            "WebSearchEnabled": True,
            "PromptRestrictions": {"BlockHighRisk": True},
            "ContentFilterEnabled": True,
        })])
        findings = self.check(idx)
        self.assertEqual(len(findings), 0)


class TestPhase6EffortAndReferences(unittest.TestCase):
    """Verify effort map entries, MS reference URLs, and controls for Phase 6."""

    def test_phase6_effort_map_entries(self):
        from app.copilot_readiness_engine import _EFFORT_MAP
        subcats = [
            "cross_tenant_access_not_assessed", "cross_tenant_access_permissive",
            "hybrid_accounts_stale_sync", "no_copilot_license_segmentation",
            "no_agent_approval_workflow", "ungoverned_external_connectors",
            "external_connector_review_needed", "copilot_security_incidents_detected",
            "no_prompt_guardrails",
        ]
        for sc in subcats:
            self.assertIn(sc, _EFFORT_MAP, f"Missing effort map entry: {sc}")

    def test_phase6_ms_reference_urls(self):
        from app.copilot_readiness_engine import _MS_REFERENCE_URLS
        refs = [
            "MS Entra — Cross-Tenant Access",
            "MS Entra — Hybrid Identity",
            "MS Admin — Copilot License Segmentation",
            "MS Copilot — Agent Approval",
            "MS Graph — External Connectors",
            "MS Defender — Copilot Incidents",
            "MS Copilot — Prompt Guardrails",
        ]
        for ref in refs:
            self.assertIn(ref, _MS_REFERENCE_URLS, f"Missing MS reference URL: {ref}")

    def test_phase6_security_controls(self):
        from app.copilot_readiness_engine import _COPILOT_SECURITY_CONTROLS
        ctrl_ids = [c[0] for c in _COPILOT_SECURITY_CONTROLS]
        expected = [
            "CTRL-CPS-014", "CTRL-GOV-022", "CTRL-GOV-023",
            "CTRL-CPS-015", "CTRL-CPS-016", "CTRL-AUD-008", "CTRL-CPS-017",
        ]
        for ctrl in expected:
            self.assertIn(ctrl, ctrl_ids, f"Missing security control: {ctrl}")

    def test_total_controls_is_89(self):
        from app.copilot_readiness_engine import _COPILOT_SECURITY_CONTROLS
        self.assertEqual(len(_COPILOT_SECURITY_CONTROLS), 89)


if __name__ == "__main__":
    unittest.main()
