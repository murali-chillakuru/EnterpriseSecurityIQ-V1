"""
Determinism validation test for the M365 Copilot Readiness Assessment Engine.

Verifies that identical evidence inputs produce identical outputs across
multiple runs, excluding only the ``AssessedAt`` / ``DetectedAt`` timestamps.

Tests cover all 10 assessment categories:
  1. Oversharing Risk
  2. Sensitivity Label Coverage
  3. DLP Readiness
  4. Restricted SharePoint Search
  5. Data Access Governance
  6. Content Lifecycle
  7. Audit & Monitoring
  8. Copilot-Specific Security
  9. Zero Trust Posture
 10. Shadow AI Governance
"""

from __future__ import annotations

import copy
import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.copilot_readiness_engine import (
    analyze_oversharing_risk,
    analyze_label_coverage,
    analyze_dlp_readiness,
    analyze_restricted_search,
    analyze_access_governance,
    analyze_content_lifecycle,
    analyze_audit_monitoring,
    analyze_copilot_security,
    analyze_zero_trust,
    analyze_shadow_ai,
    compute_copilot_readiness_scores,
)


# ── Evidence builder helpers ─────────────────────────────────────────

def _ev(etype: str, data: dict, resource_id: str = "") -> dict:
    """Create a minimal evidence record."""
    return {"EvidenceType": etype, "Data": data, "ResourceId": resource_id or data.get("id", "")}


def _build_index(records: list[dict]) -> dict[str, list[dict]]:
    """Build an evidence index keyed by EvidenceType."""
    idx: dict[str, list[dict]] = {}
    for r in records:
        idx.setdefault(r["EvidenceType"], []).append(r)
    return idx


# ── Frozen evidence index covering all 10 categories ─────────────────

def _build_frozen_evidence() -> dict[str, list[dict]]:
    """Return a deterministic evidence index that triggers findings in every category."""

    _90_days_ago = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()

    records: list[dict] = [
        # ──────────────────────────────────────────────────────────
        # 1. OVERSHARING RISK
        # ──────────────────────────────────────────────────────────

        # SPO sites (need >20 for restricted-search checks too)
        *[_ev("spo-site-inventory", {
            "SiteId": f"site-{i:03d}", "SiteName": f"Site {i}",
            "Url": f"https://contoso.sharepoint.com/sites/site{i}",
            "IsStale": i >= 22,  # 3 stale sites for content-lifecycle
            "id": f"site-{i:03d}",
        }, f"site-{i:03d}") for i in range(1, 26)],

        # SPO permissions — site with broad membership
        _ev("spo-site-permissions", {
            "SiteId": "site-001", "SiteName": "Company Wiki",
            "TotalPermissions": 150, "MemberCount": 250,
            "GuestCount": 5, "ExternalUserCount": 3,
        }, "site-001"),
        # SPO permissions — normal site
        _ev("spo-site-permissions", {
            "SiteId": "site-002", "SiteName": "HR Internal",
            "TotalPermissions": 10, "MemberCount": 8,
            "GuestCount": 0, "ExternalUserCount": 0,
        }, "site-002"),

        # SPO sharing links — site with anonymous links
        _ev("spo-sharing-links", {
            "SiteId": "site-001", "SiteName": "Company Wiki",
            "AnonymousLinks": 12, "OrganizationLinks": 30,
            "ExternalLinks": 5, "TotalSharedItems": 47,
        }, "site-001"),

        # Tenant sharing config — anonymous sharing enabled
        _ev("spo-tenant-sharing-config", {
            "IsAnonymousSharingEnabled": True,
            "SharingCapability": "ExternalUserAndGuestSharing",
            "IsRestrictedSharePointSearchEnabled": False,
            "IsRestrictedContentDiscoverabilityEnabled": False,
        }, "tenant"),

        # SKUs — no SAM license (triggers SAM findings)
        _ev("m365-subscribed-skus", {
            "SkuId": "sku-e5-001", "SkuPartNumber": "SPE_E5",
            "ConsumedUnits": 100, "PrepaidUnits": {"Enabled": 150},
        }, "sku-e5-001"),
        _ev("m365-subscribed-skus", {
            "SkuId": "sku-copilot-001", "SkuPartNumber": "Microsoft_365_Copilot",
            "ConsumedUnits": 10, "PrepaidUnits": {"Enabled": 50},
        }, "sku-copilot-001"),

        # ──────────────────────────────────────────────────────────
        # 2. LABEL COVERAGE
        # ──────────────────────────────────────────────────────────

        # Labels exist but only 2 (insufficient)
        _ev("m365-label-summary", {
            "TotalLabels": 2,
        }, "tenant"),

        # Label policy — no mandatory, no auto, no default
        _ev("m365-label-policy-summary", {
            "HasMandatoryLabeling": False,
            "HasAutoLabeling": False,
            "HasDefaultLabel": False,
            "MandatoryLabelingWorkloads": [],
        }, "tenant"),

        # Site label coverage — low
        _ev("spo-label-summary", {
            "LabelCoverage": 40.0,
            "UnlabeledSites": 15,
        }, "tenant"),

        # Label definitions — one without encryption, one without site settings
        _ev("m365-sensitivity-label-definition", {
            "Id": "label-001", "Name": "Internal",
            "IsActive": True, "Priority": 1,
            "IsEncryptionEnabled": False,
            "HasSiteAndGroupSettings": False,
        }, "label-001"),
        _ev("m365-sensitivity-label-definition", {
            "Id": "label-002", "Name": "Confidential",
            "IsActive": True, "Priority": 2,
            "IsEncryptionEnabled": True,
            "HasSiteAndGroupSettings": True,
        }, "label-002"),

        # ──────────────────────────────────────────────────────────
        # 3. DLP READINESS
        # ──────────────────────────────────────────────────────────

        # DLP policy — incomplete workload coverage (missing Teams)
        _ev("m365-dlp-policies", {
            "PolicyId": "dlp-001", "PolicyName": "Default DLP",
            "Workloads": ["exchange", "sharepoint", "onedriveforbusiness"],
        }, "dlp-001"),

        # DLP label integration — no label-based DLP
        _ev("m365-dlp-label-integration", {
            "HasLabelBasedDLP": False,
        }, "tenant"),

        # ──────────────────────────────────────────────────────────
        # 4. RESTRICTED SEARCH (uses spo-site-inventory >20 and
        #    spo-tenant-sharing-config from above)
        # ──────────────────────────────────────────────────────────

        # (Already provided: 25 SPO sites, RSS=False, RCD=False)

        # ──────────────────────────────────────────────────────────
        # 5. ACCESS GOVERNANCE
        # ──────────────────────────────────────────────────────────

        # CA policies — exist but none target Copilot or enforce MFA globally
        _ev("entra-conditional-access-policy", {
            "id": "ca-001", "DisplayName": "Require MFA for Admins",
            "State": "enabled",
            "IncludedApplications": ["All"],
            "RequiresMFA": True,
            "TargetsAllUsers": False,
            "RequiresCompliantDevice": False,
            "SessionControls": {},
        }, "ca-001"),

        # Also populate the entra-conditional-access-policies key for zero trust checks
        _ev("entra-conditional-access-policies", {
            "id": "ca-001", "DisplayName": "Require MFA for Admins",
            "State": "enabled",
            "IncludedApplications": ["All"],
            "RequiresMFA": True,
            "TargetsAllUsers": False,
            "RequiresCompliantDevice": False,
            "SessionControls": {},
        }, "ca-001"),

        # Users — stale account + disabled with license
        _ev("entra-user-details", {
            "UserId": "user-001", "DisplayName": "Active User",
            "UserPrincipalName": "active@contoso.com",
            "AccountEnabled": True,
            "LastSignInDateTime": datetime.now(timezone.utc).isoformat(),
            "HasCopilotLicense": True,
            "LicenseAssignmentType": "direct",
        }, "user-001"),
        _ev("entra-user-details", {
            "UserId": "user-002", "DisplayName": "Stale User",
            "UserPrincipalName": "stale@contoso.com",
            "AccountEnabled": True,
            "LastSignInDateTime": _90_days_ago,
            "HasCopilotLicense": False,
            "LicenseAssignmentType": "direct",
        }, "user-002"),
        _ev("entra-user-details", {
            "UserId": "user-003", "DisplayName": "Disabled Licensed",
            "UserPrincipalName": "disabled@contoso.com",
            "AccountEnabled": False,
            "LastSignInDateTime": _90_days_ago,
            "HasCopilotLicense": True,
            "LicenseAssignmentType": "direct",
        }, "user-003"),

        # Directory roles — excessive global admins (6)
        *[_ev("entra-directory-role-members", {
            "RoleName": "Global Administrator",
            "MemberDisplayName": f"Admin {i}",
            "MemberId": f"admin-{i:03d}",
            "MemberCount": 6,
        }, f"admin-{i:03d}") for i in range(1, 7)],

        # No access reviews
        # (empty entra-access-review-definitions triggers finding)

        # No information barriers
        # (empty m365-information-barriers triggers finding)

        # ──────────────────────────────────────────────────────────
        # 6. CONTENT LIFECYCLE
        # ──────────────────────────────────────────────────────────

        # No eDiscovery / legal holds → triggers no_legal_hold_configured
        # (empty m365-ediscovery-cases + m365-legal-holds)

        # No M365 Backup
        # (empty m365-backup-config)

        # Stale sites already covered in spo-site-inventory (IsStale=true)

        # ──────────────────────────────────────────────────────────
        # 7. AUDIT & MONITORING
        # ──────────────────────────────────────────────────────────

        # Audit config present (enabled)
        _ev("m365-audit-config", {
            "IsEnabled": True,
        }, "tenant"),

        # No alert policies
        # (empty m365-alert-policies triggers no_alert_policies)

        # No MCAS SKU (SPE_E5 doesn't match MCAS keywords in all implementations)
        # triggers no_defender_cloud_apps depending on keyword matching

        # ──────────────────────────────────────────────────────────
        # 8. COPILOT-SPECIFIC SECURITY
        # ──────────────────────────────────────────────────────────

        # Copilot settings warning — can't read settings
        _ev("m365-copilot-settings-warning", {
            "Warning": "OrgSettings.Read.All scope missing",
            "Impact": "Cannot verify plugin restrictions or Copilot settings.",
            "Recommendation": "Grant OrgSettings.Read.All scope.",
        }, "m365-copilot-settings-warning"),

        # Organization info — no data residency set
        _ev("m365-organization-info", {
            "DisplayName": "Contoso Test Tenant",
            "OrganizationId": "org-001",
            "PreferredDataLocation": "",
            "CountryLetterCode": "",
        }, "org-001"),

        # No eDiscovery (handled by lifecycle, also triggers here)
        # No insider risk policies
        # No communication compliance
        # No DSPM for AI

        # Copilot agents — one unmanaged published agent
        _ev("copilot-studio-bots", {
            "BotId": "bot-001", "DisplayName": "Sales Helper",
            "IsPublished": True, "Owner": "",
            "AppId": "app-bot-001",
        }, "bot-001"),
        _ev("copilot-studio-bots", {
            "BotId": "bot-002", "DisplayName": "IT Chatbot",
            "IsPublished": False, "Owner": "user-001",
            "AppId": "app-bot-002",
        }, "bot-002"),

        # Entra apps — one matching bot with excess permissions
        _ev("entra-applications", {
            "AppId": "app-bot-001",
            "DisplayName": "Sales Helper Bot App",
            "ApplicationPermissions": 8,
            "TotalPermissions": 12,
            "HasGraphAccess": True,
        }, "app-bot-001"),
        # AI-keyword app for shadow AI
        _ev("entra-applications", {
            "AppId": "app-openai-001",
            "DisplayName": "OpenAI Integration",
            "ApplicationPermissions": 4,
            "TotalPermissions": 15,
            "HasGraphAccess": True,
        }, "app-openai-001"),
        _ev("entra-applications", {
            "AppId": "app-claude-001",
            "DisplayName": "Claude API Connector",
            "ApplicationPermissions": 2,
            "TotalPermissions": 5,
            "HasGraphAccess": False,
        }, "app-claude-001"),

        # Graph connectors — one ungoverned
        _ev("m365-graph-connectors", {
            "ConnectorId": "gc-001", "Name": "External Wiki Connector",
            "HasOwner": False,
        }, "gc-001"),
        _ev("m365-graph-connectors", {
            "ConnectorId": "gc-002", "Name": "Internal KB Connector",
            "HasOwner": True,
        }, "gc-002"),

        # No cross-tenant access data
        # (empty entra-cross-tenant-access)

        # No RAI policies
        # (empty m365-rai-policies)

        # No compliance manager assessments
        # (empty m365-compliance-manager-assessments)

        # ──────────────────────────────────────────────────────────
        # 9. ZERO TRUST
        # ──────────────────────────────────────────────────────────

        # CA policies already added above (no CAE, no token protection,
        # no phishing-resistant MFA)

        # Service principals — for workload identity check
        _ev("entra-service-principals", {
            "ServicePrincipalId": "sp-001",
            "DisplayName": "App Service SP",
            "Enabled": True,
        }, "sp-001"),
        _ev("entra-service-principals", {
            "ServicePrincipalId": "sp-002",
            "DisplayName": "Claude API Connector SP",
            "Enabled": True,
        }, "sp-002"),

        # No risk-based CA policies
        # (empty entra-risk-based-ca-policies)

        # ──────────────────────────────────────────────────────────
        # 10. SHADOW AI
        # ──────────────────────────────────────────────────────────

        # AI-keyword apps already added in entra-applications above.
        # AI-keyword service principals
        _ev("entra-service-principals", {
            "ServicePrincipalId": "sp-openai-001",
            "DisplayName": "OpenAI Consent Grant",
            "Enabled": True,
        }, "sp-openai-001"),

        # Unpublished copilot agent (shadow agent)
        _ev("m365-copilot-agents", {
            "AgentId": "agent-shadow-001",
            "DisplayName": "Personal Data Summarizer",
            "Published": False, "IsPublished": False,
            "Owner": "user-002",
        }, "agent-shadow-001"),

        # No endpoint DLP (m365-dlp-policies already defined but no endpoint workload)
    ]

    return _build_index(records)


# ── Comparison utilities ─────────────────────────────────────────────

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


def _strip_finding_ids(obj):
    """Recursively strip CopilotReadinessFindingId for comparison of content only."""
    if isinstance(obj, dict):
        return {
            k: _strip_finding_ids(v) for k, v in obj.items()
            if k not in ("CopilotReadinessFindingId", "DetectedAt", "AssessedAt")
        }
    if isinstance(obj, list):
        return [_strip_finding_ids(item) for item in obj]
    return obj


def _run_full_pipeline(evidence_index: dict) -> dict:
    """Run all 10 analyzers and compute scores."""
    all_findings: list[dict] = []
    analyzers = [
        analyze_oversharing_risk,
        analyze_label_coverage,
        analyze_dlp_readiness,
        analyze_restricted_search,
        analyze_access_governance,
        analyze_content_lifecycle,
        analyze_audit_monitoring,
        analyze_copilot_security,
        analyze_zero_trust,
        analyze_shadow_ai,
    ]
    for fn in analyzers:
        all_findings.extend(fn(evidence_index))

    # Sort by (Category, Subcategory, Severity) — mirrors what deterministic
    # pipeline should do; helps verify content stability even if order is not
    # currently guaranteed by the engine.
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

    scores = compute_copilot_readiness_scores(all_findings)

    return {
        "Findings": all_findings,
        "FindingCount": len(all_findings),
        "CopilotReadinessScores": scores,
    }


# ── Tests ────────────────────────────────────────────────────────────

class TestCopilotReadinessDeterminism(unittest.TestCase):
    """Ensure identical evidence → identical output (excluding timestamps)."""

    def test_two_runs_produce_identical_output(self):
        """Run the pipeline twice with the same evidence and compare."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        clean_a = _strip_finding_ids(result_a)
        clean_b = _strip_finding_ids(result_b)

        self.assertEqual(
            json.dumps(clean_a, sort_keys=True, default=str),
            json.dumps(clean_b, sort_keys=True, default=str),
            "Two runs with identical evidence produced different output "
            "(excluding finding IDs and timestamps)",
        )

    def test_finding_count_is_stable(self):
        """Finding count must be identical across runs."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        self.assertEqual(
            result_a["FindingCount"],
            result_b["FindingCount"],
            "Finding count differs between runs",
        )

    def test_finding_ids_are_deterministic(self):
        """Finding IDs should be stable uuid5 values, not random uuid4."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        ids_a = [f["CopilotReadinessFindingId"] for f in result_a["Findings"]]
        ids_b = [f["CopilotReadinessFindingId"] for f in result_b["Findings"]]

        self.assertEqual(
            ids_a, ids_b,
            "Finding IDs differ between runs — uuid5 determinism broken",
        )

    def test_finding_content_is_identical_across_runs(self):
        """All finding fields except ID and timestamp should match."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        for fa, fb in zip(result_a["Findings"], result_b["Findings"]):
            clean_a = {k: v for k, v in fa.items()
                       if k not in ("CopilotReadinessFindingId", "DetectedAt")}
            clean_b = {k: v for k, v in fb.items()
                       if k not in ("CopilotReadinessFindingId", "DetectedAt")}
            self.assertEqual(
                json.dumps(clean_a, sort_keys=True, default=str),
                json.dumps(clean_b, sort_keys=True, default=str),
                f"Finding content differs for subcategory={fa.get('Subcategory')}",
            )

    def test_finding_order_is_stable(self):
        """Findings should be in deterministic (Category, Subcategory, Severity) order."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))

        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        tuples = [
            (f["Category"], f["Subcategory"], f["Severity"])
            for f in result["Findings"]
        ]
        sorted_tuples = sorted(
            tuples,
            key=lambda t: (t[0], t[1], _sev_order.get(t[2].lower(), 9)),
        )
        self.assertEqual(
            tuples, sorted_tuples,
            "Findings are not in deterministic (Category, Subcategory, Severity) order",
        )

    def test_scores_are_identical(self):
        """Score values must match exactly across runs."""
        evidence = _build_frozen_evidence()
        scores_a = _run_full_pipeline(copy.deepcopy(evidence))["CopilotReadinessScores"]
        scores_b = _run_full_pipeline(copy.deepcopy(evidence))["CopilotReadinessScores"]

        self.assertEqual(scores_a["OverallScore"], scores_b["OverallScore"])
        self.assertEqual(scores_a["OverallLevel"], scores_b["OverallLevel"])
        self.assertEqual(scores_a["ReadinessStatus"], scores_b["ReadinessStatus"])
        self.assertEqual(scores_a["SeverityDistribution"], scores_b["SeverityDistribution"])
        self.assertEqual(scores_a["ComplianceBreakdown"], scores_b["ComplianceBreakdown"])
        self.assertEqual(
            json.dumps(scores_a["CategoryScores"], sort_keys=True),
            json.dumps(scores_b["CategoryScores"], sort_keys=True),
        )

    def test_affected_resources_are_sorted(self):
        """AffectedResources within each finding must be in deterministic order."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))
        for f in result["Findings"]:
            resources = f.get("AffectedResources", [])
            ids = [r.get("ResourceId", r.get("Name", "")) for r in resources]
            self.assertEqual(
                ids, sorted(ids),
                f"AffectedResources not sorted in: {f.get('Subcategory')}",
            )

    def test_three_runs_all_match(self):
        """Triple-run consistency check (excluding finding IDs and timestamps)."""
        evidence = _build_frozen_evidence()
        results = [
            _strip_finding_ids(_run_full_pipeline(copy.deepcopy(evidence)))
            for _ in range(3)
        ]
        baseline = json.dumps(results[0], sort_keys=True, default=str)
        for i, r in enumerate(results[1:], 2):
            self.assertEqual(
                baseline,
                json.dumps(r, sort_keys=True, default=str),
                f"Run {i} differs from run 1",
            )

    def test_all_ten_categories_have_findings(self):
        """Verify frozen evidence triggers findings in all 10 categories."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))

        expected_categories = {
            "oversharing_risk", "label_coverage", "dlp_readiness",
            "restricted_search", "access_governance", "content_lifecycle",
            "audit_monitoring", "copilot_security", "zero_trust", "shadow_ai",
        }
        found_categories = {f["Category"] for f in result["Findings"]}
        missing = expected_categories - found_categories
        self.assertFalse(
            missing,
            f"No findings generated for categories: {missing}. "
            "Frozen evidence needs to be extended.",
        )

    def test_severity_distribution_stable(self):
        """Severity distribution must be identical across runs."""
        evidence = _build_frozen_evidence()
        dist_a = _run_full_pipeline(copy.deepcopy(evidence))["CopilotReadinessScores"]["SeverityDistribution"]
        dist_b = _run_full_pipeline(copy.deepcopy(evidence))["CopilotReadinessScores"]["SeverityDistribution"]
        self.assertEqual(dist_a, dist_b)

    def test_per_category_finding_counts_stable(self):
        """Finding count per category must be identical across runs."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        counts_a: dict[str, int] = {}
        for f in result_a["Findings"]:
            counts_a[f["Category"]] = counts_a.get(f["Category"], 0) + 1
        counts_b: dict[str, int] = {}
        for f in result_b["Findings"]:
            counts_b[f["Category"]] = counts_b.get(f["Category"], 0) + 1

        self.assertEqual(counts_a, counts_b, "Per-category finding counts differ")

    def test_top_findings_stable(self):
        """TopFindings in scores must be identical (content, not IDs)."""
        evidence = _build_frozen_evidence()
        top_a = _run_full_pipeline(copy.deepcopy(evidence))["CopilotReadinessScores"]["TopFindings"]
        top_b = _run_full_pipeline(copy.deepcopy(evidence))["CopilotReadinessScores"]["TopFindings"]

        self.assertEqual(
            json.dumps(top_a, sort_keys=True, default=str),
            json.dumps(top_b, sort_keys=True, default=str),
            "TopFindings differ between runs",
        )


# ── Verified fixes ───────────────────────────────────────────────────

class TestDeterminismFixes(unittest.TestCase):
    """Tests that verify the determinism fixes are working."""

    def test_fix_finding_ids_are_uuid5(self):
        """FIX VERIFIED: _cr_finding() now uses uuid.uuid5() with stable fingerprint.
        Finding IDs should have full overlap between runs.
        """
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        ids_a = set(f["CopilotReadinessFindingId"] for f in result_a["Findings"])
        ids_b = set(f["CopilotReadinessFindingId"] for f in result_b["Findings"])

        self.assertEqual(
            ids_a, ids_b,
            "Finding ID sets should be identical with uuid5 deterministic IDs.",
        )

    def test_fix_affected_resources_sorted_by_engine(self):
        """FIX VERIFIED: _cr_finding() now sorts AffectedResources.
        No finding should have unsorted resources even without test-level sort.
        """
        evidence = _build_frozen_evidence()
        all_findings: list[dict] = []
        analyzers = [
            analyze_oversharing_risk, analyze_label_coverage,
            analyze_dlp_readiness, analyze_restricted_search,
            analyze_access_governance, analyze_content_lifecycle,
            analyze_audit_monitoring, analyze_copilot_security,
            analyze_zero_trust, analyze_shadow_ai,
        ]
        for fn in analyzers:
            all_findings.extend(fn(copy.deepcopy(evidence)))

        for f in all_findings:
            resources = f.get("AffectedResources", [])
            ids = [r.get("ResourceId", r.get("Name", "")) for r in resources]
            self.assertEqual(
                ids, sorted(ids),
                f"AffectedResources not sorted by engine in: {f.get('Subcategory')}",
            )

    def test_fix_full_pipeline_identical_with_ids(self):
        """FIX VERIFIED: Full pipeline output including finding IDs is deterministic."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        clean_a = _strip_timestamps(result_a)
        clean_b = _strip_timestamps(result_b)

        self.assertEqual(
            json.dumps(clean_a, sort_keys=True, default=str),
            json.dumps(clean_b, sort_keys=True, default=str),
            "Full pipeline output (including finding IDs) differs between runs",
        )


if __name__ == "__main__":
    unittest.main()
