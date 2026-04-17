"""Copilot Readiness orchestrator — runs all evaluators and builds the final assessment result."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from app.auth import ComplianceCredentials
from app.copilot_evaluators.finding import _CR_FINDING_NS
from app.copilot_evaluators.oversharing import analyze_oversharing_risk
from app.copilot_evaluators.labels import analyze_label_coverage
from app.copilot_evaluators.dlp import analyze_dlp_readiness
from app.copilot_evaluators.restricted_search import analyze_restricted_search
from app.copilot_evaluators.access_governance import analyze_access_governance
from app.copilot_evaluators.content_lifecycle import analyze_content_lifecycle
from app.copilot_evaluators.audit_monitoring import analyze_audit_monitoring
from app.copilot_evaluators.copilot_security import analyze_copilot_security
from app.copilot_evaluators.zero_trust import analyze_zero_trust
from app.copilot_evaluators.shadow_ai import analyze_shadow_ai
from app.copilot_evaluators.scoring import compute_copilot_readiness_scores
from app.copilot_evaluators.controls_matrix import build_security_controls_matrix, _EFFORT_MAP
from app.copilot_evaluators.enrichment import enrich_compliance_mapping
from app.copilot_evaluators.inventory import (
    _build_site_inventory, _build_license_inventory, _build_label_inventory,
    _build_app_protection_inventory, _build_ca_policy_inventory,
    _build_groups_inventory, _build_dlp_inventory,
    _build_entra_apps_inventory, _build_service_principal_inventory,
)
from app.copilot_evaluators.collector import _cr_collect

log = logging.getLogger(__name__)


async def run_copilot_readiness_assessment(
    creds: ComplianceCredentials,
    evidence: list[dict] | None = None,
    subscriptions: list[dict] | None = None,
) -> dict:
    """Run complete M365 Copilot readiness assessment.

    Reuses evidence from a prior assessment if provided;
    otherwise collects SPO/OneDrive and M365 label evidence.
    """
    if subscriptions is None:
        subscriptions = await creds.list_subscriptions()

    evidence_index: dict[str, list[dict]] = {}
    if evidence:
        for ev in evidence:
            etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
            if etype:
                evidence_index.setdefault(etype, []).append(ev)

    has_evidence = bool(evidence_index)
    if not has_evidence:
        log.info("No existing evidence — running targeted collection for Copilot readiness")
        evidence_index = await _cr_collect(creds, subscriptions)

    log.info("Running oversharing risk analysis …")
    oversharing_findings = analyze_oversharing_risk(evidence_index)

    log.info("Running sensitivity label coverage analysis …")
    label_findings = analyze_label_coverage(evidence_index)

    log.info("Running DLP readiness analysis …")
    dlp_findings = analyze_dlp_readiness(evidence_index)

    log.info("Running Restricted SharePoint Search analysis …")
    rss_findings = analyze_restricted_search(evidence_index)

    log.info("Running data access governance analysis …")
    access_findings = analyze_access_governance(evidence_index)

    log.info("Running content lifecycle analysis …")
    lifecycle_findings = analyze_content_lifecycle(evidence_index)

    log.info("Running audit & monitoring analysis …")
    audit_findings = analyze_audit_monitoring(evidence_index)

    log.info("Running Copilot-specific security analysis …")
    copilot_sec_findings = analyze_copilot_security(evidence_index)

    log.info("Running Zero Trust posture analysis …")
    zero_trust_findings = analyze_zero_trust(evidence_index)

    log.info("Running Shadow AI risk analysis …")
    shadow_ai_findings = analyze_shadow_ai(evidence_index)

    all_findings = (
        oversharing_findings + label_findings + dlp_findings
        + rss_findings + access_findings + lifecycle_findings
        + audit_findings + copilot_sec_findings
        + zero_trust_findings + shadow_ai_findings
    )

    # Tag each finding with remediation effort estimate
    for f in all_findings:
        sc = f.get("Subcategory", "")
        f["Effort"] = _EFFORT_MAP.get(sc, "moderate")

    # Enrich each finding with compliance framework mappings
    enrich_compliance_mapping(all_findings)

    # ── Deterministic ordering ───────────────────────────────────────
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            _sev_order.get(f.get("Severity", "medium").lower(), 9),
        )
    )

    log.info("Computing Copilot readiness scores (%d findings) …", len(all_findings))
    scores = compute_copilot_readiness_scores(all_findings)

    log.info("Building security controls matrix …")
    controls_matrix = build_security_controls_matrix(all_findings)

    # Build inventories for report
    site_inventory = _build_site_inventory(evidence_index)
    license_inventory = _build_license_inventory(evidence_index)
    label_inventory = _build_label_inventory(evidence_index)
    ca_policy_inventory = _build_ca_policy_inventory(evidence_index)
    groups_inventory = _build_groups_inventory(evidence_index)
    dlp_inventory = _build_dlp_inventory(evidence_index)
    entra_apps_inventory = _build_entra_apps_inventory(evidence_index)
    service_principal_inventory = _build_service_principal_inventory(evidence_index)
    app_protection_inventory = _build_app_protection_inventory(evidence_index)

    # Extract tenant info from organization evidence
    _org_ev = evidence_index.get("m365-organization-info", [])
    _org_data = (_org_ev[0].get("Data", _org_ev[0].get("data", {})) if _org_ev else {})
    _tenant_display = _org_data.get("DisplayName", "")
    _tenant_org_id = _org_data.get("OrganizationId", "")

    return {
        "AssessmentId": str(uuid.uuid5(
            _CR_FINDING_NS,
            f"cr-assessment|{creds.tenant_id}|{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M')}",
        )),
        "AssessmentType": "M365CopilotReadiness",
        "AssessedAt": datetime.now(timezone.utc).isoformat(),
        "TenantId": creds.tenant_id,
        "TenantDisplayName": _tenant_display,
        "SubscriptionCount": len(subscriptions),
        "EvidenceSource": "existing_assessment" if has_evidence else "targeted_collection",
        "EvidenceRecordCount": sum(len(v) for v in evidence_index.values()),
        "CopilotReadinessScores": scores,
        "Findings": all_findings,
        "FindingCount": len(all_findings),
        "SecurityControlsMatrix": controls_matrix,
        "SiteInventory": site_inventory,
        "LicenseInventory": license_inventory,
        "LabelInventory": label_inventory,
        "CAPolicyInventory": ca_policy_inventory,
        "GroupsInventory": groups_inventory,
        "DLPInventory": dlp_inventory,
        "EntraAppsInventory": entra_apps_inventory,
        "ServicePrincipalInventory": service_principal_inventory,
        "AppProtectionInventory": app_protection_inventory,
        "Categories": {
            "oversharing_risk": oversharing_findings,
            "label_coverage": label_findings,
            "dlp_readiness": dlp_findings,
            "restricted_search": rss_findings,
            "access_governance": access_findings,
            "content_lifecycle": lifecycle_findings,
            "audit_monitoring": audit_findings,
            "copilot_security": copilot_sec_findings,
            "zero_trust": zero_trust_findings,
            "shadow_ai": shadow_ai_findings,
        },
        "CategoryCounts": {
            "oversharing_risk": len(oversharing_findings),
            "label_coverage": len(label_findings),
            "dlp_readiness": len(dlp_findings),
            "restricted_search": len(rss_findings),
            "access_governance": len(access_findings),
            "content_lifecycle": len(lifecycle_findings),
            "audit_monitoring": len(audit_findings),
            "copilot_security": len(copilot_sec_findings),
            "zero_trust": len(zero_trust_findings),
            "shadow_ai": len(shadow_ai_findings),
        },
    }
