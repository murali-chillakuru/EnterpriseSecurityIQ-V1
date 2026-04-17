"""
Evaluation Engine
Loads framework mappings, indexes evidence, dispatches to domain evaluators.
Supports: FedRAMP, CIS, ISO-27001, NIST-800-53, PCI-DSS, MCSB,
          HIPAA, SOC2, GDPR, NIST-CSF, CSA-CCM.

Scoring: severity-weighted compliance scoring with partial credit.
"""

from __future__ import annotations
import json, pathlib
from typing import Any
from app.models import (
    FindingRecord, Status, Severity,
)
from app.config import ThresholdConfig
from app.logger import log
from app.postureiq_evaluators import access, identity, data_protection, logging_eval, network, governance
from app.postureiq_evaluators import incident_response, change_management, business_continuity, asset_management
from app.postureiq_reports.evidence_catalog import enrich_missing_evidence

FRAMEWORKS_DIR = pathlib.Path(__file__).parent.parent / "postureiq_frameworks"

AVAILABLE_FRAMEWORKS = {
    "FedRAMP": "fedramp-mappings.json",
    "CIS": "cis-mappings.json",
    "ISO-27001": "iso-27001-mappings.json",
    "NIST-800-53": "nist-800-53-mappings.json",
    "PCI-DSS": "pci-dss-mappings.json",
    "MCSB": "mcsb-mappings.json",
    "HIPAA": "hipaa-mappings.json",
    "SOC2": "soc2-mappings.json",
    "GDPR": "gdpr-mappings.json",
    "NIST-CSF": "nist-csf-mappings.json",
    "CSA-CCM": "csa-ccm-mappings.json",
}

# Severity weights for compliance scoring
_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# ── Risk Scoring Factors ─────────────────────────────────────────────────
# Exploitability: how easy it is to exploit a misconfiguration.
# Blast radius: how wide the impact if exploited.
# Combined with severity to produce a 0-100 risk score per finding.

_EXPLOITABILITY = {
    # Check function name → exploitability factor (0.0-1.0)
    # 1.0 = trivially exploitable (public exposure), 0.3 = requires insider access
    "check_network_segmentation": 0.8,
    "check_nsg_rules": 0.9,
    "check_storage_security": 0.9,
    "check_firewall_protection": 0.7,
    "check_account_management": 0.6,
    "check_mfa_enforcement": 0.95,
    "check_conditional_access": 0.85,
    "check_pim_configuration": 0.5,
    "check_encryption_at_rest": 0.4,
    "check_encryption_in_transit": 0.8,
    "check_key_management": 0.5,
    "check_sql_security": 0.7,
    "check_aks_security": 0.7,
    "check_diagnostic_settings": 0.3,
    "check_nsg_flow_logs": 0.3,
    "check_policy_compliance": 0.4,
    "check_continuous_monitoring": 0.3,
    "check_private_endpoint_adoption": 1.0,
    "check_webapp_detailed_security": 0.8,
    "check_container_app_network": 0.7,
    "check_apim_network_security": 0.7,
    "check_dns_security": 0.6,
    "check_sentinel_monitoring": 0.3,
    "check_workload_identity_security": 0.6,
    "check_auth_methods_security": 0.8,
}

_BLAST_RADIUS = {
    # Domain → blast radius factor (0.0-1.0)
    # 1.0 = tenant-wide impact, 0.4 = single resource
    "identity": 1.0,
    "access": 0.9,
    "network": 0.8,
    "data_protection": 0.7,
    "governance": 0.6,
    "logging": 0.4,
    "incident_response": 0.5,
    "change_management": 0.4,
    "business_continuity": 0.5,
    "asset_management": 0.3,
}


def compute_risk_score(finding: dict) -> float:
    """Compute a 0-100 risk score for a single finding.

    Formula: severity_weight × exploitability × blast_radius × 100 / max_possible
    Where max_possible = 4 (critical) × 1.0 × 1.0 = 4.0
    """
    sev = finding.get("Severity", "medium")
    sev_w = _SEVERITY_WEIGHT.get(sev, 2) / 4.0  # normalise to 0-1
    check = finding.get("EvaluationLogic", "")
    exploit = _EXPLOITABILITY.get(check, 0.5)
    domain = finding.get("Domain", "")
    blast = _BLAST_RADIUS.get(domain, 0.5)
    return round(sev_w * exploit * blast * 100, 1)


def enrich_findings_with_risk(findings: list[dict]) -> list[dict]:
    """Add RiskScore and RiskTier to each finding."""
    for f in findings:
        if f.get("Status") != "non_compliant":
            continue
        score = compute_risk_score(f)
        f["RiskScore"] = score
        if score >= 75:
            f["RiskTier"] = "Critical"
        elif score >= 50:
            f["RiskTier"] = "High"
        elif score >= 25:
            f["RiskTier"] = "Medium"
        else:
            f["RiskTier"] = "Low"
    return findings


# Domain → evaluator dispatch map
DOMAIN_EVALUATORS = {
    "access": access.evaluate_access,
    "identity": identity.evaluate_identity,
    "data_protection": data_protection.evaluate_data_protection,
    "logging": logging_eval.evaluate_logging,
    "network": network.evaluate_network,
    "governance": governance.evaluate_governance,
    "incident_response": incident_response.evaluate_incident_response,
    "change_management": change_management.evaluate_change_management,
    "business_continuity": business_continuity.evaluate_business_continuity,
    "asset_management": asset_management.evaluate_asset_management,
}

# Cross-domain dispatch: evaluation_logic → hosting domain.
# Used as fallback when a control's domain evaluator doesn't have the handler.
_CROSS_DOMAIN_MAP: dict[str, str] = {
    "check_storage_security": "network",
    "check_user_lifecycle": "identity",
    "check_vm_security": "data_protection",
    "check_pim_configuration": "governance",
    "check_account_management": "access",
    "check_nsg_flow_logs": "logging",
    "check_aks_security": "data_protection",
    "check_nsg_rules": "network",
    "check_sql_security": "data_protection",
    "check_continuous_monitoring": "governance",
    "check_policy_compliance": "governance",
    "check_function_app_security": "data_protection",
    "check_messaging_security": "data_protection",
    "check_redis_security": "data_protection",
    "check_cosmosdb_advanced_security": "data_protection",
    "check_data_analytics_security": "data_protection",
    "check_purview_classification": "data_protection",
    "check_dns_security": "network",
    "check_aks_advanced_security": "network",
    "check_apim_advanced_security": "network",
    "check_frontdoor_cdn_security": "network",
    "check_private_endpoint_adoption": "network",
    "check_sentinel_monitoring": "incident_response",
    "check_alert_response_coverage": "incident_response",
    "check_defender_posture_advanced": "governance",
    "check_ai_content_safety": "governance",
    "check_regulatory_compliance": "governance",
    "check_workload_identity_security": "identity",
    "check_auth_methods_security": "identity",
    "check_managed_identity_hygiene": "identity",
}


def _load_mappings(framework: str = "FedRAMP") -> tuple[str, list[dict]]:
    """Load mappings for a specific framework. Returns (framework_name, controls)."""
    filename = AVAILABLE_FRAMEWORKS.get(framework)
    if not filename:
        log.warning("Unknown framework '%s', falling back to FedRAMP", framework)
        filename = AVAILABLE_FRAMEWORKS["FedRAMP"]
        framework = "FedRAMP"
    path = FRAMEWORKS_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    controls = data.get("controls", data) if isinstance(data, dict) else data
    fw_name = data.get("frameworkName", framework) if isinstance(data, dict) else framework
    return fw_name, controls


def _index_evidence(evidence: list[dict]) -> dict[str, list[dict]]:
    """Index evidence by EvidenceType for fast lookup.

    Each list is sorted by ResourceId for deterministic iteration order.
    """
    idx: dict[str, list[dict]] = {}
    for e in evidence:
        etype = e.get("EvidenceType", "")
        if etype:
            idx.setdefault(etype, []).append(e)
    # Sort each list by ResourceId for deterministic evaluator traversal
    for etype in idx:
        idx[etype].sort(key=lambda e: e.get("ResourceId", ""))
    return idx


def evaluate_all(
    evidence: list[dict],
    frameworks: list[str] | None = None,
    domains: list[str] | None = None,
    thresholds: ThresholdConfig | None = None,
) -> dict[str, Any]:
    """
    Run compliance evaluations against collected evidence for one or more frameworks.
    Optionally filter to specific domains (e.g. ['access', 'network']).
    Returns dict with findings, control_results, summary, framework_summaries.
    """
    if not frameworks:
        frameworks = ["FedRAMP"]
    if thresholds is None:
        thresholds = ThresholdConfig()

    idx = _index_evidence(evidence)

    all_findings: list[dict] = []
    control_results: list[dict] = []
    missing_evidence: list[dict] = []
    framework_summaries: dict[str, dict] = {}

    for fw_key in frameworks:
        fw_name, mappings = _load_mappings(fw_key)
        log.info("Evaluating framework: %s (%d controls)", fw_name, len(mappings))

        fw_findings: list[dict] = []
        fw_controls: list[dict] = []
        fw_missing: list[dict] = []

        for control in mappings:
            control_id = control["control_id"]
            domain = control.get("domain", "")
            severity = control.get("severity", "medium")
            title = control.get("title", "")
            evidence_types = control.get("evidence_types", [])
            eval_func_name = control.get("evaluation_logic", "")
            recommendation = control.get("recommendation", "")

            # Skip domains not in the filter (if specified)
            if domains and domain not in domains:
                continue

            # Gather relevant evidence (primary + compensating)
            relevant = []
            missing_types = []
            for etype in evidence_types:
                items = idx.get(etype, [])
                if items:
                    relevant.extend(items)
                else:
                    missing_types.append(etype)

            # Compensating control logic: if primary evidence is missing,
            # check whether alternative evidence can satisfy the control.
            compensating_types = control.get("compensating_evidence", [])
            compensating_used = []
            if missing_types and not relevant and compensating_types:
                for ctype in compensating_types:
                    comp_items = idx.get(ctype, [])
                    if comp_items:
                        relevant.extend(comp_items)
                        compensating_used.append(ctype)
                if compensating_used:
                    log.debug("Compensating evidence for %s: %s",
                              control_id, compensating_used)

            if missing_types and not relevant:
                fw_missing.append({
                    "ControlId": control_id,
                    "Framework": fw_key,
                    "MissingTypes": missing_types,
                    "Severity": severity,
                })
                fw_controls.append({
                    "ControlId": control_id,
                    "Framework": fw_key,
                    "ControlTitle": title,
                    "Status": Status.MISSING_EVIDENCE.value,
                    "Severity": severity,
                    "Domain": domain,
                    "FindingCount": 0,
                    "EvidenceCount": 0,
                })
                continue

            # Dispatch to domain evaluator
            evaluator = DOMAIN_EVALUATORS.get(domain)
            if not evaluator:
                log.warning("No evaluator for domain %s (control %s)", domain, control_id)
                continue

            # Inject framework into control dict for evaluators
            control["_framework"] = fw_key

            try:
                findings = evaluator(
                    control_id=control_id,
                    control=control,
                    evidence=relevant,
                    evidence_index=idx,
                    thresholds=thresholds,
                )

                # Cross-domain fallback: if primary evaluator returned
                # not_assessed (no handler), try the domain that owns the
                # evaluation_logic function.
                if (findings
                        and all(f.get("Status") == "not_assessed" for f in findings)):
                    alt_domain = _CROSS_DOMAIN_MAP.get(eval_func_name)
                    if alt_domain and alt_domain != domain:
                        alt_eval = DOMAIN_EVALUATORS.get(alt_domain)
                        if alt_eval:
                            try:
                                alt_findings = alt_eval(
                                    control_id=control_id,
                                    control=control,
                                    evidence=relevant,
                                    evidence_index=idx,
                                    thresholds=thresholds,
                                )
                                if not all(f.get("Status") == "not_assessed"
                                           for f in alt_findings):
                                    findings = alt_findings
                                    log.debug("Cross-domain: %s (%s→%s)",
                                              control_id, domain, alt_domain)
                            except Exception:
                                pass  # keep original findings

                # Tag findings with the correct framework
                for f in findings:
                    f["Framework"] = fw_key
                    f["EvaluationLogic"] = eval_func_name
            except Exception as exc:
                log.error("Evaluator error for %s: %s", control_id, exc)
                findings = [FindingRecord(
                    control_id=control_id,
                    framework=fw_key,
                    control_title=title,
                    status=Status.NON_COMPLIANT,
                    severity=Severity(severity),
                    domain=domain,
                    description=f"Evaluation error: {exc}",
                    recommendation=recommendation,
                ).to_dict()]

            # Determine overall control status
            statuses = [f.get("Status", "not_assessed") for f in findings]
            if any(s == "non_compliant" for s in statuses):
                overall = Status.NON_COMPLIANT.value
            elif all(s == "compliant" for s in statuses):
                overall = Status.COMPLIANT.value
            elif any(s in ("partial", "missing_evidence") for s in statuses) or missing_types:
                overall = Status.PARTIAL.value
            elif any(s == "not_assessed" for s in statuses):
                overall = Status.NOT_ASSESSED.value
            else:
                overall = Status.COMPLIANT.value

            fw_controls.append({
                "ControlId": control_id,
                "Framework": fw_key,
                "ControlTitle": title,
                "Status": overall,
                "Severity": severity,
                "Domain": domain,
                "FindingCount": len(findings),
                "EvidenceCount": len(relevant),
            })

            # Sort findings for deterministic output order
            findings.sort(key=lambda f: (f.get("Description", ""), f.get("ResourceId", "")))
            fw_findings.extend(findings)

        # Sort framework-level lists for deterministic output
        fw_findings.sort(key=lambda f: (f.get("ControlId", ""), f.get("Description", ""), f.get("ResourceId", "")))
        fw_controls.sort(key=lambda c: c["ControlId"])
        fw_missing.sort(key=lambda m: m["ControlId"])

        # Per-framework summary (severity-weighted scoring)
        fw_total = len(fw_controls)
        fw_compliant = sum(1 for c in fw_controls if c["Status"] == "compliant")
        fw_score = _weighted_score(fw_controls)
        framework_summaries[fw_key] = {
            "FrameworkName": fw_name,
            "TotalControls": fw_total,
            "Compliant": fw_compliant,
            "NonCompliant": sum(1 for c in fw_controls if c["Status"] == "non_compliant"),
            "Partial": sum(1 for c in fw_controls if c["Status"] == "partial"),
            "MissingEvidence": sum(1 for c in fw_controls if c["Status"] == "missing_evidence"),
            "NotAssessed": sum(1 for c in fw_controls if c["Status"] == "not_assessed"),
            "ComplianceScore": fw_score,
        }
        log.info("  %s: %d controls, score %.1f%%", fw_key, fw_total, fw_score)

        all_findings.extend(fw_findings)
        control_results.extend(fw_controls)
        missing_evidence.extend(fw_missing)

    # Overall summary across all frameworks (severity-weighted scoring)
    total_controls = len(control_results)
    compliant = sum(1 for c in control_results if c["Status"] == "compliant")
    non_compliant = sum(1 for c in control_results if c["Status"] == "non_compliant")
    partial = sum(1 for c in control_results if c["Status"] == "partial")
    missing = sum(1 for c in control_results if c["Status"] == "missing_evidence")
    not_assessed = sum(1 for c in control_results if c["Status"] == "not_assessed")
    score = _weighted_score(control_results)

    # Enrich non-compliant findings with risk scores
    enrich_findings_with_risk(all_findings)

    # Risk summary
    nc_findings = [f for f in all_findings if f.get("Status") == "non_compliant"]
    risk_summary = {
        "CriticalRisk": sum(1 for f in nc_findings if f.get("RiskTier") == "Critical"),
        "HighRisk": sum(1 for f in nc_findings if f.get("RiskTier") == "High"),
        "MediumRisk": sum(1 for f in nc_findings if f.get("RiskTier") == "Medium"),
        "LowRisk": sum(1 for f in nc_findings if f.get("RiskTier") == "Low"),
        "TopRisks": sorted(
            [{"ControlId": f.get("ControlId"), "Description": f.get("Description", "")[:120],
              "RiskScore": f.get("RiskScore", 0), "RiskTier": f.get("RiskTier", ""),
              "Domain": f.get("Domain", ""), "ResourceId": f.get("ResourceId", "")}
             for f in nc_findings if f.get("RiskScore", 0) >= 50],
            key=lambda x: x["RiskScore"], reverse=True,
        )[:20],
    }

    summary = {
        "TotalControls": total_controls,
        "Compliant": compliant,
        "NonCompliant": non_compliant,
        "Partial": partial,
        "MissingEvidence": missing,
        "NotAssessed": not_assessed,
        "ComplianceScore": score,
        "TotalFindings": len(all_findings),
        "TotalEvidence": len(evidence),
        "CriticalFindings": sum(1 for f in all_findings if f.get("Severity") == "critical"),
        "HighFindings": sum(1 for f in all_findings if f.get("Severity") == "high"),
        "MediumFindings": sum(1 for f in all_findings if f.get("Severity") == "medium"),
        "Frameworks": frameworks,
        "FrameworkSummaries": framework_summaries,
        "DomainScores": _domain_scores(control_results),
        "OverallMaturity": _maturity_level(control_results),
        "RiskSummary": risk_summary,
    }

    log.info("Evaluation complete: %d frameworks, %d controls, score %.1f%%, critical-risk findings: %d",
             len(frameworks), total_controls, score, risk_summary["CriticalRisk"])
    return {
        "findings": all_findings,
        "control_results": control_results,
        "missing_evidence": enrich_missing_evidence(missing_evidence),
        "summary": summary,
    }


def _weighted_score(controls: list[dict]) -> float:
    """Severity-weighted compliance score with partial credit.

    - Compliant controls earn full weight.
    - Partial controls earn 50% weight.
    - Missing evidence and not-assessed controls are excluded
      from scoring (they don't drag the score down).
    - Non-compliant controls earn 0.
    """
    earned = 0.0
    possible = 0.0
    for c in controls:
        status = c.get("Status", "not_assessed")
        # Exclude missing_evidence and not_assessed from scoring
        if status in ("missing_evidence", "not_assessed"):
            continue
        w = _SEVERITY_WEIGHT.get(c.get("Severity", "medium"), 2)
        possible += w
        if status == "compliant":
            earned += w
        elif status == "partial":
            earned += w * 0.5
    return round((earned / possible) * 100, 1) if possible > 0 else 0.0


def _domain_scores(control_results: list[dict]) -> dict[str, dict]:
    """Severity-weighted domain scores with partial credit.

    Controls with ``missing_evidence`` are tracked separately and excluded
    from the Total/Compliant counts so absent resources don't reduce scores.
    """
    domains: dict[str, dict] = {}
    for cr in control_results:
        d = cr.get("Domain", "other")
        if d not in domains:
            domains[d] = {"Total": 0, "Compliant": 0, "MissingEvidence": 0, "controls": []}
        if cr["Status"] == "missing_evidence":
            domains[d]["MissingEvidence"] += 1
        else:
            domains[d]["Total"] += 1
            if cr["Status"] == "compliant":
                domains[d]["Compliant"] += 1
        domains[d]["controls"].append(cr)
    for d in domains:
        ctrls = domains[d].pop("controls")
        domains[d]["Score"] = _weighted_score(ctrls)
        domains[d]["MaturityLevel"] = _maturity_level(ctrls)
    return domains


# ── Maturity Levels ──────────────────────────────────────────────────────
# Beyond pass/fail, score each domain on a maturity scale:
#   1-Initial  2-Managed  3-Defined  4-Measured  5-Optimized
# Based on the ratio of passing controls *and* the depth of critical coverage.

_MATURITY_LABELS = {1: "Initial", 2: "Managed", 3: "Defined", 4: "Measured", 5: "Optimized"}


def _maturity_level(controls: list[dict]) -> dict:
    """Calculate maturity level for a set of controls in one domain.

    Factors:
      - pass_ratio:    fraction of scored controls that are compliant/partial
      - critical_pass: fraction of critical+high controls that pass
      - depth_ratio:   fraction of controls that have evidence (not missing/not_assessed)
    """
    if not controls:
        return {"Level": 1, "Label": "Initial"}

    scored = [c for c in controls
              if c.get("Status") not in ("missing_evidence", "not_assessed")]
    total_scored = len(scored)

    if total_scored == 0:
        return {"Level": 1, "Label": "Initial"}

    pass_count = sum(1 for c in scored if c["Status"] in ("compliant", "partial"))
    pass_ratio = pass_count / total_scored

    critical_high = [c for c in scored if c.get("Severity") in ("critical", "high")]
    critical_pass = (
        sum(1 for c in critical_high if c["Status"] in ("compliant", "partial"))
        / len(critical_high)
    ) if critical_high else pass_ratio

    depth_ratio = total_scored / len(controls) if controls else 0

    # Composite score (0-100)
    composite = (pass_ratio * 50) + (critical_pass * 30) + (depth_ratio * 20)

    if composite >= 90:
        level = 5
    elif composite >= 75:
        level = 4
    elif composite >= 55:
        level = 3
    elif composite >= 30:
        level = 2
    else:
        level = 1

    return {"Level": level, "Label": _MATURITY_LABELS[level]}
