"""
Copilot Readiness — Compliance framework mapping enrichment.

Maps every Copilot readiness finding subcategory to 11 compliance frameworks:
CIS, NIST-800-53, NIST-CSF, ISO-27001, PCI-DSS, HIPAA, SOC2, GDPR, FedRAMP, MCSB, CSA-CCM
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Subcategory → framework control-ID mapping
# 11 frameworks per subcategory
# ══════════════════════════════════════════════════════════════════════════════

_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    # ── Oversharing Risk ─────────────────────────────────────────────────
    "unable_to_assess": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CA-2", "RA-3"], "NIST-CSF": ["ID.RA-1"],
        "ISO-27001": ["A.5.25"], "PCI-DSS": ["12.2"], "HIPAA": ["164.308(a)(8)"],
        "SOC2": ["CC3.2"], "GDPR": ["Art.35(1)"], "FedRAMP": ["CA-2", "RA-3"],
        "MCSB": ["GS-1"], "CSA-CCM": ["GRC-01"],
    },
    "broad_site_membership": {
        "CIS": ["1.22"], "NIST-800-53": ["AC-6", "AC-3"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.5.18"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"], "FedRAMP": ["AC-6", "AC-6(1)"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-05", "DSP-10"],
    },
    "everyone_permissions": {
        "CIS": ["1.22"], "NIST-800-53": ["AC-3", "AC-6"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.8.3"], "PCI-DSS": ["7.1", "7.2.1"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(4)"], "SOC2": ["CC6.1"],
        "GDPR": ["Art.25(2)", "Art.32(1)"], "FedRAMP": ["AC-3", "AC-6"],
        "MCSB": ["PA-7", "DP-9"], "CSA-CCM": ["IAM-05", "DSP-10"],
    },
    "anonymous_link_exposure": {
        "CIS": ["3.7"], "NIST-800-53": ["AC-3", "AC-4"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.5.14", "A.8.3"], "PCI-DSS": ["7.1", "1.3.1"],
        "HIPAA": ["164.312(a)(1)", "164.312(e)(1)"], "SOC2": ["CC6.1", "CC6.7"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-3", "SC-7"],
        "MCSB": ["DP-9", "NS-1"], "CSA-CCM": ["DSP-10", "IVS-03"],
    },
    "external_sharing_posture": {
        "CIS": ["3.7"], "NIST-800-53": ["AC-4", "SC-7"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.5.14", "A.8.3"], "PCI-DSS": ["1.3.1", "7.1"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["CC6.1", "CC6.7"],
        "GDPR": ["Art.44", "Art.32(1)"], "FedRAMP": ["AC-4", "SC-7"],
        "MCSB": ["DP-9"], "CSA-CCM": ["DSP-10", "DSP-14"],
    },
    "no_sharepoint_advanced_management": {
        "CIS": ["3.7"], "NIST-800-53": ["AC-6", "CA-7"], "NIST-CSF": ["DE.CM-3"],
        "ISO-27001": ["A.5.15", "A.8.16"], "PCI-DSS": ["7.1", "10.6"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC6.1", "CC4.1"],
        "GDPR": ["Art.25(1)", "Art.32(1)"], "FedRAMP": ["AC-6", "CA-7"],
        "MCSB": ["PA-7", "GS-1"], "CSA-CCM": ["IAM-05", "GRC-01"],
    },
    "no_sam_restricted_access_control": {
        "CIS": ["1.22"], "NIST-800-53": ["AC-3", "AC-6"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.8.3"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.32(1)"], "FedRAMP": ["AC-3", "AC-6"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-10", "DSP-05"],
    },
    "no_sam_site_lifecycle_policy": {
        "CIS": ["3.11"], "NIST-800-53": ["MP-6", "SI-12"], "NIST-CSF": ["PR.DS-3"],
        "ISO-27001": ["A.8.10", "A.5.33"], "PCI-DSS": ["3.1", "9.4"],
        "HIPAA": ["164.310(d)(2)(i)"], "SOC2": ["CC6.5", "A1.1"],
        "GDPR": ["Art.5(1e)", "Art.17(1)"], "FedRAMP": ["MP-6", "SI-12"],
        "MCSB": ["DP-8"], "CSA-CCM": ["DSP-16", "BCR-03"],
    },
    "no_sam_dag_reports": {
        "CIS": ["1.22"], "NIST-800-53": ["AC-6", "CA-7"], "NIST-CSF": ["DE.CM-3"],
        "ISO-27001": ["A.5.15", "A.8.16"], "PCI-DSS": ["7.1", "10.6"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC4.1", "CC6.1"],
        "GDPR": ["Art.25(1)", "Art.5(2)"], "FedRAMP": ["AC-6", "CA-7"],
        "MCSB": ["PA-7", "GS-1"], "CSA-CCM": ["IAM-05", "GRC-01"],
    },
    "high_permission_blast_radius": {
        "CIS": ["1.22"], "NIST-800-53": ["AC-6", "AC-6(1)"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.5.18"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(4)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"], "FedRAMP": ["AC-6", "AC-6(1)"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-05", "IAM-10"],
    },
    "external_sharing_risk_score": {
        "CIS": ["3.7"], "NIST-800-53": ["AC-4", "SC-7"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.5.14", "A.8.3"], "PCI-DSS": ["1.3.1", "7.1"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["CC6.1", "CC6.7"],
        "GDPR": ["Art.44", "Art.46"], "FedRAMP": ["AC-4", "SC-7"],
        "MCSB": ["DP-9", "NS-1"], "CSA-CCM": ["DSP-10", "DSP-14"],
    },
    # ── Label Coverage ───────────────────────────────────────────────────
    "label_api_inaccessible": {
        "CIS": ["3.1"], "NIST-800-53": ["CA-2", "RA-3"], "NIST-CSF": ["ID.RA-1"],
        "ISO-27001": ["A.5.25"], "PCI-DSS": ["12.2"], "HIPAA": ["164.308(a)(8)"],
        "SOC2": ["CC3.2"], "GDPR": ["Art.35(1)"], "FedRAMP": ["CA-2", "RA-3"],
        "MCSB": ["GS-1"], "CSA-CCM": ["GRC-01"],
    },
    "no_labels_defined": {
        "CIS": ["3.1"], "NIST-800-53": ["MP-4", "RA-2"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.5.12", "A.5.13"], "PCI-DSS": ["3.4", "9.6.1"],
        "HIPAA": ["164.312(a)(2)(iv)", "164.312(c)(1)"], "SOC2": ["C1.1", "CC6.1"],
        "GDPR": ["Art.25(1)", "Art.32(1)"], "FedRAMP": ["RA-2", "MP-4"],
        "MCSB": ["DP-1", "DP-2"], "CSA-CCM": ["DSP-05", "DSP-01"],
    },
    "insufficient_labels": {
        "CIS": ["3.1"], "NIST-800-53": ["RA-2", "MP-4"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.5.12", "A.5.13"], "PCI-DSS": ["9.6.1"],
        "HIPAA": ["164.312(c)(1)"], "SOC2": ["C1.1"],
        "GDPR": ["Art.25(1)"], "FedRAMP": ["RA-2"],
        "MCSB": ["DP-1"], "CSA-CCM": ["DSP-05"],
    },
    "no_mandatory_labeling": {
        "CIS": ["3.1"], "NIST-800-53": ["MP-4", "AC-3"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.5.12", "A.5.13"], "PCI-DSS": ["3.4", "9.6.1"],
        "HIPAA": ["164.312(c)(1)"], "SOC2": ["C1.1", "CC5.2"],
        "GDPR": ["Art.25(1)", "Art.5(1f)"], "FedRAMP": ["MP-4", "AC-3"],
        "MCSB": ["DP-1", "DP-2"], "CSA-CCM": ["DSP-05", "DSP-01"],
    },
    "no_auto_labeling": {
        "CIS": ["3.1"], "NIST-800-53": ["RA-2", "SI-4"], "NIST-CSF": ["DE.CM-1"],
        "ISO-27001": ["A.5.12", "A.8.16"], "PCI-DSS": ["3.4", "11.5"],
        "HIPAA": ["164.312(c)(1)"], "SOC2": ["C1.1", "CC7.1"],
        "GDPR": ["Art.25(1)", "Art.32(1)"], "FedRAMP": ["RA-2", "SI-4"],
        "MCSB": ["DP-1", "DP-2"], "CSA-CCM": ["DSP-05", "DSP-01"],
    },
    "low_site_label_coverage": {
        "CIS": ["3.1"], "NIST-800-53": ["RA-2", "MP-4"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.5.12", "A.5.13"], "PCI-DSS": ["3.4"],
        "HIPAA": ["164.312(c)(1)"], "SOC2": ["C1.1"],
        "GDPR": ["Art.25(1)", "Art.32(1)"], "FedRAMP": ["RA-2", "MP-4"],
        "MCSB": ["DP-1"], "CSA-CCM": ["DSP-05"],
    },
    "no_default_label": {
        "CIS": ["3.1"], "NIST-800-53": ["MP-4", "CM-2"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.5.12", "A.5.13"], "PCI-DSS": ["3.4"],
        "HIPAA": ["164.312(c)(1)"], "SOC2": ["C1.1", "CC5.2"],
        "GDPR": ["Art.25(1)", "Art.25(2)"], "FedRAMP": ["MP-4", "CM-2"],
        "MCSB": ["DP-1"], "CSA-CCM": ["DSP-05", "DSP-01"],
    },
    "mandatory_labeling_incomplete_scope": {
        "CIS": ["3.1"], "NIST-800-53": ["MP-4", "CM-7"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.5.12"], "PCI-DSS": ["3.4"],
        "HIPAA": ["164.312(c)(1)"], "SOC2": ["C1.1"],
        "GDPR": ["Art.25(1)"], "FedRAMP": ["MP-4"],
        "MCSB": ["DP-1"], "CSA-CCM": ["DSP-05"],
    },
    "labels_without_encryption": {
        "CIS": ["3.1"], "NIST-800-53": ["SC-28", "SC-13"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.8.24", "A.5.13"], "PCI-DSS": ["3.4", "3.5"],
        "HIPAA": ["164.312(a)(2)(iv)"], "SOC2": ["C1.1", "CC6.1"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["SC-28", "SC-13"],
        "MCSB": ["DP-4", "DP-2"], "CSA-CCM": ["CEK-03", "DSP-17"],
    },
    "labels_without_site_group_settings": {
        "CIS": ["3.1"], "NIST-800-53": ["AC-3", "MP-4"], "NIST-CSF": ["PR.DS-1"],
        "ISO-27001": ["A.5.13", "A.5.15"], "PCI-DSS": ["7.1"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1"],
        "GDPR": ["Art.25(1)"], "FedRAMP": ["AC-3"],
        "MCSB": ["DP-1"], "CSA-CCM": ["DSP-05"],
    },
    # ── DLP Readiness ────────────────────────────────────────────────────
    "no_dlp_policies": {
        "CIS": ["3.1"], "NIST-800-53": ["AC-4", "SC-7"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.8.12"], "PCI-DSS": ["3.4", "4.2"],
        "HIPAA": ["164.312(e)(1)", "164.312(c)(1)"], "SOC2": ["C1.1", "CC6.7"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-4", "SC-7"],
        "MCSB": ["DP-2", "DP-3"], "CSA-CCM": ["DSP-05", "DSP-17"],
    },
    "no_label_based_dlp": {
        "CIS": ["3.1"], "NIST-800-53": ["AC-4", "MP-4"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.8.12", "A.5.13"], "PCI-DSS": ["3.4"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["C1.1", "CC6.7"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-4"],
        "MCSB": ["DP-2"], "CSA-CCM": ["DSP-05", "DSP-17"],
    },
    "incomplete_workload_coverage": {
        "CIS": ["3.1"], "NIST-800-53": ["AC-4", "CM-7"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.8.12"], "PCI-DSS": ["3.4", "4.2"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["C1.1"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["AC-4", "CM-7"],
        "MCSB": ["DP-2"], "CSA-CCM": ["DSP-05"],
    },
    "no_endpoint_dlp": {
        "CIS": ["3.1"], "NIST-800-53": ["AC-4", "MP-7"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.8.12", "A.8.1"], "PCI-DSS": ["3.4", "4.2"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["C1.1", "CC6.7"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-4", "MP-7"],
        "MCSB": ["DP-2", "ES-1"], "CSA-CCM": ["DSP-05", "DSP-17"],
    },
    # ── Restricted Search ────────────────────────────────────────────────
    "rss_not_configured": {
        "CIS": ["3.7"], "NIST-800-53": ["AC-3", "AC-4"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.8.3"], "PCI-DSS": ["7.1"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"], "FedRAMP": ["AC-3", "AC-4"],
        "MCSB": ["PA-7", "DP-9"], "CSA-CCM": ["DSP-10", "IAM-10"],
    },
    "rcd_not_configured": {
        "CIS": ["3.7"], "NIST-800-53": ["AC-3", "AC-4"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.8.3"], "PCI-DSS": ["7.1"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"], "FedRAMP": ["AC-3", "AC-4"],
        "MCSB": ["PA-7", "DP-9"], "CSA-CCM": ["DSP-10", "IAM-10"],
    },
    # ── Access Governance ────────────────────────────────────────────────
    "ca_unable_to_assess": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CA-2", "RA-3"], "NIST-CSF": ["ID.RA-1"],
        "ISO-27001": ["A.5.25"], "PCI-DSS": ["12.2"], "HIPAA": ["164.308(a)(8)"],
        "SOC2": ["CC3.2"], "GDPR": ["Art.35(1)"], "FedRAMP": ["CA-2"],
        "MCSB": ["GS-1"], "CSA-CCM": ["GRC-01"],
    },
    "no_copilot_ca_policy": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-3", "AC-2"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.5.15", "A.8.5"], "PCI-DSS": ["7.1", "8.3"],
        "HIPAA": ["164.312(a)(1)", "164.312(d)"], "SOC2": ["CC6.1", "CC6.2"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-3", "AC-2"],
        "MCSB": ["IM-7", "PA-7"], "CSA-CCM": ["IAM-02", "IAM-10"],
    },
    "copilot_deployment_scope_denied": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CA-2"], "NIST-CSF": ["ID.RA-1"],
        "ISO-27001": ["A.5.25"], "PCI-DSS": ["12.2"], "HIPAA": ["164.308(a)(8)"],
        "SOC2": ["CC3.2"], "GDPR": ["Art.35(1)"], "FedRAMP": ["CA-2"],
        "MCSB": ["GS-1"], "CSA-CCM": ["GRC-01"],
    },
    "copilot_deployment_unknown": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CM-2", "CA-2"], "NIST-CSF": ["ID.AM-2"],
        "ISO-27001": ["A.5.9", "A.5.25"], "PCI-DSS": ["2.1"], "HIPAA": ["164.308(a)(1)"],
        "SOC2": ["CC3.2"], "GDPR": ["Art.35(1)"], "FedRAMP": ["CM-2", "CA-2"],
        "MCSB": ["GS-1", "AM-1"], "CSA-CCM": ["GRC-01", "AIS-01"],
    },
    "no_copilot_license": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CM-8"], "NIST-CSF": ["ID.AM-1"],
        "ISO-27001": ["A.5.9"], "PCI-DSS": ["2.4"], "HIPAA": ["164.308(a)(1)"],
        "SOC2": ["CC3.1"], "GDPR": ["Art.30(1)"], "FedRAMP": ["CM-8"],
        "MCSB": ["AM-1"], "CSA-CCM": ["AIS-01"],
    },
    "copilot_licenses_unassigned": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CM-8", "AC-2"], "NIST-CSF": ["ID.AM-1"],
        "ISO-27001": ["A.5.9", "A.5.18"], "PCI-DSS": ["2.4"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC3.1"],
        "GDPR": ["Art.30(1)"], "FedRAMP": ["CM-8", "AC-2"],
        "MCSB": ["AM-1"], "CSA-CCM": ["AIS-01"],
    },
    "low_copilot_license_utilization": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CM-8"], "NIST-CSF": ["ID.AM-1"],
        "ISO-27001": ["A.5.9"], "PCI-DSS": ["2.4"], "HIPAA": ["164.308(a)(1)"],
        "SOC2": ["CC3.1"], "GDPR": ["Art.30(1)"], "FedRAMP": ["CM-8"],
        "MCSB": ["AM-1"], "CSA-CCM": ["AIS-01"],
    },
    "no_access_reviews": {
        "CIS": ["1.1.4"], "NIST-800-53": ["AC-2(3)", "AC-6(7)"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18", "A.5.15"], "PCI-DSS": ["7.2", "8.1.4"],
        "HIPAA": ["164.308(a)(3)(ii)(A)"], "SOC2": ["CC6.2", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"], "FedRAMP": ["AC-2(3)", "AC-6(7)"],
        "MCSB": ["PA-4"], "CSA-CCM": ["IAM-06", "IAM-10"],
    },
    "no_information_barriers": {
        "CIS": ["1.1.1"], "NIST-800-53": ["AC-4", "AC-3"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.3", "A.5.15"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(4)"], "SOC2": ["CC6.1", "CC6.4"],
        "GDPR": ["Art.25(2)", "Art.5(1b)"], "FedRAMP": ["AC-4", "AC-3"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-10", "DSP-05"],
    },
    "no_mfa_enforcement": {
        "CIS": ["1.1.2"], "NIST-800-53": ["IA-2(1)", "IA-2(2)"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.5"], "PCI-DSS": ["8.3.1", "8.4.2"],
        "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1", "CC6.6"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["IA-2(1)", "IA-2(2)"],
        "MCSB": ["IM-4"], "CSA-CCM": ["IAM-02", "IAM-03"],
    },
    "no_pim_configured": {
        "CIS": ["1.1.6"], "NIST-800-53": ["AC-2(7)", "AC-6(2)"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.8.2", "A.5.18"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.32(1)", "Art.25(2)"], "FedRAMP": ["AC-2(7)", "AC-6(2)"],
        "MCSB": ["PA-2"], "CSA-CCM": ["IAM-04", "IAM-10"],
    },
    "no_named_locations": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-17", "SC-7"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.20", "A.5.15"], "PCI-DSS": ["1.2", "1.3"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["CC6.1", "CC6.6"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["AC-17", "SC-7"],
        "MCSB": ["IM-7", "NS-1"], "CSA-CCM": ["IAM-02", "IVS-03"],
    },
    "no_signin_risk_policy": {
        "CIS": ["1.2.6"], "NIST-800-53": ["SI-4", "AC-7"], "NIST-CSF": ["DE.CM-1"],
        "ISO-27001": ["A.8.16", "A.8.5"], "PCI-DSS": ["8.3", "10.7"],
        "HIPAA": ["164.308(a)(6)(ii)"], "SOC2": ["CC6.1", "CC7.2"],
        "GDPR": ["Art.32(1)", "Art.33(1)"], "FedRAMP": ["SI-4", "AC-7"],
        "MCSB": ["IM-4", "LT-1"], "CSA-CCM": ["IAM-02", "TVM-01"],
    },
    "no_device_compliance": {
        "CIS": ["1.2.1"], "NIST-800-53": ["CM-8", "AC-19"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.1", "A.8.9"], "PCI-DSS": ["2.2", "6.3.3"],
        "HIPAA": ["164.310(d)(1)"], "SOC2": ["CC6.1", "CC6.8"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["CM-8", "AC-19"],
        "MCSB": ["ES-1", "IM-7"], "CSA-CCM": ["IAM-02", "AIS-02"],
    },
    "stale_accounts_detected": {
        "CIS": ["1.1.4"], "NIST-800-53": ["AC-2(3)", "PS-4"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18", "A.5.16"], "PCI-DSS": ["8.1.4", "8.2.6"],
        "HIPAA": ["164.308(a)(3)(ii)(C)"], "SOC2": ["CC6.2", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.5(1e)"], "FedRAMP": ["AC-2(3)", "PS-4"],
        "MCSB": ["PA-4"], "CSA-CCM": ["IAM-06", "HRS-04"],
    },
    "excessive_global_admins": {
        "CIS": ["1.1.3"], "NIST-800-53": ["AC-6(5)", "AC-5"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.8.2", "A.5.3"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.32(1)", "Art.25(2)"], "FedRAMP": ["AC-6(5)", "AC-5"],
        "MCSB": ["PA-1", "PA-2"], "CSA-CCM": ["IAM-04", "IAM-05"],
    },
    "shared_accounts_detected": {
        "CIS": ["1.1.1"], "NIST-800-53": ["AC-2", "IA-4"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.5.16", "A.8.5"], "PCI-DSS": ["8.5", "8.1"],
        "HIPAA": ["164.312(a)(2)(i)"], "SOC2": ["CC6.1", "CC6.2"],
        "GDPR": ["Art.5(2)", "Art.32(1)"], "FedRAMP": ["AC-2", "IA-4"],
        "MCSB": ["IM-1"], "CSA-CCM": ["IAM-02", "IAM-09"],
    },
    "no_group_based_licensing": {
        "CIS": ["1.1.1"], "NIST-800-53": ["AC-2", "CM-2"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18"], "PCI-DSS": ["7.1"],
        "HIPAA": ["164.308(a)(4)"], "SOC2": ["CC6.3"],
        "GDPR": ["Art.25(2)"], "FedRAMP": ["AC-2"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-06"],
    },
    "no_session_signin_frequency": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-11", "AC-12"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.5"], "PCI-DSS": ["8.1.8", "8.6.3"],
        "HIPAA": ["164.312(a)(2)(iii)"], "SOC2": ["CC6.1"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["AC-11", "AC-12"],
        "MCSB": ["IM-7"], "CSA-CCM": ["IAM-02"],
    },
    "no_persistent_browser_control": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-11", "AC-12"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.5"], "PCI-DSS": ["8.1.8"],
        "HIPAA": ["164.312(a)(2)(iii)"], "SOC2": ["CC6.1"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["AC-11", "AC-12"],
        "MCSB": ["IM-7"], "CSA-CCM": ["IAM-02"],
    },
    "mailbox_delegation_fullaccess": {
        "CIS": ["1.22"], "NIST-800-53": ["AC-3", "AC-6"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.5.18"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(4)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"], "FedRAMP": ["AC-3", "AC-6"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-05", "IAM-10"],
    },
    "shared_mailbox_over_delegated": {
        "CIS": ["1.22"], "NIST-800-53": ["AC-6", "AC-6(1)"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.15", "A.5.18"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"], "FedRAMP": ["AC-6", "AC-6(1)"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-05"],
    },
    "ib_segments_not_assigned": {
        "CIS": ["1.1.1"], "NIST-800-53": ["AC-4", "AC-3"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.3", "A.5.15"], "PCI-DSS": ["7.1"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.4"],
        "GDPR": ["Art.25(2)"], "FedRAMP": ["AC-4"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-10"],
    },
    "disabled_users_with_copilot_license": {
        "CIS": ["1.1.4"], "NIST-800-53": ["AC-2(3)", "PS-4"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18", "A.5.16"], "PCI-DSS": ["8.1.4"],
        "HIPAA": ["164.308(a)(3)(ii)(C)"], "SOC2": ["CC6.2"],
        "GDPR": ["Art.25(2)"], "FedRAMP": ["AC-2(3)", "PS-4"],
        "MCSB": ["PA-4"], "CSA-CCM": ["IAM-06", "HRS-04"],
    },
    "no_app_protection_policies": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-19", "MP-5"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.8.1", "A.8.12"], "PCI-DSS": ["4.2", "9.4"],
        "HIPAA": ["164.312(e)(1)", "164.312(c)(1)"], "SOC2": ["CC6.7", "CC6.8"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-19", "MP-5"],
        "MCSB": ["ES-1", "DP-3"], "CSA-CCM": ["DSP-17", "AIS-02"],
    },
    "app_protection_platform_gaps": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-19", "MP-5"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.8.1"], "PCI-DSS": ["4.2"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["CC6.7"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["AC-19"],
        "MCSB": ["ES-1"], "CSA-CCM": ["DSP-17"],
    },
    "hybrid_accounts_stale_sync": {
        "CIS": ["1.1.4"], "NIST-800-53": ["AC-2", "IA-4"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.5.16", "A.5.18"], "PCI-DSS": ["8.1.4"],
        "HIPAA": ["164.308(a)(3)(ii)(A)"], "SOC2": ["CC6.2"],
        "GDPR": ["Art.25(2)"], "FedRAMP": ["AC-2", "IA-4"],
        "MCSB": ["IM-1"], "CSA-CCM": ["IAM-06"],
    },
    "no_copilot_license_segmentation": {
        "CIS": ["1.1.1"], "NIST-800-53": ["AC-2", "CM-3"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18", "A.8.9"], "PCI-DSS": ["7.1"],
        "HIPAA": ["164.308(a)(4)"], "SOC2": ["CC6.3", "CC8.1"],
        "GDPR": ["Art.25(2)"], "FedRAMP": ["AC-2", "CM-3"],
        "MCSB": ["PA-7", "GS-1"], "CSA-CCM": ["IAM-06"],
    },
    # ── Content Lifecycle ────────────────────────────────────────────────
    "no_legal_hold_configured": {
        "CIS": ["3.11"], "NIST-800-53": ["AU-11", "SI-12"], "NIST-CSF": ["PR.DS-3"],
        "ISO-27001": ["A.5.28", "A.5.33"], "PCI-DSS": ["10.7", "3.1"],
        "HIPAA": ["164.312(c)(1)", "164.316(b)(2)(i)"], "SOC2": ["C1.2", "A1.1"],
        "GDPR": ["Art.17(3)", "Art.5(1e)"], "FedRAMP": ["AU-11", "SI-12"],
        "MCSB": ["DP-8"], "CSA-CCM": ["DSP-16", "BCR-03"],
    },
    "stale_content_exposure": {
        "CIS": ["3.11"], "NIST-800-53": ["MP-6", "SI-12"], "NIST-CSF": ["PR.DS-3"],
        "ISO-27001": ["A.8.10", "A.5.33"], "PCI-DSS": ["3.1", "9.4"],
        "HIPAA": ["164.310(d)(2)(i)"], "SOC2": ["CC6.5"],
        "GDPR": ["Art.5(1e)", "Art.17(1)"], "FedRAMP": ["MP-6", "SI-12"],
        "MCSB": ["DP-8"], "CSA-CCM": ["DSP-16"],
    },
    "retention_assessment_needed": {
        "CIS": ["3.11"], "NIST-800-53": ["AU-11", "SI-12"], "NIST-CSF": ["PR.DS-3"],
        "ISO-27001": ["A.5.33"], "PCI-DSS": ["10.7", "3.1"],
        "HIPAA": ["164.316(b)(2)(i)"], "SOC2": ["C1.2"],
        "GDPR": ["Art.5(1e)"], "FedRAMP": ["AU-11", "SI-12"],
        "MCSB": ["DP-8"], "CSA-CCM": ["DSP-16"],
    },
    "no_m365_backup": {
        "CIS": ["3.11"], "NIST-800-53": ["CP-9", "CP-6"], "NIST-CSF": ["PR.IR-4"],
        "ISO-27001": ["A.5.29", "A.5.30"], "PCI-DSS": ["10.7"],
        "HIPAA": ["164.308(a)(7)(ii)(A)"], "SOC2": ["A1.1", "A1.2"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["CP-9", "CP-6"],
        "MCSB": ["BR-1", "BR-2"], "CSA-CCM": ["BCR-03", "BCR-11"],
    },
    # ── Audit & Monitoring ───────────────────────────────────────────────
    "audit_logging_unknown": {
        "CIS": ["5.1"], "NIST-800-53": ["AU-2", "AU-3"], "NIST-CSF": ["DE.CM-3"],
        "ISO-27001": ["A.8.15"], "PCI-DSS": ["10.1", "10.2"],
        "HIPAA": ["164.312(b)"], "SOC2": ["CC7.2", "CC7.3"],
        "GDPR": ["Art.30(1)", "Art.5(2)"], "FedRAMP": ["AU-2", "AU-3"],
        "MCSB": ["LT-3", "LT-4"], "CSA-CCM": ["LOG-01", "LOG-03"],
    },
    "copilot_interaction_audit": {
        "CIS": ["5.1"], "NIST-800-53": ["AU-2", "AU-12"], "NIST-CSF": ["DE.CM-3"],
        "ISO-27001": ["A.8.15", "A.8.16"], "PCI-DSS": ["10.2", "10.6"],
        "HIPAA": ["164.312(b)"], "SOC2": ["CC7.2"],
        "GDPR": ["Art.30(1)", "Art.5(2)"], "FedRAMP": ["AU-2", "AU-12"],
        "MCSB": ["LT-3"], "CSA-CCM": ["LOG-01", "LOG-05"],
    },
    "no_alert_policies": {
        "CIS": ["5.2"], "NIST-800-53": ["SI-4", "IR-5"], "NIST-CSF": ["DE.AE-2"],
        "ISO-27001": ["A.8.16"], "PCI-DSS": ["10.6", "10.7"],
        "HIPAA": ["164.308(a)(6)(ii)"], "SOC2": ["CC7.2", "CC7.3"],
        "GDPR": ["Art.33(1)", "Art.5(2)"], "FedRAMP": ["SI-4", "IR-5"],
        "MCSB": ["LT-1", "LT-2"], "CSA-CCM": ["SEF-01", "LOG-09"],
    },
    "no_defender_cloud_apps": {
        "CIS": ["2.1.1"], "NIST-800-53": ["SI-4", "AC-4"], "NIST-CSF": ["DE.CM-1"],
        "ISO-27001": ["A.8.16", "A.5.23"], "PCI-DSS": ["10.6", "11.4"],
        "HIPAA": ["164.308(a)(6)(ii)"], "SOC2": ["CC7.1", "CC7.2"],
        "GDPR": ["Art.32(1)", "Art.33(1)"], "FedRAMP": ["SI-4", "AC-4"],
        "MCSB": ["LT-1"], "CSA-CCM": ["TVM-01", "LOG-09"],
    },
    "no_copilot_usage_analytics": {
        "CIS": ["5.1"], "NIST-800-53": ["AU-6", "CA-7"], "NIST-CSF": ["DE.AE-3"],
        "ISO-27001": ["A.8.15", "A.8.16"], "PCI-DSS": ["10.6"],
        "HIPAA": ["164.312(b)"], "SOC2": ["CC4.1", "CC7.2"],
        "GDPR": ["Art.5(2)"], "FedRAMP": ["AU-6", "CA-7"],
        "MCSB": ["LT-4"], "CSA-CCM": ["LOG-05"],
    },
    "copilot_audit_events_not_analyzed": {
        "CIS": ["5.1"], "NIST-800-53": ["AU-6", "AU-6(1)"], "NIST-CSF": ["DE.AE-2"],
        "ISO-27001": ["A.8.15", "A.8.16"], "PCI-DSS": ["10.6", "10.7"],
        "HIPAA": ["164.312(b)"], "SOC2": ["CC7.2", "CC7.3"],
        "GDPR": ["Art.5(2)", "Art.30(1)"], "FedRAMP": ["AU-6", "AU-6(1)"],
        "MCSB": ["LT-4"], "CSA-CCM": ["LOG-05", "LOG-09"],
    },
    "no_prompt_pattern_monitoring": {
        "CIS": ["5.2"], "NIST-800-53": ["SI-4", "SI-4(4)"], "NIST-CSF": ["DE.CM-1"],
        "ISO-27001": ["A.8.16"], "PCI-DSS": ["10.6", "11.5"],
        "HIPAA": ["164.308(a)(6)(ii)"], "SOC2": ["CC7.2"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["SI-4", "SI-4(4)"],
        "MCSB": ["LT-1"], "CSA-CCM": ["TVM-01", "LOG-09"],
    },
    "copilot_security_incidents_detected": {
        "CIS": ["5.2"], "NIST-800-53": ["IR-4", "IR-5"], "NIST-CSF": ["RS.AN-3"],
        "ISO-27001": ["A.5.26", "A.5.28"], "PCI-DSS": ["10.6", "12.10"],
        "HIPAA": ["164.308(a)(6)"], "SOC2": ["CC7.3", "CC7.4"],
        "GDPR": ["Art.33(1)", "Art.34(1)"], "FedRAMP": ["IR-4", "IR-5"],
        "MCSB": ["IR-1", "LT-1"], "CSA-CCM": ["SEF-01", "SEF-03"],
    },
    # ── Copilot Security ─────────────────────────────────────────────────
    "copilot_plugins_unrestricted": {
        "CIS": ["2.1.1"], "NIST-800-53": ["CM-7", "SA-9"], "NIST-CSF": ["PR.PS-1"],
        "ISO-27001": ["A.8.9", "A.5.23"], "PCI-DSS": ["2.2", "6.3"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC6.8", "CC8.1"],
        "GDPR": ["Art.25(1)", "Art.28"], "FedRAMP": ["CM-7", "SA-9"],
        "MCSB": ["AM-5"], "CSA-CCM": ["AIS-02", "AIS-04"],
    },
    "data_residency_unverified": {
        "CIS": ["1.1.1"], "NIST-800-53": ["SA-9(5)", "SC-7"], "NIST-CSF": ["GV.OC-3"],
        "ISO-27001": ["A.5.23"], "PCI-DSS": ["12.8", "3.1"],
        "HIPAA": ["164.314(a)"], "SOC2": ["CC2.3", "P6.1"],
        "GDPR": ["Art.44", "Art.46"], "FedRAMP": ["SA-9(5)", "SC-7"],
        "MCSB": ["DP-5"], "CSA-CCM": ["DSP-14", "DSP-19"],
    },
    "no_ediscovery_configured": {
        "CIS": ["3.11"], "NIST-800-53": ["AU-11", "IR-4"], "NIST-CSF": ["RS.AN-3"],
        "ISO-27001": ["A.5.28"], "PCI-DSS": ["10.7", "12.10"],
        "HIPAA": ["164.316(b)(2)(i)"], "SOC2": ["C1.2"],
        "GDPR": ["Art.17(3)", "Art.30(1)"], "FedRAMP": ["AU-11", "IR-4"],
        "MCSB": ["DP-8"], "CSA-CCM": ["DSP-16", "SEF-03"],
    },
    "no_insider_risk_policies": {
        "CIS": ["5.2"], "NIST-800-53": ["PM-12", "SI-4"], "NIST-CSF": ["DE.CM-3"],
        "ISO-27001": ["A.5.7", "A.8.16"], "PCI-DSS": ["10.6", "12.7"],
        "HIPAA": ["164.308(a)(3)(ii)(A)"], "SOC2": ["CC7.2", "CC9.2"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"], "FedRAMP": ["PM-12", "SI-4"],
        "MCSB": ["LT-1"], "CSA-CCM": ["HRS-09", "SEF-01"],
    },
    "no_communication_compliance": {
        "CIS": ["5.2"], "NIST-800-53": ["SI-4", "AU-2"], "NIST-CSF": ["DE.CM-1"],
        "ISO-27001": ["A.8.16", "A.8.15"], "PCI-DSS": ["10.2", "10.6"],
        "HIPAA": ["164.312(b)", "164.308(a)(6)(ii)"], "SOC2": ["CC7.2"],
        "GDPR": ["Art.32(1)", "Art.5(2)"], "FedRAMP": ["SI-4", "AU-2"],
        "MCSB": ["LT-1", "LT-3"], "CSA-CCM": ["LOG-01", "SEF-01"],
    },
    "no_dspm_for_ai": {
        "CIS": ["3.1"], "NIST-800-53": ["RA-3", "PM-16"], "NIST-CSF": ["ID.RA-1"],
        "ISO-27001": ["A.5.7", "A.5.12"], "PCI-DSS": ["12.2", "6.1"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC3.2", "CC9.1"],
        "GDPR": ["Art.35(1)", "Art.25(1)"], "FedRAMP": ["RA-3", "PM-16"],
        "MCSB": ["DP-1", "GS-1"], "CSA-CCM": ["GRC-01", "DSP-01"],
    },
    "dspm_oversharing_not_reviewed": {
        "CIS": ["3.1"], "NIST-800-53": ["AC-6", "RA-3"], "NIST-CSF": ["ID.RA-1"],
        "ISO-27001": ["A.5.15", "A.5.7"], "PCI-DSS": ["7.1", "12.2"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC3.2", "CC6.1"],
        "GDPR": ["Art.25(1)", "Art.35(1)"], "FedRAMP": ["AC-6", "RA-3"],
        "MCSB": ["PA-7", "GS-1"], "CSA-CCM": ["IAM-05", "GRC-01"],
    },
    "unmanaged_copilot_agents": {
        "CIS": ["2.1.1"], "NIST-800-53": ["CM-7", "SA-9"], "NIST-CSF": ["GV.SC-4"],
        "ISO-27001": ["A.5.23", "A.8.9"], "PCI-DSS": ["6.3", "2.2"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC6.8", "CC8.1"],
        "GDPR": ["Art.28", "Art.25(1)"], "FedRAMP": ["CM-7", "SA-9"],
        "MCSB": ["AM-5"], "CSA-CCM": ["AIS-02", "GRC-01"],
    },
    "agent_over_permissioned": {
        "CIS": ["2.1.1"], "NIST-800-53": ["AC-6", "SA-9"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18", "A.5.23"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.32(1)", "Art.25(2)"], "FedRAMP": ["AC-6", "SA-9"],
        "MCSB": ["PA-7", "AM-5"], "CSA-CCM": ["IAM-05", "AIS-04"],
    },
    "no_regulatory_framework_mapping": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CA-2", "PL-2"], "NIST-CSF": ["GV.OC-2"],
        "ISO-27001": ["A.5.1", "A.5.25"], "PCI-DSS": ["12.1", "12.2"],
        "HIPAA": ["164.308(a)(8)"], "SOC2": ["CC1.4", "CC3.2"],
        "GDPR": ["Art.5(2)", "Art.24(1)"], "FedRAMP": ["CA-2", "PL-2"],
        "MCSB": ["GS-1", "GS-2"], "CSA-CCM": ["GRC-01", "GRC-02"],
    },
    "multi_geo_copilot_residency": {
        "CIS": ["1.1.1"], "NIST-800-53": ["SA-9(5)"], "NIST-CSF": ["GV.OC-3"],
        "ISO-27001": ["A.5.23"], "PCI-DSS": ["12.8"],
        "HIPAA": ["164.314(a)"], "SOC2": ["P6.1"],
        "GDPR": ["Art.44", "Art.46"], "FedRAMP": ["SA-9(5)"],
        "MCSB": ["DP-5"], "CSA-CCM": ["DSP-14", "DSP-19"],
    },
    "no_rai_policy": {
        "CIS": ["1.1.1"], "NIST-800-53": ["PM-9", "PL-2"], "NIST-CSF": ["GV.RM-1"],
        "ISO-27001": ["A.5.1"], "PCI-DSS": ["12.1"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC1.4", "CC9.1"],
        "GDPR": ["Art.22", "Art.35(1)"], "FedRAMP": ["PM-9", "PL-2"],
        "MCSB": ["GS-1"], "CSA-CCM": ["GRC-01"],
    },
    "cross_tenant_access_not_assessed": {
        "CIS": ["1.1.1"], "NIST-800-53": ["CA-2", "AC-20"], "NIST-CSF": ["GV.SC-4"],
        "ISO-27001": ["A.5.25", "A.5.19"], "PCI-DSS": ["12.8"],
        "HIPAA": ["164.314(a)"], "SOC2": ["CC9.2"],
        "GDPR": ["Art.28", "Art.44"], "FedRAMP": ["CA-2", "AC-20"],
        "MCSB": ["IM-7"], "CSA-CCM": ["IAM-12", "GRC-01"],
    },
    "cross_tenant_access_permissive": {
        "CIS": ["1.1.1"], "NIST-800-53": ["AC-20", "AC-4"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.19", "A.5.14"], "PCI-DSS": ["7.1", "12.8"],
        "HIPAA": ["164.314(a)"], "SOC2": ["CC6.1", "CC9.2"],
        "GDPR": ["Art.44", "Art.46"], "FedRAMP": ["AC-20", "AC-4"],
        "MCSB": ["IM-7"], "CSA-CCM": ["IAM-12", "DSP-14"],
    },
    "no_agent_approval_workflow": {
        "CIS": ["2.1.1"], "NIST-800-53": ["CM-3", "CM-7"], "NIST-CSF": ["PR.PS-1"],
        "ISO-27001": ["A.8.9", "A.8.25"], "PCI-DSS": ["6.3", "6.4"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC8.1"],
        "GDPR": ["Art.25(1)"], "FedRAMP": ["CM-3", "CM-7"],
        "MCSB": ["AM-5", "GS-1"], "CSA-CCM": ["AIS-02", "AIS-04"],
    },
    "ungoverned_external_connectors": {
        "CIS": ["2.1.1"], "NIST-800-53": ["SA-9", "CM-7"], "NIST-CSF": ["GV.SC-4"],
        "ISO-27001": ["A.5.23", "A.5.19"], "PCI-DSS": ["12.8", "6.3"],
        "HIPAA": ["164.314(a)"], "SOC2": ["CC9.2", "CC6.8"],
        "GDPR": ["Art.28", "Art.32(1)"], "FedRAMP": ["SA-9", "CM-7"],
        "MCSB": ["AM-5"], "CSA-CCM": ["AIS-02", "GRC-01"],
    },
    "external_connector_review_needed": {
        "CIS": ["2.1.1"], "NIST-800-53": ["SA-9", "AC-6"], "NIST-CSF": ["GV.SC-4"],
        "ISO-27001": ["A.5.23", "A.5.18"], "PCI-DSS": ["12.8", "7.1"],
        "HIPAA": ["164.314(a)"], "SOC2": ["CC9.2", "CC6.3"],
        "GDPR": ["Art.28", "Art.25(2)"], "FedRAMP": ["SA-9", "AC-6"],
        "MCSB": ["AM-5", "PA-7"], "CSA-CCM": ["AIS-02", "IAM-05"],
    },
    "no_prompt_guardrails": {
        "CIS": ["2.1.1"], "NIST-800-53": ["SI-4", "CM-7"], "NIST-CSF": ["DE.CM-1"],
        "ISO-27001": ["A.8.16", "A.8.9"], "PCI-DSS": ["6.5", "6.4"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC7.2", "CC8.1"],
        "GDPR": ["Art.25(1)", "Art.32(1)"], "FedRAMP": ["SI-4", "CM-7"],
        "MCSB": ["LT-1", "AM-5"], "CSA-CCM": ["AIS-04", "TVM-01"],
    },
    # ── Zero Trust ───────────────────────────────────────────────────────
    "no_continuous_access_evaluation": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-2(12)", "SI-4"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.5", "A.8.16"], "PCI-DSS": ["8.3", "10.7"],
        "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1", "CC7.2"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["AC-2(12)", "SI-4"],
        "MCSB": ["IM-7"], "CSA-CCM": ["IAM-02", "IAM-14"],
    },
    "no_token_protection": {
        "CIS": ["1.2.1"], "NIST-800-53": ["SC-23", "IA-5"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.5", "A.8.24"], "PCI-DSS": ["8.3", "4.1"],
        "HIPAA": ["164.312(d)", "164.312(e)(1)"], "SOC2": ["CC6.1", "CC6.7"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["SC-23", "IA-5"],
        "MCSB": ["IM-7"], "CSA-CCM": ["IAM-14", "CEK-03"],
    },
    "no_phishing_resistant_mfa": {
        "CIS": ["1.1.2"], "NIST-800-53": ["IA-2(6)", "IA-5(2)"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.5"], "PCI-DSS": ["8.3.2", "8.4.2"],
        "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1", "CC6.6"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["IA-2(6)", "IA-5(2)"],
        "MCSB": ["IM-4"], "CSA-CCM": ["IAM-03"],
    },
    "no_authentication_context": {
        "CIS": ["1.2.1"], "NIST-800-53": ["AC-3(13)", "IA-10"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.5", "A.5.15"], "PCI-DSS": ["7.1", "8.3"],
        "HIPAA": ["164.312(a)(1)", "164.312(d)"], "SOC2": ["CC6.1"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-3(13)", "IA-10"],
        "MCSB": ["IM-7", "PA-7"], "CSA-CCM": ["IAM-02", "IAM-10"],
    },
    "workload_identity_unprotected": {
        "CIS": ["1.1.6"], "NIST-800-53": ["IA-9", "SI-4"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.5.16", "A.8.5"], "PCI-DSS": ["8.6", "10.6"],
        "HIPAA": ["164.312(d)"], "SOC2": ["CC6.1", "CC7.2"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["IA-9", "SI-4"],
        "MCSB": ["IM-3", "IM-7"], "CSA-CCM": ["IAM-09", "IAM-14"],
    },
    "no_compliant_network_check": {
        "CIS": ["1.2.1"], "NIST-800-53": ["SC-7", "AC-17"], "NIST-CSF": ["PR.AA-1"],
        "ISO-27001": ["A.8.20", "A.8.5"], "PCI-DSS": ["1.2", "1.3"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["CC6.1", "CC6.6"],
        "GDPR": ["Art.32(1)"], "FedRAMP": ["SC-7", "AC-17"],
        "MCSB": ["NS-1", "IM-7"], "CSA-CCM": ["IVS-03", "IAM-02"],
    },
    # ── Shadow AI ────────────────────────────────────────────────────────
    "unauthorized_ai_apps_detected": {
        "CIS": ["2.1.1"], "NIST-800-53": ["CM-7", "SA-9"], "NIST-CSF": ["GV.SC-4"],
        "ISO-27001": ["A.5.23", "A.8.9"], "PCI-DSS": ["6.3", "12.8"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC6.8", "CC9.2"],
        "GDPR": ["Art.28", "Art.25(1)"], "FedRAMP": ["CM-7", "SA-9"],
        "MCSB": ["AM-5", "GS-1"], "CSA-CCM": ["AIS-02", "GRC-01"],
    },
    "ai_consent_grants_detected": {
        "CIS": ["2.1.1"], "NIST-800-53": ["AC-6", "SA-9"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18", "A.5.23"], "PCI-DSS": ["7.1", "12.8"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.28", "Art.32(1)"], "FedRAMP": ["AC-6", "SA-9"],
        "MCSB": ["PA-7", "IM-1"], "CSA-CCM": ["IAM-05", "AIS-02"],
    },
    "shadow_copilot_agents_detected": {
        "CIS": ["2.1.1"], "NIST-800-53": ["CM-7", "SA-9"], "NIST-CSF": ["GV.SC-4"],
        "ISO-27001": ["A.5.23", "A.8.9"], "PCI-DSS": ["6.3", "2.2"],
        "HIPAA": ["164.308(a)(1)"], "SOC2": ["CC6.8", "CC8.1"],
        "GDPR": ["Art.28", "Art.25(1)"], "FedRAMP": ["CM-7", "SA-9"],
        "MCSB": ["AM-5"], "CSA-CCM": ["AIS-02", "GRC-01"],
    },
    "no_ai_app_governance": {
        "CIS": ["2.1.1"], "NIST-800-53": ["PM-16", "SI-4"], "NIST-CSF": ["DE.CM-1"],
        "ISO-27001": ["A.8.16", "A.5.23"], "PCI-DSS": ["11.4", "12.8"],
        "HIPAA": ["164.308(a)(6)(ii)"], "SOC2": ["CC7.1", "CC9.2"],
        "GDPR": ["Art.32(1)", "Art.28"], "FedRAMP": ["PM-16", "SI-4"],
        "MCSB": ["LT-1", "AM-5"], "CSA-CCM": ["TVM-01", "AIS-02"],
    },
    "ai_apps_overpermissioned": {
        "CIS": ["2.1.1"], "NIST-800-53": ["AC-6", "AC-6(1)"], "NIST-CSF": ["PR.AA-5"],
        "ISO-27001": ["A.5.18", "A.5.23"], "PCI-DSS": ["7.1", "7.2"],
        "HIPAA": ["164.312(a)(1)"], "SOC2": ["CC6.1", "CC6.3"],
        "GDPR": ["Art.25(2)", "Art.32(1)"], "FedRAMP": ["AC-6", "AC-6(1)"],
        "MCSB": ["PA-7"], "CSA-CCM": ["IAM-05", "AIS-04"],
    },
    "no_ai_dlp_web_restrictions": {
        "CIS": ["3.1"], "NIST-800-53": ["AC-4", "SC-7"], "NIST-CSF": ["PR.DS-2"],
        "ISO-27001": ["A.8.12", "A.8.20"], "PCI-DSS": ["1.3.1", "4.2"],
        "HIPAA": ["164.312(e)(1)"], "SOC2": ["C1.1", "CC6.7"],
        "GDPR": ["Art.32(1)", "Art.25(1)"], "FedRAMP": ["AC-4", "SC-7"],
        "MCSB": ["DP-2", "NS-1"], "CSA-CCM": ["DSP-05", "IVS-03"],
    },
}

# ══════════════════════════════════════════════════════════════════════════════
# Per-control reference details (key = "Framework:ControlID")
# ══════════════════════════════════════════════════════════════════════════════

_CONTROL_DETAILS: dict[str, dict[str, str]] = {
    # ── CIS M365 / Azure Foundations ─────────────────────────────────────
    "CIS:1.1.1": {"title": "Ensure security defaults or CA policies are enabled", "rationale": "Security defaults provide baseline identity protection for all users.", "recommendation": "Enable Security Defaults or configure equivalent Conditional Access policies."},
    "CIS:1.1.2": {"title": "Ensure MFA is enabled for all users", "rationale": "MFA blocks 99.9% of credential-based attacks.", "recommendation": "Enforce MFA via Conditional Access for all users and all cloud apps."},
    "CIS:1.1.3": {"title": "Ensure fewer than 5 Global Administrators", "rationale": "Excessive GAs increase blast radius of privilege escalation.", "recommendation": "Reduce Global Admins to ≤ 5 and use least-privilege admin roles."},
    "CIS:1.1.4": {"title": "Ensure accounts are reviewed for activity", "rationale": "Stale accounts retain permissions and expand attack surface.", "recommendation": "Review accounts quarterly; disable inactive accounts after 90 days."},
    "CIS:1.1.6": {"title": "Ensure PIM is used for privileged roles", "rationale": "Standing admin access increases the window of opportunity for attackers.", "recommendation": "Enable Privileged Identity Management for just-in-time role elevation."},
    "CIS:1.2.1": {"title": "Ensure Conditional Access policies are configured", "rationale": "CA policies enforce context-aware access decisions.", "recommendation": "Create CA policies for MFA, device compliance, location, and session controls."},
    "CIS:1.2.6": {"title": "Ensure sign-in risk policy is configured", "rationale": "Risk-based policies detect anomalous sign-in behavior.", "recommendation": "Configure sign-in risk CA policy to block or challenge risky sign-ins."},
    "CIS:1.22": {"title": "Ensure least privilege access", "rationale": "Excessive permissions expand the blast radius of compromised accounts.", "recommendation": "Review access assignments and reduce to least-privilege."},
    "CIS:2.1.1": {"title": "Ensure Defender for Cloud Apps is enabled", "rationale": "CASB capabilities provide visibility into shadow IT and AI apps.", "recommendation": "Enable Defender for Cloud Apps for app governance and shadow AI detection."},
    "CIS:3.1": {"title": "Ensure data classification and labeling", "rationale": "Classification enables appropriate protection of sensitive data.", "recommendation": "Define and enforce sensitivity labels and DLP policies organization-wide."},
    "CIS:3.7": {"title": "Ensure public/anonymous access is restricted", "rationale": "Public access bypasses all identity-based access controls.", "recommendation": "Disable anonymous sharing and restrict external access to named guests."},
    "CIS:3.11": {"title": "Ensure data retention and recovery controls", "rationale": "Without retention controls, data may be lost or improperly disposed.", "recommendation": "Configure retention policies, backup, and legal hold as needed."},
    "CIS:5.1": {"title": "Ensure unified audit logging is enabled", "rationale": "Audit logs provide evidence for incident investigation and compliance.", "recommendation": "Enable unified audit logging and configure adequate retention."},
    "CIS:5.2": {"title": "Ensure alert policies are configured", "rationale": "Alerts enable proactive detection of security-relevant activity.", "recommendation": "Configure alert policies for suspicious activity and compliance events."},
    # ── NIST 800-53 Rev 5 ────────────────────────────────────────────────
    "NIST-800-53:AC-2": {"title": "Account Management", "rationale": "Manages the lifecycle of accounts to prevent unauthorized access.", "recommendation": "Implement automated account provisioning, review, and deprovisioning."},
    "NIST-800-53:AC-2(3)": {"title": "Disable Accounts", "rationale": "Inactive accounts are attack vectors for credential compromise.", "recommendation": "Automatically disable accounts inactive for 90+ days."},
    "NIST-800-53:AC-3": {"title": "Access Enforcement", "rationale": "Enforces approved authorizations for access to resources.", "recommendation": "Implement RBAC and CA policies to enforce least-privilege access."},
    "NIST-800-53:AC-4": {"title": "Information Flow Enforcement", "rationale": "Controls information flows between systems and users.", "recommendation": "Configure DLP, information barriers, and sharing restrictions."},
    "NIST-800-53:AC-6": {"title": "Least Privilege", "rationale": "Users should only have access necessary for their job functions.", "recommendation": "Apply least-privilege principles across all access assignments."},
    "NIST-800-53:AC-6(5)": {"title": "Privileged Accounts", "rationale": "Privileged access must be tightly controlled and monitored.", "recommendation": "Limit privileged roles and use PIM for just-in-time elevation."},
    "NIST-800-53:AC-11": {"title": "Session Lock", "rationale": "Unattended sessions can be exploited by physical or remote attackers.", "recommendation": "Configure session timeouts and sign-in frequency controls."},
    "NIST-800-53:AC-19": {"title": "Access Control for Mobile Devices", "rationale": "Mobile devices accessing corporate data must be governed.", "recommendation": "Deploy MAM/MDM policies for Copilot-accessing devices."},
    "NIST-800-53:AC-20": {"title": "Use of External Systems", "rationale": "External system connections must be authorized and monitored.", "recommendation": "Configure cross-tenant access and external collaboration policies."},
    "NIST-800-53:AU-2": {"title": "Audit Events", "rationale": "Audit logging is essential for accountability and incident response.", "recommendation": "Enable unified audit logging for all M365 workloads."},
    "NIST-800-53:AU-6": {"title": "Audit Record Review", "rationale": "Unreviewed audit data provides no security value.", "recommendation": "Establish regular audit log review and automated analysis."},
    "NIST-800-53:AU-11": {"title": "Audit Record Retention", "rationale": "Audit records must be retained for legal and compliance requirements.", "recommendation": "Configure retention policies meeting organizational requirements."},
    "NIST-800-53:CA-2": {"title": "Control Assessments", "rationale": "Regular assessments verify security controls are effective.", "recommendation": "Conduct regular security assessments of Copilot deployment."},
    "NIST-800-53:CA-7": {"title": "Continuous Monitoring", "rationale": "Continuous monitoring detects security issues in near-real-time.", "recommendation": "Implement continuous monitoring via Defender and audit analytics."},
    "NIST-800-53:CM-3": {"title": "Configuration Change Control", "rationale": "Uncontrolled changes introduce security vulnerabilities.", "recommendation": "Use change management processes for Copilot configuration changes."},
    "NIST-800-53:CM-7": {"title": "Least Functionality", "rationale": "Unnecessary capabilities increase attack surface.", "recommendation": "Restrict Copilot plugins and connectors to approved list only."},
    "NIST-800-53:CM-8": {"title": "System Component Inventory", "rationale": "Asset inventory is foundational to managing security.", "recommendation": "Maintain inventory of Copilot licenses, agents, and integrations."},
    "NIST-800-53:CP-9": {"title": "System Backup", "rationale": "Backups ensure recovery from data loss or corruption.", "recommendation": "Configure M365 Backup for Exchange, OneDrive, and SharePoint."},
    "NIST-800-53:IA-2(1)": {"title": "MFA for Privileged Accounts", "rationale": "Privileged accounts require the strongest authentication.", "recommendation": "Enforce MFA for all accounts, especially privileged roles."},
    "NIST-800-53:IA-2(6)": {"title": "Access to Accounts — MFA via Hardware Token", "rationale": "Phishing-resistant MFA prevents real-time credential theft.", "recommendation": "Require FIDO2 or Windows Hello for Business for high-value accounts."},
    "NIST-800-53:IR-4": {"title": "Incident Handling", "rationale": "Effective incident handling minimizes damage from security events.", "recommendation": "Establish Copilot-specific incident response procedures."},
    "NIST-800-53:MP-4": {"title": "Media Storage", "rationale": "Information classification ensures appropriate handling.", "recommendation": "Apply sensitivity labels to classify and protect stored content."},
    "NIST-800-53:MP-6": {"title": "Media Sanitization", "rationale": "Stale data must be properly disposed of or archived.", "recommendation": "Configure lifecycle policies to archive or delete stale content."},
    "NIST-800-53:PM-12": {"title": "Insider Threat Program", "rationale": "Insider threats require dedicated detection capabilities.", "recommendation": "Configure Insider Risk Management policies for Copilot monitoring."},
    "NIST-800-53:PM-16": {"title": "Threat Awareness Program", "rationale": "Organizations must maintain awareness of evolving threats.", "recommendation": "Monitor AI-specific threats and shadow AI adoption patterns."},
    "NIST-800-53:RA-2": {"title": "Security Categorization", "rationale": "Data must be categorized to apply appropriate protections.", "recommendation": "Define and apply sensitivity label taxonomy for all content."},
    "NIST-800-53:RA-3": {"title": "Risk Assessment", "rationale": "Risk assessments identify and prioritize security gaps.", "recommendation": "Conduct Copilot readiness risk assessment before deployment."},
    "NIST-800-53:SA-9": {"title": "External System Services", "rationale": "Third-party services must be governed and monitored.", "recommendation": "Review AI app registrations, connectors, and third-party integrations."},
    "NIST-800-53:SC-7": {"title": "Boundary Protection", "rationale": "Network boundaries control information flow between zones.", "recommendation": "Configure sharing restrictions and network-based CA policies."},
    "NIST-800-53:SC-23": {"title": "Session Authenticity", "rationale": "Session tokens must be protected from theft and replay.", "recommendation": "Enable token protection (binding) in Conditional Access policies."},
    "NIST-800-53:SC-28": {"title": "Protection of Information at Rest", "rationale": "Stored data must be encrypted to prevent unauthorized access.", "recommendation": "Enable encryption on sensitivity labels for data-at-rest protection."},
    "NIST-800-53:SI-4": {"title": "System Monitoring", "rationale": "Continuous monitoring detects security threats and anomalies.", "recommendation": "Configure Defender, alert policies, and prompt pattern monitoring."},
    "NIST-800-53:SI-12": {"title": "Information Management and Retention", "rationale": "Information must be retained and disposed per policy.", "recommendation": "Configure retention policies and legal holds for Copilot data."},
}


# ══════════════════════════════════════════════════════════════════════════════
# Public enrichment function
# ══════════════════════════════════════════════════════════════════════════════

def enrich_compliance_mapping(findings: list[dict]) -> list[dict]:
    """Add ComplianceMapping and ComplianceDetails to each finding."""
    for f in findings:
        subcat = f.get("Subcategory", "")
        mapping = _COMPLIANCE_MAP.get(subcat)
        if mapping:
            f["ComplianceMapping"] = mapping
            details: dict[str, dict[str, str]] = {}
            for fw, ctrls in mapping.items():
                for ctrl in ctrls:
                    key = f"{fw}:{ctrl}"
                    if key in _CONTROL_DETAILS:
                        details[key] = _CONTROL_DETAILS[key]
            if details:
                f["ComplianceDetails"] = details
    return findings
