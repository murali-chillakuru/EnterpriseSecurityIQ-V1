"""
Data Security — Compliance mapping, resource enrichment, remediation impact.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from app.datasec_evaluators.finding import DS_FINDING_NS as _DS_FINDING_NS, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

# Maps each finding subcategory → framework control IDs.
# 8 frameworks: CIS, PCI-DSS (v4.0.1), HIPAA, NIST-800-53 (Rev 5),
#               ISO-27001 (2022), SOC2, NIST-CSF (2.0), MCSB (1.0)

_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    # ── Storage ──────────────────────────────────────────────────────────
    "blob_public_access": {
        "CIS": ["3.7"], "PCI-DSS": ["1.3.1", "7.1"], "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["AC-3", "SC-7"], "ISO-27001": ["A.8.3"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["DP-9"],
        "CSA-CCM": ["DSP-10", "IVS-03"],
        "FedRAMP": ["AC-3", "SC-7"],
        "GDPR": ["Art.25(1)", "Art.32(1)"],
    },
    "storage_https": {
        "CIS": ["3.1"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-8"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.DS-2"], "MCSB": ["DP-3"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-8", "SC-8(1)"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "storage_network_rules": {
        "CIS": ["3.8"], "PCI-DSS": ["1.2.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(2)"],
    },
    "soft_delete_disabled": {
        "CIS": ["3.11"], "PCI-DSS": ["10.7"], "HIPAA": ["164.312(c)(1)"],
        "NIST-800-53": ["CP-9"], "ISO-27001": ["A.5.29"],
        "SOC2": ["A1.1"], "NIST-CSF": ["PR.IP-4"], "MCSB": ["BR-1"],
        "CSA-CCM": ["BCR-03", "DSP-16"],
        "FedRAMP": ["CP-9", "CP-6"],
        "GDPR": ["Art.32(1)", "Art.5(1d)"],
    },
    "min_tls_weak": {
        "CIS": ["3.2"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-8"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.DS-2"], "MCSB": ["DP-3"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-8", "SC-8(1)"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "shared_key_enabled": {
        "CIS": ["3.3"], "PCI-DSS": ["8.2.1"], "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-5"], "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.5"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["IM-1"],
        "CSA-CCM": ["IAM-02", "CEK-01"],
        "FedRAMP": ["IA-5", "IA-2(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "no_blob_logging": {
        "CIS": ["5.1.2"], "PCI-DSS": ["10.2"], "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-2"], "ISO-27001": ["A.8.15"],
        "SOC2": ["CC8.2"], "NIST-CSF": ["DE.AE-1"], "MCSB": ["LT-3"],
        "CSA-CCM": ["LOG-01", "LOG-03"],
        "FedRAMP": ["AU-2", "AU-3"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    "blob_versioning_disabled": {
        "CIS": ["3.11"], "PCI-DSS": ["10.7"], "HIPAA": ["164.312(c)(1)"],
        "NIST-800-53": ["CP-9"], "ISO-27001": ["A.5.29"],
        "SOC2": ["A1.1"], "NIST-CSF": ["PR.IP-4"], "MCSB": ["BR-1"],
        "CSA-CCM": ["BCR-03", "DSP-16"],
        "FedRAMP": ["CP-9", "CP-6"],
        "GDPR": ["Art.32(1)", "Art.5(1d)"],
    },
    # ── Database ─────────────────────────────────────────────────────────
    "sql_tde_disabled": {
        "CIS": ["4.1.1"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC8.3"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-28", "SC-28(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "sql_auditing_disabled": {
        "CIS": ["4.1.3"], "PCI-DSS": ["10.2"], "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-2"], "ISO-27001": ["A.8.15"],
        "SOC2": ["CC8.2"], "NIST-CSF": ["DE.AE-1"], "MCSB": ["LT-3"],
        "CSA-CCM": ["LOG-01", "LOG-05"],
        "FedRAMP": ["AU-2", "AU-12"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    "sql_atp_disabled": {
        "CIS": ["4.2.1"], "PCI-DSS": ["11.4"], "HIPAA": ["164.308(a)(6)(ii)"],
        "NIST-800-53": ["SI-4"], "ISO-27001": ["A.8.16"],
        "SOC2": ["CC9.1"], "NIST-CSF": ["DE.AE-2"], "MCSB": ["LT-1"],
        "CSA-CCM": ["TVM-01", "LOG-09"],
        "FedRAMP": ["SI-4", "SI-4(5)"],
        "GDPR": ["Art.32(1)", "Art.33(1)"],
    },
    "sql_no_ddm": {
        "CIS": ["4.2.2"], "PCI-DSS": ["3.3"], "HIPAA": ["164.514(a)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.11"],
        "SOC2": ["C1.1"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["DSP-05", "DSP-17"],
        "FedRAMP": ["SC-28", "AC-3"],
        "GDPR": ["Art.25(2)", "Art.5(1c)"],
    },
    "sql_no_rls": {
        "CIS": ["4.2.3"], "PCI-DSS": ["7.1"], "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["AC-3"], "ISO-27001": ["A.5.15"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["PA-7"],
        "CSA-CCM": ["IAM-10", "DSP-05"],
        "FedRAMP": ["AC-3", "AC-6"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"],
    },
    # ── Cosmos DB ────────────────────────────────────────────────────────
    "cosmosdb_public_access": {
        "CIS": ["4.5.1"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.12"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "eventual_consistency": {
        "CIS": ["4.5.3"], "PCI-DSS": ["3.6"], "HIPAA": ["164.312(c)(1)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["PI1.1"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["DSP-16", "BCR-01"],
        "FedRAMP": ["SC-28", "CP-9"],
        "GDPR": ["Art.5(1d)", "Art.32(1)"],
    },
    # ── Key Vault ────────────────────────────────────────────────────────
    "access_policy_model": {
        "CIS": ["8.1"], "PCI-DSS": ["3.5.2"], "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["AC-3"], "ISO-27001": ["A.5.15"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["PA-7"],
        "CSA-CCM": ["IAM-10", "CEK-01"],
        "FedRAMP": ["AC-3", "AC-6"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "purge_protection_off": {
        "CIS": ["8.2"], "PCI-DSS": ["3.5.3"], "HIPAA": ["164.312(c)(1)"],
        "NIST-800-53": ["CP-9"], "ISO-27001": ["A.5.29"],
        "SOC2": ["A1.1"], "NIST-CSF": ["PR.IP-4"], "MCSB": ["BR-1"],
        "CSA-CCM": ["BCR-03", "CEK-05"],
        "FedRAMP": ["CP-9", "CP-6"],
        "GDPR": ["Art.32(1)", "Art.5(1d)"],
    },
    "no_expiry_set": {
        "CIS": ["8.4"], "PCI-DSS": ["3.6.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["IA-5"], "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.5"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["IM-3"],
        "CSA-CCM": ["CEK-04", "IAM-09"],
        "FedRAMP": ["IA-5", "IA-5(1)"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "cert_no_auto_renewal": {
        "CIS": ["8.5"], "PCI-DSS": ["3.6.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["IA-5"], "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.5"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["IM-3"],
        "CSA-CCM": ["CEK-04", "IAM-09"],
        "FedRAMP": ["IA-5", "SC-17"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "keys_not_hsm_backed": {
        "CIS": ["8.6"], "PCI-DSS": ["3.5.2"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC8.3"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["CEK-02", "CEK-05"],
        "FedRAMP": ["SC-12", "SC-12(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Encryption ───────────────────────────────────────────────────────
    "disk_encryption_missing": {
        "CIS": ["7.1"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC8.3"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-28", "SC-28(1)"],
        "GDPR": ["Art.32(1)", "Art.34(3a)"],
    },
    # ── Data Access ──────────────────────────────────────────────────────
    "overprivileged_access": {
        "CIS": ["1.22"], "PCI-DSS": ["7.1"], "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["AC-6"], "ISO-27001": ["A.5.18"],
        "SOC2": ["CC6.3"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["PA-7"],
        "CSA-CCM": ["IAM-05", "IAM-10"],
        "FedRAMP": ["AC-6", "AC-6(1)"],
        "GDPR": ["Art.25(2)", "Art.5(1f)"],
    },
    # ── Threat Detection ─────────────────────────────────────────────────
    "defender_coverage_gaps": {
        "CIS": ["2.1.1"], "PCI-DSS": ["11.4"], "HIPAA": ["164.308(a)(6)(ii)"],
        "NIST-800-53": ["SI-4"], "ISO-27001": ["A.8.16"],
        "SOC2": ["CC9.1"], "NIST-CSF": ["DE.AE-2"], "MCSB": ["LT-1"],
        "CSA-CCM": ["TVM-01", "TVM-02"],
        "FedRAMP": ["SI-4", "RA-5"],
        "GDPR": ["Art.32(1)", "Art.33(1)"],
    },
    "audit_log_short_retention": {
        "CIS": ["5.1.4"], "PCI-DSS": ["10.7"], "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-6"], "ISO-27001": ["A.8.15"],
        "SOC2": ["CC8.2"], "NIST-CSF": ["DE.AE-1"], "MCSB": ["LT-5b"],
        "CSA-CCM": ["LOG-05", "LOG-11"],
        "FedRAMP": ["AU-11", "AU-6"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    # ── Network ──────────────────────────────────────────────────────────
    "nsg_data_ports_open": {
        "CIS": ["6.1"], "PCI-DSS": ["1.2.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-3"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "IVS-06"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── DLP ───────────────────────────────────────────────────────────────
    "no_dlp_policies": {
        "PCI-DSS": ["3.1"], "HIPAA": ["164.312(c)(1)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["C1.1"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["DSP-01", "DSP-05"],
        "FedRAMP": ["SC-28", "MP-4"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "dlp_no_sensitive_info_types": {
        "PCI-DSS": ["3.4"], "HIPAA": ["164.514(a)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.11"],
        "SOC2": ["C1.1"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["DSP-01", "DSP-05"],
        "FedRAMP": ["SC-28", "MP-4"],
        "GDPR": ["Art.25(2)", "Art.5(1c)"],
    },
    # ── Database — AAD-only auth ─────────────────────────────────────────
    "sql_local_auth_enabled": {
        "CIS": ["4.1.5"], "PCI-DSS": ["8.2.1"], "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-2"], "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["IM-1"],
        "CSA-CCM": ["IAM-02", "IAM-04"],
        "FedRAMP": ["IA-2", "IA-2(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── PostgreSQL/MySQL — AAD auth ──────────────────────────────────────
    "pg_mysql_no_aad_auth": {
        "CIS": ["4.3.7"], "PCI-DSS": ["8.2.1"], "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-2"], "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["IM-1"],
        "CSA-CCM": ["IAM-02", "IAM-04"],
        "FedRAMP": ["IA-2", "IA-2(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Data Access — managed identity ───────────────────────────────────
    "no_managed_identity": {
        "CIS": ["1.17"], "PCI-DSS": ["8.2.1"], "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-5"], "ISO-27001": ["A.5.16"],
        "SOC2": ["CC6.5"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["IM-3"],
        "CSA-CCM": ["IAM-02", "IAM-09"],
        "FedRAMP": ["IA-5", "IA-2"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Backup/DR — resource locks ───────────────────────────────────────
    "no_resource_lock": {
        "CIS": ["8.3"], "PCI-DSS": ["10.7"], "HIPAA": ["164.312(c)(1)"],
        "NIST-800-53": ["CM-5"], "ISO-27001": ["A.8.32"],
        "SOC2": ["CC8.4"], "NIST-CSF": ["PR.IP-3"], "MCSB": ["PV-9"],
        "CSA-CCM": ["BCR-03", "DSP-16"],
        "FedRAMP": ["CM-5", "CM-3"],
        "GDPR": ["Art.32(1)", "Art.5(1d)"],
    },
    # ── Network — Data Factory / Synapse ─────────────────────────────────
    "adf_no_managed_vnet": {
        "CIS": ["6.5"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.22"],
        "SOC2": ["CC6.8"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "IVS-06"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "synapse_no_exfiltration_protection": {
        "CIS": ["6.5"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.22"],
        "SOC2": ["CC6.8"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "AC-4"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    # ── Private Endpoints — AI services ──────────────────────────────────
    "ai_services_public_access": {
        "CIS": ["6.2"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.5.23"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Encryption — Log Analytics ───────────────────────────────────────
    "log_analytics_no_cmk": {
        "CIS": ["7.3"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC8.3"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["CEK-03", "CEK-01"],
        "FedRAMP": ["SC-28", "SC-12"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Threat Detection — immutable logs ────────────────────────────────
    "no_immutable_audit_logs": {
        "CIS": ["5.1.5"], "PCI-DSS": ["10.3"], "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-2"], "ISO-27001": ["A.8.15"],
        "SOC2": ["CC8.2"], "NIST-CSF": ["DE.AE-1"], "MCSB": ["LT-3"],
        "CSA-CCM": ["LOG-03", "LOG-11"],
        "FedRAMP": ["AU-9", "AU-9(4)"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    # ── Redis ────────────────────────────────────────────────────────────
    "redis_non_ssl_port": {
        "CIS": ["4.6.1"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-8"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.DS-2"], "MCSB": ["DP-3"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-8", "SC-8(1)"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "redis_weak_tls": {
        "CIS": ["4.6.2"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-8"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.DS-2"], "MCSB": ["DP-3"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-8", "SC-8(1)"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "redis_no_firewall": {
        "CIS": ["4.6.3"], "PCI-DSS": ["1.2.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-3"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "IVS-06"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Messaging ────────────────────────────────────────────────────────
    "eventhub_public_access": {
        "CIS": ["6.3"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "servicebus_public_access": {
        "CIS": ["6.3"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "messaging_weak_tls": {
        "CIS": ["6.4"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-8"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.DS-2"], "MCSB": ["DP-3"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-8", "SC-8(1)"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    # ── Aliases — scanner subcategory name variants ─────────────────────────
    "purge_protection_disabled": {
        "CIS": ["8.2"], "PCI-DSS": ["3.5.3"], "HIPAA": ["164.312(c)(1)"],
        "NIST-800-53": ["CP-9"], "ISO-27001": ["A.5.29"],
        "SOC2": ["A1.1"], "NIST-CSF": ["PR.IP-4"], "MCSB": ["BR-1"],
        "CSA-CCM": ["BCR-03", "CEK-05"],
        "FedRAMP": ["CP-9", "CP-6"],
        "GDPR": ["Art.32(1)", "Art.5(1d)"],
    },
    "legacy_access_policy_model": {
        "CIS": ["8.1"], "PCI-DSS": ["3.5.2"], "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["AC-3"], "ISO-27001": ["A.5.15"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["PA-7"],
        "CSA-CCM": ["IAM-10", "CEK-01"],
        "FedRAMP": ["AC-3", "AC-6"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Key Vault — network restrictions ─────────────────────────────────
    "no_network_restrictions": {
        "CIS": ["8.7"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Purview ──────────────────────────────────────────────────────────
    "purview_public_access": {
        "CIS": ["6.2"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.5.23"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "purview_no_private_endpoint": {
        "CIS": ["6.2"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.5.23"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "purview_scan_coverage_gap": {
        "CIS": ["2.1.1"], "PCI-DSS": ["11.4"], "HIPAA": ["164.308(a)(6)(ii)"],
        "NIST-800-53": ["PM-5"], "ISO-27001": ["A.5.9"],
        "SOC2": ["CC3.2"], "NIST-CSF": ["ID.AM-1"], "MCSB": ["AM-2"],
        "CSA-CCM": ["TVM-02", "DSP-01"],
        "FedRAMP": ["RA-5", "PM-5"],
        "GDPR": ["Art.35(1)", "Art.30(1)"],
    },
    "purview_scan_issues": {
        "CIS": ["2.1.1"], "PCI-DSS": ["11.4"], "HIPAA": ["164.308(a)(6)(ii)"],
        "NIST-800-53": ["CA-7"], "ISO-27001": ["A.8.8"],
        "SOC2": ["CC7.1"], "NIST-CSF": ["DE.CM-8"], "MCSB": ["PV-5"],
        "CSA-CCM": ["TVM-02", "DSP-01"],
        "FedRAMP": ["RA-5", "CA-7"],
        "GDPR": ["Art.35(1)", "Art.30(1)"],
    },
    # ── Encryption alias ─────────────────────────────────────────────────
    "managed_disk_no_cmk": {
        "CIS": ["7.1"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC8.3"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["CEK-03", "CEK-01"],
        "FedRAMP": ["SC-28", "SC-12"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Data Access — diagnostics ────────────────────────────────────────
    "no_diagnostic_settings": {
        "CIS": ["5.1.2"], "PCI-DSS": ["10.2"], "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-2"], "ISO-27001": ["A.8.15"],
        "SOC2": ["CC8.2"], "NIST-CSF": ["DE.AE-1"], "MCSB": ["LT-3"],
        "CSA-CCM": ["LOG-01", "LOG-03"],
        "FedRAMP": ["AU-2", "AU-3"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    # ── Private Endpoints — generic ──────────────────────────────────────
    "no_private_endpoint": {
        "CIS": ["6.2"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"], "ISO-27001": ["A.5.23"],
        "SOC2": ["CC6.7"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-1"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Network — DDoS ───────────────────────────────────────────────────
    "no_ddos_protection": {
        "CIS": ["6.6"], "PCI-DSS": ["1.2.1"], "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-5"], "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.1"], "NIST-CSF": ["PR.AC-5"], "MCSB": ["NS-5"],
        "CSA-CCM": ["IVS-09", "IVS-06"],
        "FedRAMP": ["SC-5", "SC-7"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    # ── Storage extras ───────────────────────────────────────────────────
    "no_sas_expiration_policy": {
        "CIS": ["3.9"], "PCI-DSS": ["3.6.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["IA-5"], "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.5"], "NIST-CSF": ["PR.AC-1"], "MCSB": ["IM-3"],
        "CSA-CCM": ["IAM-09", "CEK-04"],
        "FedRAMP": ["IA-5", "IA-5(1)"],
        "GDPR": ["Art.32(1)", "Art.5(1f)"],
    },
    "no_immutability_policy": {
        "CIS": ["5.1.5"], "PCI-DSS": ["10.3"], "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-2"], "ISO-27001": ["A.8.15"],
        "SOC2": ["CC8.2"], "NIST-CSF": ["DE.AE-1"], "MCSB": ["LT-3"],
        "CSA-CCM": ["LOG-11", "DSP-16"],
        "FedRAMP": ["AU-9", "AU-9(4)"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    "change_feed_disabled": {
        "CIS": ["3.12"], "PCI-DSS": ["10.2"], "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-2"], "ISO-27001": ["A.8.15"],
        "SOC2": ["CC8.2"], "NIST-CSF": ["DE.AE-1"], "MCSB": ["LT-3"],
        "CSA-CCM": ["LOG-01", "LOG-03"],
        "FedRAMP": ["AU-2", "AU-3"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    # ── Encryption — scanner aliases ────────────────────────────────────────
    "unencrypted_disks": {
        "CIS": ["7.1"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC8.3"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-28", "SC-28(1)"],
        "GDPR": ["Art.32(1)", "Art.34(3a)"],
    },
    "no_encryption_at_host": {
        "CIS": ["7.2"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-28"], "ISO-27001": ["A.8.24"],
        "SOC2": ["CC8.3"], "NIST-CSF": ["PR.DS-1"], "MCSB": ["DP-4"],
        "CSA-CCM": ["CEK-03", "DSP-17"],
        "FedRAMP": ["SC-28", "SC-28(1)"],
        "GDPR": ["Art.32(1)", "Art.34(3a)"],
    },
    # ── Threat Detection — action groups ────────────────────────────────────
    "no_security_action_groups": {
        "CIS": ["2.1.1"], "PCI-DSS": ["11.4"], "HIPAA": ["164.308(a)(6)(ii)"],
        "NIST-800-53": ["IR-6"], "ISO-27001": ["A.5.25"],
        "SOC2": ["CC9.1"], "NIST-CSF": ["RS.CO-2"], "MCSB": ["LT-1"],
        "CSA-CCM": ["TVM-01", "LOG-09"],
        "FedRAMP": ["IR-6", "SI-4"],
        "GDPR": ["Art.33(1)", "Art.34(1)"],
    },

    # ── AI Services ──────────────────────────────────────────────────
    "ai_key_auth_enabled": {
        "CIS": ["9.1"],
        "PCI-DSS": ["8.3.1"],
        "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-2"],
        "ISO-27001": ["A.8.5"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.AC-1"],
        "MCSB": ["IM-1"],
        "CSA-CCM": ["IAM-02", "IAM-04"],
        "FedRAMP": ["IA-2", "IA-2(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "ai_no_managed_identity": {
        "CIS": ["9.2"],
        "PCI-DSS": ["8.6"],
        "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["IA-5"],
        "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.AC-7"],
        "MCSB": ["IM-3"],
        "CSA-CCM": ["IAM-02", "IAM-09"],
        "FedRAMP": ["IA-5", "IA-2"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "ai_no_cmk": {
        "CIS": ["9.3"],
        "PCI-DSS": ["3.5.2"],
        "HIPAA": ["164.312(a)(2)(iv)"],
        "NIST-800-53": ["SC-12"],
        "ISO-27001": ["A.8.24"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.DS-1"],
        "MCSB": ["DP-5"],
        "CSA-CCM": ["CEK-03", "CEK-01"],
        "FedRAMP": ["SC-12", "SC-28"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Data Pipeline ────────────────────────────────────────────────
    "adf_public_access": {
        "CIS": ["6.1"],
        "PCI-DSS": ["1.3.1"],
        "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"],
        "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.6"],
        "NIST-CSF": ["PR.AC-5"],
        "MCSB": ["NS-2"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "adf_no_managed_identity": {
        "CIS": ["6.2"],
        "PCI-DSS": ["8.6"],
        "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["IA-5"],
        "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.AC-7"],
        "MCSB": ["IM-3"],
        "CSA-CCM": ["IAM-02", "IAM-09"],
        "FedRAMP": ["IA-5", "IA-2"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "adf_no_git_integration": {
        "CIS": ["6.3"],
        "PCI-DSS": ["6.5.4"],
        "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["CM-3"],
        "ISO-27001": ["A.8.32"],
        "SOC2": ["CC8.1"],
        "NIST-CSF": ["PR.IP-3"],
        "MCSB": ["PV-6"],
        "CSA-CCM": ["GRC-01", "DSP-16"],
        "FedRAMP": ["CM-3", "CM-5"],
        "GDPR": ["Art.32(1)", "Art.5(2)"],
    },
    "synapse_public_access": {
        "CIS": ["6.4"],
        "PCI-DSS": ["1.3.1"],
        "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"],
        "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.6"],
        "NIST-CSF": ["PR.AC-5"],
        "MCSB": ["NS-2"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "synapse_sql_auth_enabled": {
        "CIS": ["6.5"],
        "PCI-DSS": ["8.3.1"],
        "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-2"],
        "ISO-27001": ["A.8.5"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.AC-1"],
        "MCSB": ["IM-1"],
        "CSA-CCM": ["IAM-02", "IAM-04"],
        "FedRAMP": ["IA-2", "IA-2(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Enhanced Messaging ───────────────────────────────────────────
    "eventhub_local_auth": {
        "CIS": ["7.1"],
        "PCI-DSS": ["8.3.1"],
        "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-2"],
        "ISO-27001": ["A.8.5"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.AC-1"],
        "MCSB": ["IM-1"],
        "CSA-CCM": ["IAM-02", "IAM-04"],
        "FedRAMP": ["IA-2", "IA-2(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "servicebus_local_auth": {
        "CIS": ["7.2"],
        "PCI-DSS": ["8.3.1"],
        "HIPAA": ["164.312(d)"],
        "NIST-800-53": ["IA-2"],
        "ISO-27001": ["A.8.5"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.AC-1"],
        "MCSB": ["IM-1"],
        "CSA-CCM": ["IAM-02", "IAM-04"],
        "FedRAMP": ["IA-2", "IA-2(1)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    "eventhub_no_capture": {
        "CIS": ["7.3"],
        "PCI-DSS": ["10.2"],
        "HIPAA": ["164.312(b)"],
        "NIST-800-53": ["AU-2"],
        "ISO-27001": ["A.8.15"],
        "SOC2": ["CC7.2"],
        "NIST-CSF": ["DE.AE-3"],
        "MCSB": ["LT-3"],
        "CSA-CCM": ["LOG-01", "LOG-05"],
        "FedRAMP": ["AU-2", "AU-11"],
        "GDPR": ["Art.30(1)", "Art.5(2)"],
    },
    # ── Enhanced Redis ───────────────────────────────────────────────
    "redis_no_patch_schedule": {
        "CIS": ["7.4"],
        "PCI-DSS": ["6.3.3"],
        "HIPAA": ["164.308(a)(5)(ii)(B)"],
        "NIST-800-53": ["SI-2"],
        "ISO-27001": ["A.8.8"],
        "SOC2": ["CC7.1"],
        "NIST-CSF": ["PR.IP-12"],
        "MCSB": ["PV-7"],
        "CSA-CCM": ["TVM-04", "IVS-05"],
        "FedRAMP": ["SI-2", "SI-2(2)"],
        "GDPR": ["Art.32(1)", "Art.32(1d)"],
    },
    "redis_public_access": {
        "CIS": ["7.5"],
        "PCI-DSS": ["1.3.1"],
        "HIPAA": ["164.312(e)(1)"],
        "NIST-800-53": ["SC-7"],
        "ISO-27001": ["A.8.20"],
        "SOC2": ["CC6.6"],
        "NIST-CSF": ["PR.AC-5"],
        "MCSB": ["NS-2"],
        "CSA-CCM": ["IVS-03", "DSP-10"],
        "FedRAMP": ["SC-7", "SC-7(5)"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Identity ─────────────────────────────────────────────────────
    "data_services_no_managed_identity": {
        "CIS": ["9.4"],
        "PCI-DSS": ["8.6"],
        "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["IA-5"],
        "ISO-27001": ["A.5.17"],
        "SOC2": ["CC6.1"],
        "NIST-CSF": ["PR.AC-7"],
        "MCSB": ["IM-3"],
        "CSA-CCM": ["IAM-02", "IAM-09"],
        "FedRAMP": ["IA-5", "IA-2"],
        "GDPR": ["Art.32(1)", "Art.25(1)"],
    },
    # ── Wave A: SQL MI, App Config, Cert Lifecycle ───────────────────────
    "sqlmi_no_atp": {"CIS": ["4.3.1"], "PCI-DSS": ["6.5.1"], "HIPAA": ["164.312(a)(1)"], "NIST-800-53": ["SI-4"], "MCSB": ["DP-2"]},
    "sqlmi_public_endpoint": {"CIS": ["4.3.2"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-2"]},
    "sqlmi_no_aad_only": {"CIS": ["4.3.3"], "PCI-DSS": ["8.3"], "HIPAA": ["164.312(d)"], "NIST-800-53": ["IA-2"], "MCSB": ["IM-1"]},
    "appconfig_public_access": {"CIS": ["9.1"], "PCI-DSS": ["1.3"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-2"]},
    "appconfig_no_private_endpoint": {"CIS": ["9.2"], "PCI-DSS": ["1.3.4"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-1"]},
    "appconfig_no_soft_delete": {"CIS": ["9.3"], "PCI-DSS": ["10.7"], "HIPAA": ["164.312(b)"], "NIST-800-53": ["CP-9"], "MCSB": ["BR-1"]},
    "cert_expiring_soon": {"CIS": ["5.1.5"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(2)"], "NIST-800-53": ["SC-17"], "MCSB": ["DP-3"]},
    "cert_no_auto_renew": {"CIS": ["5.1.6"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-17"], "MCSB": ["DP-3"]},
    "cert_weak_key": {"CIS": ["5.1.7"], "PCI-DSS": ["3.6.1"], "HIPAA": ["164.312(a)(2)(iv)"], "NIST-800-53": ["SC-12"], "MCSB": ["DP-4"]},
    # ── Wave B: Databricks, APIM, Front Door, Secret Sprawl ──────────────
    "databricks_no_vnet": {"CIS": ["8.1"], "PCI-DSS": ["1.3.1"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-1"]},
    "databricks_no_cmk": {"CIS": ["8.2"], "PCI-DSS": ["3.5.2"], "HIPAA": ["164.312(a)(2)(iv)"], "NIST-800-53": ["SC-12"], "MCSB": ["DP-5"]},
    "databricks_public_access": {"CIS": ["8.3"], "PCI-DSS": ["1.3"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-2"]},
    "apim_no_vnet": {"CIS": ["10.1"], "PCI-DSS": ["1.3"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-1"]},
    "apim_no_managed_identity": {"CIS": ["10.2"], "PCI-DSS": ["8.3"], "HIPAA": ["164.312(d)"], "NIST-800-53": ["IA-5"], "MCSB": ["IM-3"]},
    "frontdoor_no_waf": {"CIS": ["11.1"], "PCI-DSS": ["6.6"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-6"]},
    "frontdoor_old_tls": {"CIS": ["11.2"], "PCI-DSS": ["4.1"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-8"], "MCSB": ["DP-3"]},
    "secret_in_app_settings": {"CIS": ["9.11"], "PCI-DSS": ["2.1", "6.3.2"], "HIPAA": ["164.312(a)(2)(iv)"], "NIST-800-53": ["SC-28", "IA-5"], "MCSB": ["DP-6"]},
    "no_keyvault_references": {"CIS": ["9.12"], "PCI-DSS": ["3.4"], "HIPAA": ["164.312(a)(2)(iv)"], "NIST-800-53": ["SC-28"], "MCSB": ["DP-6"]},
    # ── Wave C: Firewall, Bastion, Policy, Defender ──────────────────────
    "firewall_no_threat_intel": {"CIS": ["12.1"], "PCI-DSS": ["5.1"], "HIPAA": ["164.312(a)(1)"], "NIST-800-53": ["SI-4"], "MCSB": ["LT-1"]},
    "firewall_no_idps": {"CIS": ["12.2"], "PCI-DSS": ["11.4"], "HIPAA": ["164.312(a)(1)"], "NIST-800-53": ["SI-4"], "MCSB": ["LT-1"]},
    "appgw_no_waf": {"CIS": ["12.3"], "PCI-DSS": ["6.6"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-6"]},
    "no_bastion_open_rdp": {"CIS": ["13.1"], "PCI-DSS": ["1.3.1", "2.2.2"], "HIPAA": ["164.312(a)(1)"], "NIST-800-53": ["AC-17"], "MCSB": ["NI-3"]},
    "bastion_shareable_links": {"CIS": ["13.2"], "PCI-DSS": ["7.1"], "HIPAA": ["164.312(d)"], "NIST-800-53": ["AC-3"], "MCSB": ["PA-7"]},
    "data_policy_noncompliant": {"CIS": ["14.1"], "PCI-DSS": ["12.1"], "HIPAA": ["164.308(a)(8)"], "NIST-800-53": ["CA-7"], "MCSB": ["GS-3"]},
    "defender_data_recs_unhealthy": {"CIS": ["14.2"], "PCI-DSS": ["6.1"], "HIPAA": ["164.308(a)(1)"], "NIST-800-53": ["RA-5"], "MCSB": ["PV-5"]},

    # ── Wave D: Stale Permissions, Data Exfiltration, CA/PIM ─────────────
    "stale_data_role_assignment": {"CIS": ["1.23"], "PCI-DSS": ["8.1.4"], "HIPAA": ["164.312(a)(1)"], "NIST-800-53": ["AC-2"], "MCSB": ["PA-4"]},
    "storage_unusual_bypass": {"CIS": ["3.8"], "PCI-DSS": ["1.3.4"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-2"]},
    "cross_sub_private_endpoint": {"CIS": ["3.9"], "PCI-DSS": ["7.1"], "HIPAA": ["164.312(a)(1)"], "NIST-800-53": ["AC-3"], "MCSB": ["NI-4"]},
    "nsg_unrestricted_outbound": {"CIS": ["6.4"], "PCI-DSS": ["1.3.4"], "HIPAA": ["164.312(e)(1)"], "NIST-800-53": ["SC-7"], "MCSB": ["NI-1"]},
    "no_mfa_ca_policy": {"CIS": ["1.1.1"], "PCI-DSS": ["8.3.1"], "HIPAA": ["164.312(d)"], "NIST-800-53": ["IA-2(1)"], "MCSB": ["IM-4"]},
    "pim_permanent_assignments": {"CIS": ["1.24"], "PCI-DSS": ["7.1.2"], "HIPAA": ["164.312(a)(1)"], "NIST-800-53": ["AC-2(5)"], "MCSB": ["PA-2"]},
    # ── Config Drift ──
    "drift_detected": {"NIST-800-53": ["CM-3", "CM-6"], "PCI-DSS": ["10.5.5", "11.5"], "MCSB": ["PV-6"], "CIS": ["5.1"]},
    # ── Supply Chain ──
    "aks_no_acr_integration": {"NIST-800-53": ["SA-12", "CM-7"], "MCSB": ["DS-6"], "CIS": ["6.1"]},
    "acr_admin_enabled": {"NIST-800-53": ["AC-6", "SA-12"], "PCI-DSS": ["7.1"], "MCSB": ["PA-7"], "CIS": ["6.2"]},
    "func_external_package": {"NIST-800-53": ["SA-12", "SI-7"], "MCSB": ["DS-6"]},

}


# ── Control details for compliance popup ──────────────────────────────────
# Keyed by "FRAMEWORK:control_id" → {title, rationale, recommendation}

_CONTROL_DETAILS: dict[str, dict[str, str]] = {
    # ── CIS Azure Foundations Benchmark v2.0 ──────────────────────────────
    "CIS:1.17":  {"title": "Ensure managed identities are used", "rationale": "Managed identities eliminate the need for credential storage, reducing secret exposure risk.", "recommendation": "Enable system-assigned or user-assigned managed identity on all supported resources."},
    "CIS:1.22":  {"title": "Ensure least privilege access", "rationale": "Excessive permissions expand the blast radius of compromised accounts.", "recommendation": "Review RBAC assignments and remove Owner/Contributor where not required."},
    "CIS:2.1.1": {"title": "Ensure Defender for Cloud is enabled", "rationale": "Defender provides threat detection, vulnerability assessment, and security recommendations.", "recommendation": "Enable Microsoft Defender for Cloud Standard tier for all resource types."},
    "CIS:3.1":   {"title": "Ensure HTTPS is enforced on storage accounts", "rationale": "HTTP transmits data in plaintext, exposing it to interception.", "recommendation": "Set 'Secure transfer required' to enabled on all storage accounts."},
    "CIS:3.2":   {"title": "Ensure minimum TLS 1.2 for storage", "rationale": "TLS versions below 1.2 have known cryptographic weaknesses.", "recommendation": "Set minimum TLS version to 1.2 on all storage accounts."},
    "CIS:3.3":   {"title": "Ensure shared key access is disabled", "rationale": "Shared keys grant full access; Entra ID RBAC provides granular, auditable control.", "recommendation": "Disable shared key access and use Entra ID authentication."},
    "CIS:3.7":   {"title": "Ensure public blob access is disabled", "rationale": "Public blob access allows anonymous read to data without authentication.", "recommendation": "Disable public blob access on all storage accounts."},
    "CIS:3.8":   {"title": "Ensure storage network rules are configured", "rationale": "Default 'Allow' network rules expose storage to any IP address.", "recommendation": "Set default network action to Deny and whitelist trusted networks."},
    "CIS:3.11":  {"title": "Ensure soft delete and versioning are enabled", "rationale": "Without soft delete, accidental or malicious deletion is irreversible.", "recommendation": "Enable blob soft delete with a minimum 7-day retention and versioning."},
    "CIS:4.1.1": {"title": "Ensure TDE is enabled on SQL databases", "rationale": "TDE encrypts data at rest, protecting against storage media theft.", "recommendation": "Enable Transparent Data Encryption on all SQL databases."},
    "CIS:4.1.3": {"title": "Ensure SQL auditing is enabled", "rationale": "Auditing provides an audit trail of database operations for investigation.", "recommendation": "Enable auditing on all SQL servers with 90+ day retention."},
    "CIS:4.1.5": {"title": "Ensure Azure AD-only authentication for SQL", "rationale": "SQL authentication uses passwords; Azure AD provides MFA and conditional access.", "recommendation": "Enable Azure AD-only authentication and disable SQL auth."},
    "CIS:4.2.1": {"title": "Ensure Advanced Threat Protection for SQL", "rationale": "ATP detects anomalous activities indicating potential threats.", "recommendation": "Enable Advanced Threat Protection on all SQL servers."},
    "CIS:4.2.2": {"title": "Ensure Dynamic Data Masking is configured", "rationale": "DDM prevents unauthorized users from viewing sensitive data.", "recommendation": "Configure DDM rules for columns containing sensitive data."},
    "CIS:4.2.3": {"title": "Ensure Row Level Security is used", "rationale": "RLS restricts row access based on user context.", "recommendation": "Implement RLS policies on tables with multi-tenant or sensitive data."},
    "CIS:4.3.7": {"title": "Ensure Azure AD auth for PostgreSQL/MySQL", "rationale": "Azure AD auth provides centralized identity management and MFA.", "recommendation": "Enable Azure AD authentication on PostgreSQL and MySQL servers."},
    "CIS:4.5.1": {"title": "Ensure Cosmos DB public access is disabled", "rationale": "Public access exposes Cosmos DB to the internet.", "recommendation": "Disable public network access and use private endpoints."},
    "CIS:4.5.3": {"title": "Ensure strong consistency for Cosmos DB", "rationale": "Eventual consistency may return stale data, risking data integrity.", "recommendation": "Use Session or stronger consistency for sensitive workloads."},
    "CIS:4.6.1": {"title": "Ensure Redis non-SSL port is disabled", "rationale": "The non-SSL port transmits data in plaintext.", "recommendation": "Disable non-SSL port (6379) on all Redis caches."},
    "CIS:4.6.2": {"title": "Ensure Redis uses TLS 1.2+", "rationale": "Older TLS versions have known vulnerabilities.", "recommendation": "Set minimum TLS version to 1.2 on all Redis caches."},
    "CIS:4.6.3": {"title": "Ensure Redis firewall rules are configured", "rationale": "Without firewall rules, Redis is accessible from any Azure IP.", "recommendation": "Configure firewall rules or use private endpoints for Redis."},
    "CIS:5.1.2": {"title": "Ensure blob storage logging is enabled", "rationale": "Without logging, unauthorized access to blobs goes undetected.", "recommendation": "Enable diagnostic logging for blob read, write, and delete operations."},
    "CIS:5.1.4": {"title": "Ensure audit log retention is sufficient", "rationale": "Short retention destroys evidence needed for incident investigation.", "recommendation": "Set audit log retention to at least 90 days."},
    "CIS:5.1.5": {"title": "Ensure immutable audit logs", "rationale": "Mutable logs can be tampered with to hide attacker activity.", "recommendation": "Enable immutability policies on audit log storage."},
    "CIS:6.1":   {"title": "Ensure NSGs restrict inbound data ports", "rationale": "Open database ports allow direct network attacks on data services.", "recommendation": "Restrict NSG rules for ports 1433, 3306, 5432, 27017 to trusted IPs."},
    "CIS:6.2":   {"title": "Ensure private endpoints for AI services", "rationale": "Public AI service endpoints expose cognitive APIs to the internet.", "recommendation": "Deploy private endpoints and disable public access for AI services."},
    "CIS:6.3":   {"title": "Ensure messaging services restrict access", "rationale": "Unrestricted messaging endpoints allow unauthorized event submission.", "recommendation": "Set default network action to Deny on Event Hub and Service Bus."},
    "CIS:6.4":   {"title": "Ensure messaging uses TLS 1.2+", "rationale": "Weak TLS on messaging exposes event streams to interception.", "recommendation": "Set minimum TLS version to 1.2 on all messaging namespaces."},
    "CIS:6.5":   {"title": "Ensure managed VNets for data integration", "rationale": "Without managed VNets, data pipelines operate on public networks.", "recommendation": "Enable managed VNet on ADF and data exfiltration protection on Synapse."},
    "CIS:7.1":   {"title": "Ensure disk encryption is enabled", "rationale": "Unencrypted disks expose data if physical media is accessed.", "recommendation": "Enable Azure Disk Encryption or server-side encryption with CMK."},
    "CIS:7.3":   {"title": "Ensure CMK for Log Analytics", "rationale": "Platform keys are shared; CMK provides customer-controlled encryption.", "recommendation": "Configure customer-managed keys for Log Analytics workspaces."},
    "CIS:8.1":   {"title": "Ensure Key Vault uses RBAC model", "rationale": "Access policies lack granularity; RBAC provides fine-grained control.", "recommendation": "Switch Key Vault permission model from Access Policy to RBAC."},
    "CIS:8.2":   {"title": "Ensure purge protection is enabled", "rationale": "Without purge protection, deleted keys/secrets are lost permanently.", "recommendation": "Enable purge protection on all Key Vaults."},
    "CIS:8.3":   {"title": "Ensure resource locks on critical resources", "rationale": "Without locks, critical resources can be accidentally deleted.", "recommendation": "Apply CanNotDelete locks on production Key Vaults and data stores."},
    "CIS:8.4":   {"title": "Ensure key/secret expiry is set", "rationale": "Non-expiring secrets persist indefinitely if compromised.", "recommendation": "Set expiry dates on all keys and secrets."},
    "CIS:8.5":   {"title": "Ensure certificate auto-renewal", "rationale": "Expired certificates cause service outages and break trust chains.", "recommendation": "Enable auto-renewal on all Key Vault certificates."},
    "CIS:8.6":   {"title": "Ensure keys are HSM-backed", "rationale": "Software-protected keys are stored in memory; HSM keys are hardware-isolated.", "recommendation": "Use HSM-backed keys for production workloads."},
    # ── PCI-DSS v4.0.1 (Jun 2024) ────────────────────────────────────────
    "PCI-DSS:1.2.1": {"title": "Restrict inbound/outbound traffic", "rationale": "Unrestricted traffic between trusted and untrusted networks enables data exfiltration.", "recommendation": "Configure firewall and NSG rules to restrict traffic to known trusted sources."},
    "PCI-DSS:1.3.1": {"title": "Restrict inbound access to CDE", "rationale": "Direct inbound access to the cardholder data environment increases breach risk.", "recommendation": "Restrict inbound CDE access to only necessary and authorized connections."},
    "PCI-DSS:3.1":   {"title": "Keep cardholder data to a minimum", "rationale": "Stored cardholder data increases the scope and impact of a breach.", "recommendation": "Implement data retention policies and minimize stored cardholder data."},
    "PCI-DSS:3.3":   {"title": "Mask PAN when displayed", "rationale": "Displaying full PAN exposes cardholder data to unauthorized viewers.", "recommendation": "Mask PAN to show only the first six and last four digits."},
    "PCI-DSS:3.4":   {"title": "Render PAN unreadable in storage", "rationale": "Readable PAN in storage is exploitable if storage is compromised. v4.0.1 clarified applicability for issuers using keyed cryptographic hashes.", "recommendation": "Use encryption, truncation, tokenization, or one-way hashing. Per v4.0.1, keyed cryptographic hashes have a Customized Approach Objective."},
    "PCI-DSS:3.5.2": {"title": "Protect cryptographic keys", "rationale": "Compromised keys expose all data encrypted with those keys.", "recommendation": "Store keys in HSMs or Key Vaults with separation of duties."},
    "PCI-DSS:3.5.3": {"title": "Restrict key access to fewest custodians", "rationale": "Broad key access increases the risk of key compromise.", "recommendation": "Limit key access to authorized custodians and enable purge protection."},
    "PCI-DSS:3.6":   {"title": "Cryptographic key management", "rationale": "Improper key management weakens the entire encryption scheme.", "recommendation": "Implement key lifecycle management including rotation and revocation."},
    "PCI-DSS:3.6.4": {"title": "Cryptographic key changes at crypto-periods", "rationale": "Keys used past their cryptoperiod are more likely to be compromised.", "recommendation": "Rotate keys and certificates before their cryptoperiod expires."},
    "PCI-DSS:4.1":   {"title": "Use strong cryptography for transmission", "rationale": "Weak or absent encryption exposes cardholder data in transit.", "recommendation": "Enforce TLS 1.2 or higher for all public-facing and internal endpoints."},
    "PCI-DSS:7.1":   {"title": "Restrict access by business need", "rationale": "Excessive access increases the risk of unauthorized data viewing or modification.", "recommendation": "Implement role-based access control with least privilege."},
    "PCI-DSS:8.2.1": {"title": "Unique identification for all users", "rationale": "Shared accounts prevent accountability and audit trail accuracy.", "recommendation": "Use unique Azure AD identities and disable local/shared authentication."},
    "PCI-DSS:10.2":  {"title": "Implement automated audit trails", "rationale": "Without audit trails, security events go undetected and uninvestigated.", "recommendation": "Enable diagnostic logging and auditing on all data resources."},
    "PCI-DSS:10.3":  {"title": "Protect audit trail from modification", "rationale": "Modifiable logs can be altered to conceal attacker activity.", "recommendation": "Enable immutability policies on audit log storage containers."},
    "PCI-DSS:10.7":  {"title": "Retain audit logs for at least one year", "rationale": "Short retention eliminates evidence needed for breach investigation.", "recommendation": "Configure 365-day retention with 90 days immediately available."},
    "PCI-DSS:11.4":  {"title": "Intrusion detection and prevention", "rationale": "Without IDS/IPS, network attacks on the CDE go undetected.", "recommendation": "Enable Microsoft Defender for Cloud and configure alert notifications."},
    # ── HIPAA Security Rule ───────────────────────────────────────────────
    "HIPAA:164.308(a)(6)(ii)": {"title": "Security Incident Procedures", "rationale": "HIPAA requires identification and response to security incidents.", "recommendation": "Enable Defender for Cloud and configure security incident alerting."},
    "HIPAA:164.312(a)(1)":     {"title": "Access Control", "rationale": "HIPAA requires technical policies to allow only authorized access to ePHI.", "recommendation": "Implement RBAC with least-privilege and conditional access."},
    "HIPAA:164.312(a)(2)(iv)": {"title": "Encryption and Decryption", "rationale": "HIPAA requires encryption as an addressable implementation specification for ePHI.", "recommendation": "Encrypt all ePHI at rest using AES-256 or equivalent."},
    "HIPAA:164.312(b)":        {"title": "Audit Controls", "rationale": "HIPAA requires mechanisms to record and examine access to ePHI.", "recommendation": "Enable logging and audit trails on all systems containing ePHI."},
    "HIPAA:164.312(c)(1)":     {"title": "Integrity Controls", "rationale": "HIPAA requires protection against improper alteration or destruction of ePHI.", "recommendation": "Enable soft delete, versioning, and immutability policies."},
    "HIPAA:164.312(d)":        {"title": "Person or Entity Authentication", "rationale": "HIPAA requires verification that persons seeking ePHI access are who they claim to be.", "recommendation": "Use Azure AD authentication with MFA rather than local accounts."},
    "HIPAA:164.312(e)(1)":     {"title": "Transmission Security", "rationale": "HIPAA requires protection of ePHI transmitted over electronic networks.", "recommendation": "Enforce TLS 1.2+, private endpoints, and network segmentation."},
    "HIPAA:164.514(a)":        {"title": "De-identification of PHI", "rationale": "HIPAA requires removal of identifiers to create de-identified data sets.", "recommendation": "Implement data masking and de-identification mechanisms."},
    # ── NIST 800-53 Rev 5 ────────────────────────────────────────────────
    "NIST-800-53:AC-3":  {"title": "Access Enforcement", "rationale": "Access enforcement ensures the principle of least privilege is applied.", "recommendation": "Implement RBAC and Conditional Access to enforce access controls."},
    "NIST-800-53:AC-6":  {"title": "Least Privilege", "rationale": "Least privilege limits user access to only what is required.", "recommendation": "Minimize Owner/Contributor assignments and use custom roles."},
    "NIST-800-53:AU-2":  {"title": "Event Logging", "rationale": "Event logging enables detection and investigation of security events.", "recommendation": "Enable diagnostic settings on all resources that support them."},
    "NIST-800-53:AU-6":  {"title": "Audit Review, Analysis, and Reporting", "rationale": "Regular audit review helps detect anomalies and security incidents.", "recommendation": "Configure Log Analytics and review logs regularly."},
    "NIST-800-53:CM-5":  {"title": "Access Restrictions for Change", "rationale": "Resource locks prevent unauthorized modifications to critical resources.", "recommendation": "Apply CanNotDelete or ReadOnly locks on production resources."},
    "NIST-800-53:CP-9":  {"title": "System Backup", "rationale": "Backups ensure data can be recovered after accidental deletion or attack.", "recommendation": "Configure backup policies with geo-redundant storage."},
    "NIST-800-53:IA-2":  {"title": "Identification and Authentication", "rationale": "Strong authentication prevents unauthorized access.", "recommendation": "Enforce MFA for all users via Conditional Access policies."},
    "NIST-800-53:IA-5":  {"title": "Authenticator Management", "rationale": "Proper authenticator management prevents credential-based attacks.", "recommendation": "Rotate credentials, set expiry, and use managed identities."},
    "NIST-800-53:SC-7":  {"title": "Boundary Protection", "rationale": "Network boundaries prevent unauthorized external access and lateral movement.", "recommendation": "Implement NSGs, Azure Firewall, and private endpoints."},
    "NIST-800-53:SC-8":  {"title": "Transmission Confidentiality and Integrity", "rationale": "Data in transit must be protected from interception and tampering.", "recommendation": "Enforce HTTPS/TLS 1.2+ for all communications."},
    "NIST-800-53:SC-28": {"title": "Protection of Information at Rest", "rationale": "Encryption at rest protects stored data from unauthorized access.", "recommendation": "Enable encryption at rest for all storage and database services."},
    "NIST-800-53:SI-4":  {"title": "System Monitoring", "rationale": "System monitoring detects attacks, anomalies, and policy violations.", "recommendation": "Enable Defender for Cloud and configure threat detection alerts."},
    # ── ISO 27001:2022 ───────────────────────────────────────────────────
    "ISO-27001:A.5.15": {"title": "Access control", "rationale": "Access control ensures only authorized individuals access information assets.", "recommendation": "Implement RBAC and Conditional Access policies."},
    "ISO-27001:A.5.16": {"title": "Identity management", "rationale": "Proper identity management ensures unique identification and accountability.", "recommendation": "Use centralized identity management through Microsoft Entra ID."},
    "ISO-27001:A.5.17": {"title": "Authentication information", "rationale": "Strong authentication prevents unauthorized access to systems and data.", "recommendation": "Enforce MFA and implement strong credential policies."},
    "ISO-27001:A.5.18": {"title": "Access rights", "rationale": "Access rights must follow the principle of least privilege.", "recommendation": "Review role assignments regularly and minimize privileged access."},
    "ISO-27001:A.5.23": {"title": "AI services security", "rationale": "AI services must enforce network isolation and disable local auth.", "recommendation": "Disable public access and local auth on AI service accounts."},
    "ISO-27001:A.5.29": {"title": "ICT readiness for business continuity", "rationale": "Business continuity requires backup infrastructure with data protection.", "recommendation": "Enable soft delete, purge protection, and geo-redundant backup."},
    "ISO-27001:A.8.3":  {"title": "Information access restriction", "rationale": "Storage containers must not allow anonymous public access.", "recommendation": "Set container access to Private and enforce authentication."},
    "ISO-27001:A.8.11": {"title": "Data masking", "rationale": "Sensitive data must be masked or de-identified to prevent unauthorized disclosure.", "recommendation": "Configure Dynamic Data Masking and sensitivity labels."},
    "ISO-27001:A.8.15": {"title": "Logging", "rationale": "Logging provides audit trails for security monitoring and incident investigation.", "recommendation": "Enable diagnostic settings on all resources for comprehensive logging."},
    "ISO-27001:A.8.16": {"title": "Monitoring activities", "rationale": "Monitoring enables detection of anomalous behavior and security incidents.", "recommendation": "Configure Azure Monitor alerts and enable threat detection."},
    "ISO-27001:A.8.20": {"title": "Networks security", "rationale": "Network security controls protect information in transit and at rest.", "recommendation": "Implement network segmentation, NSGs, and firewall rules."},
    "ISO-27001:A.8.22": {"title": "Segregation of networks", "rationale": "Network segregation limits blast radius of breaches.", "recommendation": "Use managed VNets, private endpoints, and firewall rules."},
    "ISO-27001:A.8.24": {"title": "Use of cryptography", "rationale": "Cryptography protects the confidentiality and integrity of information.", "recommendation": "Enable encryption for data at rest and in transit with TLS 1.2+."},
    "ISO-27001:A.8.32": {"title": "Change management", "rationale": "Formal change management prevents unauthorized modifications.", "recommendation": "Apply resource locks and assign policies with deny effects."},
    # ── SOC 2 Type II ────────────────────────────────────────────────────
    "SOC2:CC6.1":  {"title": "Logical Access Controls", "rationale": "Logical access controls restrict system access to authorized users.", "recommendation": "Implement RBAC, network rules, and private endpoints."},
    "SOC2:CC6.3":  {"title": "Removal or Modification of Access", "rationale": "Access must be reviewed and revoked when no longer needed.", "recommendation": "Conduct regular access reviews and remove excessive permissions."},
    "SOC2:CC6.5":  {"title": "Access Credentials", "rationale": "Credentials must be managed securely through their lifecycle.", "recommendation": "Use managed identities, set key expiry, and rotate credentials."},
    "SOC2:CC6.7":  {"title": "AI Services Access Controls", "rationale": "AI and data services must enforce encrypted communication.", "recommendation": "Enforce HTTPS/TLS 1.2+ and use private endpoints."},
    "SOC2:CC6.8":  {"title": "ML Workspace Network Controls", "rationale": "Data integration services must use private network connectivity.", "recommendation": "Enable managed VNet and disable public access."},
    "SOC2:CC6.12": {"title": "Cosmos DB Data Protection", "rationale": "Cosmos DB must restrict network access to protect data.", "recommendation": "Disable public access and configure private endpoints."},
    "SOC2:CC8.2":  {"title": "Sensitive Access Logging", "rationale": "Access to sensitive data must be logged for accountability.", "recommendation": "Enable diagnostic logging and audit trails."},
    "SOC2:CC8.3":  {"title": "Encryption of Sensitive Data", "rationale": "Sensitive data must be encrypted at rest and in transit.", "recommendation": "Enable TDE, disk encryption, and CMK where available."},
    "SOC2:CC8.4":  {"title": "Change Tracking and Monitoring", "rationale": "Changes to critical resources must be tracked and auditable.", "recommendation": "Apply resource locks and monitor change activity."},
    "SOC2:CC9.1":  {"title": "Detection of Anomalies", "rationale": "Anomaly detection surfaces potential security incidents.", "recommendation": "Enable Defender for Cloud and Advanced Threat Protection."},
    "SOC2:A1.1":   {"title": "System Availability Objectives", "rationale": "Availability objectives require backup and recovery capabilities.", "recommendation": "Enable soft delete, versioning, and geo-redundant backup."},
    "SOC2:C1.1":   {"title": "Confidentiality Objectives", "rationale": "Confidentiality requires data classification and protection controls.", "recommendation": "Implement DLP policies and data masking rules."},
    "SOC2:PI1.1":  {"title": "Processing Integrity Objectives", "rationale": "Processing integrity ensures data is accurate and reliable.", "recommendation": "Use strong consistency and integrity verification mechanisms."},
    # ── NIST CSF 2.0 ─────────────────────────────────────────────────────
    "NIST-CSF:PR.AC-1": {"title": "Access Control Policy", "rationale": "Access control policies define how identities and credentials are managed.", "recommendation": "Implement centralized IAM with MFA and credential management."},
    "NIST-CSF:PR.AC-3": {"title": "Remote Access Management", "rationale": "Remote access must be managed and restricted to authorized connections.", "recommendation": "Restrict inbound NSG rules to known trusted IP ranges."},
    "NIST-CSF:PR.AC-5": {"title": "Access Restrictions", "rationale": "Network integrity requires segmentation and access restrictions.", "recommendation": "Implement network segmentation with private endpoints and firewall rules."},
    "NIST-CSF:PR.DS-1": {"title": "Data Security Measures", "rationale": "Data-at-rest must be protected through encryption and access control.", "recommendation": "Enable encryption at rest and implement data classification."},
    "NIST-CSF:PR.DS-2": {"title": "Data in Transit Protection", "rationale": "Data-in-transit must be protected through strong encryption.", "recommendation": "Enforce TLS 1.2+ on all endpoints and disable plaintext protocols."},
    "NIST-CSF:PR.IP-3": {"title": "Configuration Change Control", "rationale": "Configuration changes must be controlled and auditable.", "recommendation": "Apply resource locks and enforce change management policies."},
    "NIST-CSF:PR.IP-4": {"title": "Backups", "rationale": "Backups are conducted and tested to ensure data recovery.", "recommendation": "Enable soft delete, versioning, and geo-redundant backup."},
    "NIST-CSF:DE.AE-1": {"title": "Audit Logging", "rationale": "A baseline of network and data operations is maintained for detection.", "recommendation": "Enable diagnostic logging on all data services."},
    "NIST-CSF:DE.AE-2": {"title": "Event Detection and Analysis", "rationale": "Detected events are analyzed to understand attack targets and methods.", "recommendation": "Enable Defender for Cloud and configure threat detection."},
    # ── MCSB (Microsoft Cloud Security Benchmark) ────────────────────────
    "MCSB:NS-1":  {"title": "Establish network segmentation boundaries", "rationale": "Network segmentation limits lateral movement and data exfiltration.", "recommendation": "Configure NSGs, private endpoints, and service endpoints."},
    "MCSB:IM-1":  {"title": "Use centralized identity and authentication", "rationale": "Centralized identity provides consistent access control and audit.", "recommendation": "Use Azure AD authentication and disable local accounts."},
    "MCSB:IM-3":  {"title": "Manage application identities securely", "rationale": "Application identities must use managed identities or certificates.", "recommendation": "Use managed identities and set credential expiry."},
    "MCSB:PA-7":  {"title": "Follow least privilege principle", "rationale": "Least privilege reduces the impact of compromised accounts.", "recommendation": "Review and minimize RBAC assignments; use custom roles."},
    "MCSB:LT-1":  {"title": "Enable threat detection capabilities", "rationale": "Threat detection surfaces attacks and anomalous behavior.", "recommendation": "Enable Defender for Cloud and Advanced Threat Protection."},
    "MCSB:LT-3":  {"title": "Enable logging for security investigation", "rationale": "Security logs provide evidence for incident investigation.", "recommendation": "Enable diagnostic settings and audit logging."},
    "MCSB:LT-5b": {"title": "Log Retention and Archival", "rationale": "Sufficient log retention supports compliance and forensic investigation.", "recommendation": "Configure log retention to at least 90 days."},
    "MCSB:DP-3":  {"title": "Encrypt sensitive data in transit", "rationale": "Data in transit must be encrypted to prevent interception.", "recommendation": "Enforce TLS 1.2+ and disable plaintext protocols."},
    "MCSB:DP-4":  {"title": "Enable data at rest encryption by default", "rationale": "Data at rest encryption protects against unauthorized media access.", "recommendation": "Enable encryption at rest for all storage and database services."},
    "MCSB:DP-9":  {"title": "Storage container public access control", "rationale": "Public access to storage containers exposes data to anonymous users.", "recommendation": "Set container access to Private on all storage accounts."},
    "MCSB:BR-1":  {"title": "Ensure regular automated backups", "rationale": "Automated backups ensure data is recoverable after incidents.", "recommendation": "Enable soft delete, versioning, and backup policies."},
    "MCSB:PV-9":  {"title": "Resource lock protection", "rationale": "Resource locks prevent accidental deletion of critical resources.", "recommendation": "Apply CanNotDelete locks on production resources."},
    # ── Additional entries for scanner subcategory aliases ────────────────
    "CIS:3.9":   {"title": "Ensure SAS expiration policy is set", "rationale": "SAS tokens without expiration provide indefinite access if leaked.", "recommendation": "Set a SAS expiration policy on each storage account (max 24h for ad-hoc tokens)."},
    "CIS:3.12":  {"title": "Ensure change feed is enabled for blobs", "rationale": "Change feed provides a log of all blob changes for audit compliance.", "recommendation": "Enable change feed on storage accounts containing regulated data."},
    "CIS:6.6":   {"title": "Ensure DDoS Protection for data VNets", "rationale": "Without DDoS protection, volumetric attacks can disrupt data services.", "recommendation": "Enable Azure DDoS Protection Standard on VNets hosting data services."},
    "CIS:8.7":   {"title": "Ensure Key Vault network access is restricted", "rationale": "Unrestricted Key Vault access exposes secrets to the internet.", "recommendation": "Configure Key Vault firewall to deny public access and use private endpoints."},
    "NIST-800-53:PM-5": {"title": "Information System Inventory", "rationale": "Maintaining an accurate inventory supports vulnerability assessment and compliance monitoring.", "recommendation": "Register all data assets in Microsoft Purview for automated discovery and scanning."},
    "NIST-800-53:SC-5":  {"title": "Denial-of-Service Protection", "rationale": "DoS attacks against data services disrupt availability of regulated data.", "recommendation": "Enable Azure DDoS Protection Standard on VNets hosting data resources."},
    "ISO-27001:A.5.9":   {"title": "Inventory of information assets", "rationale": "ISO 27001 requires identifying and maintaining an inventory of information assets.", "recommendation": "Register data sources in Microsoft Purview for centralized asset inventory."},
    "SOC2:CC3.2":  {"title": "Risk identification and assessment", "rationale": "SOC 2 requires identifying and assessing risks to achieving service commitments.", "recommendation": "Use Microsoft Purview scans to identify unclassified or unprotected data assets."},
    "NIST-CSF:ID.AM-1":  {"title": "Physical devices and systems inventoried", "rationale": "NIST CSF requires maintaining an inventory of all hardware and data assets.", "recommendation": "Enable Microsoft Purview auto-scanning for complete data estate visibility."},
    "MCSB:AM-2":  {"title": "Use only approved services", "rationale": "Unregistered data services may not meet compliance scanning requirements.", "recommendation": "Register all data services in Microsoft Purview and enforce scanning policies."},
    "MCSB:NS-5":  {"title": "Deploy DDoS protection", "rationale": "The Microsoft Cloud Security Benchmark recommends DDoS protection for internet-facing resources.", "recommendation": "Enable Azure DDoS Protection Standard on data-hosting VNets."},
    "PCI-DSS:8.3":   {"title": "Secure authentication for all access", "rationale": "PCI-DSS v4.0.1 requires MFA for CDE access; phishing-resistant mechanisms satisfy MFA without a separate factor.", "recommendation": "Enable phishing-resistant MFA or configure Azure AD Conditional Access with MFA."},
    "CIS:7.2":   {"title": "Ensure encryption-at-host is enabled", "rationale": "Encryption-at-host covers temp disks and disk caches that standard disk encryption may miss.", "recommendation": "Enable encryption-at-host on all VMs processing sensitive data."},
    "NIST-800-53:IR-6": {"title": "Incident Reporting", "rationale": "NIST requires timely reporting of security incidents to appropriate authorities.", "recommendation": "Configure Defender for Cloud alert action groups with email and webhook notifications."},
    "ISO-27001:A.5.25": {"title": "Assessment and decision on information security events", "rationale": "ISO 27001 requires classifying and prioritizing information security events.", "recommendation": "Set up Defender for Cloud action groups to route security alerts for triage."},
    "NIST-CSF:RS.CO-2": {"title": "Incidents reported consistent with criteria", "rationale": "NIST CSF requires reporting incidents to appropriate stakeholders.", "recommendation": "Configure security alert action groups to notify the SOC and management."},
    "NIST-800-53:CA-7": {"title": "Continuous monitoring", "rationale": "Ongoing assessment detects configuration drift and new vulnerabilities.", "recommendation": "Ensure Purview scans run on schedule and resolve any scan failures promptly."},
    "ISO-27001:A.8.8": {"title": "Management of technical vulnerabilities", "rationale": "Unscanned data sources may harbor unclassified sensitive data.", "recommendation": "Investigate and fix Purview scan failures to maintain classification coverage."},
    "SOC2:CC7.1": {"title": "Detection and monitoring activities", "rationale": "Monitoring controls must detect anomalies in data classification.", "recommendation": "Ensure all data sources are actively scanned by Purview."},
    "NIST-CSF:DE.CM-8": {"title": "Vulnerability scans are performed", "rationale": "Regular scans identify sensitive data exposure and classification gaps.", "recommendation": "Re-run failed Purview scans and verify scan credentials."},
    "MCSB:PV-5": {"title": "Perform vulnerability assessments", "rationale": "Regular assessments identify data security gaps before they are exploited.", "recommendation": "Review Purview scan results and remediate any scan issues."},

    # ── AI Services controls ─────────────────────────────────────────
    "CIS:9.1": {"title": "Ensure AI Services disable local authentication", "rationale": "Key-based auth uses static shared secrets vulnerable to leakage. Azure AD provides MFA, conditional access, and audit trails.", "recommendation": "Disable local (key) authentication on all AI/Cognitive Services accounts."},
    "CIS:9.2": {"title": "Ensure AI Services use managed identity", "rationale": "Managed identity eliminates stored credentials and provides automatic rotation.", "recommendation": "Enable system-assigned managed identity on AI Services."},
    "CIS:9.3": {"title": "Ensure AI Services use customer-managed keys", "rationale": "CMK provides organizational control over encryption keys for custom models and training data.", "recommendation": "Configure CMK encryption for AI Services accounts."},
    "CIS:9.4": {"title": "Ensure data services use managed identity", "rationale": "Managed identity eliminates connection strings, shared keys, and other stored credentials.", "recommendation": "Enable managed identity on all data pipeline and messaging services."},
    "MCSB:IM-1": {"title": "Use centralized identity and authentication system", "rationale": "Centralized identity management through Azure AD reduces credential sprawl and enables consistent policy enforcement.", "recommendation": "Disable local/key authentication and use Azure AD/Entra ID for all service access."},
    "MCSB:IM-3": {"title": "Manage application identities securely", "rationale": "Managed identities provide automatic credential rotation and eliminate secrets management overhead.", "recommendation": "Use managed identities instead of service principals or shared keys."},
    "MCSB:NS-2": {"title": "Secure cloud services with network controls", "rationale": "Network controls restrict the attack surface by limiting which networks can reach the service.", "recommendation": "Disable public access and use private endpoints or VNet integration."},
    "MCSB:DP-5": {"title": "Use customer-managed key option in data at rest encryption when required", "rationale": "CMK provides additional control over encryption, including key rotation and revocation.", "recommendation": "Configure CMK for services processing sensitive data."},
    "MCSB:PV-6": {"title": "Rapidly and automatically remediate vulnerabilities", "rationale": "Automated remediation reduces the window of exposure from known vulnerabilities.", "recommendation": "Implement CI/CD with automated security scanning."},
    "MCSB:PV-7": {"title": "Conduct regular red team operations", "rationale": "Regular patching and maintenance windows reduce risk from known vulnerabilities.", "recommendation": "Configure maintenance windows and auto-patching for managed services."},
    "MCSB:LT-3": {"title": "Enable logging for security investigation", "rationale": "Comprehensive logging enables detection of unauthorized access and supports forensic investigation.", "recommendation": "Enable capture, diagnostic settings, and audit logging."},
    # ── Data Pipeline controls ───────────────────────────────────────
    "CIS:6.1": {"title": "Ensure Data Factory disables public network access", "rationale": "Public access exposes management and data plane APIs to the Internet.", "recommendation": "Disable public network access on Data Factory."},
    "CIS:6.2": {"title": "Ensure Data Factory uses managed identity", "rationale": "Managed identity removes the need for stored credentials in linked services.", "recommendation": "Enable system-assigned managed identity on Data Factory."},
    "CIS:6.3": {"title": "Ensure Data Factory has Git integration", "rationale": "Git integration provides version control, change audit, and rollback capability for data pipelines.", "recommendation": "Configure Git repository integration for Data Factory."},
    "CIS:6.4": {"title": "Ensure Synapse disables public network access", "rationale": "Public access exposes SQL pools, Spark pools, and pipelines to the Internet.", "recommendation": "Disable public network access on Synapse workspaces."},
    "CIS:6.5": {"title": "Ensure Synapse enforces Azure AD-only authentication", "rationale": "SQL authentication uses passwords vulnerable to brute-force and lacks MFA.", "recommendation": "Enable Azure AD-only authentication on Synapse workspaces."},
    "NIST-800-53:CM-3": {"title": "Configuration Change Control", "rationale": "Formal change management prevents unauthorized or accidental modifications to systems.", "recommendation": "Implement version-controlled configuration management with Git integration."},
    "ISO-27001:A.8.32": {"title": "Change management", "rationale": "Changes to information processing facilities and systems should be subject to change management procedures.", "recommendation": "Implement version control and change approval workflows."},
    "PCI-DSS:6.5.4": {"title": "Insecure communications", "rationale": "Ensure all software development follows secure coding guidelines including change control.", "recommendation": "Use Git-based version control for all code and configuration changes."},
    # ── Enhanced Messaging controls ──────────────────────────────────
    "CIS:7.1": {"title": "Ensure Event Hub disables local authentication", "rationale": "SAS keys are static secrets that grant unrestricted access. Azure AD provides per-principal scoping.", "recommendation": "Disable local auth on Event Hub namespaces."},
    "CIS:7.2": {"title": "Ensure Service Bus disables local authentication", "rationale": "SAS keys provide shared, unscoped access. Azure AD RBAC enables least-privilege access control.", "recommendation": "Disable local auth on Service Bus namespaces."},
    "CIS:7.3": {"title": "Ensure Event Hub capture is enabled", "rationale": "Capture provides a persistent archive of all events for compliance, audit, and replay.", "recommendation": "Enable Event Hub capture for event archival."},
    # ── Enhanced Redis controls ──────────────────────────────────────
    "CIS:7.4": {"title": "Ensure Redis has a configured patch schedule", "rationale": "Uncontrolled patching can cause unexpected downtime. Scheduled patches reduce vulnerability exposure.", "recommendation": "Configure a maintenance window for Redis patching."},
    "CIS:7.5": {"title": "Ensure Redis disables public network access", "rationale": "Redis caches storing session data and PII should not be accessible from the public Internet.", "recommendation": "Deploy private endpoints and disable public access."},
    # ── Wave A+B+C control details ───────────────────────────────────────
    "CIS:4.3.1": {"title": "Ensure SQL MI has Advanced Threat Protection enabled", "rationale": "ATP detects anomalous activities indicating potential threats to SQL MI databases.", "recommendation": "Enable ATP on all SQL Managed Instances."},
    "CIS:4.3.2": {"title": "Ensure SQL MI public data endpoint is disabled", "rationale": "The public endpoint exposes SQL MI to Internet-based attacks.", "recommendation": "Disable the public data endpoint for SQL MI."},
    "CIS:8.1": {"title": "Ensure Databricks workspace uses VNET injection", "rationale": "VNET injection isolates Databricks compute from the shared multitenant network.", "recommendation": "Deploy Databricks with custom VNET injection."},
    "CIS:8.2": {"title": "Ensure Databricks uses customer-managed encryption keys", "rationale": "CMK gives the organization control over encryption key lifecycle and rotation.", "recommendation": "Configure CMK for Databricks managed services."},
    "CIS:9.1": {"title": "Ensure App Configuration disables public network access", "rationale": "Configuration stores may contain secrets and feature flags that should not be Internet-accessible.", "recommendation": "Disable public network access on App Configuration."},
    "CIS:9.11": {"title": "Ensure web app settings do not contain plaintext secrets", "rationale": "Plain-text secrets in app settings are exposed via ARM exports and portal access.", "recommendation": "Store secrets in Key Vault and use Key Vault References."},
    "CIS:10.1": {"title": "Ensure APIM is deployed with VNET integration", "rationale": "Without VNET, APIM exposes backend APIs and credentials on the public Internet.", "recommendation": "Enable Internal or External VNET mode on APIM."},
    "CIS:11.1": {"title": "Ensure Front Door has a WAF policy in Prevention mode", "rationale": "WAF blocks OWASP Top-10 attacks, SQL injection, and data exfiltration payloads.", "recommendation": "Associate a WAF policy in Prevention mode."},
    "CIS:12.1": {"title": "Ensure Azure Firewall has threat intelligence enabled", "rationale": "Threat intel filters traffic from known malicious IPs and domains.", "recommendation": "Set threat intelligence mode to Alert or Deny."},
    "CIS:12.2": {"title": "Ensure Azure Firewall Premium has IDPS enabled", "rationale": "IDPS detects data exfiltration, C2 communications, and lateral movement.", "recommendation": "Enable IDPS in Alert or Deny mode."},
    "CIS:13.1": {"title": "Ensure no NSGs allow direct RDP/SSH from Internet", "rationale": "Direct RDP/SSH enables brute-force attacks and potential data exfiltration.", "recommendation": "Deploy Azure Bastion and remove public RDP/SSH rules."},
    "CIS:14.1": {"title": "Ensure data-related Azure Policy assignments are compliant", "rationale": "Non-compliant policy assignments indicate unenforced data protection controls.", "recommendation": "Remediate non-compliant resources or adjust policy assignments."},
    "CIS:14.2": {"title": "Ensure Defender data-protection recommendations are healthy", "rationale": "Unhealthy Defender recommendations indicate known security gaps.", "recommendation": "Review and remediate all unhealthy data-protection recommendations."},

    # ── CSA Cloud Controls Matrix v4 ─────────────────────────────────────
    "CSA-CCM:DSP-01": {"title": "Data Security & Privacy - Data Classification", "rationale": "Personal and sensitive data must be classified and labelled to apply appropriate handling and protection.", "recommendation": "Implement automated data classification and apply sensitivity labels."},
    "CSA-CCM:DSP-05": {"title": "Data Security & Privacy - Data Flow", "rationale": "Data flows must be documented and access restricted to authorised principals.", "recommendation": "Map data flows and enforce row-level/column-level security on sensitive stores."},
    "CSA-CCM:DSP-10": {"title": "Data Security & Privacy - Data Protection", "rationale": "Data at rest and in transit must be encrypted and network-isolated from untrusted sources.", "recommendation": "Disable public access, deploy private endpoints, and enforce TLS 1.2+."},
    "CSA-CCM:DSP-16": {"title": "Data Security & Privacy - Retention & Disposal", "rationale": "Data retention policies protect against accidental loss and ensure recoverability.", "recommendation": "Enable soft delete, versioning, immutability policies, and resource locks."},
    "CSA-CCM:DSP-17": {"title": "Data Security & Privacy - Encryption", "rationale": "Encryption in transit and at rest prevents unauthorised data access.", "recommendation": "Enforce TLS 1.2+, enable TDE, disk encryption, and CMK where required."},
    "CSA-CCM:CEK-01": {"title": "Cryptography - Key Management", "rationale": "Cryptographic keys must be managed with RBAC and stored securely.", "recommendation": "Use Azure Key Vault with RBAC model instead of access policies."},
    "CSA-CCM:CEK-02": {"title": "Cryptography - Key Generation", "rationale": "Weak key generation increases risk of cryptographic compromise.", "recommendation": "Use HSM-backed keys with minimum 2048-bit RSA or P-256 EC."},
    "CSA-CCM:CEK-03": {"title": "Cryptography - Encryption", "rationale": "Encryption protects data confidentiality both in transit and at rest.", "recommendation": "Enable encryption at rest (TDE/CMK), in transit (TLS 1.2+), and at host."},
    "CSA-CCM:CEK-04": {"title": "Cryptography - Key Rotation", "rationale": "Non-rotating keys accumulate risk over time.", "recommendation": "Set expiration dates on keys/secrets/certificates and enable auto-rotation."},
    "CSA-CCM:CEK-05": {"title": "Cryptography - Key Protection", "rationale": "Key material must be protected against deletion and extraction.", "recommendation": "Enable purge protection and use HSM-backed keys."},
    "CSA-CCM:IAM-02": {"title": "Identity - Strong Authentication", "rationale": "Weak authentication methods expose services to credential-based attacks.", "recommendation": "Disable local auth/shared keys; use Entra ID with MFA and managed identities."},
    "CSA-CCM:IAM-04": {"title": "Identity - Centralised Authentication", "rationale": "Decentralised authentication prevents consistent policy enforcement.", "recommendation": "Enable Azure AD-only authentication on all data services."},
    "CSA-CCM:IAM-05": {"title": "Identity - Least Privilege", "rationale": "Excessive privileges expand blast radius of compromised accounts.", "recommendation": "Review and remove stale role assignments; use PIM for privileged access."},
    "CSA-CCM:IAM-09": {"title": "Identity - Credential Lifecycle", "rationale": "Credentials without lifecycle management become attack vectors.", "recommendation": "Use managed identities; set expiration on keys, secrets, and certificates."},
    "CSA-CCM:IAM-10": {"title": "Identity - Access Control", "rationale": "Coarse access controls allow unauthorised data access.", "recommendation": "Use RBAC-based Key Vault access, row-level security, and fine-grained permissions."},
    "CSA-CCM:IAM-14": {"title": "Identity - Remote Access", "rationale": "Direct RDP/SSH access bypasses audit and control mechanisms.", "recommendation": "Use Azure Bastion for remote access; disable public RDP/SSH ports."},
    "CSA-CCM:IVS-03": {"title": "Infrastructure - Network Security", "rationale": "Public network exposure increases attack surface for data services.", "recommendation": "Deploy private endpoints, restrict NSGs, and disable public access."},
    "CSA-CCM:IVS-05": {"title": "Infrastructure - Vulnerability Management", "rationale": "Unpatched infrastructure components contain known vulnerabilities.", "recommendation": "Enable automated patching and maintenance windows for all data services."},
    "CSA-CCM:IVS-06": {"title": "Infrastructure - Perimeter Security", "rationale": "Missing perimeter controls allow direct attacks on data services.", "recommendation": "Deploy WAF, firewall with threat intelligence, and DDoS protection."},
    "CSA-CCM:IVS-09": {"title": "Infrastructure - Availability", "rationale": "DDoS attacks can cause service disruption and data unavailability.", "recommendation": "Enable DDoS Protection Standard on VNets hosting data services."},
    "CSA-CCM:LOG-01": {"title": "Logging - Audit Logging", "rationale": "Without audit logs, security incidents go undetected.", "recommendation": "Enable diagnostic settings and blob storage logging on all data resources."},
    "CSA-CCM:LOG-03": {"title": "Logging - Log Integrity", "rationale": "Mutable logs can be tampered with to conceal attacker activity.", "recommendation": "Enable immutable audit logs and immutability policies on log storage."},
    "CSA-CCM:LOG-05": {"title": "Logging - Log Retention", "rationale": "Short retention destroys evidence needed for incident investigation.", "recommendation": "Retain audit logs for at least 90 days; enable Event Hub capture."},
    "CSA-CCM:LOG-09": {"title": "Logging - Threat Detection", "rationale": "Without threat detection, active attacks are not identified in time.", "recommendation": "Enable Microsoft Defender and Advanced Threat Protection on all data services."},
    "CSA-CCM:LOG-11": {"title": "Logging - Tamper Protection", "rationale": "Log tampering prevents forensic analysis after an incident.", "recommendation": "Enable immutability policies and resource locks on audit log storage."},
    "CSA-CCM:TVM-01": {"title": "Threat Management - Detection", "rationale": "Threat detection is essential for identifying active attacks on data stores.", "recommendation": "Enable Defender for Storage/SQL/CosmosDB, WAF, and firewall threat intelligence."},
    "CSA-CCM:TVM-02": {"title": "Threat Management - Vulnerability Assessment", "rationale": "Unscanned resources may contain known vulnerabilities.", "recommendation": "Enable Purview scanning and Defender security recommendations for all data resources."},
    "CSA-CCM:TVM-04": {"title": "Threat Management - Patch Management", "rationale": "Unpatched components are vulnerable to known exploits.", "recommendation": "Configure patch schedules for Redis and enable automated dependency scanning."},
    "CSA-CCM:GRC-01": {"title": "Governance - Policy Compliance", "rationale": "Non-compliant configurations drift from security baselines.", "recommendation": "Enforce Azure Policy for data security; integrate pipelines with version control."},
    "CSA-CCM:GRC-03": {"title": "Governance - Risk Management", "rationale": "Unaddressed policy violations accumulate enterprise risk.", "recommendation": "Remediate non-compliant Azure Policy assignments and Defender recommendations."},
    "CSA-CCM:BCR-01": {"title": "Business Continuity - Planning", "rationale": "Without consistency guarantees, data integrity cannot be maintained during failover.", "recommendation": "Use Session or stronger consistency for Cosmos DB workloads with sensitive data."},
    "CSA-CCM:BCR-03": {"title": "Business Continuity - Data Resilience", "rationale": "Accidental or malicious deletion without recoverability is a business continuity risk.", "recommendation": "Enable soft delete, purge protection, versioning, and resource locks."},
    # ── FedRAMP ──────────────────────────────────────────────────────────
    "FedRAMP:AC-2": {"title": "Account Management", "rationale": "Unused or stale accounts increase the attack surface for data services.", "recommendation": "Review and remove stale data role assignments; configure access reviews."},
    "FedRAMP:AC-2(3)": {"title": "Disable Inactive Accounts", "rationale": "Inactive accounts with data access expand the blast radius.", "recommendation": "Remove data role assignments unused for 90+ days."},
    "FedRAMP:AC-2(5)": {"title": "Inactivity Logout", "rationale": "Permanent privileged assignments bypass time-bound controls.", "recommendation": "Use PIM with time-limited activations for data access roles."},
    "FedRAMP:AC-3": {"title": "Access Enforcement", "rationale": "Incorrect access controls expose data to unauthorised users.", "recommendation": "Use RBAC-based access, row-level security, and private endpoints."},
    "FedRAMP:AC-4": {"title": "Information Flow Enforcement", "rationale": "Unrestricted data flows increase exfiltration risk.", "recommendation": "Enable Synapse data exfiltration protection and restrict network bypass rules."},
    "FedRAMP:AC-6": {"title": "Least Privilege", "rationale": "Excessive permissions expand the blast radius of compromised identities.", "recommendation": "Remove Owner/Contributor where Reader or specific data roles suffice."},
    "FedRAMP:AC-6(1)": {"title": "Authorize Access to Security Functions", "rationale": "Over-privileged access to security functions enables configuration tampering.", "recommendation": "Restrict Key Vault, Defender, and policy management to dedicated security roles."},
    "FedRAMP:AC-17": {"title": "Remote Access", "rationale": "Direct RDP/SSH bypasses auditing and MFA controls.", "recommendation": "Use Azure Bastion; close public RDP/SSH ports in NSGs."},
    "FedRAMP:AC-17(2)": {"title": "Protection of Confidentiality/Integrity", "rationale": "Remote access must use encrypted channels to protect data.", "recommendation": "Enforce Bastion with TLS; disable shareable links."},
    "FedRAMP:AU-2": {"title": "Audit Events", "rationale": "Without audit logging, security events go undetected.", "recommendation": "Enable diagnostic settings, blob logging, and change feed on data resources."},
    "FedRAMP:AU-3": {"title": "Content of Audit Records", "rationale": "Incomplete audit records prevent effective incident investigation.", "recommendation": "Ensure diagnostic settings capture read, write, and delete operations."},
    "FedRAMP:AU-9": {"title": "Protection of Audit Information", "rationale": "Mutable audit logs can be tampered with to hide attacker activity.", "recommendation": "Enable immutability policies and resource locks on audit storage."},
    "FedRAMP:AU-9(4)": {"title": "Access by Subset of Privileged Users", "rationale": "Broad access to audit logs enables tampering by compromised admins.", "recommendation": "Enable immutability and restrict log storage access to security team."},
    "FedRAMP:AU-11": {"title": "Audit Record Retention", "rationale": "Short retention destroys evidence needed for investigation.", "recommendation": "Retain audit logs for 90+ days; enable Event Hub capture for long-term archival."},
    "FedRAMP:AU-12": {"title": "Audit Generation", "rationale": "Audit trail generation is required for forensic analysis.", "recommendation": "Enable SQL auditing, diagnostic settings, and blob logging."},
    "FedRAMP:CA-2": {"title": "Security Assessments", "rationale": "Periodic assessment identifies configuration drift and new vulnerabilities.", "recommendation": "Run regular policy compliance assessments and remediate non-compliant resources."},
    "FedRAMP:CA-7": {"title": "Continuous Monitoring", "rationale": "Point-in-time assessments miss emerging threats.", "recommendation": "Enable Defender continuous monitoring and Purview scanning schedules."},
    "FedRAMP:CM-3": {"title": "Configuration Change Control", "rationale": "Uncontrolled changes introduce undocumented risk.", "recommendation": "Use Git integration for ADF/Synapse; monitor configuration drift."},
    "FedRAMP:CM-5": {"title": "Access Restrictions for Change", "rationale": "Unrestricted change access enables unauthorised modifications.", "recommendation": "Apply resource locks and restrict change management to authorised roles."},
    "FedRAMP:CM-6": {"title": "Configuration Settings", "rationale": "Deviations from secure baselines create vulnerabilities.", "recommendation": "Enforce Azure Policy baselines and remediate drift detections."},
    "FedRAMP:CM-7": {"title": "Least Functionality", "rationale": "Unnecessary features increase the attack surface.", "recommendation": "Disable admin accounts on ACR and unnecessary service features."},
    "FedRAMP:CP-6": {"title": "Alternate Storage Site", "rationale": "Data must be recoverable from an alternate location.", "recommendation": "Enable geo-redundant backups and cross-region replication."},
    "FedRAMP:CP-9": {"title": "Information System Backup", "rationale": "Without backup protection, data loss from deletion is irreversible.", "recommendation": "Enable soft delete, purge protection, versioning, and blob snapshots."},
    "FedRAMP:IA-2": {"title": "Identification and Authentication", "rationale": "Weak authentication methods expose data services to credential attacks.", "recommendation": "Disable local/SQL auth; require Azure AD-only authentication."},
    "FedRAMP:IA-2(1)": {"title": "Multi-Factor Authentication", "rationale": "Single-factor auth is vulnerable to credential theft.", "recommendation": "Enforce MFA via Conditional Access for all data service access."},
    "FedRAMP:IA-2(2)": {"title": "MFA for Non-Privileged Accounts", "rationale": "Non-privileged accounts accessing sensitive data still need MFA.", "recommendation": "Apply MFA Conditional Access policies to all users accessing data resources."},
    "FedRAMP:IA-5": {"title": "Authenticator Management", "rationale": "Unmanaged credentials become persistent attack vectors.", "recommendation": "Use managed identities; set expiration on keys, secrets, and SAS tokens."},
    "FedRAMP:IA-5(1)": {"title": "Password-Based Authentication", "rationale": "Password credentials must have expiration and complexity requirements.", "recommendation": "Set SAS expiration policies and secret/key expiration dates."},
    "FedRAMP:IA-5(7)": {"title": "No Embedded Unencrypted Static Authenticators", "rationale": "Secrets in plaintext config are trivially extractable.", "recommendation": "Use Key Vault references instead of embedding secrets in app settings."},
    "FedRAMP:IR-6": {"title": "Incident Reporting", "rationale": "Without alert routing, security incidents are not reported to responders.", "recommendation": "Configure security action groups for Defender and threat detection alerts."},
    "FedRAMP:MP-4": {"title": "Media Storage", "rationale": "Sensitive data on storage media must be protected.", "recommendation": "Enable DLP policies and classify sensitive information types."},
    "FedRAMP:PM-5": {"title": "Information System Inventory", "rationale": "Unscanned assets cannot be assessed for vulnerabilities.", "recommendation": "Ensure Purview scans cover all data stores and resolve scan failures."},
    "FedRAMP:RA-5": {"title": "Vulnerability Scanning", "rationale": "Unscanned resources may contain exploitable vulnerabilities.", "recommendation": "Enable Defender recommendations and Purview vulnerability scanning."},
    "FedRAMP:SA-12": {"title": "Supply Chain Protection", "rationale": "Third-party components introduce supply chain risk.", "recommendation": "Use ACR for container images; scan dependencies; disable external package sources."},
    "FedRAMP:SC-5": {"title": "Denial of Service Protection", "rationale": "DDoS attacks disrupt data service availability.", "recommendation": "Enable DDoS Protection Standard on VNets hosting data services."},
    "FedRAMP:SC-7": {"title": "Boundary Protection", "rationale": "Public network exposure increases attack surface for data stores.", "recommendation": "Deploy private endpoints, restrict NSGs, disable public access on all data services."},
    "FedRAMP:SC-7(5)": {"title": "Deny by Default / Allow by Exception", "rationale": "Default-allow network rules expose data services to any source.", "recommendation": "Set default network action to Deny; whitelist only trusted networks."},
    "FedRAMP:SC-8": {"title": "Transmission Confidentiality and Integrity", "rationale": "Unencrypted transit enables interception of sensitive data.", "recommendation": "Enforce HTTPS-only, TLS 1.2+, and disable non-SSL ports."},
    "FedRAMP:SC-8(1)": {"title": "Cryptographic Protection", "rationale": "Encryption in transit must use strong algorithms.", "recommendation": "Set minimum TLS version to 1.2 on all data services."},
    "FedRAMP:SC-12": {"title": "Cryptographic Key Establishment and Management", "rationale": "Weak key management undermines encryption effectiveness.", "recommendation": "Use HSM-backed keys and customer-managed keys for sensitive data."},
    "FedRAMP:SC-12(1)": {"title": "Availability", "rationale": "Key unavailability blocks data access; keys must be resilient.", "recommendation": "Use HSM-backed keys with purge protection and automated rotation."},
    "FedRAMP:SC-17": {"title": "Public Key Infrastructure Certificates", "rationale": "Expired or weak certificates break TLS and trust chains.", "recommendation": "Monitor certificate expiration, enable auto-renewal, use 2048-bit+ RSA or P-256."},
    "FedRAMP:SC-28": {"title": "Protection of Information at Rest", "rationale": "Unencrypted data at rest is exposed to storage media theft.", "recommendation": "Enable TDE, disk encryption, CMK, and DLP policies."},
    "FedRAMP:SC-28(1)": {"title": "Cryptographic Protection", "rationale": "Encryption at rest must use strong algorithms and key management.", "recommendation": "Use customer-managed keys and enable encryption at host."},
    "FedRAMP:SI-2": {"title": "Flaw Remediation", "rationale": "Unpatched systems are vulnerable to known exploits.", "recommendation": "Enable patch schedules for Redis and remediate unhealthy Defender recommendations."},
    "FedRAMP:SI-2(2)": {"title": "Automated Flaw Remediation Status", "rationale": "Manual patching is slow and error-prone.", "recommendation": "Enable automated patching and maintenance windows."},
    "FedRAMP:SI-4": {"title": "Information System Monitoring", "rationale": "Without monitoring, active attacks on data services go undetected.", "recommendation": "Enable Defender, ATP, WAF, and firewall threat intelligence."},
    "FedRAMP:SI-4(4)": {"title": "Inbound and Outbound Communications Traffic", "rationale": "Uninspected traffic enables data exfiltration.", "recommendation": "Enable IDPS on Azure Firewall for traffic to data services."},
    "FedRAMP:SI-4(5)": {"title": "System-Generated Alerts", "rationale": "ATP generates alerts for anomalous data access patterns.", "recommendation": "Enable SQL ATP, Defender for Storage, and Cosmos DB threat detection."},
    "FedRAMP:SI-7": {"title": "Software, Firmware, and Information Integrity", "rationale": "Tampered dependencies compromise runtime integrity.", "recommendation": "Use ACR image signing and pin dependency versions."},
    # ── GDPR ────────────────────────────────────────────────────────────
    "GDPR:Art.5(1c)": {"title": "Principles - Data Minimisation", "rationale": "Personal data must be adequate, relevant, and limited to what is necessary.", "recommendation": "Apply data masking, row-level security, and classify data to identify unnecessary exposure."},
    "GDPR:Art.5(1d)": {"title": "Principles - Accuracy", "rationale": "Personal data must be accurate and kept up to date; inaccurate data must be erased.", "recommendation": "Enable soft delete, versioning, and strong consistency to preserve data accuracy."},
    "GDPR:Art.5(1f)": {"title": "Principles - Integrity & Confidentiality", "rationale": "Processing must ensure appropriate security including protection against unauthorised access and loss.", "recommendation": "Enforce encryption, strong auth, least privilege, TLS 1.2+, and network isolation."},
    "GDPR:Art.5(2)": {"title": "Principles - Accountability", "rationale": "The controller must demonstrate compliance with data protection principles.", "recommendation": "Enable audit logging, diagnostic settings, change feed, and retain logs for 90+ days."},
    "GDPR:Art.24(1)": {"title": "Responsibility of Controller", "rationale": "The controller must implement appropriate measures to ensure and demonstrate compliance.", "recommendation": "Enforce Azure Policy compliance and remediate non-compliant data resources."},
    "GDPR:Art.25(1)": {"title": "Data Protection by Design", "rationale": "Implement data protection principles in system design \u2014 encryption, access control, network isolation.", "recommendation": "Deploy private endpoints, disable public access, use managed identities, enable encryption."},
    "GDPR:Art.25(2)": {"title": "Data Protection by Default", "rationale": "By default, only necessary data should be accessible for the specific purpose.", "recommendation": "Apply least privilege, row-level security, data masking, and restrict network access."},
    "GDPR:Art.28(1)": {"title": "Processor", "rationale": "Controllers must only use processors providing sufficient guarantees for appropriate measures.", "recommendation": "Use ACR for container images; scan third-party dependencies; disable external package sources."},
    "GDPR:Art.30(1)": {"title": "Records of Processing Activities", "rationale": "Controllers must maintain records of processing activities including purposes and categories.", "recommendation": "Enable audit logging, diagnostic settings, Purview scanning, and change tracking."},
    "GDPR:Art.32(1)": {"title": "Security of Processing", "rationale": "Implement appropriate technical and organisational measures to ensure security.", "recommendation": "Enable encryption, access controls, network isolation, threat detection, and patching."},
    "GDPR:Art.32(1d)": {"title": "Security - Testing & Evaluation", "rationale": "Regularly test and evaluate the effectiveness of security measures.", "recommendation": "Enable automated patching, Defender recommendations, and periodic security assessments."},
    "GDPR:Art.33(1)": {"title": "Notification of Breach to Authority", "rationale": "Breaches must be notified within 72 hours; detection is prerequisite.", "recommendation": "Enable ATP, Defender, and security action groups for breach detection and alerting."},
    "GDPR:Art.34(1)": {"title": "Communication of Breach to Data Subject", "rationale": "High-risk breaches must be communicated to affected data subjects.", "recommendation": "Configure security action groups to route alerts to incident response teams."},
    "GDPR:Art.34(3a)": {"title": "Exceptions - Encryption", "rationale": "Notification is not required if data was encrypted and keys were not compromised.", "recommendation": "Enable encryption at rest and at host to limit breach notification obligations."},
    "GDPR:Art.35(1)": {"title": "Data Protection Impact Assessment", "rationale": "High-risk processing requires DPIA; asset discovery supports this.", "recommendation": "Ensure Purview scanning covers all data stores for DPIA completeness."},
}


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


# ── Per-resource risk & remediation enrichment ────────────────────────────

# Map subcategory → (risk_template, remediation_cli_template)
# Placeholders: {name}, {rid}, {rg} are substituted per resource
_RESOURCE_RISK_MAP: dict[str, tuple[str, str]] = {
    # ── Storage ──────────────────────────────────────────────────────────
    "blob_public_access": (
        "This storage account allows anonymous public read access to blobs. Any internet user can read data without authentication, risking data exfiltration.",
        "az storage account update -n {name} -g {rg} --allow-blob-public-access false",
    ),
    "https_not_enforced": (
        "HTTP traffic is accepted, exposing data in transit to interception via man-in-the-middle attacks.",
        "az storage account update -n {name} -g {rg} --https-only true",
    ),
    "network_unrestricted": (
        "The default network rule is 'Allow', enabling any IP address to access this storage account. An attacker with valid credentials can connect from any network.",
        "az storage account update -n {name} -g {rg} --default-action Deny",
    ),
    "soft_delete_disabled": (
        "Blob soft-delete is disabled, so accidental or malicious deletion is irreversible. No recovery window exists for deleted data.",
        "az storage blob service-properties delete-policy update --account-name {name} --enable true --days-retained 14",
    ),
    "weak_tls": (
        "This account accepts TLS versions older than 1.2, which have known cryptographic weaknesses exploitable for data interception.",
        "az storage account update -n {name} -g {rg} --min-tls-version TLS1_2",
    ),
    "shared_key_enabled": (
        "Shared key (storage account key) access is enabled. Compromised keys grant full access to all data. Entra ID (RBAC) is the recommended auth model.",
        "az storage account update -n {name} -g {rg} --allow-shared-key-access false",
    ),
    "no_infrastructure_encryption": (
        "Infrastructure encryption (double encryption at rest) is not enabled. A single encryption layer compromise could expose stored data.",
        "az storage account update -n {name} -g {rg} --require-infrastructure-encryption true",
    ),
    "anonymous_containers": (
        "One or more blob containers on this account have anonymous access level set to container or blob, exposing contents to unauthenticated users.",
        "az storage container set-permission --account-name {name} --name <container> --public-access off",
    ),
    "no_sas_expiration_policy": (
        "No SAS expiration policy is configured, allowing creation of SAS tokens with unlimited or excessively long validity, increasing risk if tokens leak.",
        "az storage account update -n {name} -g {rg} --key-exp-days 90",
    ),
    "no_immutability_policy": (
        "No account-level immutability policy exists. Compliance-critical data can be modified or deleted, violating retention requirements.",
        "az storage account update -n {name} -g {rg} --immutability-period 365 --immutability-state Unlocked",
    ),
    "blob_versioning_disabled": (
        "Blob versioning is disabled. Changes to blobs overwrite data with no version history, preventing recovery from accidental overwrites or ransomware.",
        "az storage account blob-service-properties update --account-name {name} -g {rg} --enable-versioning true",
    ),
    "change_feed_disabled": (
        "Change feed is disabled, so blob change events are not tracked. This limits audit capability and compliance monitoring for data access patterns.",
        "az storage account blob-service-properties update --account-name {name} -g {rg} --enable-change-feed true",
    ),
    "no_blob_logging": (
        "Diagnostic logging for blob read/write/delete operations is not enabled. Without logs, there is no visibility into data access patterns or breach investigation.",
        "az storage logging update --account-name {name} --log rwd --retention 90 --services b",
    ),
    "no_lifecycle_management": (
        "No lifecycle management policy exists. Stale data is retained indefinitely, increasing storage costs and expanding the data attack surface.",
        "az storage account management-policy create --account-name {name} -g {rg} --policy @lifecycle-policy.json",
    ),
    "overly_permissive_bypass": (
        "Network bypass rules are overly permissive (e.g. AzureServices, Logging, Metrics). This can allow unintended services to access storage data.",
        "az storage account update -n {name} -g {rg} --bypass None",
    ),
    "wildcard_cors_origin": (
        "CORS is configured with a wildcard (*) origin, permitting any website to make cross-origin requests and potentially exfiltrate data via browser-based attacks.",
        "az storage cors clear --account-name {name} --services bfqt",
    ),
    # ── Database / SQL ───────────────────────────────────────────────────
    "tde_disabled": (
        "Transparent Data Encryption (TDE) is not enabled. Data at rest is stored in plaintext, vulnerable to physical media theft or unauthorized backup access.",
        "az sql db tde set --database <db> --server {name} -g {rg} --status Enabled",
    ),
    "auditing_disabled": (
        "SQL auditing is not enabled. Database operations are not logged, eliminating forensic capability for security incident investigation.",
        "az sql server audit-policy update --name {name} -g {rg} --state Enabled --storage-account <storage>",
    ),
    "threat_protection_disabled": (
        "Advanced Threat Protection is not enabled. SQL injection, anomalous access patterns, and brute-force attacks will not be detected or alerted.",
        "az sql server threat-policy update --name {name} -g {rg} --state Enabled",
    ),
    "open_firewall": (
        "A firewall rule permits broad IP ranges. An attacker within that IP range can directly connect to the SQL server.",
        "az sql server firewall-rule delete --name <rule> --server {name} -g {rg}",
    ),
    "sql_open_firewall": (
        "A SQL Server firewall rule permits broad IP ranges or 0.0.0.0/0. An attacker within that range can directly connect.",
        "az sql server firewall-rule delete --name <rule> --server {name} -g {rg}",
    ),
    "sql_allow_azure_services": (
        "The 'Allow Azure Services' rule (0.0.0.0) is enabled, permitting connections from any Azure IP, including other tenants' resources.",
        "az sql server firewall-rule delete --name AllowAllWindowsAzureIps --server {name} -g {rg}",
    ),
    "sql_public_access": (
        "Public network access is enabled. The server is reachable from the Internet, increasing attack surface for credential-based intrusion.",
        "az sql server update -n {name} -g {rg} --public-network-access Disabled",
    ),
    "sql_tde_service_managed_key": (
        "TDE is enabled but uses a service-managed key. Customer-managed keys (CMK) provide additional control and meet stricter compliance requirements.",
        "az sql server tde-key set --server {name} -g {rg} --server-key-type AzureKeyVault --kid <key-uri>",
    ),
    "sql_va_disabled": (
        "SQL Vulnerability Assessment is disabled. Known database misconfigurations and security weaknesses will not be detected.",
        "az sql server va-setting update --server {name} -g {rg} --storage-account <storage> --state Enabled",
    ),
    "sql_no_long_term_retention": (
        "Long-term backup retention is not configured. Without LTR, backups older than the short-term retention window are lost, violating recovery objectives.",
        "az sql db ltr-policy set --server {name} -g {rg} --database <db> --weekly-retention P4W --monthly-retention P12M --yearly-retention P5Y",
    ),
    "sql_no_ddm": (
        "Dynamic Data Masking is not configured. Sensitive columns (SSN, email, etc.) are visible in full to non-privileged users.",
        "az sql db ddm create --server {name} -g {rg} --database <db> --schema dbo --table <table> --column <col> --masking-function Default",
    ),
    "sql_no_rls": (
        "Row-Level Security is not implemented. All users can query all rows, potentially exposing tenant or department data cross-boundary.",
        "# Enable RLS via T-SQL: CREATE SECURITY POLICY on {name}",
    ),
    "sql_unlabeled_sensitive_columns": (
        "Sensitive columns detected by data discovery are not labeled. Without classification labels, DLP and audit policies cannot identify sensitive data access.",
        "az sql db classification update --server {name} -g {rg} --database <db> --schema <schema> --table <table> --column <col> --label <label> --information-type <type>",
    ),
    "no_geo_backup": (
        "Geo-redundant backup is not enabled. A regional outage could result in permanent data loss if the primary region is unavailable.",
        "az sql server update -n {name} -g {rg} --backup-storage-redundancy Geo",
    ),
    "no_high_availability": (
        "Zone-redundant or failover group high availability is not configured. A zone failure could cause prolonged database downtime.",
        "az sql db update --server {name} -g {rg} --name <db> --zone-redundant true",
    ),
    "audit_log_short_retention": (
        "SQL audit log retention is set to less than 90 days. Short retention limits forensic investigation capability for historical incidents.",
        "az sql server audit-policy update --name {name} -g {rg} --retention-days 90",
    ),
    # ── Cosmos DB ────────────────────────────────────────────────────────
    "public_access_enabled": (
        "Public network access is enabled on this Cosmos DB account. The database is reachable from the public Internet, increasing attack surface.",
        "az cosmosdb update -n {name} -g {rg} --public-network-access DISABLED",
    ),
    "key_auth_enabled": (
        "Primary/secondary key authentication is enabled. Compromised keys grant full data-plane access. Disable key auth and use Entra ID RBAC.",
        "az cosmosdb update -n {name} -g {rg} --disable-key-based-metadata-write-access true",
    ),
    "no_ip_firewall": (
        "No IP firewall rules are configured. Any IP address with valid credentials can connect, increasing risk of unauthorized data access.",
        "az cosmosdb update -n {name} -g {rg} --ip-range-filter <allowed-ips>",
    ),
    "no_cmk": (
        "Customer-managed keys are not configured. Data is encrypted with Microsoft-managed keys, limiting control over key rotation and revocation.",
        "az cosmosdb update -n {name} -g {rg} --key-uri <key-vault-key-uri>",
    ),
    "cosmosdb_periodic_backup": (
        "Periodic backup is enabled instead of continuous backup. Point-in-time restore is not available, limiting recovery granularity.",
        "az cosmosdb update -n {name} -g {rg} --backup-policy-type Continuous",
    ),
    "periodic_backup": (
        "Periodic backup policy is configured instead of continuous. Point-in-time restore granularity is limited to backup intervals.",
        "az cosmosdb update -n {name} -g {rg} --backup-policy-type Continuous",
    ),
    "eventual_consistency": (
        "Default consistency is set to Eventual, which may cause stale reads. For data integrity-sensitive workloads, consider Session or Strong consistency.",
        "az cosmosdb update -n {name} -g {rg} --default-consistency-level Session",
    ),
    "ssl_not_enforced": (
        "SSL/TLS enforcement is not configured. Connections may transmit data in plaintext, exposing it to network interception.",
        "# Enforce SSL via Cosmos DB SDK configuration or portal settings for {name}",
    ),
    # ── Key Vault ────────────────────────────────────────────────────────
    "purge_protection_disabled": (
        "Purge protection is not enabled. Deleted secrets, keys, and certificates can be permanently purged before the retention period expires, with no recovery possible.",
        "az keyvault update --name {name} -g {rg} --enable-purge-protection true",
    ),
    "legacy_access_policy_model": (
        "This vault uses the legacy access-policy model instead of Azure RBAC. Access policies are coarse-grained and do not support conditional access or PIM.",
        "az keyvault update --name {name} -g {rg} --enable-rbac-authorization true",
    ),
    "no_network_restrictions": (
        "The Key Vault firewall is open (default action: Allow). Secrets, keys, and certificates can be accessed from any network, increasing exposure to credential theft.",
        "az keyvault update --name {name} -g {rg} --default-action Deny",
    ),
    "expiring_items": (
        "Secrets or keys are expiring soon. Unrotated credentials approaching expiry can cause application outages and increase compromise risk.",
        "az keyvault secret set-attributes --vault-name {name} --name <secret> --expires <new-date>",
    ),
    "expired_items": (
        "Secrets, keys, or certificates have expired. Expired credentials can cause authentication failures and indicate poor key management hygiene.",
        "az keyvault secret set-attributes --vault-name {name} --name <secret> --expires <new-date>",
    ),
    "no_expiry_set": (
        "Secrets have no expiration date. Leaked long-lived secrets grant indefinite access to resources until manually revoked.",
        "az keyvault secret set-attributes --vault-name {name} --name <secret> --expires $(date -d '+90 days' -u +%Y-%m-%dT%H:%M:%SZ)",
    ),
    "broad_access_policies": (
        "Access policies grant overly broad permissions (e.g. Get+List+Set+Delete on all secret/key/cert). Follow least-privilege and restrict to required operations.",
        "az keyvault set-policy --name {name} -g {rg} --object-id <id> --secret-permissions get list",
    ),
    "sp_broad_keyvault_access": (
        "A service principal has overly broad Key Vault access permissions. Compromise of this identity could expose all vault contents.",
        "az keyvault set-policy --name {name} -g {rg} --spn <app-id> --secret-permissions get list",
    ),
    "keys_not_hsm_backed": (
        "Keys are software-protected rather than HSM-backed. HSM keys provide stronger protection against key extraction and meet FIPS 140-2 Level 2+ requirements.",
        "az keyvault key create --vault-name {name} --name <key> --kty RSA-HSM",
    ),
    "cert_no_auto_renewal": (
        "Certificates do not have auto-renewal configured. Manual renewal processes risk expiry-related outages and service disruptions.",
        "az keyvault certificate set-attributes --vault-name {name} --name <cert> --policy @auto-renew-policy.json",
    ),
    "no_cmk_encryption": (
        "Key Vault is not using customer-managed keys for its own encryption. Service-managed encryption limits control over key lifecycle.",
        "# Configure CMK for Key Vault {name} via portal or ARM template",
    ),
    "vault_not_geo_redundant": (
        "Key Vault does not have geo-redundancy. A regional failure could make secrets, keys, and certificates unavailable.",
        "# Key Vault in {rg} is not geo-redundant. Azure Key Vault provides automatic geo-replication by default in paired regions.",
    ),
    "vault_no_cmk_encryption": (
        "Key Vault {name} is not using customer-managed keys for vault-level encryption.",
        "# Configure CMK for Key Vault {name} via portal or ARM template",
    ),
    # ── Encryption ───────────────────────────────────────────────────────
    "unencrypted_disks": (
        "The OS/data disk is not encrypted. Data at rest on this VM can be read if the underlying physical media is compromised or the disk snapshot is accessed.",
        "az vm encryption enable --name {name} -g {rg} --disk-encryption-keyvault <vault-name>",
    ),
    "no_encryption_at_host": (
        "Encryption-at-host is not enabled. Temporary disks and caches on the VM host remain unencrypted, potentially exposing sensitive data through host-level access.",
        "az vm update --name {name} -g {rg} --set securityProfile.encryptionAtHost=true",
    ),
    "managed_disk_no_cmk": (
        "This managed disk uses platform-managed keys only. Customer-managed keys provide an additional layer of control and allow key rotation per organizational policy.",
        "az disk update --name {name} -g {rg} --encryption-type EncryptionAtRestWithCustomerKey --disk-encryption-set <des-id>",
    ),
    "pmk_only_disk_encryption": (
        "This disk uses platform-managed keys (PMK) only. CMK provides additional control and compliance alignment for encryption key management.",
        "az disk update --name {name} -g {rg} --encryption-type EncryptionAtRestWithCustomerKey --disk-encryption-set <des-id>",
    ),
    # ── Data Access ──────────────────────────────────────────────────────
    "no_diagnostic_settings": (
        "Diagnostic settings are not configured. Access logs, metric data, and audit trails are not being collected, limiting visibility into who accessed data and when.",
        "az monitor diagnostic-settings create --resource {rid} --name ciq-diag --workspace <la-id> --logs '[{{\"enabled\":true}}]'",
    ),
    "broad_data_plane_rbac": (
        "Overly broad data-plane RBAC assignments (e.g. Storage Blob Data Contributor at subscription scope) grant excessive data access across resources.",
        "# Review and scope down RBAC assignments for {name} to resource-level",
    ),
    "owner_contributor_on_data_services": (
        "Owner or Contributor role is assigned on data services. These built-in roles grant full control including data-plane access. Use data-specific roles instead.",
        "# Replace Owner/Contributor with least-privilege data role on {name}",
    ),
    "sensitive_tagged_resources": (
        "This resource has been tagged with sensitive data classifications but lacks corresponding protection controls (encryption, network isolation, or DLP).",
        "# Review protection controls for sensitive resource {name} in {rg}",
    ),
    # ── Private Endpoints ────────────────────────────────────────────────
    "no_private_endpoint": (
        "This data service has no private endpoint configured. Traffic flows over the public Internet rather than a private Microsoft backbone, increasing interception risk.",
        "az network private-endpoint create --name {name}-pe -g {rg} --vnet-name <vnet> --subnet <subnet> --private-connection-resource-id {rid} --group-ids <group> --connection-name {name}-conn",
    ),
    "pe_pending_approval": (
        "A private endpoint connection is in pending approval state. Until approved, the resource remains accessible only via public network.",
        "az network private-endpoint-connection approve --resource-name {name} -g {rg} --name <pe-conn-name> --type <resource-type>",
    ),
    # ── Purview ──────────────────────────────────────────────────────────
    "purview_public_access": (
        "Public network access is enabled on this Purview account. Sensitive data catalog information and classification results are accessible from any network.",
        "az purview account update --name {name} -g {rg} --public-network-access Disabled",
    ),
    "purview_no_private_endpoint": (
        "No private endpoints configured for this Purview account. API and portal access traverses public networks.",
        "az network private-endpoint create --name {name}-pe -g {rg} --vnet-name <vnet> --subnet <subnet> --private-connection-resource-id {rid} --group-ids account",
    ),
    "purview_no_managed_identity": (
        "Purview account does not use a managed identity. Managed identities eliminate the need for stored credentials and simplify secure access to data sources.",
        "az purview account update --name {name} -g {rg} --managed-identity-type SystemAssigned",
    ),
    "no_purview_account": (
        "No Microsoft Purview account exists in this environment. Without Purview, data classification, governance, and lineage tracking are unavailable.",
        "az purview account create --name <purview-name> -g {rg} -l <location> --managed-identity-type SystemAssigned",
    ),
    "no_data_classification": (
        "No data classification or sensitivity labeling has been applied. Without classification, DLP policies and access controls cannot distinguish sensitive from non-sensitive data.",
        "# Register data sources in Purview and configure classification scans for {name}",
    ),
    "purview_scan_coverage_gap": (
        "Data services are not registered as Purview data sources. Unscanned resources have no classification metadata, creating blind spots in data governance.",
        "# Register {name} as a data source in Microsoft Purview and configure scan schedules",
    ),
    "purview_scan_issues": (
        "Purview scans for this data source have failed or returned errors. Classification results are incomplete or outdated.",
        "# Re-run or troubleshoot Purview scan for {name}. Check credentials and network connectivity.",
    ),
    # ── M365 DLP ─────────────────────────────────────────────────────────
    "no_dlp_policies": (
        "No Microsoft 365 DLP policies exist. Sensitive data (PII, financial, health) can be shared externally without detection or prevention.",
        "# Create DLP policies in Microsoft Purview Compliance portal targeting sensitive info types",
    ),
    "dlp_policy_disabled": (
        "A DLP policy exists but is disabled. Sensitive data is not being protected and violations are not being detected.",
        "# Enable DLP policy via Microsoft Purview Compliance portal for {name}",
    ),
    "dlp_coverage_gap": (
        "DLP policies do not cover all workloads (Exchange, SharePoint, OneDrive, Teams). Gaps allow sensitive data to be shared through uncovered channels.",
        "# Extend DLP policy coverage to include all workloads for {name}",
    ),
    "dlp_notify_only": (
        "DLP policy is in notification-only mode. Violations are detected and users are notified but data sharing is not blocked.",
        "# Update DLP policy {name} from Notify to Block mode for high-confidence matches",
    ),
    "dlp_weak_rules": (
        "DLP rules have low confidence thresholds or minimal sensitive info type coverage. This increases false positives and misses real violations.",
        "# Strengthen DLP rules for {name}: increase confidence levels and add sensitive info types",
    ),
    "dlp_no_sensitive_info_types": (
        "DLP policy does not reference specific sensitive information types. Generic rules will miss targeted data like SSN, credit card numbers, or health records.",
        "# Add sensitive information types (SSN, CC#, IBAN, etc.) to DLP policy {name}",
    ),
    "high_severity_dlp_alerts": (
        "High-severity DLP alerts have been triggered, indicating active data loss incidents requiring immediate investigation.",
        "# Investigate high-severity DLP alerts for {name} in Microsoft Purview Compliance portal",
    ),
    "no_dlp_alerts_with_policies": (
        "DLP policies exist but no alert rules are configured. Violations occur silently without notifying security teams.",
        "# Configure alert policies for DLP rule matches in Microsoft Purview Compliance portal",
    ),
    # ── M365 / SharePoint ────────────────────────────────────────────────
    "anonymous_sharing_enabled": (
        "Anonymous sharing is enabled on SharePoint/OneDrive. Anyone with a link can access shared content without authentication.",
        "# Disable anonymous sharing via SharePoint admin center or Set-SPOTenant -SharingCapability ExternalUserSharingOnly",
    ),
    "anonymous_sharing_links": (
        "Active anonymous sharing links exist. Content is accessible to anyone with the link URL, without authentication.",
        "# Review and remove anonymous sharing links via SharePoint admin center for {name}",
    ),
    "excessive_guest_access": (
        "Excessive guest user access detected. External users have broad access to internal sites and content.",
        "# Review and restrict guest access permissions for {name} via SharePoint admin center",
    ),
    "overshared_sites": (
        "Sites are shared with more users than expected. Broad sharing increases the risk of accidental data exposure.",
        "# Audit sharing permissions on {name} and restrict to required users/groups",
    ),
    "stale_sites": (
        "Inactive SharePoint sites with stale content still have active permissions. Orphaned sites increase attack surface.",
        "# Archive or delete stale site {name} and revoke permissions",
    ),
    "unlabeled_sites": (
        "SharePoint sites lack sensitivity labels. Without labels, data governance and DLP policies cannot be applied effectively.",
        "# Apply sensitivity labels to site {name} via SharePoint admin center or compliance portal",
    ),
    "no_retention_labels": (
        "No retention labels are configured. Documents can be deleted or modified without lifecycle governance, violating compliance retention requirements.",
        "# Create and publish retention labels via Microsoft Purview Records Management",
    ),
    "retention_labels_unused": (
        "Retention labels exist but are not applied to any content. Label policies are ineffective without actual label assignment.",
        "# Auto-apply retention labels or publish label policies to target locations",
    ),
    "no_ediscovery_cases": (
        "No eDiscovery cases are configured. Legal hold and investigation workflows are unavailable for compliance and litigation readiness.",
        "# Create eDiscovery cases in Microsoft Purview for litigation readiness",
    ),
    # ── Data Classification ──────────────────────────────────────────────
    "sql_unlabeled_sensitive_columns": (
        "Sensitive columns detected by SQL data discovery do not have classification labels applied. DLP policies cannot identify sensitive data access without labels.",
        "az sql db classification update --server {name} -g {rg} --database <db> --schema <schema> --table <table> --column <col> --label <label> --information-type <type>",
    ),
    # ── File Sync ────────────────────────────────────────────────────────
    "storage_sync_detected": (
        "Azure File Sync is detected. Ensure sync groups and cloud tiering are configured securely to prevent unintended data exposure.",
        "# Review Azure File Sync configuration for {name} in {rg}",
    ),
    "file_sync_public_access": (
        "Storage Sync Service allows public network access. Sync traffic traverses the public Internet, increasing data interception risk.",
        "az storagesync update --name {name} -g {rg} --incoming-traffic-policy AllowVirtualNetworksOnly",
    ),
    "file_sync_no_private_endpoint": (
        "No private endpoint is configured for the Storage Sync Service. Sync operations occur over public networks.",
        "az network private-endpoint create --name {name}-pe -g {rg} --vnet-name <vnet> --subnet <subnet> --private-connection-resource-id {rid} --group-ids afs",
    ),
    "cloud_tiering_disabled": (
        "Cloud tiering is disabled. All files are kept locally, increasing on-premises storage costs and reducing the benefit of Azure File Sync.",
        "# Enable cloud tiering on server endpoint for {name} via portal or PowerShell",
    ),
    "stale_registered_servers": (
        "Registered servers have not synced recently. Stale servers may have outdated data and create inconsistency risks.",
        "# Investigate stale registered server {name} and re-register or remove",
    ),
    # ── Backup & DR ──────────────────────────────────────────────────────
    "unprotected_vms": (
        "This VM is not protected by Azure Backup. Data loss from accidental deletion, ransomware, or disk failure would be unrecoverable.",
        "az backup protection enable-for-vm --resource-group {rg} --vault-name <vault> --vm {name} --policy-name DefaultPolicy",
    ),
    "vault_not_geo_redundant": (
        "Recovery Services vault is not geo-redundant. A regional disaster could result in loss of all backup data.",
        "az backup vault backup-properties set --name <vault> -g {rg} --backup-storage-redundancy GeoRedundant",
    ),
    # ── Container Security ───────────────────────────────────────────────
    "acr_admin_enabled": (
        "Admin user is enabled on the container registry. Admin credentials are shared and cannot be scoped, increasing the risk of unauthorized image pushes.",
        "az acr update -n {name} -g {rg} --admin-enabled false",
    ),
    "acr_no_quarantine": (
        "Image quarantine is not enabled. Pushed images can be pulled immediately without vulnerability scanning or approval.",
        "az acr config quarantine update -n {name} --status Enabled",
    ),
    "acr_no_vulnerability_scanning": (
        "Container image vulnerability scanning is not configured. Vulnerable base images and dependencies can be deployed to production undetected.",
        "az acr config content-trust update -n {name} --status Enabled",
    ),
    "aks_rbac_issues": (
        "AKS cluster does not have Azure AD RBAC integration. Kubernetes RBAC alone lacks identity lifecycle management and conditional access.",
        "az aks update -n {name} -g {rg} --enable-azure-rbac --enable-aad",
    ),
    "aks_no_network_policy": (
        "No Kubernetes network policy is configured. Pods can communicate freely, enabling lateral movement if a pod is compromised.",
        "# Deploy Calico or Azure network policies to restrict pod-to-pod traffic on {name}",
    ),
    "aks_no_pod_security": (
        "Pod security admission is not configured. Containers can run as root, mount host paths, or use privileged mode, increasing breakout risk.",
        "# Configure Pod Security Standards (restricted/baseline) on AKS cluster {name}",
    ),
    # ── Network Segmentation ────────────────────────────────────────────
    "no_ddos_protection": (
        "DDoS Protection Standard is not enabled on this VNet. Volumetric attacks can saturate network bandwidth and disrupt data service availability.",
        "az network ddos-protection create -g {rg} -n {name}-ddos ; az network vnet update -n {name} -g {rg} --ddos-protection-plan {name}-ddos",
    ),
    "nsg_permissive_data_ports": (
        "NSG rules allow inbound traffic to data ports (1433, 3306, 5432, 27017, etc.) from broad IP ranges. Databases are accessible to unauthorized networks.",
        "az network nsg rule update -g {rg} --nsg-name {name} --name <rule> --source-address-prefixes <trusted-ips>",
    ),
    "subnet_missing_service_endpoints": (
        "Subnets hosting data services do not have service endpoints configured. Traffic to Azure services traverses public IPs instead of the Azure backbone.",
        "az network vnet subnet update -g {rg} --vnet-name <vnet> --name {name} --service-endpoints Microsoft.Storage Microsoft.Sql Microsoft.KeyVault",
    ),
    # ── Data Residency ───────────────────────────────────────────────────
    "resource_location_outlier": (
        "This resource is deployed in a region outside the expected geographic boundary. Cross-region deployment may violate data residency requirements.",
        "# Migrate {name} from current region to compliant region in {rg}",
    ),
    "geo_replication_cross_boundary": (
        "Geo-replication is configured across geographic boundaries. Data replicates to regions that may be subject to different data sovereignty laws.",
        "# Review geo-replication settings for {name} and ensure target regions comply with data residency requirements",
    ),
    # ── Threat Detection ─────────────────────────────────────────────────
    "defender_coverage_gaps": (
        "Microsoft Defender for Cloud is not enabled for this service type. Threat detection, anomaly alerts, and vulnerability assessments are not active.",
        "az security pricing create -n {name} --tier Standard",
    ),
    "defender_storage_disabled": (
        "Microsoft Defender for Storage is not enabled. Malware uploads, suspicious access patterns, and data exfiltration will not be detected.",
        "az security pricing create -n StorageAccounts --tier Standard",
    ),
    "defender_sql_disabled": (
        "Microsoft Defender for SQL is not enabled. SQL injection, brute-force, and anomalous query patterns will not trigger alerts.",
        "az security pricing create -n SqlServers --tier Standard",
    ),
    "defender_keyvault_disabled": (
        "Microsoft Defender for Key Vault is not enabled. Unusual secret access, credential harvesting, and suspicious vault operations will not be detected.",
        "az security pricing create -n KeyVaults --tier Standard",
    ),
    "defender_storage_sdd_disabled": (
        "Sensitive Data Discovery in Defender for Storage is not enabled. Sensitive data exposure through misconfigured containers will not be flagged.",
        "# Enable Sensitive Data Discovery via Defender for Storage settings in Azure portal",
    ),
    "defender_sdd_sensitive_data_found": (
        "Sensitive data has been discovered by Defender in storage. This data requires immediate classification and access control review.",
        "# Review sensitive data alerts for {name} in Defender for Cloud and apply appropriate access restrictions",
    ),
    "no_security_action_groups": (
        "No Azure Monitor action groups are configured for security alerts. Critical security events are not routed to response teams.",
        "az monitor action-group create -n SecurityAlerts -g {rg} --action email security-team security@contoso.com",
    ),
    # ── RBAC / Access ────────────────────────────────────────────────────
    "public_network_access": (
        "Public network access is enabled on this resource. The service is reachable from the Internet, expanding the attack surface.",
        "# Disable public network access on {name} via resource-specific CLI or portal",
    ),
    # ── Database AAD-only auth ───────────────────────────────────────────
    "sql_local_auth_enabled": (
        "Local (SQL) authentication is enabled on this SQL server. Passwords can be brute-forced or leaked. Azure AD-only authentication enforces MFA and Conditional Access.",
        "az sql server ad-only-auth enable -n {name} -g {rg}",
    ),
    # ── PostgreSQL/MySQL AAD auth ────────────────────────────────────────
    "pg_mysql_no_aad_auth": (
        "This PostgreSQL/MySQL server does not have Azure AD authentication configured. Database access relies solely on local passwords without MFA or centralized identity governance.",
        "az postgres flexible-server ad-admin create -g {rg} -s {name} --display-name <admin> --object-id <oid>",
    ),
    # ── Managed Identity ─────────────────────────────────────────────────
    "no_managed_identity": (
        "This data service does not use managed identity. Inter-service authentication relies on credentials (keys, passwords, connection strings) that can be leaked or compromised.",
        "az resource update --ids {resource_id} --set identity.type=SystemAssigned",
    ),
    # ── Resource Locks ───────────────────────────────────────────────────
    "no_resource_lock": (
        "No CanNotDelete or ReadOnly lock is set on this critical data service. Accidental or malicious deletion could result in permanent data loss.",
        "az lock create --name DoNotDelete --resource {resource_id} --lock-type CanNotDelete",
    ),
    # ── Data Factory ─────────────────────────────────────────────────────
    "adf_no_managed_vnet": (
        "This Data Factory does not use a managed virtual network. Integration runtimes can exfiltrate data to arbitrary external endpoints.",
        "# Enable managed VNet for {name} in Azure Portal > Data Factory > Managed virtual network",
    ),
    # ── Synapse ──────────────────────────────────────────────────────────
    "synapse_no_exfiltration_protection": (
        "This Synapse workspace lacks managed VNet or data exfiltration protection. Pipelines and Spark pools can send data to arbitrary external endpoints.",
        "# Managed VNet must be enabled at workspace creation. Recreate {name} with managed VNet and exfiltration protection.",
    ),
    # ── AI Services ──────────────────────────────────────────────────────
    "ai_services_public_access": (
        "This AI/Cognitive Services account has public network access enabled. Sensitive data processed through AI APIs (OCR, speech, custom models) is exposed to network-level attacks.",
        "az cognitiveservices account update -n {name} -g {rg} --public-network-access Disabled",
    ),
    # ── Log Analytics CMK ────────────────────────────────────────────────
    "log_analytics_no_cmk": (
        "This Log Analytics workspace uses Microsoft-managed encryption keys. Security logs and audit trails lack customer-controlled encryption.",
        "az monitor log-analytics cluster create -n <cluster> -g {rg} --sku-capacity 500 --identity-type SystemAssigned",
    ),
    # ── Immutable Audit Logs ─────────────────────────────────────────────
    "no_immutable_audit_logs": (
        "This Log Analytics workspace does not have immutable ingestion enabled. An attacker could tamper with or delete security logs.",
        "# Enable immutable audit on {name} via Azure Portal > Log Analytics > Properties",
    ),
    # ── Auto-labeling ────────────────────────────────────────────────────
    "no_auto_labeling": (
        "No auto-labeling policies are configured. Sensitivity labels must be applied manually, leading to inconsistent data classification.",
        "# Configure auto-labeling in compliance.microsoft.com > Information protection > Auto-labeling",
    ),
    # ── Data Minimization ────────────────────────────────────────────────
    "no_data_minimization": (
        "No retention labels enforce automatic deletion. Stale data accumulates indefinitely, increasing the blast radius of breaches.",
        "# Create retention labels with deletion action in compliance.microsoft.com > Data lifecycle management",
    ),
    # ── Redis ────────────────────────────────────────────────────────────
    "redis_weak_tls": (
        "This Redis cache accepts TLS versions older than 1.2, which have known cryptographic vulnerabilities.",
        "az redis update -n {name} -g {rg} --set minimumTlsVersion=1.2",
    ),
    "redis_non_ssl_port": (
        "The non-SSL port (6379) is enabled, transmitting cached data (sessions, tokens, PII) in plaintext.",
        "az redis update -n {name} -g {rg} --set enableNonSslPort=false",
    ),
    "redis_no_firewall": (
        "No firewall rules or private endpoints are configured. This Redis cache is accessible from any Azure IP address.",
        "az redis firewall-rules create -n {name} -g {rg} --rule-name AllowVNet --start-ip <ip> --end-ip <ip>",
    ),
    # ── Messaging ────────────────────────────────────────────────────────
    "eventhub_public_access": (
        "This Event Hub namespace has no network restrictions. Streaming data is accessible from any network.",
        "az eventhubs namespace network-rule-set update -g {rg} --namespace-name {name} --default-action Deny",
    ),
    "servicebus_public_access": (
        "This Service Bus namespace has no network restrictions. Message queues and topics are accessible from any network.",
        "az servicebus namespace network-rule-set update -g {rg} --namespace-name {name} --default-action Deny",
    ),
    "messaging_weak_tls": (
        "This messaging service accepts TLS versions older than 1.2, exposing data in transit to interception.",
        "az eventhubs namespace update -n {name} -g {rg} --minimum-tls-version 1.2",
    ),

    # ── AI Services ──────────────────────────────────────────────────
    "ai_key_auth_enabled": (
        "AI Services account allows key-based authentication. Static API keys can be leaked in code, logs, or config files, granting unscoped access.",
        "az cognitiveservices account update -n {name} -g {rg} --custom-domain <domain> --disable-local-auth true",
    ),
    "ai_no_managed_identity": (
        "AI Services account has no managed identity. Authentication requires stored credentials, increasing the risk of credential exposure.",
        "az cognitiveservices account identity assign -n {name} -g {rg}",
    ),
    "ai_no_cmk": (
        "AI Services account uses platform-managed keys. Custom models, training data, and inference logs are encrypted with Microsoft-managed keys only.",
        "az cognitiveservices account update -n {name} -g {rg} --encryption-key-source Microsoft.KeyVault --encryption-key-name <key> --encryption-key-vault <vault-uri>",
    ),
    # ── Data Pipeline ────────────────────────────────────────────────
    "adf_public_access": (
        "Data Factory allows public network access. Management APIs and data movement are reachable from the Internet.",
        "az datafactory update -n {name} -g {rg} --public-network-access Disabled",
    ),
    "adf_no_managed_identity": (
        "Data Factory has no managed identity. Linked services require stored credentials for data source access.",
        "az datafactory update -n {name} -g {rg} --identity-type SystemAssigned",
    ),
    "adf_no_git_integration": (
        "Data Factory is not connected to a Git repository. Pipeline changes are not version-controlled and cannot be audited or rolled back.",
        "# Configure Git integration via Azure Portal > Data Factory > Management Hub > Git configuration",
    ),
    "synapse_public_access": (
        "Synapse workspace allows public network access. SQL pools and Spark pools are reachable from the public Internet.",
        "# Disable public access via Azure Portal > Synapse workspace > Networking",
    ),
    "synapse_sql_auth_enabled": (
        "Synapse workspace allows SQL authentication. Passwords can be brute-forced and lack MFA or conditional access.",
        "# Enable Azure AD-only auth via Azure Portal > Synapse workspace > Azure Active Directory",
    ),
    # ── Enhanced Messaging ───────────────────────────────────────────
    "eventhub_local_auth": (
        "Event Hub namespace allows SAS/local authentication. SAS keys are static shared secrets that grant unrestricted access to all Event Hubs.",
        "az eventhubs namespace update -n {name} -g {rg} --disable-local-auth true",
    ),
    "servicebus_local_auth": (
        "Service Bus namespace allows SAS/local authentication. SAS keys provide shared, unscoped access to all queues and topics.",
        "az servicebus namespace update -n {name} -g {rg} --disable-local-auth true",
    ),
    "eventhub_no_capture": (
        "Event Hub capture is not enabled. Events are consumed and discarded without a persistent audit trail for compliance.",
        "az eventhubs eventhub update -g {rg} --namespace-name <ns> -n <hub> --enable-capture true --capture-interval 300 --storage-account <storage-id>",
    ),
    # ── Enhanced Redis ───────────────────────────────────────────────
    "redis_no_patch_schedule": (
        "Redis cache does not have a configured patch schedule. Updates may apply during business hours, causing unexpected downtime.",
        "az redis patch-schedule create -n {name} -g {rg} --schedule-entries dayOfWeek=Sunday startHourUtc=2",
    ),
    "redis_public_access": (
        "Redis cache allows public network access with no private endpoints. Cached data (sessions, tokens, PII) is accessible from the Internet.",
        "az redis update -n {name} -g {rg} --set publicNetworkAccess=Disabled",
    ),
    # ── Identity ─────────────────────────────────────────────────────
    "data_services_no_managed_identity": (
        "Data pipeline or messaging service does not use managed identity. Authentication relies on stored credentials and connection strings.",
        "# Enable system-assigned managed identity via: az resource update --ids {rid} --set identity.type=SystemAssigned",
    ),
    # ── Wave A+B+C risk map ──────────────────────────────────────────────
    "sqlmi_no_atp": (
        "SQL Managed Instance without Advanced Threat Protection cannot detect anomalous database activities like SQL injection or data exfiltration.",
        "az sql mi threat-policy update --resource-group {rg} --managed-instance {name} --state Enabled",
    ),
    "sqlmi_public_endpoint": (
        "SQL MI public data endpoint exposes the database to Internet-originated attacks including brute-force and data theft.",
        "az sql mi update -g {rg} -n {name} --public-data-endpoint-enabled false",
    ),
    "appconfig_public_access": (
        "App Configuration with public access may expose secrets, connection strings, and feature flags to unauthorized parties.",
        "az appconfig update -n {name} -g {rg} --enable-public-network false",
    ),
    "cert_expiring_soon": (
        "Certificates expiring within 30 days risk service outages and broken TLS trust chains if not renewed.",
        "az keyvault certificate create --vault-name {vault} -n {name} -p @policy.json",
    ),
    "cert_weak_key": (
        "Certificates with RSA keys below 2048 bits can be factored with modern hardware, compromising encrypted data.",
        "# Re-issue with: az keyvault certificate create --vault-name {vault} -n {name} --policy @stronger-policy.json",
    ),
    "databricks_no_vnet": (
        "Databricks workspace without VNET injection runs on shared infrastructure; data traverses Microsoft-managed networks.",
        "az databricks workspace create -n {name} -g {rg} --vnet <vnet> --private-subnet <sub1> --public-subnet <sub2>",
    ),
    "databricks_public_access": (
        "Databricks with public network access exposes the workspace control plane to anyone on the Internet.",
        "az databricks workspace update -n {name} -g {rg} --public-network-access Disabled",
    ),
    "apim_no_vnet": (
        "APIM without VNET integration routes API traffic through the public Internet, exposing backend credentials in transit.",
        "az apim update -n {name} -g {rg} --virtual-network-type Internal",
    ),
    "frontdoor_no_waf": (
        "Front Door without WAF cannot block SQL injection, XSS, or data exfiltration payloads targeting backend APIs.",
        "az network front-door waf-policy create -g {rg} -n {name}-waf --mode Prevention",
    ),
    "secret_in_app_settings": (
        "Secrets stored as plain text in web app settings are visible in ARM exports, deployment logs, and to any Reader.",
        "# Move to Key Vault: az webapp config appsettings set -g {rg} -n {name} --settings SECRET=@Microsoft.KeyVault(SecretUri=...)",
    ),
    "firewall_no_threat_intel": (
        "Azure Firewall with threat intelligence disabled allows traffic from known malicious IPs to reach internal data services.",
        "az network firewall update -g {rg} -n {name} --threat-intel-mode Deny",
    ),
    "firewall_no_idps": (
        "Azure Firewall without IDPS cannot detect data exfiltration, command-and-control traffic, or lateral movement patterns.",
        "az network firewall policy intrusion-detection add -g {rg} --policy-name {name} --mode Alert",
    ),
    "appgw_no_waf": (
        "Application Gateway without WAF SKU cannot inspect or block malicious payloads targeting backend data APIs.",
        "az network application-gateway update -g {rg} -n {name} --sku WAF_v2",
    ),
    "no_bastion_open_rdp": (
        "Direct RDP/SSH exposure from Internet enables brute-force attacks and data exfiltration via remote sessions.",
        "az network bastion create -n {name}-bastion -g {rg} --vnet-name <vnet> --public-ip-address <pip>",
    ),
    "bastion_shareable_links": (
        "Bastion shareable links allow unauthenticated URL-based VM access, bypassing RBAC and audit controls.",
        "az network bastion update -n {name} -g {rg} --enable-shareable-link false",
    ),
    "data_policy_noncompliant": (
        "Non-compliant data-related Azure Policy assignments indicate governance controls are not being enforced.",
        "az policy state trigger-scan --resource-group {rg}",
    ),
    "defender_data_recs_unhealthy": (
        "Unhealthy Defender for Cloud data-protection recommendations indicate known security gaps flagged by Microsoft.",
        "az security assessment list --query [?status.code=='Unhealthy']",
    ),

    # ── Wave D risk map ──────────────────────────────────────────────────
    "stale_data_role_assignment": (
        "Stale RBAC assignment grants data access to an identity with no recent sign-in activity — a prime target for credential theft.",
        "az role assignment delete --ids {rid}",
    ),
    "storage_unusual_bypass": (
        "Unusual storage firewall bypass may allow trusted-service abuse for data exfiltration.",
        "az storage account update -n {name} -g {rg} --bypass AzureServices",
    ),
    "cross_sub_private_endpoint": (
        "Cross-subscription private endpoint may enable data exfiltration to external subscriptions.",
        "az storage account private-endpoint-connection reject --account-name {name} -g {rg} --name {conn}",
    ),
    "nsg_unrestricted_outbound": (
        "Unrestricted outbound access enables data exfiltration via HTTPS to attacker-controlled endpoints.",
        "az network nsg rule update -g {rg} --nsg-name {name} -n {rule} --destination-address-prefix <ServiceTag>",
    ),
    "no_mfa_ca_policy": (
        "Without MFA, data admin accounts can be compromised with stolen passwords alone.",
        "# Create Conditional Access policy via Azure Portal > Entra ID > Security > Conditional Access",
    ),
    "pim_permanent_assignments": (
        "Permanent PIM assignments grant standing privileged access, violating least-privilege and increasing breach impact.",
        "# Convert to eligible via Azure Portal > Entra ID > PIM > Azure AD Roles",
    ),
    # ── Config Drift ──
    "drift_detected": (
        "Security-sensitive property changed — may indicate unauthorized modification or policy bypass.",
        "az resource show --ids <id> --query properties",
    ),
    # ── Supply Chain ──
    "aks_no_acr_integration": (
        "AKS may pull images from untrusted registries without ACR integration.",
        "az aks update -n <cluster> -g <rg> --attach-acr <acr-name>",
    ),
    "acr_admin_enabled": (
        "Admin user provides static, unrestricted push/pull credentials — supply chain injection risk.",
        "az acr update -n <name> --admin-enabled false",
    ),
    "func_external_package": (
        "Function app code loaded from external URL — compromised source leads to code injection.",
        "az functionapp config appsettings set -n <name> -g <rg> --settings WEBSITE_RUN_FROM_PACKAGE=1",
    ),


}


def enrich_per_resource_details(findings: list[dict]) -> list[dict]:
    """Add Severity, Risk, and ResourceRemediation to each AffectedResource.

    Uses the finding-level severity/description/remediation as defaults,
    then applies subcategory-specific risk and CLI templates with per-resource
    name/ID substitution.
    """
    for f in findings:
        sev = f.get("Severity", "medium")
        desc = f.get("Description", "")
        subcat = f.get("Subcategory", "")
        finding_rem = f.get("Remediation", {})
        finding_cli = finding_rem.get("AzureCLI", "")

        risk_template, cli_template = _RESOURCE_RISK_MAP.get(subcat, ("", ""))

        for ar in f.get("AffectedResources", []):
            if not isinstance(ar, dict):
                continue
            ar["Severity"] = sev

            res_name = ar.get("Name", ar.get("name", ""))
            res_id = ar.get("ResourceId", ar.get("resource_id", ar.get("id", "")))
            rg = ""
            if isinstance(res_id, str) and "/resourceGroups/" in res_id:
                parts = res_id.split("/resourceGroups/")
                if len(parts) > 1:
                    rg = parts[1].split("/")[0]

            subs = {"name": res_name, "rid": res_id, "rg": rg}

            ar["Risk"] = risk_template if risk_template else desc

            if cli_template:
                try:
                    ar["ResourceRemediation"] = cli_template.format(**subs)
                except (KeyError, IndexError):
                    ar["ResourceRemediation"] = cli_template
            elif finding_cli:
                ar["ResourceRemediation"] = finding_cli
            else:
                ar["ResourceRemediation"] = ""

    return findings


# ── Remediation Impact Scoring ────────────────────────────────────────────

def compute_remediation_impact(findings: list[dict], scores: dict) -> dict:
    """Calculate projected score improvement if findings are remediated by severity.

    Returns a dict with estimated overall scores after fixing all
    critical, high, medium, and low findings respectively.
    """
    current_overall = scores.get("OverallScore", 0)
    if not findings:
        return {
            "CurrentScore": current_overall,
            "IfCriticalFixed": current_overall,
            "IfHighFixed": current_overall,
            "IfAllFixed": 0,
            "CriticalRemediationImpact": 0,
            "HighRemediationImpact": 0,
        }

    total_weight = sum(
        _SEVERITY_WEIGHTS.get(f.get("Severity", "medium").lower(), 5.0)
        for f in findings
    )
    if total_weight == 0:
        return {
            "CurrentScore": current_overall,
            "IfCriticalFixed": current_overall,
            "IfHighFixed": current_overall,
            "IfAllFixed": 0,
            "CriticalRemediationImpact": 0,
            "HighRemediationImpact": 0,
        }

    critical_weight = sum(
        _SEVERITY_WEIGHTS.get("critical", 10.0)
        for f in findings if f.get("Severity", "").lower() == "critical"
    )
    high_weight = sum(
        _SEVERITY_WEIGHTS.get("high", 7.5)
        for f in findings if f.get("Severity", "").lower() == "high"
    )

    critical_pct = critical_weight / total_weight if total_weight else 0
    high_pct = high_weight / total_weight if total_weight else 0

    return {
        "CurrentScore": current_overall,
        "IfCriticalFixed": round(current_overall * (1 - critical_pct), 1),
        "IfHighFixed": round(current_overall * (1 - critical_pct - high_pct), 1),
        "IfAllFixed": 0,
        "CriticalRemediationImpact": round(current_overall * critical_pct, 1),
        "HighRemediationImpact": round(current_overall * high_pct, 1),
    }


# ====================================================================
# 6b. FINDING CONSOLIDATION — merge overlapping findings per category
# ====================================================================

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _finding_resource_ids(finding: dict) -> set[str]:
    """Extract the set of resource IDs from a finding."""
    return {
        ar.get("ResourceId", ar.get("resource_id", ar.get("id", "")))
        for ar in finding.get("AffectedResources", [])
        if isinstance(ar, dict)
    }


def _overlap_ratio(set_a: set[str], set_b: set[str]) -> float:
    """Overlap as fraction of the smaller set (1.0 = full containment)."""
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / min(len(set_a), len(set_b))


def _merge_finding_group(category: str, group: list[dict]) -> dict:
    """Merge a list of related findings into a single composite finding."""
    # Highest severity wins
    best_sev = min(group, key=lambda f: _SEV_RANK.get(
        f.get("Severity", "medium").lower(), 5
    )).get("Severity", "medium")

    # Union affected resources, deduped by ResourceId
    seen: dict[str, dict] = {}
    merged_res: list[dict] = []
    for f in group:
        subcat = f.get("Subcategory", "")
        for ar in f.get("AffectedResources", []):
            if not isinstance(ar, dict):
                continue
            rid = ar.get("ResourceId", ar.get("resource_id", ar.get("id", "")))
            if rid not in seen:
                seen[rid] = ar
                merged_res.append(ar)
            # Tag each resource with the gaps that flagged it
            gaps = seen[rid].setdefault("Gaps", [])
            if subcat and subcat not in gaps:
                gaps.append(subcat)

    count = len(merged_res)

    # Build composite title / description
    gap_titles = [f.get("Title", "") for f in group]
    cat_label = category.replace("_", " ").title()
    title = f"{count} resource(s) with {len(group)} {cat_label} gaps"
    desc = "Consolidated finding:\n" + "\n".join(
        f"  \u2022 {t}" for t in gap_titles
    )

    # Merge remediation steps
    rem_desc: list[str] = []
    rem_cli: list[str] = []
    for f in group:
        rem = f.get("Remediation", {})
        if rem.get("Description"):
            rem_desc.append(f"\u2022 {rem['Description']}")
        if rem.get("AzureCLI"):
            rem_cli.append(f"# {f.get('Subcategory', '')}\n{rem['AzureCLI']}")

    merged_from = [
        {
            "Subcategory": f.get("Subcategory", ""),
            "Title": f.get("Title", ""),
            "Severity": f.get("Severity", ""),
            "AffectedCount": f.get("AffectedCount", 0),
            "OriginalFindingId": f.get("DataSecurityFindingId", ""),
        }
        for f in group
    ]

    # Union compliance mappings from child findings
    merged_compliance: dict[str, list[str]] = {}
    merged_details: dict[str, dict[str, str]] = {}
    for f in group:
        cm = f.get("ComplianceMapping", {})
        for fw, ctrls in cm.items():
            existing = merged_compliance.setdefault(fw, [])
            for c in ctrls:
                if c not in existing:
                    existing.append(c)
        for key, det in f.get("ComplianceDetails", {}).items():
            if key not in merged_details:
                merged_details[key] = det

    # Deterministic ID for merged finding: fingerprint from child finding IDs
    child_ids = sorted(m["OriginalFindingId"] for m in merged_from)
    merge_fingerprint = f"{category}|consolidated|{'|'.join(child_ids)}"
    merged_finding_id = str(uuid.uuid5(_DS_FINDING_NS, merge_fingerprint))

    result: dict = {
        "DataSecurityFindingId": merged_finding_id,
        "Category": category,
        "Subcategory": f"{category}_consolidated",
        "Title": title,
        "Description": desc,
        "Severity": best_sev,
        "AffectedResources": merged_res,
        "AffectedCount": count,
        "Remediation": {
            "Description": "\n".join(rem_desc),
            "AzureCLI": "\n\n".join(rem_cli),
        },
        "DetectedAt": datetime.now(timezone.utc).isoformat(),
        "MergedFrom": merged_from,
        "MergedCount": len(group),
    }
    if merged_compliance:
        result["ComplianceMapping"] = merged_compliance
    if merged_details:
        result["ComplianceDetails"] = merged_details
    return result


def consolidate_findings(
    findings: list[dict], *, threshold: float = 0.80
) -> list[dict]:
    """Merge findings within the same category that share overlapping resources.

    Two findings are merged when their affected-resource sets overlap by at
    least *threshold* (measured against the smaller set).  Findings with no
    affected resources are never merged.
    """
    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        by_cat.setdefault(f.get("Category", "unknown"), []).append(f)

    consolidated: list[dict] = []
    for cat, cat_fs in by_cat.items():
        if len(cat_fs) <= 1:
            consolidated.extend(cat_fs)
            continue

        items = [(f, _finding_resource_ids(f)) for f in cat_fs]
        used: set[int] = set()

        for i, (fi, ri) in enumerate(items):
            if i in used:
                continue
            # Skip findings with no resources from merging
            if not ri:
                consolidated.append(fi)
                used.add(i)
                continue

            group = [fi]
            group_ids = set(ri)
            used.add(i)

            for j, (fj, rj) in enumerate(items):
                if j in used or not rj:
                    continue
                if _overlap_ratio(group_ids, rj) >= threshold:
                    group.append(fj)
                    group_ids |= rj
                    used.add(j)

            if len(group) == 1:
                consolidated.append(group[0])
            else:
                consolidated.append(_merge_finding_group(cat, group))

    return consolidated

