"""
Data Security — Database Security evaluator — SQL checks.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_database_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_sql_tde(evidence_index))
    findings.extend(_check_sql_auditing(evidence_index))
    findings.extend(_check_sql_threat_protection(evidence_index))
    findings.extend(_check_sql_firewall(evidence_index))
    findings.extend(_check_sql_allow_azure_services(evidence_index))
    findings.extend(_check_sql_tde_key_source(evidence_index))
    findings.extend(_check_sql_public_access(evidence_index))
    findings.extend(_check_sql_ddm(evidence_index))
    findings.extend(_check_sql_rls(evidence_index))
    findings.extend(_check_sql_aad_only_auth(evidence_index))
    return findings


def _check_sql_aad_only_auth(idx: dict) -> list[dict]:
    """Flag SQL servers that have not enforced Azure AD-only authentication."""
    sqls = idx.get("azure-sql-server", [])
    local_auth: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        aad_only = data.get("azureADOnlyAuthentication",
                   data.get("AzureADOnlyAuthentication",
                   data.get("administrators", {}).get("azureADOnlyAuthentication")))
        if aad_only is not True:
            local_auth.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if local_auth:
        return [_ds_finding(
            "database", "sql_local_auth_enabled",
            f"{len(local_auth)} SQL servers with local (SQL) authentication still enabled",
            "Local SQL authentication uses passwords that can be brute-forced or leaked. "
            "Azure AD-only authentication enforces MFA, Conditional Access, and centralized "
            "identity governance for all database connections.",
            "high", local_auth,
            {"Description": "Enable Azure AD-only authentication on all SQL servers.",
             "AzureCLI": "az sql server ad-only-auth enable -n <server> -g <rg>"},
        )]
    return []


def _check_sql_tde(idx: dict) -> list[dict]:
    sqls = idx.get("azure-sql-server", [])
    no_tde: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        tde = data.get("TransparentDataEncryption", data.get("tde_enabled"))
        if tde is False:
            no_tde.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_tde:
        return [_ds_finding(
            "database", "tde_disabled",
            f"{len(no_tde)} SQL servers without Transparent Data Encryption",
            "Data at rest is unencrypted, exposing it if physical media is compromised.",
            "critical", no_tde,
            {"Description": "Enable TDE on all SQL databases.",
             "AzureCLI": "az sql db tde set -g <rg> -s <server> -d <db> --status Enabled"},
        )]
    return []


def _check_sql_auditing(idx: dict) -> list[dict]:
    sqls = idx.get("azure-sql-server", [])
    no_audit: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        auditing = data.get("AuditingEnabled", data.get("auditing_enabled"))
        if auditing is False:
            no_audit.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_audit:
        return [_ds_finding(
            "database", "auditing_disabled",
            f"{len(no_audit)} SQL servers without auditing",
            "SQL auditing is required for security monitoring and compliance.",
            "high", no_audit,
            {"Description": "Enable SQL auditing to a storage account or Log Analytics workspace.",
             "AzureCLI": "az sql server audit-policy update -g <rg> -n <server> "
                         "--state Enabled --storage-account <storage-id>"},
        )]
    return []


def _check_sql_threat_protection(idx: dict) -> list[dict]:
    sqls = idx.get("azure-sql-server", [])
    no_atp: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        atp = data.get("AdvancedThreatProtection", data.get("threat_protection_enabled"))
        if atp is False:
            no_atp.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_atp:
        return [_ds_finding(
            "database", "threat_protection_disabled",
            f"{len(no_atp)} SQL servers without Advanced Threat Protection",
            "ATP detects anomalous activities indicating potential SQL injection and brute-force attacks.",
            "high", no_atp,
            {"Description": "Enable Advanced Threat Protection on SQL servers.",
             "AzureCLI": "az sql server threat-policy update -g <rg> -n <server> --state Enabled"},
        )]
    return []


def _check_sql_firewall(idx: dict) -> list[dict]:
    sqls = idx.get("azure-sql-server", [])
    exposed: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        for rule in data.get("FirewallRules", data.get("firewall_rules", [])):
            start = rule.get("StartIpAddress", rule.get("start_ip_address", ""))
            end = rule.get("EndIpAddress", rule.get("end_ip_address", ""))
            if start == "0.0.0.0" and end in ("255.255.255.255", "0.0.0.0"):
                exposed.append({
                    "Type": "SQLServer",
                    "Name": data.get("Name", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "RuleName": rule.get("Name", rule.get("name", "")),
                })
                break
    if exposed:
        return [_ds_finding(
            "database", "sql_open_firewall",
            f"{len(exposed)} SQL servers with 0.0.0.0/0 firewall rules",
            "Allow-all firewall rules expose SQL to the entire Internet or all Azure services.",
            "high", exposed,
            {"Description": "Remove permissive rules; use private endpoints.",
             "AzureCLI": "az sql server firewall-rule delete -g <rg> -s <server> -n <rule>"},
        )]
    return []


def _check_sql_allow_azure_services(idx: dict) -> list[dict]:
    """Flag SQL servers with 'Allow Azure services' firewall rule (CIS 4.5)."""
    sqls = idx.get("azure-sql-server", [])
    flagged: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        for rule in data.get("FirewallRules", data.get("firewall_rules", [])):
            name = rule.get("Name", rule.get("name", "")).lower()
            start = rule.get("StartIpAddress", rule.get("start_ip_address", ""))
            end = rule.get("EndIpAddress", rule.get("end_ip_address", ""))
            if (name == "allowallazureips" or
                    (start == "0.0.0.0" and end == "0.0.0.0")):
                flagged.append({
                    "Type": "SQLServer",
                    "Name": data.get("Name", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "RuleName": rule.get("Name", rule.get("name", "")),
                })
                break
    if flagged:
        return [_ds_finding(
            "database", "sql_allow_azure_services",
            f"{len(flagged)} SQL servers allow access from all Azure services",
            "The 'Allow Azure services and resources to access this server' rule "
            "permits any Azure-hosted workload to connect, including from other tenants. "
            "This significantly expands the attack surface (CIS 4.5).",
            "high", flagged,
            {"Description": "Remove the AllowAllAzureIps rule; use private endpoints instead.",
             "AzureCLI": "az sql server firewall-rule delete -g <rg> -s <server> -n AllowAllAzureIps"},
        )]
    return []


def _check_sql_tde_key_source(idx: dict) -> list[dict]:
    """Flag SQL servers using service-managed TDE keys instead of CMK (MCSB 2.3)."""
    sqls = idx.get("azure-sql-server", [])
    svc_managed: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        key_source = data.get("TdeKeySource", data.get("tdeKeySource", ""))
        tde = data.get("TransparentDataEncryption", data.get("tde_enabled"))
        # Only flag if TDE is enabled but using service-managed keys
        if tde is not False and key_source and "servicemanaged" in str(key_source).lower():
            svc_managed.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "KeySource": str(key_source),
            })
    if svc_managed:
        return [_ds_finding(
            "database", "sql_tde_service_managed_key",
            f"{len(svc_managed)} SQL servers using service-managed TDE keys",
            "TDE with service-managed keys provides baseline encryption but does not give "
            "customer control over key lifecycle. Customer-managed keys (CMK) stored in "
            "Key Vault provide data sovereignty and key rotation control.",
            "medium", svc_managed,
            {"Description": "Configure TDE with customer-managed keys from Azure Key Vault.",
             "AzureCLI": (
                 "az sql server tde-key set -g <rg> -s <server> "
                 "--server-key-type AzureKeyVault --kid <key-vault-key-url>"
             )},
        )]
    return []


def _check_sql_public_access(idx: dict) -> list[dict]:
    """Flag SQL servers with public network access enabled."""
    sqls = idx.get("azure-sql-server", [])
    public: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        pna = data.get("publicNetworkAccess", data.get("PublicNetworkAccess", "")).lower()
        if pna == "enabled":
            public.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "database", "sql_public_access",
            f"{len(public)} SQL servers with public network access enabled",
            "SQL servers reachable from the public internet have a larger attack surface. "
            "Use private endpoints for all data-plane connectivity.",
            "high", public,
            {"Description": "Disable public network access and use private endpoints.",
             "AzureCLI": "az sql server update -g <rg> -n <server> --public-network-access Disabled"},
        )]
    return []


def _check_sql_ddm(idx: dict) -> list[dict]:
    """Flag SQL databases without Dynamic Data Masking on sensitive columns."""
    sqls = idx.get("azure-sql-server", [])
    no_ddm: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        databases = data.get("_databases", [])
        for db in databases:
            ddm_rules = db.get("DataMaskingRules", db.get("dataMaskingRules", []))
            rec_labels = db.get("RecommendedSensitivityLabels", [])
            # If there are sensitive columns recommended but no DDM rules
            if rec_labels and not ddm_rules:
                no_ddm.append({
                    "Type": "SQLDatabase",
                    "Name": f"{data.get('Name', data.get('name', 'Unknown'))}/{db.get('name', 'Unknown')}",
                    "ResourceId": db.get("id", ev.get("ResourceId", "")),
                    "SensitiveColumns": len(rec_labels),
                    "MaskingRules": 0,
                })
        # Also flag if DDM is explicitly disabled at server level
        ddm_enabled = data.get("DataMaskingEnabled", data.get("dataMaskingEnabled"))
        if ddm_enabled is False:
            no_ddm.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "Issue": "DDM explicitly disabled",
            })
    if no_ddm:
        return [_ds_finding(
            "database", "sql_no_ddm",
            f"{len(no_ddm)} SQL databases without Dynamic Data Masking on sensitive columns",
            "Dynamic Data Masking (DDM) obfuscates sensitive data in query results for "
            "non-privileged users without changing the underlying data. Databases with "
            "sensitive columns (PII, financial data) should use DDM to limit exposure.",
            "medium", no_ddm,
            {"Description": "Configure DDM rules for sensitive columns.",
             "AzureCLI": (
                 "az sql db update -g <rg> -s <server> -n <db> "
                 "--data-masking-rule column=<col> masking-function=Default"
             ),
             "PortalSteps": [
                 "Azure Portal > SQL Database > Dynamic Data Masking",
                 "Add masking rules for sensitive columns (SSN, email, credit card)",
                 "Choose masking function: Default, Email, Random, Custom text",
             ]},
        )]
    return []


def _check_sql_rls(idx: dict) -> list[dict]:
    """Flag SQL databases without Row-Level Security policies on multi-tenant tables."""
    sqls = idx.get("azure-sql-server", [])
    no_rls: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        databases = data.get("_databases", [])
        for db in databases:
            rls_policies = db.get("SecurityPolicies", db.get("securityPolicies", []))
            rls_enabled = db.get("RowLevelSecurityEnabled", db.get("rowLevelSecurityEnabled"))
            if rls_enabled is False:
                no_rls.append({
                    "Type": "SQLDatabase",
                    "Name": f"{data.get('Name', data.get('name', 'Unknown'))}/{db.get('name', 'Unknown')}",
                    "ResourceId": db.get("id", ev.get("ResourceId", "")),
                    "Issue": "RLS explicitly disabled",
                })
    if no_rls:
        return [_ds_finding(
            "database", "sql_no_rls",
            f"{len(no_rls)} SQL databases with Row-Level Security disabled",
            "Row-Level Security (RLS) filters rows returned by queries based on "
            "the executing user's identity. Multi-tenant databases without RLS "
            "risk cross-tenant data leakage.",
            "medium", no_rls,
            {"Description": "Implement RLS policies on multi-tenant or sensitive tables.",
             "PortalSteps": [
                 "Create a security predicate function that filters by user/tenant",
                 "CREATE SECURITY POLICY [FilterPolicy] ADD FILTER PREDICATE dbo.fn_securitypredicate(TenantId) ON dbo.Table",
                 "Test with different user contexts to verify row filtering",
             ]},
        )]
    return []


