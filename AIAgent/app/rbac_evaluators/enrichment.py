"""
RBAC — Compliance mapping, control details, and enrichment.

Maps RBAC finding subcategories to 11 compliance frameworks:
CIS, PCI-DSS (v4.0.1), HIPAA, NIST-800-53 (Rev 5), ISO-27001 (2022),
SOC2, NIST-CSF (2.0), MCSB (1.0), CSA-CCM (4.0), FedRAMP, GDPR.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# ── Subcategory → framework control IDs ──────────────────────────────────

_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    # ── Standing Owner / User Access Admin at high scope ─────────────────
    "standing_owner_high_scope": {
        "CIS": ["1.22", "1.23"],
        "PCI-DSS": ["7.1", "7.2.2"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(4)(ii)(C)"],
        "NIST-800-53": ["AC-2", "AC-6", "AC-6(1)", "AC-6(5)"],
        "ISO-27001": ["A.5.15", "A.5.18", "A.8.2"],
        "SOC2": ["CC6.1", "CC6.3"],
        "NIST-CSF": ["PR.AC-4", "PR.AC-6"],
        "MCSB": ["PA-1", "PA-2"],
        "CSA-CCM": ["IAM-04", "IAM-05", "IAM-09"],
        "FedRAMP": ["AC-2", "AC-6", "AC-6(5)"],
        "GDPR": ["Art.5(1f)", "Art.25(2)", "Art.32(1)"],
    },
    # ── Contributor at Management Group scope ────────────────────────────
    "contributor_mg_scope": {
        "CIS": ["1.22"],
        "PCI-DSS": ["7.1", "7.2.2"],
        "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["AC-6", "AC-6(1)"],
        "ISO-27001": ["A.5.15", "A.5.18"],
        "SOC2": ["CC6.1", "CC6.3"],
        "NIST-CSF": ["PR.AC-4"],
        "MCSB": ["PA-7"],
        "CSA-CCM": ["IAM-04", "IAM-05"],
        "FedRAMP": ["AC-6", "AC-6(1)"],
        "GDPR": ["Art.5(1f)", "Art.25(2)"],
    },
    # ── Service Principal with Owner role ────────────────────────────────
    "sp_with_owner": {
        "CIS": ["1.22", "1.23"],
        "PCI-DSS": ["7.1", "8.6"],
        "HIPAA": ["164.312(a)(1)", "164.312(d)"],
        "NIST-800-53": ["AC-6", "AC-6(5)", "IA-5"],
        "ISO-27001": ["A.5.15", "A.5.18", "A.8.2"],
        "SOC2": ["CC6.1", "CC6.3", "CC6.5"],
        "NIST-CSF": ["PR.AC-4", "PR.AC-7"],
        "MCSB": ["PA-1", "IM-3"],
        "CSA-CCM": ["IAM-04", "IAM-05", "IAM-09"],
        "FedRAMP": ["AC-6", "AC-6(5)", "IA-5"],
        "GDPR": ["Art.5(1f)", "Art.25(2)", "Art.32(1)"],
    },
    # ── Large group with privileged role ─────────────────────────────────
    "large_privileged_group": {
        "CIS": ["1.22"],
        "PCI-DSS": ["7.1", "7.2.2"],
        "HIPAA": ["164.312(a)(1)", "164.308(a)(3)(ii)(A)"],
        "NIST-800-53": ["AC-2", "AC-6", "AC-6(7)"],
        "ISO-27001": ["A.5.15", "A.5.18", "A.8.2"],
        "SOC2": ["CC6.1", "CC6.2", "CC6.3"],
        "NIST-CSF": ["PR.AC-4", "PR.AC-1"],
        "MCSB": ["PA-7", "GS-6"],
        "CSA-CCM": ["IAM-04", "IAM-06"],
        "FedRAMP": ["AC-2", "AC-6", "AC-6(7)"],
        "GDPR": ["Art.5(1f)", "Art.25(2)"],
    },
    # ── Custom role at high scope ────────────────────────────────────────
    "custom_role_high_scope": {
        "CIS": ["1.22", "1.24"],
        "PCI-DSS": ["7.1", "7.2.1"],
        "HIPAA": ["164.312(a)(1)"],
        "NIST-800-53": ["AC-3", "AC-6", "AC-6(2)"],
        "ISO-27001": ["A.5.15", "A.8.2"],
        "SOC2": ["CC6.1", "CC6.3"],
        "NIST-CSF": ["PR.AC-4"],
        "MCSB": ["PA-7"],
        "CSA-CCM": ["IAM-04", "IAM-10"],
        "FedRAMP": ["AC-3", "AC-6", "AC-6(2)"],
        "GDPR": ["Art.5(1f)", "Art.25(2)"],
    },
    # ── SP with Contributor at broad scope ───────────────────────────────
    "sp_contributor_broad_scope": {
        "CIS": ["1.22"],
        "PCI-DSS": ["7.1", "8.6"],
        "HIPAA": ["164.312(a)(1)", "164.312(d)"],
        "NIST-800-53": ["AC-6", "AC-6(1)", "IA-5"],
        "ISO-27001": ["A.5.15", "A.5.18"],
        "SOC2": ["CC6.1", "CC6.3", "CC6.5"],
        "NIST-CSF": ["PR.AC-4", "PR.AC-7"],
        "MCSB": ["PA-7", "IM-3"],
        "CSA-CCM": ["IAM-04", "IAM-05", "IAM-09"],
        "FedRAMP": ["AC-6", "AC-6(1)", "IA-5"],
        "GDPR": ["Art.5(1f)", "Art.25(2)"],
    },
}


# ── Control details — contextual info for each control ───────────────────

_CONTROL_DETAILS: dict[str, dict[str, str]] = {
    # ── CIS Azure Foundations Benchmark v2.0 ──────────────────────────────
    "CIS:1.22": {"title": "Ensure least privilege access", "rationale": "Excessive permissions expand the blast radius of compromised accounts.", "recommendation": "Review RBAC assignments and remove Owner/Contributor where not required."},
    "CIS:1.23": {"title": "Ensure custom roles are reviewed regularly", "rationale": "Custom Owner-equivalent roles bypass built-in guardrails.", "recommendation": "Audit custom roles monthly; replace with built-in roles where possible."},
    "CIS:1.24": {"title": "Ensure no subscription-level custom roles with broad actions", "rationale": "Custom roles with wildcard actions grant excessive permissions.", "recommendation": "Narrow action lists in custom role definitions to specific operations."},

    # ── PCI-DSS v4.0.1 ───────────────────────────────────────────────────
    "PCI-DSS:7.1":   {"title": "Restrict access by business need", "rationale": "Excessive access increases the risk of unauthorized data viewing or modification.", "recommendation": "Implement role-based access control with least privilege."},
    "PCI-DSS:7.2.1": {"title": "Access control model covers all components", "rationale": "Gaps in the access control model expose unprotected system components.", "recommendation": "Ensure every Azure resource scope has explicit role assignments."},
    "PCI-DSS:7.2.2": {"title": "Access is assigned based on job classification", "rationale": "Job-based access prevents privilege creep beyond role requirements.", "recommendation": "Map Azure roles to job functions and review quarterly."},
    "PCI-DSS:8.6":   {"title": "Use of system and service accounts managed", "rationale": "Unmanaged service accounts persist with standing access after personnel changes.", "recommendation": "Inventory all service principals and rotate credentials regularly."},

    # ── HIPAA Security Rule ──────────────────────────────────────────────
    "HIPAA:164.308(a)(3)(ii)(A)": {"title": "Authorization and/or Supervision", "rationale": "Workforce members must be authorized before accessing ePHI.", "recommendation": "Ensure group memberships reflect authorized access only."},
    "HIPAA:164.308(a)(4)(ii)(C)": {"title": "Access Establishment and Modification", "rationale": "Access provisioning and revocation must follow formal procedures.", "recommendation": "Use PIM for just-in-time access instead of standing assignments."},
    "HIPAA:164.312(a)(1)":        {"title": "Access Control", "rationale": "HIPAA requires technical policies to allow only authorized access to ePHI.", "recommendation": "Implement RBAC with least-privilege and conditional access."},
    "HIPAA:164.312(d)":           {"title": "Person or Entity Authentication", "rationale": "HIPAA requires verification of identity before granting access.", "recommendation": "Use Azure AD authentication with MFA for all service principals."},

    # ── NIST 800-53 Rev 5 ────────────────────────────────────────────────
    "NIST-800-53:AC-2":    {"title": "Account Management", "rationale": "Proper account management prevents orphaned and over-privileged accounts.", "recommendation": "Implement access reviews and automated de-provisioning."},
    "NIST-800-53:AC-3":    {"title": "Access Enforcement", "rationale": "Access enforcement ensures the principle of least privilege is applied.", "recommendation": "Use Azure RBAC with deny assignments where needed."},
    "NIST-800-53:AC-6":    {"title": "Least Privilege", "rationale": "Least privilege limits user access to only what is required for their job.", "recommendation": "Minimize Owner/Contributor assignments and use PIM for elevation."},
    "NIST-800-53:AC-6(1)": {"title": "Authorize Access to Security Functions", "rationale": "Security functions require explicit authorization beyond normal access.", "recommendation": "Restrict Owner and User Access Administrator to break-glass accounts."},
    "NIST-800-53:AC-6(2)": {"title": "Non-Privileged Access for Non-Security Functions", "rationale": "Users should use non-privileged accounts for non-security tasks.", "recommendation": "Separate privileged and non-privileged accounts."},
    "NIST-800-53:AC-6(5)": {"title": "Privileged Accounts", "rationale": "Privileged accounts must be restricted to specific personnel.", "recommendation": "Use PIM with time-bound activation and MFA for privileged roles."},
    "NIST-800-53:AC-6(7)": {"title": "Review of User Privileges", "rationale": "Regular review ensures privileges remain aligned with job requirements.", "recommendation": "Conduct quarterly access reviews via Entra Identity Governance."},
    "NIST-800-53:IA-5":    {"title": "Authenticator Management", "rationale": "Proper authenticator management prevents credential-based attacks.", "recommendation": "Rotate credentials, set expiry, and use managed identities."},

    # ── ISO 27001:2022 ───────────────────────────────────────────────────
    "ISO-27001:A.5.15": {"title": "Access control", "rationale": "Access control ensures only authorized individuals access information assets.", "recommendation": "Implement RBAC and Conditional Access policies."},
    "ISO-27001:A.5.18": {"title": "Access rights", "rationale": "Access rights must follow the principle of least privilege.", "recommendation": "Review role assignments regularly and minimize privileged access."},
    "ISO-27001:A.8.2":  {"title": "Privileged access rights", "rationale": "Privileged access must be restricted, monitored, and time-limited.", "recommendation": "Use PIM for all Owner and User Access Administrator roles."},

    # ── SOC 2 Type II ────────────────────────────────────────────────────
    "SOC2:CC6.1": {"title": "Logical Access Controls", "rationale": "Logical access controls restrict system access to authorized users.", "recommendation": "Implement RBAC, network rules, and conditional access."},
    "SOC2:CC6.2": {"title": "Role-Based Access", "rationale": "Role-based access ensures permissions are assigned by job function.", "recommendation": "Map Azure roles to job functions with periodic review."},
    "SOC2:CC6.3": {"title": "Access Modification and Revocation", "rationale": "Timely modification and revocation prevents unauthorized access persistence.", "recommendation": "Use PIM with automatic expiration for privileged roles."},
    "SOC2:CC6.5": {"title": "Service Account Management", "rationale": "Service accounts must be managed with the same rigor as user accounts.", "recommendation": "Inventory service principals and assign least-privilege roles."},

    # ── NIST CSF 2.0 ─────────────────────────────────────────────────────
    "NIST-CSF:PR.AC-1": {"title": "Identity and credential management", "rationale": "Proper identity management prevents unauthorized access.", "recommendation": "Use centralized identity management via Microsoft Entra ID."},
    "NIST-CSF:PR.AC-4": {"title": "Access permissions and authorizations", "rationale": "Permissions must incorporate least privilege and separation of duties.", "recommendation": "Use PIM and access reviews to enforce least privilege."},
    "NIST-CSF:PR.AC-6": {"title": "Remote access management", "rationale": "Remote access must be managed and monitored.", "recommendation": "Use Conditional Access policies to control remote access."},
    "NIST-CSF:PR.AC-7": {"title": "Machine identity management", "rationale": "Service principals and managed identities must be governed.", "recommendation": "Use managed identities and restrict SP permissions."},

    # ── MCSB 1.0 ─────────────────────────────────────────────────────────
    "MCSB:PA-1": {"title": "Protect and limit highly privileged users", "rationale": "Highly privileged accounts are the primary target for attackers.", "recommendation": "Limit permanent Owner/Global Admin to ≤5 accounts; use PIM."},
    "MCSB:PA-2": {"title": "Restrict administrative access to business-critical systems", "rationale": "Admin access to critical systems must be tightly controlled.", "recommendation": "Use PIM with MFA and justification for critical scope access."},
    "MCSB:PA-7": {"title": "Follow just enough administration principle", "rationale": "Excessive permissions expand the attack surface.", "recommendation": "Use custom roles scoped to specific actions and resources."},
    "MCSB:GS-6": {"title": "Review and update governance and security strategy", "rationale": "Strategy must be reviewed to adapt to evolving threats.", "recommendation": "Regular review of RBAC assignments and group memberships."},
    "MCSB:IM-3": {"title": "Use managed identities for Azure resources", "rationale": "Managed identities eliminate credential management overhead.", "recommendation": "Replace service principal secrets with managed identities."},

    # ── CSA-CCM 4.0 ──────────────────────────────────────────────────────
    "CSA-CCM:IAM-04": {"title": "Separation of Duties", "rationale": "SoD prevents single actors from having conflicting privileges.", "recommendation": "Separate Owner from Contributor; use PIM for elevation."},
    "CSA-CCM:IAM-05": {"title": "Least Privilege", "rationale": "Least privilege minimizes damage from compromised accounts.", "recommendation": "Assign minimum required roles at the narrowest scope."},
    "CSA-CCM:IAM-06": {"title": "User Access Provisioning", "rationale": "Access must be provisioned through formal processes.", "recommendation": "Use Entra Identity Governance and access packages."},
    "CSA-CCM:IAM-09": {"title": "Privileged Access Management", "rationale": "Privileged accounts require enhanced controls.", "recommendation": "Enforce PIM with time-bound activation, MFA, and approval workflows."},
    "CSA-CCM:IAM-10": {"title": "Management of Privileged Access Rights", "rationale": "Privileged access rights must be regularly reviewed and certified.", "recommendation": "Conduct quarterly privileged access reviews."},

    # ── FedRAMP ──────────────────────────────────────────────────────────
    "FedRAMP:AC-2":    {"title": "Account Management", "rationale": "FedRAMP requires formal account management processes.", "recommendation": "Implement automated provisioning and de-provisioning."},
    "FedRAMP:AC-3":    {"title": "Access Enforcement", "rationale": "FedRAMP requires technical enforcement of access control policies.", "recommendation": "Use Azure RBAC and Conditional Access."},
    "FedRAMP:AC-6":    {"title": "Least Privilege", "rationale": "FedRAMP requires least privilege for all account types.", "recommendation": "Minimize standing privileged assignments."},
    "FedRAMP:AC-6(1)": {"title": "Authorize Access to Security Functions", "rationale": "Security functions require explicit authorization.", "recommendation": "Limit Owner role to break-glass accounts only."},
    "FedRAMP:AC-6(2)": {"title": "Non-Privileged Access for Non-Security Functions", "rationale": "Non-security functions must use non-privileged accounts.", "recommendation": "Separate admin and user accounts."},
    "FedRAMP:AC-6(5)": {"title": "Privileged Accounts", "rationale": "Privileged accounts must be restricted and time-limited.", "recommendation": "Use PIM with time-bound activation."},
    "FedRAMP:AC-6(7)": {"title": "Review of User Privileges", "rationale": "Regular review prevents privilege accumulation.", "recommendation": "Conduct quarterly access reviews."},
    "FedRAMP:IA-5":    {"title": "Authenticator Management", "rationale": "FedRAMP requires strong credential management.", "recommendation": "Rotate credentials and use managed identities."},

    # ── GDPR ─────────────────────────────────────────────────────────────
    "GDPR:Art.5(1f)":  {"title": "Integrity and confidentiality", "rationale": "Personal data must be processed with appropriate security measures.", "recommendation": "Enforce least privilege and access controls on all data scopes."},
    "GDPR:Art.25(2)":  {"title": "Data protection by default", "rationale": "Only data necessary for specific purposes should be accessible.", "recommendation": "Restrict access to the minimum required for each role."},
    "GDPR:Art.32(1)":  {"title": "Security of processing", "rationale": "Appropriate technical measures must protect personal data.", "recommendation": "Implement PIM, access reviews, and strong authentication."},
}


# ── Public enrichment function ───────────────────────────────────────────

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
