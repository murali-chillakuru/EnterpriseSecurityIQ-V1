# EnterpriseSecurityIQ Compliance Assessment Report

**Generated:** 2025-01-15T11:00:00Z
**Tenant ID:** 00000000-0000-0000-0000-000000000000
**Assessment ID:** sample-assessment

## 1. Assessment Scope

| Item | Value |
| --- | --- |
| Frameworks Evaluated | mcsb, nist-800-53 |
| Total Controls | 24 |
| Evidence Records | 42 |
| Assessment Mode | Read-Only (Control Plane) |

## 2. Methodology

This assessment was performed using EnterpriseSecurityIQ, which collects evidence from Azure Resource Manager
and Microsoft Graph APIs using **read-only** operations. Findings are mapped to compliance framework controls
and evaluated against collected evidence. No tenant resources were created, modified, or deleted.

> **Important:** This assessment evaluates control-plane configurations only. Data-plane analysis,
> penetration testing, and manual procedure verification are outside scope and should be performed separately.

## 3. Executive Summary

| Metric | Count |
| --- | --- |
| Compliant | 14 |
| Non-Compliant | 5 |
| Missing Evidence | 3 |
| Not Assessed | 2 |

**Overall Compliance Rate:** 58.3% (14 of 24 controls)

### Non-Compliant Findings by Severity

| Severity | Count |
| --- | --- |
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 1 |

## 4. Framework Summaries

### MCSB

| Status | Count |
| --- | --- |
| Compliant | 7 |
| Non-Compliant | 3 |
| Missing Evidence | 1 |
| Not Assessed | 1 |

Compliance Rate: **58.3%**

### NIST-800-53

| Status | Count |
| --- | --- |
| Compliant | 7 |
| Non-Compliant | 2 |
| Missing Evidence | 2 |
| Not Assessed | 1 |

Compliance Rate: **58.3%**

## 5. Domain Summaries

### Access

| Status | Count |
| --- | --- |
| Compliant | 3 |
| Non-Compliant | 1 |
| Missing Evidence | 0 |
| Not Assessed | 0 |

### Identity

| Status | Count |
| --- | --- |
| Compliant | 4 |
| Non-Compliant | 2 |
| Missing Evidence | 1 |
| Not Assessed | 0 |

### Logging

| Status | Count |
| --- | --- |
| Compliant | 2 |
| Non-Compliant | 1 |
| Missing Evidence | 1 |
| Not Assessed | 1 |

## 6. Critical and High Severity Findings

### [CRITICAL] MCSB-IM-1 - Use centralized identity system

- **Framework:** mcsb
- **Domain:** Identity
- **Status:** non_compliant
- **Description:** External identity providers detected without conditional access federation controls.
- **Rationale:** A centralized identity system reduces fragmentation and authentication bypass risks.
- **Recommendation:** Consolidate identity to Microsoft Entra ID and enforce CA policies for federated access.

### [HIGH] MCSB-PA-1 - Separate privileged access

- **Framework:** mcsb
- **Domain:** Access
- **Status:** non_compliant
- **Description:** 3 users with Owner role at subscription scope. Privileged/non-privileged separation not enforced.
- **Rationale:** Separating privileged accounts limits blast radius of compromised credentials.
- **Recommendation:** Use PIM for just-in-time privileged access and dedicated admin accounts.

### [HIGH] NIST-AC-6 - Least privilege

- **Framework:** nist-800-53
- **Domain:** Access
- **Status:** non_compliant
- **Description:** 5 Owner-level role assignments found. Review for least privilege compliance.
- **Rationale:** Least privilege minimizes potential damage from compromised or misused accounts.
- **Recommendation:** Replace Owner assignments with scoped, purpose-specific roles.

## 7. All Findings

| Control ID | Framework | Title | Status | Severity | Domain |
| --- | --- | --- | --- | --- | --- |
| MCSB-IM-1 | mcsb | Use centralized identity system | non_compliant | critical | Identity |
| MCSB-IM-4 | mcsb | Enable MFA for all users | compliant | critical | Identity |
| MCSB-PA-1 | mcsb | Separate privileged access | non_compliant | high | Access |
| MCSB-LT-1 | mcsb | Enable logging | compliant | high | Logging |
| MCSB-NS-1 | mcsb | Network segmentation | compliant | medium | Network |
| NIST-IA-2 | nist-800-53 | User authentication | compliant | critical | Identity |
| NIST-AC-6 | nist-800-53 | Least privilege | non_compliant | high | Access |
| NIST-AU-6 | nist-800-53 | Audit review | compliant | medium | Logging |

## 8. Evidence Summary

| Evidence Type | Count |
| --- | --- |
| azure-diagnostic-setting | 8 |
| azure-policy-assignment | 5 |
| azure-rbac-assignment | 7 |
| azure-resource | 12 |
| entra-conditional-access-policy | 4 |
| entra-directory-role | 6 |

## 9. Missing Evidence

| Control ID | Framework | Required Evidence | Reason |
| --- | --- | --- | --- |
| MCSB-GS-2 | mcsb | azure-policy-assignment | No approved services policy detected |
| NIST-SI-2 | nist-800-53 | azure-policy-assignment | No vulnerability scanning policies collected |
| NIST-SC-13 | nist-800-53 | azure-policy-assignment | No CMK enforcement evidence |

## 10. Prioritized Recommendations

1. **[CRITICAL] MCSB-IM-1** - Consolidate identity to Microsoft Entra ID and enforce CA policies for federated access.
2. **[HIGH] MCSB-PA-1** - Use PIM for just-in-time privileged access and dedicated admin accounts.
3. **[HIGH] NIST-AC-6** - Replace Owner assignments with scoped, purpose-specific roles.
4. **[MEDIUM] MCSB-NS-2** - Ensure all subnets have associated NSGs.
5. **[LOW] NIST-CM-8** - Improve resource tagging for complete asset inventory.

## 11. Appendix

### Assessment Details

- **Tool:** EnterpriseSecurityIQ
- **Version:** 1.0.0
- **Collection Method:** Azure Resource Manager + Microsoft Graph (read-only)
- **Frameworks:** mcsb, nist-800-53

### Limitations

- This assessment covers **control-plane** configurations only.
- Data-plane settings (e.g., TLS versions, storage access keys) require separate verification.
- Conditional Access policy effectiveness depends on user/group assignment scope.
- PIM role assignments reflect point-in-time state; activated roles may vary.
- NSG flow logs and detailed network traffic analysis are outside scope.

---
*Report generated by EnterpriseSecurityIQ. This report is informational and does not constitute a formal audit.*
