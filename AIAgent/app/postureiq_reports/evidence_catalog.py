"""
Evidence Type Catalog — Missing Evidence Metadata
Provides human-readable descriptions, categories, and resolution guidance
for each evidence type that may appear as "missing" in compliance reports.
"""

from __future__ import annotations

# Categories for missing evidence classification
CATEGORY_LICENSE = "License / Feature Required"
CATEGORY_RESOURCE = "Resource Not Deployed"
CATEGORY_CONFIG = "Feature Not Configured"
CATEGORY_PERMISSION = "Insufficient Permissions"
CATEGORY_API = "API / Collector Issue"

EVIDENCE_CATALOG: dict[str, dict[str, str]] = {
    # ── Entra ID — PIM ──────────────────────────────────────────
    "entra-pim-eligible-assignment": {
        "display_name": "PIM Eligible Role Assignments",
        "source": "Entra ID",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "No PIM eligible role assignments were returned from Microsoft Graph. "
            "This typically means Privileged Identity Management (PIM) has not been "
            "onboarded in the tenant. If the tenant has Entra ID P2 licenses "
            "(standalone or via M365 E5 / EMS E5), PIM is available but requires "
            "a one-time activation. All privileged roles are currently standing "
            "(permanent) assignments with no just-in-time activation workflow."
        ),
        "resolution": (
            "1. Open Entra admin center → Identity Governance → Privileged Identity Management.\n"
            "2. Click 'Consent to PIM' if prompted (first-time onboarding).\n"
            "3. Convert standing Global Admin and other privileged role assignments to PIM-eligible.\n"
            "4. Configure activation rules: require MFA, set max duration (e.g. 8 hours), require justification."
        ),
    },
    "entra-pim-policy-rule": {
        "display_name": "PIM Policy Rules (Activation Settings)",
        "source": "Entra ID",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "PIM policy rules (activation duration, MFA requirements) could not be collected. "
            "The PIM service provider returned a 'MissingProvider' error, confirming PIM "
            "has not been onboarded. Once PIM is activated, role management policies are "
            "automatically created for each directory role."
        ),
        "resolution": (
            "1. Onboard PIM in Entra admin center → Identity Governance → Privileged Identity Management.\n"
            "2. Open PIM → Entra Roles → Settings and configure activation rules for each role.\n"
            "3. Set MFA on activation, maximum activation duration, and justification requirements."
        ),
    },
    "entra-pim-policy": {
        "display_name": "PIM Policies",
        "source": "Entra ID",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "PIM role management policies were not found. PIM has not been onboarded "
            "in this tenant. If Entra ID P2 is licensed (standalone or via M365 E5 / EMS E5), "
            "PIM is available but requires one-time activation by a Global Administrator."
        ),
        "resolution": (
            "1. Navigate to Entra admin center → Privileged Identity Management.\n"
            "2. Click 'Consent to PIM' to complete the one-time onboarding.\n"
            "3. Configure role settings (activation rules, approvals) for each directory role."
        ),
    },

    # ── Entra ID — Identity Protection ──────────────────────────
    "entra-risky-user": {
        "display_name": "Risky Users (Identity Protection)",
        "source": "Entra ID",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "No risky user data was returned from the Identity Protection API. "
            "If the tenant has Entra ID P2 (via M365 E5 / EMS E5), Identity Protection "
            "is available but the sign-in risk and user risk policies may not be enabled, "
            "or there are genuinely no risky users detected (which is a positive finding)."
        ),
        "resolution": (
            "1. Open Entra admin center → Protection → Identity Protection.\n"
            "2. Enable the Sign-in risk policy (e.g. block high risk, require MFA for medium).\n"
            "3. Enable the User risk policy (e.g. require password change for high risk).\n"
            "4. If no risky users appear in the portal, the API result is accurate (no risk detected)."
        ),
    },
    "entra-risk-detection": {
        "display_name": "Risk Detections (Identity Protection)",
        "source": "Entra ID",
        "category": CATEGORY_LICENSE,
        "explanation": (
            "No risk detection events were returned. Identity Protection may not be actively "
            "monitoring sign-ins, or no risks have been detected recently."
        ),
        "resolution": (
            "1. Verify Entra ID P2 license is active.\n"
            "2. Enable sign-in risk and user risk policies in Identity Protection.\n"
            "3. Check Entra admin center → Protection → Identity Protection → Risk detections.\n"
            "4. If the portal shows no detections, the result is accurate."
        ),
    },
    "entra-risky-service-principal": {
        "display_name": "Risky Service Principals",
        "source": "Entra ID",
        "category": CATEGORY_LICENSE,
        "explanation": (
            "No risky service principal data was returned. This requires Workload Identity Premium license."
        ),
        "resolution": (
            "1. Verify Workload Identity Premium license is available.\n"
            "2. Check Entra admin center → Protection → Identity Protection → Risky workload identities."
        ),
    },

    # ── Azure — Defender for Cloud ──────────────────────────────
    "azure-defender-pricing": {
        "display_name": "Microsoft Defender for Cloud Plans",
        "source": "Azure",
        "category": CATEGORY_API,
        "explanation": (
            "Defender for Cloud pricing plans could not be retrieved. The API call failed "
            "with a missing 'scope_id' parameter, indicating an SDK compatibility issue "
            "with the current Azure Security Center client version."
        ),
        "resolution": (
            "1. This is a known collector issue — the Azure SDK requires a scope_id parameter.\n"
            "2. As a workaround, check Defender plans manually: Azure Portal → Microsoft Defender for Cloud → Environment Settings.\n"
            "3. Ensure Defender plans (Servers, App Service, SQL, Storage, etc.) are enabled.\n"
            "4. A collector fix is pending for the next release."
        ),
    },
    "azure-auto-provisioning": {
        "display_name": "Defender Auto-Provisioning Settings",
        "source": "Azure",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "Auto-provisioning settings could not be retrieved. This may be due to Defender for Cloud "
            "not being configured, or the API returning an error."
        ),
        "resolution": (
            "1. Open Azure Portal → Microsoft Defender for Cloud → Environment Settings.\n"
            "2. Select your subscription → Settings & Monitoring.\n"
            "3. Enable Log Analytics agent or Azure Monitor agent auto-provisioning."
        ),
    },
    "azure-security-contact": {
        "display_name": "Defender Security Contact",
        "source": "Azure",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "No security contact configuration was found for Defender for Cloud. "
            "Email notifications for security alerts may not be configured."
        ),
        "resolution": (
            "1. Azure Portal → Microsoft Defender for Cloud → Environment Settings.\n"
            "2. Select subscription → Email notifications.\n"
            "3. Add security contact email(s) and enable notifications for high-severity alerts."
        ),
    },

    # ── Azure — Network ─────────────────────────────────────────
    "azure-firewall": {
        "display_name": "Azure Firewall",
        "source": "Azure",
        "category": CATEGORY_RESOURCE,
        "explanation": (
            "No Azure Firewall resources were found in the subscriptions scanned. "
            "This does not necessarily indicate non-compliance — the environment may use "
            "NSGs, NVAs, or third-party firewalls instead."
        ),
        "resolution": (
            "1. If Azure Firewall is required by your compliance framework, deploy one in a hub VNet.\n"
            "2. If using alternative firewall solutions (NSGs, Palo Alto, Fortinet), "
            "document this as a compensating control.\n"
            "3. No action needed if network security is enforced via other means."
        ),
    },

    # ── Azure — Compute / Data ──────────────────────────────────
    "azure-sql-server": {
        "display_name": "Azure SQL Servers",
        "source": "Azure",
        "category": CATEGORY_RESOURCE,
        "explanation": (
            "No Azure SQL Server resources were found. If the environment does not use "
            "Azure SQL Database, this evidence type is not applicable."
        ),
        "resolution": (
            "1. If Azure SQL is not in use, this can be classified as 'Not Applicable'.\n"
            "2. If Azure SQL is expected, verify the scanning account has Reader access to "
            "the subscriptions containing SQL resources.\n"
            "3. Check for SQL Managed Instances or other database services that may be in use."
        ),
    },
    "azure-aks-cluster": {
        "display_name": "Azure Kubernetes Service (AKS) Clusters",
        "source": "Azure",
        "category": CATEGORY_RESOURCE,
        "explanation": (
            "No AKS clusters were found in the subscriptions scanned. If the environment "
            "does not use Kubernetes, this evidence type is not applicable."
        ),
        "resolution": (
            "1. If AKS is not in use, this can be classified as 'Not Applicable'.\n"
            "2. If AKS clusters are expected, verify the scanning account has Reader access.\n"
            "3. Check if containerized workloads use Azure Container Apps or other services instead."
        ),
    },

    # ── Azure — Monitoring ──────────────────────────────────────
    "azure-alert-rule": {
        "display_name": "Azure Monitor Alert Rules",
        "source": "Azure",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "No Azure Monitor alert rules were found. This means real-time alerting for "
            "security events, resource health, and performance anomalies is not configured."
        ),
        "resolution": (
            "1. Azure Portal → Monitor → Alerts → Create alert rule.\n"
            "2. Configure alerts for: failed sign-ins, resource deletions, security events.\n"
            "3. Set up action groups with email/SMS/webhook notifications.\n"
            "4. Consider using Azure Monitor Baseline Alerts (AMBA) for quick setup."
        ),
    },
    "azure-action-group": {
        "display_name": "Azure Monitor Action Groups",
        "source": "Azure",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "No Azure Monitor action groups were found. Action groups define notification "
            "targets (email, SMS, webhook) for alert rules."
        ),
        "resolution": (
            "1. Azure Portal → Monitor → Alerts → Action groups → Create.\n"
            "2. Add notification channels (email, SMS, Logic App, webhook).\n"
            "3. Link action groups to your alert rules."
        ),
    },
    "azure-log-analytics": {
        "display_name": "Azure Log Analytics Workspaces",
        "source": "Azure",
        "category": CATEGORY_RESOURCE,
        "explanation": (
            "No Log Analytics workspaces were found. Centralized logging is a key compliance "
            "requirement for audit trails and security monitoring."
        ),
        "resolution": (
            "1. Create a Log Analytics workspace in Azure Portal → Log Analytics workspaces.\n"
            "2. Configure diagnostic settings on key resources to send logs to the workspace.\n"
            "3. Enable Microsoft Sentinel if advanced SIEM capabilities are needed."
        ),
    },

    # ── Entra ID — Governance ───────────────────────────────────
    "entra-access-review": {
        "display_name": "Entra Access Reviews",
        "source": "Entra ID",
        "category": CATEGORY_CONFIG,
        "explanation": (
            "No access reviews were found. Access reviews ensure periodic re-certification "
            "of user access to resources and roles."
        ),
        "resolution": (
            "1. Entra admin center → Identity Governance → Access reviews → New access review.\n"
            "2. Configure reviews for privileged directory roles (at minimum).\n"
            "3. Set review frequency (quarterly recommended) and auto-apply results."
        ),
    },
}


def get_evidence_metadata(evidence_type: str) -> dict[str, str]:
    """
    Return metadata for a given evidence type.
    Falls back to a generic entry if the type is not in the catalog.
    """
    if evidence_type in EVIDENCE_CATALOG:
        return EVIDENCE_CATALOG[evidence_type]
    # Generic fallback
    source = "Entra ID" if evidence_type.startswith("entra-") else "Azure"
    return {
        "display_name": evidence_type.replace("-", " ").title(),
        "source": source,
        "category": CATEGORY_CONFIG,
        "explanation": (
            f"No data was collected for evidence type '{evidence_type}'. "
            "The collector may have returned empty results due to the resource or feature "
            "not being present in the environment."
        ),
        "resolution": (
            f"1. Verify that the feature or resource related to '{evidence_type}' "
            "exists in your environment.\n"
            "2. Check that the scanning account has sufficient permissions.\n"
            "3. Review collector logs for any errors during data collection."
        ),
    }


def enrich_missing_evidence(missing_items: list[dict]) -> list[dict]:
    """
    Enrich the raw missing evidence list with human-readable metadata.
    Each item gets additional fields: DisplayName, Source, Category,
    Explanation, Resolution, and a per-type breakdown.
    """
    enriched = []
    for item in missing_items:
        m = dict(item)  # shallow copy
        types_detail = []
        categories = set()
        for etype in item.get("MissingTypes", []):
            meta = get_evidence_metadata(etype)
            types_detail.append({
                "EvidenceType": etype,
                "DisplayName": meta["display_name"],
                "Source": meta["source"],
                "Category": meta["category"],
                "Explanation": meta["explanation"],
                "Resolution": meta["resolution"],
            })
            categories.add(meta["category"])

        m["TypesDetail"] = types_detail
        m["Categories"] = sorted(categories)
        # Primary category (pick the most impactful)
        category_priority = [
            CATEGORY_API, CATEGORY_LICENSE, CATEGORY_PERMISSION,
            CATEGORY_CONFIG, CATEGORY_RESOURCE,
        ]
        m["PrimaryCategory"] = next(
            (c for c in category_priority if c in categories),
            CATEGORY_CONFIG,
        )
        enriched.append(m)
    return enriched
