"""Sensitivity label coverage evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


def analyze_label_coverage(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess sensitivity label readiness for M365 Copilot."""
    # Guard: if the label collector couldn't reach any label API, we cannot
    # distinguish "no labels defined" from "API inaccessible".  Return a
    # single "unable to assess" finding instead of false positives.
    warnings = evidence_index.get("m365-label-collection-warning", [])
    if warnings:
        w_data = warnings[0].get("Data", warnings[0].get("data", {}))
        return [_cr_finding(
            "label_coverage", "label_api_inaccessible",
            "Sensitivity label coverage could not be assessed — label API inaccessible",
            w_data.get("Impact", "Cannot determine whether sensitivity labels are defined."),
            "high",
            [{"Type": "LabelAPI", "Name": "Sensitivity Labels API",
              "ResourceId": "m365-label-api-warning",
              "Warning": w_data.get("Warning", "LabelAPIInaccessible")}],
            {"Description": w_data.get("Recommendation",
                "Assign the Information Protection Reader role or ensure "
                "the tenant has an E5 / Information Protection P2 license."),
             "PortalSteps": [
                 "Go to Entra admin center > Roles & administrators",
                 "Assign 'Information Protection Reader' to the assessment user/service principal",
                 "Alternatively, verify E5 or Information Protection P2 licensing",
                 "Re-run the Copilot Readiness assessment",
             ]},
            compliance_status="gap",
        )]

    findings: list[dict] = []
    findings.extend(_check_label_definitions(evidence_index))
    findings.extend(_check_mandatory_labeling(evidence_index))
    findings.extend(_check_auto_labeling(evidence_index))
    findings.extend(_check_site_label_coverage(evidence_index))
    findings.extend(_check_default_label(evidence_index))
    findings.extend(_check_mandatory_labeling_scope(evidence_index))
    findings.extend(_check_label_encryption_gaps(evidence_index))
    return findings


def _check_label_definitions(idx: dict) -> list[dict]:
    """Check if sensitivity labels are defined."""
    summary = idx.get("m365-label-summary", [])
    for ev in summary:
        data = ev.get("Data", ev.get("data", {}))
        total = data.get("TotalLabels", 0)
        if total == 0:
            return [_cr_finding(
                "label_coverage", "no_labels_defined",
                "No sensitivity labels defined — critical Copilot prerequisite missing",
                "Sensitivity labels are essential for M365 Copilot governance. Without labels, "
                "there is no mechanism to control how Copilot handles sensitive content.",
                "critical",
                [{"Type": "LabelConfig", "Name": "Sensitivity Labels",
                  "ResourceId": "m365-label-summary", "TotalLabels": 0}],
                {"Description": "Define sensitivity labels in Microsoft Purview Compliance Center.",
                 "PortalSteps": ["Go to Microsoft Purview compliance portal > Information protection > Labels", "Click '+ Create a label' to create your label taxonomy", "Create at minimum: Public, Internal, Confidential, Highly Confidential", "Publish labels via label policies"]},
                compliance_status="gap",
            )]
        elif total < 3:
            return [_cr_finding(
                "label_coverage", "insufficient_labels",
                f"Only {total} sensitivity labels defined — may be insufficient for Copilot governance",
                "A mature label taxonomy typically includes at least Public, Internal, Confidential, "
                "and Highly Confidential levels for effective Copilot data governance.",
                "medium",
                [{"Type": "LabelConfig", "Name": "Sensitivity Labels",
                  "ResourceId": "m365-label-summary", "TotalLabels": total}],
                {"Description": "Expand label taxonomy to cover all sensitivity tiers.",
                 "PortalSteps": ["Go to Microsoft Purview compliance portal > Information protection > Labels", "Review existing labels for gaps in sensitivity coverage", "Add sub-labels (e.g., Confidential\\Anyone, Confidential\\Recipients Only)", "Publish updated labels via label policies"]},
                compliance_status="partial",
            )]
    return []


def _check_mandatory_labeling(idx: dict) -> list[dict]:
    """Check if mandatory labeling is enforced."""
    policy = idx.get("m365-label-policy-summary", [])
    for ev in policy:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasMandatoryLabeling"):
            return [_cr_finding(
                "label_coverage", "no_mandatory_labeling",
                "Mandatory labeling is not enforced — Copilot may process unlabeled content",
                "Without mandatory labeling, users can create and share content without "
                "classification. Copilot will process this unlabeled content without "
                "sensitivity-aware guardrails.",
                "high",
                [{"Type": "LabelPolicy", "Name": "Mandatory Labeling",
                  "ResourceId": "m365-label-policy", "HasMandatoryLabeling": False}],
                {"Description": "Enable mandatory labeling in label policies for all M365 apps.",
                 "PowerShell": "Set-LabelPolicy -Identity <PolicyName> -AdvancedSettings @{MandatoryLabeling='true'}",
                 "PortalSteps": ["Go to Microsoft Purview compliance portal > Information protection > Label policies", "Edit your label policy > Policy settings", "Enable 'Require users to apply a label to their emails and documents'", "Save and publish changes"]},
                compliance_status="gap",
            )]
    return []


def _check_auto_labeling(idx: dict) -> list[dict]:
    """Check if auto-labeling is configured for sensitive content."""
    policy = idx.get("m365-label-policy-summary", [])
    for ev in policy:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasAutoLabeling"):
            return [_cr_finding(
                "label_coverage", "no_auto_labeling",
                "Auto-labeling is not configured — existing content may remain unclassified",
                "Auto-labeling automatically classifies content containing sensitive information "
                "(PII, financial data, etc.). Without it, existing content accessed by Copilot "
                "may lack appropriate labels.",
                "medium",
                [{"Type": "LabelPolicy", "Name": "Auto-Labeling",
                  "ResourceId": "m365-label-policy", "HasAutoLabeling": False}],
                {"Description": "Configure auto-labeling policies for sensitive information types.",
                 "PortalSteps": ["Go to Microsoft Purview compliance portal > Information protection > Auto-labeling", "Click '+ Create auto-labeling policy'", "Select sensitive information types (PII, financial, health)", "Choose target locations (Exchange, SharePoint, OneDrive)", "Map each SIT to the appropriate sensitivity label", "Run in simulation mode first, then enable"]},
                compliance_status="gap",
            )]
    return []


def _check_site_label_coverage(idx: dict) -> list[dict]:
    """Check sensitivity label coverage on SharePoint sites."""
    summary = idx.get("spo-label-summary", [])
    for ev in summary:
        data = ev.get("Data", ev.get("data", {}))
        coverage = data.get("LabelCoverage", 0)
        unlabeled = data.get("UnlabeledSites", 0)
        if coverage < 80 and unlabeled > 0:
            sev = "high" if coverage < 50 else "medium"
            return [_cr_finding(
                "label_coverage", "low_site_label_coverage",
                f"SharePoint site label coverage is {coverage}% — {unlabeled} sites unlabeled",
                "Copilot indexes SharePoint content. Sites without sensitivity labels "
                "cannot enforce label-based protections on Copilot interactions.",
                sev,
                [{"Type": "SPOLabelCoverage", "Name": "Site Labels",
                  "ResourceId": "spo-label-summary",
                  "Coverage": f"{coverage}%", "UnlabeledSites": unlabeled}],
                {"Description": "Apply sensitivity labels to all SharePoint sites.",
             "PowerShell": "Set-SPOSite -Identity <SiteUrl> -SensitivityLabel <LabelId>",
             "PortalSteps": ["Go to SharePoint admin center > Sites > Active sites", "Select each unlabeled site > Settings (gear icon)", "Under 'Sensitivity', choose the appropriate label", "Repeat for all unlabeled sites"]},
                compliance_status="partial" if coverage > 0 else "gap",
            )]
    return []


def _check_default_label(idx: dict) -> list[dict]:
    """Check if a default sensitivity label is configured in label policies."""
    policy = idx.get("m365-label-policy-summary", [])
    for ev in policy:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasDefaultLabel"):
            return [_cr_finding(
                "label_coverage", "no_default_label",
                "No default sensitivity label configured — new content will be unlabeled",
                "Without a default label, newly created documents and emails start without "
                "any classification. Copilot will process this unlabeled content without "
                "sensitivity-aware protections until a user manually labels it.",
                "medium",
                [{"Type": "LabelPolicy", "Name": "Default Label",
                  "ResourceId": "m365-label-policy", "HasDefaultLabel": False}],
                {"Description": "Set a default sensitivity label (e.g., 'Internal') in label policies.",
                 "PowerShell": "Set-LabelPolicy -Identity <PolicyName> -AdvancedSettings @{DefaultLabelId='<LabelId>'}",
                 "PortalSteps": [
                     "Go to Microsoft Purview compliance portal > Information protection > Label policies",
                     "Edit your label policy > Default settings",
                     "Set 'Apply this label by default to documents' to an appropriate label",
                     "Set 'Apply this label by default to emails' similarly",
                     "Save and publish",
                 ]},
                compliance_status="gap",
            )]
    return []


def _check_mandatory_labeling_scope(idx: dict) -> list[dict]:
    """Check if mandatory labeling is enforced across all M365 workloads."""
    policies = idx.get("m365-label-policy-summary", [])
    if not policies:
        return []  # _check_mandatory_labeling already flags missing policy
    for ev in policies:
        data = ev.get("Data", ev.get("data", {}))
        mandatory = data.get("MandatoryLabeling", False) or data.get("IsMandatory", False)
        if not mandatory:
            continue
        workloads = data.get("MandatoryLabelingWorkloads", [])
        if isinstance(workloads, list) and workloads:
            missing: list[str] = []
            required = ["Word", "Excel", "PowerPoint", "Outlook", "Teams", "SharePoint"]
            for wl in required:
                if not any(wl.lower() in str(w).lower() for w in workloads):
                    missing.append(wl)
            if missing:
                return [_cr_finding(
                    "label_coverage", "mandatory_labeling_incomplete_scope",
                    f"Mandatory labeling not enforced for {', '.join(missing)} — partial protection",
                    "Mandatory labeling is enabled but does not cover all M365 workloads. "
                    "Unlabeled content in uncovered workloads can be surfaced by Copilot "
                    "without sensitivity context or DLP protection.",
                    "medium",
                    [{"Type": "LabelPolicy", "Name": "Mandatory Labeling Scope",
                      "ResourceId": "m365-label-policy",
                      "MissingWorkloads": missing,
                      "CoveredWorkloads": workloads}],
                    {"Description": "Extend mandatory labeling to all Office workloads.",
                     "PortalSteps": [
                         "Go to Microsoft Purview > Information protection > Label policies",
                         "Edit the label policy with mandatory labeling",
                         "Under 'Policy settings', expand workload coverage",
                         "Enable for: Word, Excel, PowerPoint, Outlook, Teams, SharePoint",
                     ]},
                    compliance_status="partial",
                )]
    return []


def _check_label_encryption_gaps(idx: dict) -> list[dict]:
    """Check for sensitivity labels missing encryption or site/group settings.

    Labels with encryption enforce access control at content level — Copilot
    honors these rights and only surfaces encrypted content to users with
    decryption rights.  Labels with site/group settings protect containers
    (SharePoint sites, Teams, M365 Groups) by controlling privacy, external
    sharing, and guest access at the container level.
    """
    labels = idx.get("m365-sensitivity-label-definition", [])
    if not labels:
        return []

    active_labels: list[dict] = []
    for ev in labels:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsActive", True):
            active_labels.append(data)

    if not active_labels:
        return []

    findings: list[dict] = []

    # Check labels without encryption
    no_encryption = [
        lbl for lbl in active_labels
        if not lbl.get("IsEncryptionEnabled", False)
    ]
    if no_encryption:
        affected = [{"Type": "SensitivityLabel", "Name": lbl.get("Name", ""),
                      "ResourceId": lbl.get("Id", lbl.get("Name", "")),
                      "Priority": lbl.get("Priority", 0)}
                     for lbl in no_encryption[:20]]
        findings.append(_cr_finding(
            "label_coverage", "labels_without_encryption",
            f"{len(no_encryption)} active sensitivity label(s) lack encryption — Copilot can surface content freely",
            "Sensitivity labels without encryption do not enforce access control at the content level. "
            "Even when content is labeled, any user with file-level permissions can access it through "
            "Copilot. Encryption ensures that only authorized users can decrypt and view the content, "
            "preventing Copilot from surfacing sensitive documents to overprivileged users.",
            "medium",
            affected,
            {"Description": "Enable encryption on high-sensitivity labels to enforce content-level "
             "access control that Copilot respects.",
             "PortalSteps": [
                 "Go to Microsoft Purview > Information protection > Labels",
                 "Edit each high-sensitivity label (Confidential, Highly Confidential)",
                 "Under 'Encryption': select 'Configure encryption settings'",
                 "Choose 'Assign permissions now' or 'Let users assign permissions'",
                 "Publish updated label policy and allow 24h for propagation",
             ]},
            compliance_status="gap",
        ))

    # Check labels without site & group settings
    no_site_group = [
        lbl for lbl in active_labels
        if not lbl.get("HasSiteAndGroupSettings", False)
    ]
    if no_site_group:
        affected = [{"Type": "SensitivityLabel", "Name": lbl.get("Name", ""),
                      "ResourceId": lbl.get("Id", lbl.get("Name", "")),
                      "Priority": lbl.get("Priority", 0)}
                     for lbl in no_site_group[:20]]
        findings.append(_cr_finding(
            "label_coverage", "labels_without_site_group_settings",
            f"{len(no_site_group)} active label(s) lack site & group settings — container-level controls missing",
            "Labels without site & group settings do not protect SharePoint sites, Teams, or "
            "M365 Groups at the container level. Without these settings, labeled containers "
            "may allow external sharing, guest access, or public privacy — enabling Copilot "
            "to index and surface content from improperly governed containers.",
            "low",
            affected,
            {"Description": "Enable site & group settings on labels to protect containers "
             "(SharePoint sites, Teams, M365 Groups).",
             "PortalSteps": [
                 "Go to Microsoft Purview > Information protection > Labels",
                 "Edit each label and enable 'Groups & sites' scope",
                 "Configure privacy (Private/Public), external sharing, and guest access settings",
                 "Publish updated label policy",
             ]},
            compliance_status="gap",
        ))

    return findings

