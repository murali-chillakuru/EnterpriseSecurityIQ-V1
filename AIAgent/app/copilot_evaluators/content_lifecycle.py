"""Content lifecycle evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


def analyze_content_lifecycle(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess content lifecycle management for Copilot readiness."""
    findings: list[dict] = []
    findings.extend(_check_stale_content_for_copilot(evidence_index))
    findings.extend(_check_retention_policies(evidence_index))
    findings.extend(_check_legal_hold_compatibility(evidence_index))
    findings.extend(_check_m365_backup(evidence_index))
    return findings


def _check_legal_hold_compatibility(idx: dict) -> list[dict]:
    """Check if legal hold mechanisms are compatible with Copilot data lifecycle."""
    cases = idx.get("m365-ediscovery-cases", [])
    holds = idx.get("m365-legal-holds", [])
    if not cases and not holds:
        return [_cr_finding(
            "content_lifecycle", "no_legal_hold_configured",
            "No legal hold or eDiscovery hold detected — Copilot data may be purged before litigation",
            "Without legal holds, Copilot interaction data and referenced content may be "
            "deleted by retention policies or user actions before it can be preserved for "
            "litigation or regulatory investigations.",
            "medium",
            [{"Type": "LegalHold", "Name": "Legal Holds",
              "ResourceId": "m365-legal-holds"}],
            {"Description": "Configure eDiscovery holds for Copilot data preservation.",
             "PortalSteps": [
                 "Go to Microsoft Purview > eDiscovery > Premium",
                 "Create a case for Copilot data preservation",
                 "Add custodians (key Copilot users)",
                 "Place data sources on hold (Teams chats, Exchange, OneDrive)",
                 "Verify hold captures Copilot interaction data",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_stale_content_for_copilot(idx: dict) -> list[dict]:
    """Flag stale content that Copilot would index."""
    sites = idx.get("spo-site-inventory", [])
    stale = [
        ev for ev in sites
        if (ev.get("Data", ev.get("data", {})).get("IsStale"))
    ]
    total = len(sites)
    stale_count = len(stale)

    if stale_count > 0 and total > 0:
        pct = round(stale_count / total * 100, 1)
        return [_cr_finding(
            "content_lifecycle", "stale_content_exposure",
            f"{stale_count}/{total} sites ({pct}%) contain stale content — Copilot will index outdated data",
            "Stale SharePoint sites contain outdated content that Copilot will index and "
            "potentially surface as current information and/or recommendations. Clean up "
            "or archive stale sites before Copilot deployment.",
            "high" if pct > 30 else "medium",
            [{"Type": "SharePointSite", "Name": ev.get("Data", ev.get("data", {})).get("SiteName", ""),
              "ResourceId": ev.get("Data", ev.get("data", {})).get("SiteId", "")}
             for ev in stale[:20]],
            {"Description": "Archive or delete stale sites. Implement a site lifecycle policy.",
             "PowerShell": "Set-SPOSite -Identity <SiteUrl> -LockState ReadOnly"},
            compliance_status="gap",
        )]
    return []


def _check_retention_policies(idx: dict) -> list[dict]:
    """Check if retention policies cover Copilot interaction data."""
    # Informational check — retention policies aren't directly collected yet
    dlp = idx.get("m365-dlp-policies", [])
    if not dlp:
        return [_cr_finding(
            "content_lifecycle", "retention_assessment_needed",
            "Retention policy coverage for Copilot interactions should be verified",
            "M365 Copilot interactions may be subject to retention requirements. "
            "Verify that retention policies cover Teams chats (where Copilot operates) "
            "and Copilot-generated content.",
            "informational",
            [{"Type": "RetentionConfig", "Name": "Copilot Retention",
              "ResourceId": "m365-retention"}],
            {"Description": "Configure retention policies in Purview for Teams and Copilot.",
             "PortalSteps": ["Go to Microsoft Purview compliance portal > Data lifecycle management > Retention policies", "Create or edit a retention policy", "Include 'Teams chats' and 'Teams channel messages' locations", "Set retention period per your compliance requirements"]},
            compliance_status="partial",
        )]
    return []


def _check_m365_backup(idx: dict) -> list[dict]:
    """Check if Microsoft 365 Backup is configured for data protection."""
    backup_evidence = idx.get("m365-backup-config", [])

    if backup_evidence:
        configured = any(
            ev.get("Data", {}).get("Enabled") or ev.get("Data", {}).get("IsEnabled")
            or ev.get("Data", {}).get("Status", "").lower() in ("enabled", "active")
            for ev in backup_evidence
        )
        if configured:
            return []

    return [_cr_finding(
        "content_lifecycle", "no_m365_backup",
        "Microsoft 365 Backup not configured — no rapid recovery for Copilot-accessible content",
        "Microsoft 365 Backup provides fast, granular restoration of Exchange, OneDrive, "
        "and SharePoint content. Without backup, accidental or malicious data modifications "
        "(including those initiated via Copilot-generated content) cannot be quickly recovered.",
        "low",
        [{"Type": "BackupConfig", "Name": "M365 Backup",
          "ResourceId": "m365-backup-config"}],
        {"Description": "Configure Microsoft 365 Backup for content protection.",
         "PortalSteps": [
             "Go to Microsoft 365 admin center > Settings > Microsoft 365 Backup",
             "Enable backup for Exchange, OneDrive, and SharePoint",
             "Configure backup policies and retention periods",
             "Verify backup health in the Backup dashboard",
             "Note: Requires Microsoft 365 Backup license (pay-as-you-go or add-on)",
         ]},
        compliance_status="gap",
    )]

