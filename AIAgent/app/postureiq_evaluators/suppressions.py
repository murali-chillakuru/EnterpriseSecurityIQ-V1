"""
Exception / Suppression System
Allows users to suppress specific findings by resource, control, or pattern.
Suppressions are loaded from a JSON file and applied after evaluation.
Includes audit trail, risk acceptance tracking, and status reporting.
"""

from __future__ import annotations
import json, pathlib, re
from datetime import datetime, timedelta, timezone
from typing import Any
from app.logger import log


def load_suppressions(path: str = "suppressions.json") -> list[dict]:
    """Load suppression rules from a JSON file.

    Each rule has:
        control_id: str | None  — exact match or glob
        resource: str | None    — regex match on resource name
        reason: str             — justification for the suppression
        expires: str | None     — ISO date; suppression expires after this date
        owner: str | None       — person who approved the exception
        risk_accepted: bool     — explicit risk acceptance flag
        ticket: str | None      — link to approval ticket (e.g. JIRA/ADO)
        created: str | None     — ISO date when the suppression was created
    """
    p = pathlib.Path(path)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        rules = data if isinstance(data, list) else data.get("suppressions", [])
        log.info("Loaded %d suppression rules from %s", len(rules), path)
        return rules
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load suppressions: %s", exc)
        return []


def apply_suppressions(
    findings: list[dict[str, Any]],
    suppressions: list[dict],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Filter findings against suppression rules.

    Returns (active_findings, suppressed_findings).
    """
    if not suppressions:
        return findings, []

    now = datetime.now(timezone.utc)
    warn_horizon = now + timedelta(days=7)
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    # Pre-check for expiring/expired rules and log warnings
    for i, rule in enumerate(suppressions):
        expires = rule.get("expires")
        if not expires:
            continue
        try:
            exp_dt = datetime.fromisoformat(expires).replace(tzinfo=timezone.utc)
            if now > exp_dt:
                log.warning("Suppression rule #%d expired on %s (control=%s, resource=%s)",
                            i + 1, expires,
                            rule.get("control_id", "*"),
                            rule.get("resource", "*"))
            elif exp_dt <= warn_horizon:
                days_left = (exp_dt - now).days
                log.warning("Suppression rule #%d expires in %d day(s) on %s (control=%s)",
                            i + 1, days_left, expires,
                            rule.get("control_id", "*"))
        except ValueError:
            log.warning("Suppression rule #%d has invalid expires date: %s", i + 1, expires)

    for f in findings:
        matched = False
        for i, rule in enumerate(suppressions):
            # Check expiry
            expires = rule.get("expires")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires).replace(tzinfo=timezone.utc)
                    if now > exp_dt:
                        continue  # rule expired
                except ValueError:
                    continue  # invalid date — skip rule

            # Match control_id
            cid_pattern = rule.get("control_id")
            if cid_pattern:
                fid = f.get("control_id", "")
                if cid_pattern != fid and not re.fullmatch(cid_pattern, fid):
                    continue

            # Match resource
            res_pattern = rule.get("resource")
            if res_pattern:
                fres = f.get("resource", "")
                if not re.search(res_pattern, fres, re.IGNORECASE):
                    continue

            # Both filters matched (or were absent) → suppressed
            f_copy = dict(f)
            f_copy["suppressed_reason"] = rule.get("reason", "No reason given")
            f_copy["suppressed_rule_index"] = i + 1
            f_copy["suppressed_expires"] = expires or "never"
            suppressed.append(f_copy)
            matched = True
            log.debug("Suppressed finding: control=%s resource=%s by rule #%d (reason: %s)",
                       f.get("control_id", "?"), f.get("resource", "?"),
                       i + 1, rule.get("reason", "N/A"))
            break

        if not matched:
            active.append(f)

    if suppressed:
        log.info("Suppressed %d finding(s) via %d rule(s)", len(suppressed),
                 len({s["suppressed_rule_index"] for s in suppressed}))

    return active, suppressed


def generate_exception_report(
    suppressions: list[dict],
    suppressed_findings: list[dict],
) -> dict[str, Any]:
    """Generate an exception tracking report.

    Returns a dict with:
    - total_rules: count of suppression rules
    - active_rules: rules currently in effect
    - expired_rules: rules past their expiry
    - expiring_soon: rules expiring within 7 days
    - missing_approval: rules without owner or ticket
    - risk_accepted: rules with explicit risk acceptance
    - audit_entries: per-rule summary for audit trail
    - suppressed_count: total findings suppressed this run
    """
    now = datetime.now(timezone.utc)
    warn_horizon = now + timedelta(days=7)

    active_rules = []
    expired_rules = []
    expiring_soon = []
    missing_approval = []
    risk_accepted = []
    audit: list[dict] = []

    for i, rule in enumerate(suppressions):
        entry: dict[str, Any] = {
            "RuleIndex": i + 1,
            "ControlId": rule.get("control_id", "*"),
            "Resource": rule.get("resource", "*"),
            "Reason": rule.get("reason", "No reason"),
            "Owner": rule.get("owner", ""),
            "Ticket": rule.get("ticket", ""),
            "RiskAccepted": rule.get("risk_accepted", False),
            "Created": rule.get("created", ""),
            "Expires": rule.get("expires", "never"),
            "Status": "active",
        }

        expires = rule.get("expires")
        is_expired = False
        if expires:
            try:
                exp_dt = datetime.fromisoformat(expires).replace(tzinfo=timezone.utc)
                if now > exp_dt:
                    entry["Status"] = "expired"
                    is_expired = True
                    expired_rules.append(entry)
                elif exp_dt <= warn_horizon:
                    days_left = (exp_dt - now).days
                    entry["Status"] = f"expiring_in_{days_left}d"
                    expiring_soon.append(entry)
            except ValueError:
                entry["Status"] = "invalid_date"

        if not is_expired:
            active_rules.append(entry)

        if not rule.get("owner") and not rule.get("ticket"):
            missing_approval.append(entry)

        if rule.get("risk_accepted"):
            risk_accepted.append(entry)

        # Count how many findings this rule suppressed
        matched = sum(1 for sf in suppressed_findings
                      if sf.get("suppressed_rule_index") == i + 1)
        entry["SuppressedCount"] = matched

        audit.append(entry)

    report = {
        "TotalRules": len(suppressions),
        "ActiveRules": len(active_rules),
        "ExpiredRules": len(expired_rules),
        "ExpiringSoon": len(expiring_soon),
        "MissingApproval": len(missing_approval),
        "RiskAccepted": len(risk_accepted),
        "SuppressedCount": len(suppressed_findings),
        "AuditEntries": audit,
        "ExpiringSoonDetails": expiring_soon,
        "MissingApprovalDetails": missing_approval[:10],
    }

    if expired_rules:
        log.warning("Exception report: %d expired suppression rules should be reviewed",
                    len(expired_rules))
    if missing_approval:
        log.warning("Exception report: %d rules lack owner/ticket — audit trail incomplete",
                    len(missing_approval))

    return report
