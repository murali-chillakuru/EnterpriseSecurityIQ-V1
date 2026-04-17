"""
Notification Integration
Send assessment summaries to Slack, Microsoft Teams, or email (via webhook).
"""

from __future__ import annotations
import json
from typing import Any
from app.logger import log

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


async def send_notification(
    summary: dict[str, Any],
    webhook_url: str,
    channel_type: str = "auto",
) -> bool:
    """Post an assessment summary to a webhook endpoint.

    channel_type: "slack", "teams", or "auto" (detect from URL).
    Returns True on success.
    """
    if not _HAS_HTTPX:
        log.warning("httpx not installed — notification skipped")
        return False

    if not webhook_url:
        return False

    if channel_type == "auto":
        if "hooks.slack.com" in webhook_url:
            channel_type = "slack"
        elif "webhook.office.com" in webhook_url or "logic.azure.com" in webhook_url:
            channel_type = "teams"
        else:
            channel_type = "generic"

    score = summary.get("ComplianceScore", 0)
    compliant = summary.get("Compliant", 0)
    total = summary.get("TotalControls", 0)
    findings_count = summary.get("findings_count", 0)

    text = (
        f"EnterpriseSecurityIQ Assessment Complete\n"
        f"Score: {score:.1f}% ({compliant}/{total} controls compliant)\n"
        f"Findings: {findings_count}"
    )

    if channel_type == "slack":
        payload = {"text": text}
    elif channel_type == "teams":
        payload = {
            "@type": "MessageCard",
            "summary": "EnterpriseSecurityIQ Assessment",
            "themeColor": "0076D7" if score >= 80 else "FF0000",
            "title": "EnterpriseSecurityIQ Assessment Complete",
            "sections": [{
                "facts": [
                    {"name": "Score", "value": f"{score:.1f}%"},
                    {"name": "Compliant", "value": f"{compliant}/{total}"},
                    {"name": "Findings", "value": str(findings_count)},
                ],
            }],
        }
    else:
        payload = {"summary": text, "score": score, "compliant": compliant, "total": total}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            log.info("Notification sent to %s (%s)", channel_type, resp.status_code)
            return True
    except Exception as exc:
        log.error("Notification failed: %s", exc)
        return False
