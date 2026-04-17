"""
EnterpriseSecurityIQ — Operational Integrations
Webhook/Email alerts, ServiceNow/Jira ticket creation,
and Azure DevOps work item creation for data security findings.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiohttp

from app.logger import log


# ── Webhook / Email Alert Dispatcher ─────────────────────────────────────


@dataclass
class WebhookConfig:
    """Configuration for a webhook alert target."""
    url: str
    enabled: bool = True
    auth_token: str = ""
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer"
    timeout_seconds: int = 30
    custom_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class EmailConfig:
    """Configuration for email alert delivery."""
    enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password: str = ""
    from_address: str = ""
    to_addresses: list[str] = field(default_factory=list)
    subject_prefix: str = "[EnterpriseSecurityIQ]"


class AlertDispatcher:
    """Dispatch alerts via webhook and/or email."""

    def __init__(
        self,
        webhooks: list[WebhookConfig] | None = None,
        email: EmailConfig | None = None,
    ):
        self._webhooks = [w for w in (webhooks or []) if w.enabled]
        self._email = email if email and email.enabled else None

    async def send_alert(self, alert: dict) -> dict[str, Any]:
        """Send alert to all configured targets."""
        results: dict[str, Any] = {}

        for i, wh in enumerate(self._webhooks):
            key = f"webhook_{i}"
            results[key] = await self._send_webhook(wh, alert)

        if self._email:
            results["email"] = self._send_email(alert)

        return results

    async def _send_webhook(self, config: WebhookConfig, alert: dict) -> dict:
        headers = dict(config.custom_headers)
        if config.auth_token:
            headers[config.auth_header] = f"{config.auth_prefix} {config.auth_token}"
        headers.setdefault("Content-Type", "application/json")

        payload = {
            "source": "EnterpriseSecurityIQ",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert": alert,
        }
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(config.url, json=payload, headers=headers) as resp:
                    if resp.status < 300:
                        log.info("[Alert] Webhook sent to %s (HTTP %d)", config.url, resp.status)
                        return {"sent": True, "status": resp.status}
                    text = await resp.text()
                    log.warning("[Alert] Webhook failed: HTTP %d — %s", resp.status, text[:200])
                    return {"sent": False, "status": resp.status, "error": text[:200]}
        except Exception as exc:
            log.warning("[Alert] Webhook error: %s", exc)
            return {"sent": False, "error": str(exc)[:200]}

    def _send_email(self, alert: dict) -> dict:
        if not self._email:
            return {"sent": False, "error": "Email not configured"}
        cfg = self._email
        alert_type = alert.get("type", "alert")
        details = alert.get("details", {})

        subject = f"{cfg.subject_prefix} {alert_type.replace('_', ' ').title()}"
        body_lines = [
            f"EnterpriseSecurityIQ Alert: {alert_type}",
            f"Time: {alert.get('timestamp', 'N/A')}",
            f"Iteration: {alert.get('iteration', 'N/A')}",
            "",
            "Details:",
        ]
        for k, v in details.items():
            body_lines.append(f"  {k}: {v}")

        msg = MIMEMultipart()
        msg["From"] = cfg.from_address
        msg["To"] = ", ".join(cfg.to_addresses)
        msg["Subject"] = subject
        msg.attach(MIMEText("\n".join(body_lines), "plain"))

        try:
            with smtplib.SMTP(cfg.smtp_server, cfg.smtp_port) as server:
                if cfg.use_tls:
                    server.starttls()
                if cfg.username:
                    server.login(cfg.username, cfg.password)
                server.send_message(msg)
            log.info("[Alert] Email sent to %s", ", ".join(cfg.to_addresses))
            return {"sent": True}
        except Exception as exc:
            log.warning("[Alert] Email error: %s", exc)
            return {"sent": False, "error": str(exc)[:200]}


# ── ServiceNow / Jira Ticket Integration ─────────────────────────────────


@dataclass
class ServiceNowConfig:
    """Configuration for ServiceNow ticket creation."""
    enabled: bool = False
    instance_url: str = ""         # e.g. https://mycompany.service-now.com
    username: str = ""
    password: str = ""
    table: str = "incident"
    assignment_group: str = ""
    caller_id: str = ""
    category: str = "Security"
    timeout_seconds: int = 30


@dataclass
class JiraConfig:
    """Configuration for Jira issue creation."""
    enabled: bool = False
    server_url: str = ""           # e.g. https://mycompany.atlassian.net
    username: str = ""
    api_token: str = ""
    project_key: str = ""
    issue_type: str = "Bug"
    priority_map: dict[str, str] = field(default_factory=lambda: {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Lowest",
    })
    labels: list[str] = field(default_factory=lambda: ["enterprisesecurityiq", "security"])
    timeout_seconds: int = 30


class TicketConnector:
    """Create tickets in ServiceNow or Jira from findings."""

    def __init__(
        self,
        servicenow: ServiceNowConfig | None = None,
        jira: JiraConfig | None = None,
    ):
        self._snow = servicenow if servicenow and servicenow.enabled else None
        self._jira = jira if jira and jira.enabled else None

    async def create_tickets(
        self,
        findings: list[dict],
        min_severity: str = "high",
    ) -> dict[str, list[dict]]:
        """
        Create tickets for findings at or above min_severity.
        Returns: {"servicenow": [...], "jira": [...]}
        """
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        threshold = sev_rank.get(min_severity, 1)

        filtered = [
            f for f in findings
            if sev_rank.get(f.get("Severity", "medium").lower(), 5) <= threshold
        ]

        results: dict[str, list[dict]] = {}

        if self._snow:
            results["servicenow"] = [
                await self._create_snow_ticket(f) for f in filtered
            ]

        if self._jira:
            results["jira"] = [
                await self._create_jira_ticket(f) for f in filtered
            ]

        return results

    async def _create_snow_ticket(self, finding: dict) -> dict:
        cfg = self._snow
        if not cfg:
            return {"created": False, "error": "ServiceNow not configured"}

        sev_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}
        sev = finding.get("Severity", "medium").lower()

        payload = {
            "short_description": f"[EnterpriseSecurityIQ] {finding.get('Title', 'Security Finding')}",
            "description": (
                f"Category: {finding.get('Category', 'N/A')}\n"
                f"Severity: {sev.upper()}\n"
                f"Affected Resources: {finding.get('AffectedCount', 0)}\n\n"
                f"{finding.get('Description', '')}\n\n"
                f"Remediation: {json.dumps(finding.get('Remediation', {}), indent=2)}"
            ),
            "impact": sev_map.get(sev, 3),
            "urgency": sev_map.get(sev, 3),
            "category": cfg.category,
            "assignment_group": cfg.assignment_group,
            "caller_id": cfg.caller_id,
        }

        import base64
        auth = base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        url = f"{cfg.instance_url.rstrip('/')}/api/now/table/{cfg.table}"
        timeout = aiohttp.ClientTimeout(total=cfg.timeout_seconds)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    if resp.status < 300:
                        data = await resp.json()
                        number = data.get("result", {}).get("number", "")
                        log.info("[SNOW] Created ticket %s for: %s", number, finding.get("Title"))
                        return {"created": True, "number": number}
                    text = await resp.text()
                    log.warning("[SNOW] Failed HTTP %d: %s", resp.status, text[:200])
                    return {"created": False, "error": f"HTTP {resp.status}"}
        except Exception as exc:
            log.warning("[SNOW] Error: %s", exc)
            return {"created": False, "error": str(exc)[:200]}

    async def _create_jira_ticket(self, finding: dict) -> dict:
        cfg = self._jira
        if not cfg:
            return {"created": False, "error": "Jira not configured"}

        sev = finding.get("Severity", "medium").lower()
        priority = cfg.priority_map.get(sev, "Medium")
        remediation = finding.get("Remediation", {})
        rem_text = ""
        if isinstance(remediation, dict):
            for k, v in remediation.items():
                if v:
                    rem_text += f"*{k}:* {v}\n"

        payload = {
            "fields": {
                "project": {"key": cfg.project_key},
                "issuetype": {"name": cfg.issue_type},
                "summary": f"[EnterpriseSecurityIQ] {finding.get('Title', 'Security Finding')}",
                "description": (
                    f"*Category:* {finding.get('Category', 'N/A')}\n"
                    f"*Severity:* {sev.upper()}\n"
                    f"*Affected Resources:* {finding.get('AffectedCount', 0)}\n\n"
                    f"{finding.get('Description', '')}\n\n"
                    f"h3. Remediation\n{rem_text}"
                ),
                "priority": {"name": priority},
                "labels": cfg.labels,
            }
        }

        import base64
        auth = base64.b64encode(f"{cfg.username}:{cfg.api_token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        }
        url = f"{cfg.server_url.rstrip('/')}/rest/api/2/issue"
        timeout = aiohttp.ClientTimeout(total=cfg.timeout_seconds)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    if resp.status < 300:
                        data = await resp.json()
                        key = data.get("key", "")
                        log.info("[JIRA] Created issue %s for: %s", key, finding.get("Title"))
                        return {"created": True, "key": key}
                    text = await resp.text()
                    log.warning("[JIRA] Failed HTTP %d: %s", resp.status, text[:200])
                    return {"created": False, "error": f"HTTP {resp.status}"}
        except Exception as exc:
            log.warning("[JIRA] Error: %s", exc)
            return {"created": False, "error": str(exc)[:200]}


# ── Azure DevOps Work Item Integration ───────────────────────────────────


@dataclass
class ADOConfig:
    """Configuration for Azure DevOps work item creation."""
    enabled: bool = False
    organization_url: str = ""     # e.g. https://dev.azure.com/myorg
    project: str = ""
    pat: str = ""                  # Personal Access Token
    work_item_type: str = "Bug"
    area_path: str = ""
    iteration_path: str = ""
    tags: str = "EnterpriseSecurityIQ;Security"
    timeout_seconds: int = 30


class ADOConnector:
    """Create Azure DevOps work items from findings."""

    def __init__(self, config: ADOConfig | None = None):
        self._cfg = config if config and config.enabled else None

    async def create_work_items(
        self,
        findings: list[dict],
        min_severity: str = "high",
    ) -> list[dict]:
        """Create ADO work items for findings at or above min_severity."""
        if not self._cfg:
            return []

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        threshold = sev_rank.get(min_severity, 1)

        filtered = [
            f for f in findings
            if sev_rank.get(f.get("Severity", "medium").lower(), 5) <= threshold
        ]

        results = []
        for finding in filtered:
            result = await self._create_work_item(finding)
            results.append(result)

        log.info("[ADO] Created %d work items", sum(1 for r in results if r.get("created")))
        return results

    async def _create_work_item(self, finding: dict) -> dict:
        cfg = self._cfg
        if not cfg:
            return {"created": False, "error": "ADO not configured"}

        sev = finding.get("Severity", "medium").lower()
        sev_priority = {"critical": "1", "high": "2", "medium": "3", "low": "4"}.get(sev, "3")
        remediation = finding.get("Remediation", {})
        rem_text = ""
        if isinstance(remediation, dict):
            for k, v in remediation.items():
                if v:
                    rem_text += f"<b>{k}:</b> {v}<br>"

        # ADO PATCH API uses JSON Patch format
        patch_doc = [
            {"op": "add", "path": "/fields/System.Title",
             "value": f"[EnterpriseSecurityIQ] {finding.get('Title', 'Security Finding')}"},
            {"op": "add", "path": "/fields/System.Description",
             "value": (
                 f"<b>Category:</b> {finding.get('Category', 'N/A')}<br>"
                 f"<b>Severity:</b> {sev.upper()}<br>"
                 f"<b>Affected Resources:</b> {finding.get('AffectedCount', 0)}<br><br>"
                 f"{finding.get('Description', '')}<br><br>"
                 f"<h3>Remediation</h3>{rem_text}"
             )},
            {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority",
             "value": sev_priority},
            {"op": "add", "path": "/fields/System.Tags",
             "value": cfg.tags},
        ]
        if cfg.area_path:
            patch_doc.append({"op": "add", "path": "/fields/System.AreaPath",
                              "value": cfg.area_path})
        if cfg.iteration_path:
            patch_doc.append({"op": "add", "path": "/fields/System.IterationPath",
                              "value": cfg.iteration_path})

        import base64
        auth = base64.b64encode(f":{cfg.pat}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json-patch+json",
        }
        url = (
            f"{cfg.organization_url.rstrip('/')}/{cfg.project}/"
            f"_apis/wit/workitems/${cfg.work_item_type}?api-version=7.1"
        )
        timeout = aiohttp.ClientTimeout(total=cfg.timeout_seconds)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=patch_doc, headers=headers) as resp:
                    if resp.status < 300:
                        data = await resp.json()
                        wi_id = data.get("id", "")
                        log.info("[ADO] Created work item #%s for: %s", wi_id, finding.get("Title"))
                        return {"created": True, "id": wi_id}
                    text = await resp.text()
                    log.warning("[ADO] Failed HTTP %d: %s", resp.status, text[:200])
                    return {"created": False, "error": f"HTTP {resp.status}"}
        except Exception as exc:
            log.warning("[ADO] Error: %s", exc)
            return {"created": False, "error": str(exc)[:200]}


# ── Factory ──────────────────────────────────────────────────────────────


def create_alert_dispatcher(config: dict) -> AlertDispatcher:
    """Create AlertDispatcher from config dict."""
    alert_cfg = config.get("alerts", {})
    webhooks = []
    for wh in alert_cfg.get("webhooks", []):
        if wh.get("enabled"):
            webhooks.append(WebhookConfig(
                url=wh["url"],
                enabled=True,
                auth_token=wh.get("auth_token", ""),
                auth_header=wh.get("auth_header", "Authorization"),
                auth_prefix=wh.get("auth_prefix", "Bearer"),
                timeout_seconds=wh.get("timeout_seconds", 30),
                custom_headers=wh.get("custom_headers", {}),
            ))
    email = None
    email_cfg = alert_cfg.get("email", {})
    if email_cfg.get("enabled"):
        email = EmailConfig(
            enabled=True,
            smtp_server=email_cfg.get("smtp_server", ""),
            smtp_port=email_cfg.get("smtp_port", 587),
            use_tls=email_cfg.get("use_tls", True),
            username=email_cfg.get("username", ""),
            password=email_cfg.get("password", ""),
            from_address=email_cfg.get("from_address", ""),
            to_addresses=email_cfg.get("to_addresses", []),
            subject_prefix=email_cfg.get("subject_prefix", "[EnterpriseSecurityIQ]"),
        )
    return AlertDispatcher(webhooks=webhooks, email=email)


def create_ticket_connector(config: dict) -> TicketConnector:
    """Create TicketConnector from config dict."""
    snow_cfg = config.get("servicenow", {})
    jira_cfg = config.get("jira", {})

    snow = None
    if snow_cfg.get("enabled"):
        snow = ServiceNowConfig(
            enabled=True,
            instance_url=snow_cfg.get("instance_url", ""),
            username=snow_cfg.get("username", ""),
            password=snow_cfg.get("password", ""),
            table=snow_cfg.get("table", "incident"),
            assignment_group=snow_cfg.get("assignment_group", ""),
            caller_id=snow_cfg.get("caller_id", ""),
            category=snow_cfg.get("category", "Security"),
        )

    jira = None
    if jira_cfg.get("enabled"):
        jira = JiraConfig(
            enabled=True,
            server_url=jira_cfg.get("server_url", ""),
            username=jira_cfg.get("username", ""),
            api_token=jira_cfg.get("api_token", ""),
            project_key=jira_cfg.get("project_key", ""),
            issue_type=jira_cfg.get("issue_type", "Bug"),
            labels=jira_cfg.get("labels", ["enterprisesecurityiq", "security"]),
        )

    return TicketConnector(servicenow=snow, jira=jira)


def create_ado_connector(config: dict) -> ADOConnector:
    """Create ADOConnector from config dict."""
    ado_cfg = config.get("azure_devops", {})
    if not ado_cfg.get("enabled"):
        return ADOConnector()

    return ADOConnector(ADOConfig(
        enabled=True,
        organization_url=ado_cfg.get("organization_url", ""),
        project=ado_cfg.get("project", ""),
        pat=ado_cfg.get("pat", ""),
        work_item_type=ado_cfg.get("work_item_type", "Bug"),
        area_path=ado_cfg.get("area_path", ""),
        iteration_path=ado_cfg.get("iteration_path", ""),
        tags=ado_cfg.get("tags", "EnterpriseSecurityIQ;Security"),
    ))
