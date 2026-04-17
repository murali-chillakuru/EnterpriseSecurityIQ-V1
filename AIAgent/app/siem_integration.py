"""
EnterpriseSecurityIQ — SIEM / SOAR Integration
Export findings and evidence to Sentinel, Splunk, or generic SIEM via webhook/syslog.
"""

from __future__ import annotations
import json
import asyncio
import aiohttp
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

from app.logger import log


# ── Configuration ──────────────────────────────────────────────────────────

@dataclass
class SIEMConfig:
    """Configuration for a SIEM target."""
    name: str                               # e.g. "sentinel", "splunk", "generic"
    enabled: bool = False
    endpoint_url: str = ""                  # Webhook / HEC / DC API URL
    auth_token: str = ""                    # Bearer token or HEC token
    auth_header: str = "Authorization"      # Header name
    auth_prefix: str = "Bearer"             # e.g. "Bearer", "Splunk"
    workspace_id: str = ""                  # Sentinel workspace ID (for DCR)
    dcr_immutable_id: str = ""              # Data Collection Rule immutable ID
    dcr_stream_name: str = ""               # e.g. "Custom-EnterpriseSecurityIQ_CL"
    batch_size: int = 100                   # Max events per request
    timeout_seconds: int = 30
    custom_headers: dict[str, str] = field(default_factory=dict)


# ── Event Formatters ───────────────────────────────────────────────────────

def _format_finding_event(finding: dict, assessment_id: str) -> dict:
    """Convert a finding dict into a SIEM-friendly event."""
    return {
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "AssessmentId": assessment_id,
        "ControlId": finding.get("ControlId", ""),
        "Framework": finding.get("Framework", ""),
        "ControlTitle": finding.get("ControlTitle", ""),
        "Status": finding.get("Status", ""),
        "Severity": finding.get("Severity", ""),
        "Domain": finding.get("Domain", ""),
        "Description": finding.get("Description", ""),
        "Recommendation": finding.get("Recommendation", ""),
        "ResourceId": finding.get("ResourceId", ""),
        "ResourceType": finding.get("ResourceType", ""),
        "FindingId": finding.get("FindingId", ""),
        "EvaluatedAt": finding.get("EvaluatedAt", ""),
    }


def _format_for_splunk(event: dict, source: str = "enterprisesecurityiq") -> dict:
    """Format event for Splunk HTTP Event Collector (HEC)."""
    return {
        "time": datetime.now(timezone.utc).timestamp(),
        "source": source,
        "sourcetype": "enterprisesecurityiq:finding",
        "event": event,
    }


def _format_for_sentinel(event: dict) -> dict:
    """Format event for Azure Monitor Data Collection Rule API."""
    return event  # Sentinel DCR expects flat records with TimeGenerated


def _format_for_generic(event: dict) -> dict:
    """Format event for generic webhook."""
    return {"source": "EnterpriseSecurityIQ", "event_type": "compliance_finding", "data": event}


# ── SIEM Exporters ─────────────────────────────────────────────────────────

class SIEMExporter:
    """Export compliance findings to configured SIEM targets."""

    def __init__(self, configs: list[SIEMConfig]):
        self._configs = {c.name: c for c in configs if c.enabled}

    @property
    def enabled_targets(self) -> list[str]:
        return list(self._configs.keys())

    async def export_findings(
        self,
        findings: list[dict],
        assessment_id: str = "",
    ) -> dict[str, dict[str, Any]]:
        """
        Export all non-compliant findings to enabled SIEM targets.
        Returns: {target_name: {"sent": int, "failed": int, "errors": [str]}}
        """
        nc_findings = [
            f for f in findings
            if f.get("Status") in ("non_compliant", "partial", "critical")
        ]
        if not nc_findings:
            log.info("[SIEM] No non-compliant findings to export.")
            return {}

        events = [_format_finding_event(f, assessment_id) for f in nc_findings]
        results: dict[str, dict] = {}

        for name, cfg in self._configs.items():
            results[name] = await self._send_to_target(cfg, events)

        return results

    async def _send_to_target(self, cfg: SIEMConfig, events: list[dict]) -> dict[str, Any]:
        """Send events to a single SIEM target in batches."""
        sent = 0
        failed = 0
        errors: list[str] = []

        formatter = {
            "sentinel": _format_for_sentinel,
            "splunk": _format_for_splunk,
            "generic": _format_for_generic,
        }.get(cfg.name, _format_for_generic)

        headers = dict(cfg.custom_headers)
        if cfg.auth_token:
            headers[cfg.auth_header] = f"{cfg.auth_prefix} {cfg.auth_token}"
        headers.setdefault("Content-Type", "application/json")

        timeout = aiohttp.ClientTimeout(total=cfg.timeout_seconds)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for i in range(0, len(events), cfg.batch_size):
                batch = events[i:i + cfg.batch_size]
                formatted = [formatter(e) for e in batch]

                # Splunk HEC expects newline-delimited JSON
                if cfg.name == "splunk":
                    body = "\n".join(json.dumps(e) for e in formatted)
                else:
                    body = json.dumps(formatted)

                try:
                    async with session.post(cfg.endpoint_url, data=body, headers=headers) as resp:
                        if resp.status < 300:
                            sent += len(batch)
                            log.info("[SIEM] %s: batch %d/%d sent (%d events)",
                                     cfg.name, i // cfg.batch_size + 1,
                                     (len(events) + cfg.batch_size - 1) // cfg.batch_size,
                                     len(batch))
                        else:
                            failed += len(batch)
                            text = await resp.text()
                            errors.append(f"HTTP {resp.status}: {text[:200]}")
                            log.warning("[SIEM] %s: batch failed HTTP %d", cfg.name, resp.status)
                except Exception as exc:
                    failed += len(batch)
                    errors.append(str(exc)[:200])
                    log.warning("[SIEM] %s: batch error: %s", cfg.name, exc)

        log.info("[SIEM] %s: sent=%d, failed=%d", cfg.name, sent, failed)
        return {"sent": sent, "failed": failed, "errors": errors}


# ── Factory ─────────────────────────────────────────────────────────────────

def create_siem_exporter(config: dict) -> SIEMExporter:
    """Create SIEMExporter from the siem_integration config section."""
    siem_cfg = config.get("siem_integration", {})
    targets = []

    for name in ("sentinel", "splunk", "generic"):
        target_cfg = siem_cfg.get(name, {})
        if target_cfg.get("enabled"):
            targets.append(SIEMConfig(
                name=name,
                enabled=True,
                endpoint_url=target_cfg.get("endpoint_url", ""),
                auth_token=target_cfg.get("auth_token", ""),
                auth_header=target_cfg.get("auth_header", "Authorization"),
                auth_prefix=target_cfg.get("auth_prefix", "Bearer" if name != "splunk" else "Splunk"),
                workspace_id=target_cfg.get("workspace_id", ""),
                dcr_immutable_id=target_cfg.get("dcr_immutable_id", ""),
                dcr_stream_name=target_cfg.get("dcr_stream_name", ""),
                batch_size=target_cfg.get("batch_size", 100),
                timeout_seconds=target_cfg.get("timeout_seconds", 30),
                custom_headers=target_cfg.get("custom_headers", {}),
            ))

    return SIEMExporter(targets)
