"""
Entra Audit Logs Collector
Sign-in logs, directory audit, named locations.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

SIGNIN_DAYS = 30
SIGNIN_LIMIT = 5000


@register_collector(name="audit_logs", plane="control", source="entra", priority=100)
async def collect_entra_audit_logs(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=SIGNIN_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Sign-in logs
        try:
            page = await graph.audit_logs.sign_ins.get()
            count = 0
            failures = 0
            ca_blocked = 0
            mfa_successes = 0
            risk_signins = 0

            while page and count < SIGNIN_LIMIT:
                for si in (page.value or []):
                    count += 1
                    if count > SIGNIN_LIMIT:
                        break

                    status = getattr(si, "status", None)
                    error_code = getattr(status, "error_code", 0) if status else 0
                    is_failure = error_code != 0
                    if is_failure:
                        failures += 1

                    # CA enforcement
                    ca_policies = getattr(si, "applied_conditional_access_policies", []) or []
                    for cap in ca_policies:
                        result = str(getattr(cap, "result", ""))
                        if "failure" in result.lower():
                            ca_blocked += 1
                            break

                    # MFA
                    auth_details = getattr(si, "mfa_detail", None)
                    if auth_details and getattr(auth_details, "auth_method", ""):
                        mfa_successes += 1

                    # Risk
                    risk_level = str(getattr(si, "risk_level_during_sign_in", "none"))
                    if risk_level not in ("none", "hidden", ""):
                        risk_signins += 1

                if page.odata_next_link and count < SIGNIN_LIMIT:
                    page = await graph.audit_logs.sign_ins.with_url(page.odata_next_link).get()
                else:
                    break

            evidence.append(make_evidence(
                source=Source.ENTRA, collector="EntraAuditLogs",
                evidence_type="entra-signin-summary",
                description=f"Sign-in logs ({SIGNIN_DAYS}d, {count} sampled)",
                data={
                    "TotalSampled": count,
                    "FailedSignIns": failures,
                    "CABlockedSignIns": ca_blocked,
                    "MfaSuccesses": mfa_successes,
                    "RiskSignIns": risk_signins,
                    "FailureRate": round((failures / count) * 100, 1) if count > 0 else 0,
                },
            ))
            log.info("  [EntraAuditLogs] %d sign-ins sampled", count)
        except Exception as exc:
            log.warning("  [EntraAuditLogs] Sign-in logs: %s", exc)

        # Directory Audit Logs (summary only)
        try:
            page = await graph.audit_logs.directory_audits.get()
            audit_count = 0
            categories = {}
            while page and audit_count < 2000:
                for entry in (page.value or []):
                    audit_count += 1
                    cat = getattr(entry, "category", "Other") or "Other"
                    categories[cat] = categories.get(cat, 0) + 1
                    if audit_count >= 2000:
                        break
                if page.odata_next_link and audit_count < 2000:
                    page = await graph.audit_logs.directory_audits.with_url(page.odata_next_link).get()
                else:
                    break

            evidence.append(make_evidence(
                source=Source.ENTRA, collector="EntraAuditLogs",
                evidence_type="entra-directory-audit-summary",
                description=f"Directory audit ({audit_count} sampled)",
                data={
                    "TotalSampled": audit_count,
                    "CategoriesBreakdown": categories,
                },
            ))
        except Exception as exc:
            log.warning("  [EntraAuditLogs] Directory audit: %s", exc)

        # Named Locations
        try:
            locations = await paginate_graph(
                graph.identity.conditional_access.named_locations
            )
            for loc in locations:
                loc_type = getattr(loc, "odata_type", "")
                is_trusted = False
                if hasattr(loc, "is_trusted"):
                    is_trusted = getattr(loc, "is_trusted", False)

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraAuditLogs",
                    evidence_type="entra-named-location",
                    description=f"Location: {getattr(loc, 'display_name', '')}",
                    data={
                        "Id": getattr(loc, "id", ""),
                        "DisplayName": getattr(loc, "display_name", ""),
                        "LocationType": loc_type,
                        "IsTrusted": is_trusted,
                    },
                    resource_type="NamedLocation",
                ))
            log.info("  [EntraAuditLogs] %d named locations", len(locations))
        except Exception as exc:
            log.warning("  [EntraAuditLogs] Named locations: %s", exc)

        return evidence

    return (await run_collector("EntraAuditLogs", Source.ENTRA, _collect)).data
