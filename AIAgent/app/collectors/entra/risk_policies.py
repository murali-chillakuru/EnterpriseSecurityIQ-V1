"""
Entra Risk & Advanced Policies Collector
Named locations, authentication methods policies,
and authentication strength policies.

Note: Risky users and risk detections are collected by
identity_protection.py to avoid duplicate API calls.
"""

from __future__ import annotations
from datetime import datetime, timezone
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence, _v, AccessDeniedError
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="risk_policies", plane="control", source="entra", priority=66)
async def collect_entra_risk_policies(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        graph = creds.get_graph_client()

        # --- Named Locations ---
        try:
            named_locations = await paginate_graph(graph.identity.conditional_access.named_locations)
            for loc in named_locations:
                loc_type = type(loc).__name__
                is_trusted = getattr(loc, "is_trusted", False)
                ip_ranges = getattr(loc, "ip_ranges", []) or []
                countries = getattr(loc, "countries_and_regions", []) or []

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraRiskPolicies",
                    evidence_type="entra-named-location",
                    description=f"Named location: {getattr(loc, 'display_name', '')}",
                    data={
                        "LocationId": getattr(loc, "id", ""),
                        "DisplayName": getattr(loc, "display_name", ""),
                        "LocationType": loc_type,
                        "IsTrusted": is_trusted,
                        "IpRangeCount": len(ip_ranges),
                        "CountriesAndRegions": countries,
                        "CreatedDateTime": str(getattr(loc, "created_date_time", "")),
                        "ModifiedDateTime": str(getattr(loc, "modified_date_time", "")),
                    },
                    resource_id=getattr(loc, "id", ""), resource_type="NamedLocation",
                ))
            log.info("  [EntraRiskPolicies] %d named locations", len(named_locations))
        except AccessDeniedError as ade:
            log.warning("  [EntraRiskPolicies] Named locations access denied (HTTP %d) — skipping", ade.status)
        except Exception as exc:
            log.warning("  [EntraRiskPolicies] Named locations failed: %s", exc)

        # --- Authentication Methods Policy ---
        try:
            auth_methods = await graph.policies.authentication_methods_policy.get()
            if auth_methods:
                configs = getattr(auth_methods, "authentication_method_configurations", []) or []
                methods_summary = []
                for cfg in configs:
                    methods_summary.append({
                        "Id": getattr(cfg, "id", ""),
                        "State": _v(getattr(cfg, "state", None)),
                        "Type": type(cfg).__name__,
                    })

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraRiskPolicies",
                    evidence_type="entra-auth-methods-policy",
                    description="Authentication methods policy",
                    data={
                        "PolicyId": getattr(auth_methods, "id", ""),
                        "Description": getattr(auth_methods, "description", ""),
                        "RegistrationEnforcement": str(getattr(auth_methods, "registration_enforcement", "")),
                        "MethodCount": len(configs),
                        "Methods": methods_summary,
                        "LastModifiedDateTime": str(getattr(auth_methods, "last_modified_date_time", "")),
                    },
                    resource_id="authentication-methods-policy", resource_type="AuthMethodsPolicy",
                ))
            log.info("  [EntraRiskPolicies] Auth methods policy collected")
        except AccessDeniedError as ade:
            log.warning("  [EntraRiskPolicies] Auth methods policy access denied (HTTP %d) — skipping", ade.status)
        except Exception as exc:
            log.warning("  [EntraRiskPolicies] Auth methods policy failed: %s", exc)

        # --- Authentication Strength Policies ---
        try:
            auth_strengths = await paginate_graph(graph.policies.authentication_strength_policies)
            for policy in auth_strengths:
                combinations = getattr(policy, "allowed_combinations", []) or []
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraRiskPolicies",
                    evidence_type="entra-auth-strength-policy",
                    description=f"Auth strength: {getattr(policy, 'display_name', '')}",
                    data={
                        "PolicyId": getattr(policy, "id", ""),
                        "DisplayName": getattr(policy, "display_name", ""),
                        "Description": getattr(policy, "description", ""),
                        "PolicyType": _v(getattr(policy, "policy_type", None)),
                        "AllowedCombinations": [_v(c) for c in combinations],
                        "CreatedDateTime": str(getattr(policy, "created_date_time", "")),
                        "ModifiedDateTime": str(getattr(policy, "modified_date_time", "")),
                    },
                    resource_id=getattr(policy, "id", ""), resource_type="AuthStrengthPolicy",
                ))
            log.info("  [EntraRiskPolicies] %d auth strength policies", len(auth_strengths))
        except AccessDeniedError as ade:
            log.warning("  [EntraRiskPolicies] Auth strength policies access denied (HTTP %d) — skipping", ade.status)
        except Exception as exc:
            log.warning("  [EntraRiskPolicies] Auth strength policies failed: %s", exc)

        return evidence

    return (await run_collector("EntraRiskPolicies", Source.ENTRA, _collect)).data
