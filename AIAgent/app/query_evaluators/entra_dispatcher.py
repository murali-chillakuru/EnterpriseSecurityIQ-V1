"""Typed Entra query dispatcher (_run_entra_query)."""

from __future__ import annotations
from typing import Any
from app.auth import ComplianceCredentials
from .entra_queries import (
    query_entra_users, query_entra_groups, query_entra_apps,
    query_entra_service_principals, query_entra_directory_roles,
    query_entra_admin_users, query_entra_conditional_access,
    query_entra_risky_users, query_entra_named_locations,
    query_entra_auth_methods_policy, query_entra_role_assignments_pim,
)
from .entra_extended import (
    _query_organization_info, _query_security_defaults,
    _query_risk_detections, _query_risky_service_principals,
    _query_access_reviews, _query_consent_grants,
    _query_federated_credentials, _query_cross_tenant_access,
    _query_sharepoint_sites, _query_sensitivity_labels,
    _query_dlp_policies,
)

async def _run_entra_query(
    creds: ComplianceCredentials,
    query_type: str,
    raw_query: str,
    top: int,
) -> dict[str, Any]:
    """Execute a typed Entra query."""
    try:
        if query_type == "disabled_users":
            results = await query_entra_users(creds, "accountEnabled eq false", top=top)
        elif query_type == "guest_users":
            results = await query_entra_users(creds, "userType eq 'Guest'", top=top)
        elif query_type == "stale_users":
            # Users who haven't signed in for 90+ days — retrieved as all users, filtered locally
            from datetime import datetime, timedelta, timezone
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            all_users = await query_entra_users(creds, top=999)
            results = []
            for u in all_users:
                last_login = u.get("lastSignInDateTime")
                if last_login:
                    try:
                        dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                        if dt < cutoff:
                            u["lastSignInDateTime"] = last_login
                            results.append(u)
                    except (ValueError, TypeError):
                        pass
                else:
                    # Never signed in
                    results.append(u)
            results = results[:top]
        elif query_type == "directory_roles":
            results = await query_entra_directory_roles(creds)
        elif query_type == "admin_users":
            results = await query_entra_admin_users(creds)
        elif query_type == "conditional_access":
            results = await query_entra_conditional_access(creds)
        elif query_type == "apps":
            results = await query_entra_apps(creds, top=top)
        elif query_type == "service_principals":
            results = await query_entra_service_principals(creds, top=top)
        elif query_type == "groups":
            results = await query_entra_groups(creds, top=top)
        elif query_type == "users":
            results = await query_entra_users(creds, top=top)
        elif query_type == "risky_users":
            results = await query_entra_risky_users(creds, top=top)
        elif query_type == "named_locations":
            results = await query_entra_named_locations(creds)
        elif query_type == "auth_methods":
            results = await query_entra_auth_methods_policy(creds)
        elif query_type == "pim_eligible":
            results = await query_entra_role_assignments_pim(creds, top=top)
        # ── v49 Entra query types ──
        elif query_type == "organization_info":
            results = await _query_organization_info(creds)
        elif query_type == "security_defaults":
            results = await _query_security_defaults(creds)
        elif query_type == "risk_detections":
            results = await _query_risk_detections(creds, top=top)
        elif query_type == "risky_service_principals":
            results = await _query_risky_service_principals(creds, top=top)
        elif query_type == "access_reviews":
            results = await _query_access_reviews(creds, top=top)
        elif query_type == "consent_grants":
            results = await _query_consent_grants(creds, top=top)
        elif query_type == "federated_credentials":
            results = await _query_federated_credentials(creds, top=top)
        elif query_type == "cross_tenant_access":
            results = await _query_cross_tenant_access(creds)
        elif query_type == "sharepoint_sites":
            results = await _query_sharepoint_sites(creds, top=top)
        elif query_type == "sensitivity_labels":
            results = await _query_sensitivity_labels(creds)
        elif query_type == "dlp_policies":
            results = await _query_dlp_policies(creds)
        else:
            results = []

        return {
            "source": "entra",
            "query_used": query_type,
            "results": results,
            "count": len(results),
        }
    except Exception as exc:
        return {
            "source": "entra",
            "query_used": query_type,
            "results": [],
            "count": 0,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Full-text evidence search
# ---------------------------------------------------------------------------

