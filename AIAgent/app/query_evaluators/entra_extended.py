"""Extended Entra / M365 query helpers (v49)."""

from __future__ import annotations
from typing import Any
from app.auth import ComplianceCredentials
from app.logger import log

async def _query_organization_info(creds: ComplianceCredentials) -> list[dict]:
    """Get tenant organization details."""
    graph = creds.get_graph_client()
    try:
        response = await graph.organization.get()
        results = []
        if response and response.value:
            for org in response.value:
                results.append({
                    "id": org.id,
                    "displayName": org.display_name,
                    "tenantType": getattr(org, "tenant_type", None),
                    "verifiedDomains": [
                        {"name": d.name, "isDefault": d.is_default, "isInitial": d.is_initial}
                        for d in (org.verified_domains or [])
                    ],
                    "createdDateTime": str(org.created_date_time) if org.created_date_time else None,
                })
        return results
    except Exception as exc:
        log.warning("Organization info query failed: %s", exc)
        return [{"error": f"Organization query failed: {exc}"}]


async def _query_security_defaults(creds: ComplianceCredentials) -> list[dict]:
    """Check if security defaults are enabled."""
    graph = creds.get_graph_client()
    try:
        policy = await graph.policies.identity_security_defaults_enforcement_policy.get()
        if policy:
            return [{
                "id": policy.id,
                "displayName": policy.display_name,
                "isEnabled": policy.is_enabled,
                "description": policy.description,
            }]
        return [{"isEnabled": "unknown", "note": "Could not retrieve policy"}]
    except Exception as exc:
        log.warning("Security defaults query failed: %s", exc)
        return [{"error": f"Security defaults query failed: {exc}"}]


async def _query_risk_detections(
    creds: ComplianceCredentials, top: int = 100,
) -> list[dict]:
    """List recent risk detections from Identity Protection."""
    graph = creds.get_graph_client()
    try:
        response = await graph.identity_protection.risk_detections.get()
        results = []
        if response and response.value:
            for d in response.value:
                results.append({
                    "id": d.id,
                    "riskEventType": d.risk_event_type,
                    "riskLevel": d.risk_level.value if d.risk_level else None,
                    "riskState": d.risk_state.value if d.risk_state else None,
                    "userDisplayName": d.user_display_name,
                    "userPrincipalName": d.user_principal_name,
                    "ipAddress": d.ip_address,
                    "detectedDateTime": str(d.detected_date_time) if d.detected_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Risk detections query failed: %s", exc)
        return [{"error": f"Risk detections query failed (needs IdentityRiskEvent.Read.All): {exc}"}]


async def _query_risky_service_principals(
    creds: ComplianceCredentials, top: int = 100,
) -> list[dict]:
    """List risky service principals from Identity Protection."""
    graph = creds.get_graph_client()
    try:
        response = await graph.identity_protection.risky_service_principals.get()
        results = []
        if response and response.value:
            for sp in response.value:
                results.append({
                    "id": sp.id,
                    "displayName": sp.display_name,
                    "appId": sp.app_id,
                    "riskLevel": sp.risk_level.value if sp.risk_level else None,
                    "riskState": sp.risk_state.value if sp.risk_state else None,
                    "riskLastUpdatedDateTime": str(sp.risk_last_updated_date_time) if sp.risk_last_updated_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Risky service principals query failed: %s", exc)
        return [{"error": f"Risky service principals query failed: {exc}"}]


async def _query_access_reviews(
    creds: ComplianceCredentials, top: int = 100,
) -> list[dict]:
    """List access review definitions."""
    graph = creds.get_graph_client()
    try:
        response = await graph.identity_governance.access_reviews.definitions.get()
        results = []
        if response and response.value:
            for ar in response.value:
                results.append({
                    "id": ar.id,
                    "displayName": ar.display_name,
                    "status": ar.status,
                    "scope": str(getattr(ar, "scope", None)),
                    "createdDateTime": str(ar.created_date_time) if ar.created_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Access reviews query failed: %s", exc)
        return [{"error": f"Access reviews query failed (needs AccessReview.Read.All): {exc}"}]


async def _query_consent_grants(
    creds: ComplianceCredentials, top: int = 200,
) -> list[dict]:
    """List OAuth2 permission grants (delegated consent)."""
    graph = creds.get_graph_client()
    try:
        response = await graph.oauth2_permission_grants.get()
        results = []
        if response and response.value:
            for g in response.value:
                results.append({
                    "id": g.id,
                    "clientId": g.client_id,
                    "consentType": g.consent_type,
                    "principalId": g.principal_id,
                    "resourceId": g.resource_id,
                    "scope": g.scope,
                })
        return results[:top]
    except Exception as exc:
        log.warning("Consent grants query failed: %s", exc)
        return [{"error": f"Consent grants query failed: {exc}"}]


async def _query_federated_credentials(
    creds: ComplianceCredentials, top: int = 100,
) -> list[dict]:
    """List federated identity credentials across app registrations."""
    graph = creds.get_graph_client()
    try:
        apps_resp = await graph.applications.get()
        results = []
        if apps_resp and apps_resp.value:
            for app in apps_resp.value:
                try:
                    fic_resp = await graph.applications.by_application_id(
                        app.id
                    ).federated_identity_credentials.get()
                    if fic_resp and fic_resp.value:
                        for fic in fic_resp.value:
                            results.append({
                                "appDisplayName": app.display_name,
                                "appId": app.app_id,
                                "credentialName": fic.name,
                                "issuer": fic.issuer,
                                "subject": fic.subject,
                                "audiences": list(fic.audiences or []),
                            })
                except Exception:
                    pass  # App may not have FIC or permission denied
        return results[:top]
    except Exception as exc:
        log.warning("Federated credentials query failed: %s", exc)
        return [{"error": f"Federated credentials query failed: {exc}"}]


async def _query_cross_tenant_access(creds: ComplianceCredentials) -> list[dict]:
    """List cross-tenant access policy partner configurations."""
    graph = creds.get_graph_client()
    try:
        response = await graph.policies.cross_tenant_access_policy.partners.get()
        results = []
        if response and response.value:
            for p in response.value:
                results.append({
                    "tenantId": p.tenant_id,
                    "isServiceProvider": getattr(p, "is_service_provider", None),
                    "inboundTrust": str(getattr(p, "inbound_trust", None)),
                    "b2bCollaborationOutbound": str(getattr(p, "b2b_collaboration_outbound", None)),
                    "b2bCollaborationInbound": str(getattr(p, "b2b_collaboration_inbound", None)),
                })
        return results
    except Exception as exc:
        log.warning("Cross-tenant access query failed: %s", exc)
        return [{"error": f"Cross-tenant access query failed: {exc}"}]


async def _query_sharepoint_sites(
    creds: ComplianceCredentials, top: int = 100,
) -> list[dict]:
    """List SharePoint sites using Graph search."""
    graph = creds.get_graph_client()
    try:
        from msgraph.generated.sites.sites_request_builder import SitesRequestBuilder
        config = SitesRequestBuilder.SitesRequestBuilderGetRequestConfiguration()
        params = SitesRequestBuilder.SitesRequestBuilderGetQueryParameters()
        params.search = "*"
        params.top = min(top, 999)
        config.query_parameters = params
        response = await graph.sites.get(request_configuration=config)
        results = []
        if response and response.value:
            for s in response.value:
                results.append({
                    "id": s.id,
                    "displayName": s.display_name,
                    "webUrl": s.web_url,
                    "createdDateTime": str(s.created_date_time) if s.created_date_time else None,
                })
        return results[:top]
    except Exception as exc:
        log.warning("SharePoint sites query failed: %s", exc)
        return [{"error": f"SharePoint sites query failed (needs Sites.Read.All): {exc}"}]


async def _query_sensitivity_labels(creds: ComplianceCredentials) -> list[dict]:
    """List sensitivity labels (Information Protection)."""
    graph = creds.get_graph_client()
    try:
        # Use the v1.0 information protection labels endpoint
        response = await graph.security.information_protection.sensitivity_labels.get()
        results = []
        if response and response.value:
            for lbl in response.value:
                results.append({
                    "id": lbl.id,
                    "name": lbl.name,
                    "description": getattr(lbl, "description", None),
                    "isActive": getattr(lbl, "is_active", None),
                    "parent": getattr(lbl, "parent", None),
                })
        return results
    except Exception as exc:
        log.warning("Sensitivity labels query failed: %s", exc)
        return [{"error": f"Sensitivity labels query failed (needs InformationProtectionPolicy.Read): {exc}"}]


async def _query_dlp_policies(creds: ComplianceCredentials) -> list[dict]:
    """List DLP policies via compliance endpoint.

    Note: MS Graph DLP policy endpoints are limited.  We attempt the
    security & compliance route; if unavailable we return a helpful note.
    """
    graph = creds.get_graph_client()
    try:
        # Try the informationProtection/policy/labels first as a proxy
        response = await graph.security.information_protection.sensitivity_labels.get()
        # DLP proper requires Security & Compliance PowerShell or
        # limited Graph beta endpoints.  Return labels as the closest proxy.
        results = []
        if response and response.value:
            for lbl in response.value:
                results.append({
                    "id": lbl.id,
                    "name": lbl.name,
                    "type": "sensitivityLabel (DLP proxy)",
                })
        if not results:
            results = [{"note": "No DLP/sensitivity labels found; full DLP policy listing requires Security & Compliance Center PowerShell."}]
        return results
    except Exception as exc:
        log.warning("DLP policies query failed: %s", exc)
        return [{"error": f"DLP policies query failed — full DLP support requires S&C PowerShell: {exc}"}]


