"""Targeted evidence collector for M365 Copilot readiness assessment."""

from __future__ import annotations

import logging

from app.auth import ComplianceCredentials

log = logging.getLogger(__name__)


async def _cr_collect(
    creds: ComplianceCredentials,
    subscriptions: list[dict],
) -> dict[str, list[dict]]:
    """Run targeted collection for Copilot readiness assessment."""
    from app.collectors.azure.sharepoint_onedrive import collect_sharepoint_onedrive
    from app.collectors.azure.m365_sensitivity_labels import collect_m365_sensitivity_labels
    from app.collectors.azure.copilot_studio import collect_copilot_studio
    from app.collectors.entra.conditional_access import collect_entra_conditional_access
    from app.collectors.base import make_evidence
    from app.models import Source

    index: dict[str, list[dict]] = {}

    collectors: list[tuple[str, object]] = [
        ("SharePoint/OneDrive", collect_sharepoint_onedrive(creds, subscriptions)),
        ("M365 Sensitivity Labels", collect_m365_sensitivity_labels(creds, subscriptions)),
        ("Copilot Studio", collect_copilot_studio(creds, subscriptions)),
        ("Entra Conditional Access", collect_entra_conditional_access(creds)),
    ]

    for name, coro in collectors:
        try:
            log.info("  Collecting %s …", name)
            records = await coro
            for ev in records:
                etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
                if etype:
                    index.setdefault(etype, []).append(ev)
            log.info("  %s: %d evidence records", name, len(records))
        except Exception as exc:
            log.warning("  %s collection failed: %s", name, exc)

    # ── Additional lightweight collections for Copilot readiness ──
    graph = creds.get_graph_client()

    # Subscribed SKUs (license check)
    try:
        skus_resp = await graph.subscribed_skus.get()
        skus = getattr(skus_resp, "value", []) or [] if skus_resp else []
        for sku in skus:
            sku_id = str(getattr(sku, "sku_id", "") or "")
            sku_part = getattr(sku, "sku_part_number", "") or ""
            consumed = getattr(sku, "consumed_units", 0) or 0
            prepaid = getattr(sku, "prepaid_units", None)
            enabled = getattr(prepaid, "enabled", 0) if prepaid else 0
            index.setdefault("m365-subscribed-skus", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="m365-subscribed-skus",
                description=f"Subscribed SKU: {sku_part}",
                data={
                    "SkuId": sku_id,
                    "SkuPartNumber": sku_part,
                    "ConsumedUnits": consumed,
                    "EnabledUnits": enabled,
                },
                resource_id=sku_id, resource_type="SubscribedSku",
            ))
        log.info("  SubscribedSkus: %d SKUs collected", len(skus))
    except Exception as exc:
        log.warning("  SubscribedSkus collection failed: %s", exc)

    # Access review definitions (identity governance)
    try:
        beta = creds.get_graph_beta_client()
        reviews_resp = await beta.identity_governance.access_reviews.definitions.get()
        reviews = getattr(reviews_resp, "value", []) or [] if reviews_resp else []
        for rev in reviews:
            rev_id = getattr(rev, "id", "") or ""
            display = getattr(rev, "display_name", "") or ""
            status = getattr(rev, "status", "") or ""
            scope = getattr(rev, "scope", None)
            scope_type = getattr(scope, "odata_type", "") if scope else ""
            index.setdefault("entra-access-review-definitions", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="entra-access-review-definitions",
                description=f"Access review: {display}",
                data={
                    "ReviewId": rev_id,
                    "DisplayName": display,
                    "Status": status,
                    "ScopeType": scope_type,
                },
                resource_id=rev_id, resource_type="AccessReviewDefinition",
            ))
        log.info("  AccessReviews: %d definitions collected", len(reviews))
    except Exception as exc:
        log.debug("  AccessReviews collection failed: %s", exc)

    # Organization info (data residency)
    try:
        org_resp = await graph.organization.get()
        orgs = getattr(org_resp, "value", []) or [] if org_resp else []
        for org_obj in orgs[:1]:
            org_id = getattr(org_obj, "id", "") or ""
            display = getattr(org_obj, "display_name", "") or ""
            country = getattr(org_obj, "country_letter_code", "") or ""
            pref_loc = getattr(org_obj, "preferred_data_location", "") or ""
            tenant_type = getattr(org_obj, "tenant_type", "") or ""
            index.setdefault("m365-organization-info", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="m365-organization-info",
                description=f"Organization: {display}",
                data={
                    "OrganizationId": org_id,
                    "DisplayName": display,
                    "CountryLetterCode": country,
                    "PreferredDataLocation": pref_loc,
                    "TenantType": tenant_type,
                },
                resource_id=org_id, resource_type="Organization",
            ))
        log.info("  Organization: collected (%s)", orgs[0].display_name if orgs else "none")
    except Exception as exc:
        log.debug("  Organization collection failed: %s", exc)

    # eDiscovery cases (beta)
    try:
        cases_resp = await beta.security.cases.ediscovery_cases.get()
        cases = getattr(cases_resp, "value", []) or [] if cases_resp else []
        for case in cases:
            case_id = getattr(case, "id", "") or ""
            display = getattr(case, "display_name", "") or ""
            status = getattr(case, "status", "") or ""
            index.setdefault("m365-ediscovery-cases", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="m365-ediscovery-cases",
                description=f"eDiscovery case: {display}",
                data={
                    "CaseId": case_id,
                    "DisplayName": display,
                    "Status": str(status),
                },
                resource_id=case_id, resource_type="eDiscoveryCase",
            ))
        log.info("  eDiscovery: %d cases collected", len(cases))
    except Exception as exc:
        log.debug("  eDiscovery collection failed: %s", exc)

    # Information barrier policies (beta)
    try:
        ib_resp = await beta.identity_governance.app_consent.app_consent_requests.get()
        # Use as a proxy — real IB policies are via compliance APIs
        # If we can access governance endpoints, check for IB segments
        ib_segments_resp = None
        try:
            ib_segments_resp = await beta.information_protection.policy.labels.get()
        except Exception:
            pass
        if ib_segments_resp:
            labels = getattr(ib_segments_resp, "value", []) or []
            if labels:
                index.setdefault("m365-information-barriers", []).append(make_evidence(
                    source=Source.ENTRA, collector="CopilotReadiness",
                    evidence_type="m365-information-barriers",
                    description="Information protection labels detected",
                    data={"LabelCount": len(labels)},
                    resource_id="ib-labels", resource_type="InformationBarrier",
                ))
    except Exception as exc:
        log.debug("  Information barriers collection failed: %s", exc)

    # Alert policies (beta security alerts as proxy)
    try:
        alerts_resp = await beta.security.alerts_v2.get()
        alerts = getattr(alerts_resp, "value", []) or [] if alerts_resp else []
        if alerts:
            index.setdefault("m365-alert-policies", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="m365-alert-policies",
                description=f"Security alerts: {len(alerts)} active",
                data={"AlertCount": len(alerts)},
                resource_id="m365-alerts", resource_type="AlertPolicy",
            ))
        log.info("  Alerts: %d security alerts collected", len(alerts))
    except Exception as exc:
        log.debug("  Alert policies collection failed: %s", exc)

    # Insider Risk Management (beta — may require E5 Insider Risk)
    try:
        # Try to access insider risk settings via beta graph
        irm_resp = None
        try:
            irm_resp = await beta.security.cases.get()
        except Exception:
            pass
        # If we have security cases, they may indicate IRM is active
        if irm_resp:
            irm_cases = getattr(irm_resp, "value", []) or []
            if irm_cases:
                index.setdefault("m365-insider-risk-policies", []).append(make_evidence(
                    source=Source.ENTRA, collector="CopilotReadiness",
                    evidence_type="m365-insider-risk-policies",
                    description=f"Security cases: {len(irm_cases)} detected",
                    data={"CaseCount": len(irm_cases)},
                    resource_id="m365-irm", resource_type="InsiderRiskPolicy",
                ))
    except Exception as exc:
        log.debug("  Insider Risk collection failed: %s", exc)

    # Named locations (Conditional Access — trusted networks)
    try:
        nl_resp = await beta.identity.conditional_access.named_locations.get()
        named_locs = getattr(nl_resp, "value", []) or [] if nl_resp else []
        for loc in named_locs:
            loc_id = getattr(loc, "id", "") or ""
            display = getattr(loc, "display_name", "") or ""
            is_trusted = getattr(loc, "is_trusted", False) or False
            odata = getattr(loc, "odata_type", "") or ""
            index.setdefault("entra-named-locations", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="entra-named-locations",
                description=f"Named location: {display}",
                data={
                    "LocationId": loc_id,
                    "DisplayName": display,
                    "IsTrusted": is_trusted,
                    "LocationType": odata,
                },
                resource_id=loc_id, resource_type="NamedLocation",
            ))
        log.info("  NamedLocations: %d collected", len(named_locs))
    except Exception as exc:
        log.debug("  Named locations collection failed: %s", exc)

    # PIM role assignment schedule instances (Privileged Identity Management)
    try:
        pim_resp = await beta.role_management.directory.role_assignment_schedule_instances.get()
        pim_assignments = getattr(pim_resp, "value", []) or [] if pim_resp else []
        for asgn in pim_assignments[:50]:  # Cap to avoid excessive data
            asgn_id = getattr(asgn, "id", "") or ""
            principal_id = getattr(asgn, "principal_id", "") or ""
            role_def_id = getattr(asgn, "role_definition_id", "") or ""
            assignment_type = getattr(asgn, "assignment_type", "") or ""
            member_type = getattr(asgn, "member_type", "") or ""
            index.setdefault("entra-pim-role-assignments", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="entra-pim-role-assignments",
                description=f"PIM role assignment: {role_def_id}",
                data={
                    "AssignmentId": asgn_id,
                    "PrincipalId": principal_id,
                    "RoleDefinitionId": role_def_id,
                    "AssignmentType": str(assignment_type),
                    "MemberType": str(member_type),
                },
                resource_id=asgn_id, resource_type="PIMRoleAssignment",
            ))
        log.info("  PIM: %d role assignment instances collected", len(pim_assignments))
    except Exception as exc:
        log.debug("  PIM collection failed: %s", exc)

    # Risk-based CA policies (check existing CA policies for sign-in risk levels)
    try:
        beta_policies_resp = await beta.identity.conditional_access.policies.get()
        beta_policies = getattr(beta_policies_resp, "value", []) or [] if beta_policies_resp else []
        for bp in beta_policies:
            conds = getattr(bp, "conditions", None)
            if not conds:
                continue
            risk_levels = getattr(conds, "sign_in_risk_levels", []) or []
            user_risk_levels = getattr(conds, "user_risk_levels", []) or []
            if risk_levels or user_risk_levels:
                bp_id = getattr(bp, "id", "") or ""
                display = getattr(bp, "display_name", "") or ""
                state = getattr(bp, "state", None)
                state_str = state.value if hasattr(state, "value") else str(state or "")
                index.setdefault("entra-risk-based-ca-policies", []).append(make_evidence(
                    source=Source.ENTRA, collector="CopilotReadiness",
                    evidence_type="entra-risk-based-ca-policies",
                    description=f"Risk-based CA: {display}",
                    data={
                        "PolicyId": bp_id,
                        "DisplayName": display,
                        "State": state_str,
                        "SignInRiskLevels": [str(r) for r in risk_levels],
                        "UserRiskLevels": [str(r) for r in user_risk_levels],
                    },
                    resource_id=bp_id, resource_type="RiskBasedCAPolicy",
                ))
        risk_count = len(index.get("entra-risk-based-ca-policies", []))
        log.info("  RiskBasedCA: %d risk-based policies found", risk_count)
    except Exception as exc:
        log.debug("  Risk-based CA policy collection failed: %s", exc)

    # Communication compliance policies (best effort via beta)
    try:
        # Communication compliance is accessed through Purview/compliance APIs.
        # The Graph beta endpoint for supervisory review can serve as a proxy.
        cc_resp = None
        try:
            cc_resp = await beta.security.cases.ediscovery_cases.get()
        except Exception:
            pass
        # If we have access to security/compliance endpoints, check for
        # communication compliance indicators via subscribed SKUs.
        cc_skus = index.get("m365-subscribed-skus", [])
        cc_keywords = ("communication_compliance", "insider_risk", "compliance_manager",
                       "information_protection", "m365_e5", "microsoft_365_e5")
        has_cc_sku = any(
            any(kw in (ev.get("Data", {}).get("SkuPartNumber", "") or "").lower() for kw in cc_keywords)
            for ev in cc_skus
        )
        if has_cc_sku:
            index.setdefault("m365-communication-compliance", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="m365-communication-compliance",
                description="Communication Compliance SKU detected",
                data={"HasComplianceSku": True, "SkuBased": True},
                resource_id="m365-communication-compliance", resource_type="CommunicationCompliance",
            ))
    except Exception as exc:
        log.debug("  Communication compliance collection failed: %s", exc)

    # M365 Groups & Teams inventory
    try:
        groups_resp = await graph.groups.get()
        groups = getattr(groups_resp, "value", []) or [] if groups_resp else []
        for grp in groups[:500]:
            grp_id = getattr(grp, "id", "") or ""
            display = getattr(grp, "display_name", "") or ""
            visibility = getattr(grp, "visibility", "") or ""
            group_types = [str(t) for t in (getattr(grp, "group_types", []) or [])]
            provisioning = [str(t) for t in (getattr(grp, "resource_provisioning_options", []) or [])]
            is_team = "Team" in provisioning
            is_unified = "Unified" in group_types
            if not is_unified:
                continue
            mail = getattr(grp, "mail", "") or ""
            mail_enabled = getattr(grp, "mail_enabled", False) or False
            security_enabled = getattr(grp, "security_enabled", False) or False
            created = getattr(grp, "created_date_time", None)
            created_str = str(created)[:10] if created else ""
            index.setdefault("m365-groups", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="m365-groups",
                description=f"M365 Group: {display}",
                data={
                    "GroupId": grp_id,
                    "DisplayName": display,
                    "Visibility": visibility or "Private",
                    "IsTeam": is_team,
                    "MailEnabled": mail_enabled,
                    "SecurityEnabled": security_enabled,
                    "Mail": mail,
                    "CreatedDate": created_str,
                },
                resource_id=grp_id, resource_type="M365Group",
            ))
        group_count = len(index.get("m365-groups", []))
        log.info("  M365Groups: %d unified groups collected", group_count)
    except Exception as exc:
        log.warning("  M365 Groups collection failed: %s", exc)

    # Entra ID Application Registrations
    try:
        apps_resp = await graph.applications.get()
        apps = getattr(apps_resp, "value", []) or [] if apps_resp else []
        for app in apps[:500]:
            app_id = getattr(app, "app_id", "") or ""
            display = getattr(app, "display_name", "") or ""
            created = getattr(app, "created_date_time", None)
            created_str = str(created)[:10] if created else ""
            sign_in_audience = getattr(app, "sign_in_audience", "") or ""
            # Collect required resource access (API permissions)
            req_access_list = getattr(app, "required_resource_access", []) or []
            api_permissions: list[str] = []
            has_graph = False
            for ra in req_access_list:
                res_app_id = getattr(ra, "resource_app_id", "") or ""
                if res_app_id == "00000003-0000-0000-c000-000000000000":
                    has_graph = True
                accesses = getattr(ra, "resource_access", []) or []
                for acc in accesses:
                    perm_type = getattr(acc, "type", "") or ""
                    api_permissions.append(perm_type)
            n_delegated = api_permissions.count("Scope")
            n_application = api_permissions.count("Role")
            # Key credential / certificate info
            key_creds = getattr(app, "key_credentials", []) or []
            pwd_creds = getattr(app, "password_credentials", []) or []
            index.setdefault("entra-applications", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="entra-applications",
                description=f"Entra App: {display}",
                data={
                    "AppId": app_id,
                    "DisplayName": display,
                    "CreatedDate": created_str,
                    "SignInAudience": sign_in_audience,
                    "HasGraphAccess": has_graph,
                    "DelegatedPermissions": n_delegated,
                    "ApplicationPermissions": n_application,
                    "TotalPermissions": n_delegated + n_application,
                    "CertificateCount": len(key_creds),
                    "SecretCount": len(pwd_creds),
                },
                resource_id=app_id, resource_type="EntraApplication",
            ))
        app_count = len(index.get("entra-applications", []))
        log.info("  EntraApps: %d application registrations collected", app_count)
    except Exception as exc:
        log.warning("  Entra applications collection failed: %s", exc)

    # Entra Service Principals (Enterprise Applications) with OAuth consent grants
    try:
        sp_resp = await graph.service_principals.get()
        sps = getattr(sp_resp, "value", []) or [] if sp_resp else []
        for sp in sps[:500]:
            sp_id = getattr(sp, "id", "") or ""
            sp_app_id = getattr(sp, "app_id", "") or ""
            display = getattr(sp, "display_name", "") or ""
            sp_type = getattr(sp, "service_principal_type", "") or ""
            enabled = getattr(sp, "account_enabled", True)
            if enabled is None:
                enabled = True
            app_roles_assigned = getattr(sp, "app_roles_assigned_to", []) or []
            tags = [str(t) for t in (getattr(sp, "tags", []) or [])]
            is_enterprise = "WindowsAzureActiveDirectoryIntegratedApp" in tags
            index.setdefault("entra-service-principals", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="entra-service-principals",
                description=f"Service Principal: {display}",
                data={
                    "ServicePrincipalId": sp_id,
                    "AppId": sp_app_id,
                    "DisplayName": display,
                    "Type": sp_type,
                    "Enabled": enabled,
                    "IsEnterprise": is_enterprise,
                    "AppRoleAssignmentCount": len(app_roles_assigned),
                },
                resource_id=sp_id, resource_type="ServicePrincipal",
            ))
        sp_count = len(index.get("entra-service-principals", []))
        log.info("  ServicePrincipals: %d collected", sp_count)
    except Exception as exc:
        log.warning("  Service principals collection failed: %s", exc)

    # ── Phase 6: Cross-tenant access policies ──
    try:
        cta_resp = await beta.policies.cross_tenant_access_policy.get()
        if cta_resp:
            default_inbound = getattr(cta_resp, "b2b_collaboration_inbound", None)
            default_outbound = getattr(cta_resp, "b2b_collaboration_outbound", None)
            inbound_allowed = True  # default is allow
            outbound_allowed = True
            if default_inbound:
                inb_apps = getattr(default_inbound, "applications", None)
                if inb_apps:
                    access_type = getattr(inb_apps, "access_type", "") or ""
                    if str(access_type).lower() == "blocked":
                        inbound_allowed = False
            if default_outbound:
                out_apps = getattr(default_outbound, "applications", None)
                if out_apps:
                    access_type = getattr(out_apps, "access_type", "") or ""
                    if str(access_type).lower() == "blocked":
                        outbound_allowed = False
            index.setdefault("entra-cross-tenant-access", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="entra-cross-tenant-access",
                description="Cross-tenant access default policy",
                data={
                    "PolicyId": "default",
                    "IsDefault": True,
                    "InboundAllowed": inbound_allowed,
                    "OutboundAllowed": outbound_allowed,
                },
                resource_id="cross-tenant-default", resource_type="CrossTenantAccessPolicy",
            ))
        log.info("  CrossTenantAccess: default policy collected")
    except Exception as exc:
        log.debug("  Cross-tenant access collection failed: %s", exc)

    # ── Phase 6: Graph connectors / external connections ──
    try:
        ext_conn_resp = await graph.external.connections.get()
        ext_conns = getattr(ext_conn_resp, "value", []) or [] if ext_conn_resp else []
        for conn in ext_conns:
            conn_id = getattr(conn, "id", "") or ""
            conn_name = getattr(conn, "name", "") or ""
            conn_desc = getattr(conn, "description", "") or ""
            state = getattr(conn, "state", "") or ""
            index.setdefault("m365-graph-connectors", []).append(make_evidence(
                source=Source.ENTRA, collector="CopilotReadiness",
                evidence_type="m365-graph-connectors",
                description=f"Graph connector: {conn_name}",
                data={
                    "ConnectorId": conn_id,
                    "Name": conn_name,
                    "Description": conn_desc,
                    "State": str(state),
                    "HasOwner": bool(conn_desc),  # Proxy — connectors with descriptions are more likely governed
                },
                resource_id=conn_id, resource_type="GraphConnector",
            ))
        log.info("  GraphConnectors: %d external connections collected", len(ext_conns))
    except Exception as exc:
        log.debug("  Graph connectors collection failed: %s", exc)

    # ── Phase 6: Defender Copilot-related incidents (best-effort) ──
    try:
        incidents_resp = await beta.security.incidents.get()
        incidents = getattr(incidents_resp, "value", []) or [] if incidents_resp else []
        copilot_incidents = []
        for inc in incidents[:200]:
            inc_id = getattr(inc, "id", "") or ""
            display = getattr(inc, "display_name", "") or ""
            severity = getattr(inc, "severity", "") or ""
            status = getattr(inc, "status", "") or ""
            # Filter for Copilot-related keywords
            display_lower = display.lower() if display else ""
            if any(kw in display_lower for kw in ("copilot", "ai", "prompt", "exfiltration")):
                copilot_incidents.append(make_evidence(
                    source=Source.ENTRA, collector="CopilotReadiness",
                    evidence_type="m365-defender-copilot-incidents",
                    description=f"Copilot incident: {display}",
                    data={
                        "IncidentId": inc_id,
                        "Title": display,
                        "Severity": str(severity),
                        "Status": str(status),
                    },
                    resource_id=inc_id, resource_type="SecurityIncident",
                ))
        for ev in copilot_incidents:
            index.setdefault("m365-defender-copilot-incidents", []).append(ev)
        log.info("  DefenderIncidents: %d Copilot-related incidents found", len(copilot_incidents))
    except Exception as exc:
        log.debug("  Defender incidents collection failed: %s", exc)

    return index

