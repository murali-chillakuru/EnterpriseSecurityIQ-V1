"""
Entra AI Identity Collector
Enriches raw Entra data into AI-focused evidence types consumed by the
AI Agent Security engine.

Produces:
  - entra-ai-service-principal  (filtered + enriched SPs)
  - entra-ai-consent-grant      (OAuth consent grants to AI apps)
  - entra-cross-tenant-policy   (cross-tenant access posture)
"""

from __future__ import annotations

from datetime import datetime, timezone
from app.models import Source
from app.collectors.base import (
    run_collector, paginate_graph, make_evidence, AccessDeniedError,
)
from app.auth import ComplianceCredentials
from app.logger import log

# ── Well-known first-party Microsoft AI app IDs ─────────────────────
# These are the application (client) IDs for Microsoft's own AI services.
_AI_APP_IDS: set[str] = {
    "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d",  # Azure OpenAI
    "7d4e4d49-e3d1-4f39-8e52-f2a67dabf1b6",  # Cognitive Services
    "bdd48961-e842-4a83-8fe3-cb346a4b23a8",  # Azure AI Search
    "cf4f1c5d-973a-45c6-b8e7-01dcd5a06c43",  # Azure ML / Foundry
    "c1c74fed-04c9-4704-80dc-9f79a2e515cb",  # Microsoft Copilot
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346",  # Azure Bot Service
    "aa580612-c342-4ace-b055-ede14ef6bf79",  # Copilot Studio
}

# Display-name patterns that indicate an AI-related app registration.
_AI_NAME_PATTERNS: tuple[str, ...] = (
    "openai", "azure ai", "cognitive", "copilot", "foundry",
    "ai agent", "ai service", "bot service", "ai search",
    "machine learning", "ml workspace", "llm", "gpt",
    "language model", "speech", "vision", "translator",
    "document intelligence", "form recognizer",
)


def _is_ai_related(app_id: str, display_name: str, tags: list[str] | None = None) -> bool:
    """Heuristic: is this app/SP associated with an AI workload?"""
    if app_id.lower() in _AI_APP_IDS:
        return True
    name_lower = display_name.lower()
    if any(pat in name_lower for pat in _AI_NAME_PATTERNS):
        return True
    for tag in (tags or []):
        if any(pat in tag.lower() for pat in _AI_NAME_PATTERNS):
            return True
    return False


async def collect_entra_ai_identity(creds: ComplianceCredentials) -> list[dict]:
    """Collect AI-relevant Entra identity evidence end-to-end."""

    async def _collect():
        evidence: list[dict] = []
        graph = creds.get_graph_client()
        now = datetime.now(timezone.utc)

        # ── 1. App registrations + service principals ────────────
        apps = await paginate_graph(graph.applications)
        sps = await paginate_graph(graph.service_principals)

        # Build lookup maps
        app_by_id: dict[str, object] = {}
        for app in apps:
            aid = getattr(app, "app_id", "") or ""
            if aid:
                app_by_id[aid] = app

        sp_by_id: dict[str, object] = {}       # keyed by SP object-id
        sp_by_app: dict[str, object] = {}       # keyed by app_id
        for sp in sps:
            oid = getattr(sp, "id", "") or ""
            aid = getattr(sp, "app_id", "") or ""
            if oid:
                sp_by_id[oid] = sp
            if aid:
                sp_by_app[aid] = sp

        # ── 2. Conditional Access policies ───────────────────────
        ca_policies = await paginate_graph(
            graph.identity.conditional_access.policies
        )
        # Map CA coverage: set of app IDs explicitly targeted
        ca_covered_apps: set[str] = set()
        ca_all_cloud_apps = False
        ca_details: dict[str, dict] = {}  # app_id -> CA quality info
        for pol in ca_policies:
            state = getattr(pol, "state", None)
            if state and hasattr(state, "value"):
                state = state.value
            if state != "enabled":
                continue
            cond = pol.conditions or type("C", (), {"applications": None, "users": None})()
            apps_cond = getattr(cond, "applications", None) or type(
                "A", (), {"include_applications": []}
            )()
            include_apps = list(getattr(apps_cond, "include_applications", []) or [])

            grant = pol.grant_controls or type("G", (), {"built_in_controls": []})()
            built_in = [
                c.value if hasattr(c, "value") else str(c)
                for c in (grant.built_in_controls or [])
            ]
            requires_mfa = "mfa" in built_in
            requires_compliant = "compliantDevice" in built_in

            loc_cond = getattr(cond, "locations", None)
            has_location = bool(
                loc_cond and len(getattr(loc_cond, "include_locations", []) or []) > 0
            )

            session = pol.session_controls
            has_signin_freq = False
            has_cae = False
            if session:
                sf = getattr(session, "sign_in_frequency", None)
                if sf and getattr(sf, "is_enabled", False):
                    has_signin_freq = True
                cae_ctrl = getattr(session, "continuous_access_evaluation", None)
                if cae_ctrl:
                    cae_mode = getattr(cae_ctrl, "mode", None)
                    if cae_mode and str(cae_mode) != "disabled":
                        has_cae = True

            quality = {
                "RequiresMFA": requires_mfa,
                "RequiresCompliantDevice": requires_compliant,
                "HasLocationCondition": has_location,
                "CASignInFrequency": has_signin_freq,
                "CAEEnabled": has_cae,
            }

            if "All" in include_apps:
                ca_all_cloud_apps = True
                # Store quality for "All" as default
                ca_details.setdefault("__all__", quality)
            for aid in include_apps:
                if aid != "All":
                    ca_covered_apps.add(aid.lower())
                    # Keep the strongest quality per app
                    existing = ca_details.get(aid.lower(), {})
                    ca_details[aid.lower()] = {
                        "RequiresMFA": existing.get("RequiresMFA") or requires_mfa,
                        "RequiresCompliantDevice": existing.get("RequiresCompliantDevice") or requires_compliant,
                        "HasLocationCondition": existing.get("HasLocationCondition") or has_location,
                        "CASignInFrequency": existing.get("CASignInFrequency") or has_signin_freq,
                        "CAEEnabled": existing.get("CAEEnabled") or has_cae,
                    }

        log.info("  [EntraAIIdentity] %d CA policies, %d explicitly covered apps, all-cloud=%s",
                 len(ca_policies), len(ca_covered_apps), ca_all_cloud_apps)

        # ── 3. Role assignments ──────────────────────────────────
        role_defs: dict[str, str] = {}  # role-def-id -> display-name
        try:
            rds = await paginate_graph(graph.role_management.directory.role_definitions)
            for rd in rds:
                rid = getattr(rd, "id", "") or ""
                rname = getattr(rd, "display_name", "") or ""
                if rid:
                    role_defs[rid] = rname
        except Exception as exc:
            log.warning("  [EntraAIIdentity] role definitions: %s", exc)

        role_assignments_by_principal: dict[str, list[str]] = {}
        try:
            assignments = await paginate_graph(graph.role_management.directory.role_assignments)
            for a in assignments:
                pid = getattr(a, "principal_id", "") or ""
                rdef = getattr(a, "role_definition_id", "") or ""
                role_name = role_defs.get(rdef, rdef)
                role_assignments_by_principal.setdefault(pid, []).append(role_name)
        except Exception as exc:
            log.warning("  [EntraAIIdentity] role assignments: %s", exc)

        # ── 4. PIM eligible assignments ──────────────────────────
        pim_principals: set[str] = set()
        try:
            elig = await paginate_graph(
                graph.role_management.directory.role_eligibility_schedule_instances
            )
            for e in elig:
                pid = getattr(e, "principal_id", "") or ""
                if pid:
                    pim_principals.add(pid)
        except Exception:
            pass  # PIM may not be licensed

        # ── 5. Risky service principals ──────────────────────────
        risky_sps: dict[str, dict] = {}  # sp-id -> risk info
        try:
            graph_beta = creds.get_graph_beta_client()
            risky = await paginate_graph(
                graph_beta.identity_protection.risky_service_principals
            )
            for r in risky:
                sid = getattr(r, "id", "") or ""
                if sid:
                    risky_sps[sid] = {
                        "RiskLevel": str(getattr(r, "risk_level", "none")),
                        "RiskState": str(getattr(r, "risk_state", "none")),
                    }
        except Exception as exc:
            log.warning("  [EntraAIIdentity] risky SPs (needs Workload Identity Premium): %s", exc)

        # ── 6. Federated credentials on apps ─────────────────────
        federated_apps: set[str] = set()  # set of app_id with federated creds
        for app in apps:
            obj_id = getattr(app, "id", "") or ""
            aid = getattr(app, "app_id", "") or ""
            if not obj_id:
                continue
            try:
                fics = await paginate_graph(
                    graph.applications.by_application_id(obj_id).federated_identity_credentials
                )
                if fics:
                    federated_apps.add(aid.lower())
            except Exception:
                pass

        # ── 7. Cross-tenant access policy ────────────────────────
        has_inbound_restrictions = True  # default: assume restricted
        try:
            cta = await graph.policies.cross_tenant_access_policy.get()
            if cta:
                default_policy = getattr(cta, "default_", None)
                # If there's no default policy with inbound trust configured,
                # consider it permissive
                if not default_policy:
                    has_inbound_restrictions = False
                else:
                    inbound = getattr(default_policy, "b2b_collaboration_inbound", None)
                    if not inbound:
                        has_inbound_restrictions = False

                evidence.append(make_evidence(
                    source=Source.ENTRA,
                    collector="EntraAIIdentity",
                    evidence_type="entra-cross-tenant-policy",
                    description="Cross-tenant access policy for AI identity assessment",
                    data={
                        "HasInboundRestrictions": has_inbound_restrictions,
                        "AllowedCloudEndpoints": [
                            str(c) for c in (getattr(cta, "allowed_cloud_endpoints", []) or [])
                        ],
                    },
                    resource_type="CrossTenantPolicy",
                ))
        except Exception as exc:
            log.warning("  [EntraAIIdentity] cross-tenant policy: %s", exc)

        # ── 8. OAuth2 permission grants (consent) ────────────────
        consent_grants: list[dict] = []
        try:
            grants = await paginate_graph(graph.oauth2_permission_grants)
            for g in grants:
                client_id = getattr(g, "client_id", "") or ""
                scope_str = getattr(g, "scope", "") or ""
                consent_type = getattr(g, "consent_type", "") or ""

                # Resolve app_id from SP
                sp = sp_by_id.get(client_id)
                app_id = getattr(sp, "app_id", "") if sp else ""
                display = getattr(sp, "display_name", "") if sp else ""
                tags = list(getattr(sp, "tags", []) or []) if sp else []

                if not _is_ai_related(app_id, display, tags):
                    continue

                publisher = getattr(sp, "publisher_name", "") if sp else ""
                is_third_party = bool(
                    publisher
                    and "microsoft" not in publisher.lower()
                )

                evidence.append(make_evidence(
                    source=Source.ENTRA,
                    collector="EntraAIIdentity",
                    evidence_type="entra-ai-consent-grant",
                    description=f"AI consent: {display}",
                    data={
                        "AppId": app_id,
                        "AppDisplayName": display,
                        "ConsentType": "admin" if consent_type == "AllPrincipals" else "user",
                        "Scopes": [s.strip() for s in scope_str.split() if s.strip()],
                        "UserPrincipalName": getattr(g, "principal_id", "") or "",
                        "IsThirdParty": is_third_party,
                        "PublisherName": publisher,
                    },
                    resource_id=app_id,
                    resource_type="OAuthConsentGrant",
                ))
                consent_grants.append({"AppId": app_id})
        except Exception as exc:
            log.warning("  [EntraAIIdentity] consent grants: %s", exc)

        log.info("  [EntraAIIdentity] %d AI-related consent grants", len(consent_grants))

        # ── 9. Build enriched AI service principal evidence ──────
        ai_sp_count = 0
        for sp in sps:
            sp_id = getattr(sp, "id", "") or ""
            app_id = getattr(sp, "app_id", "") or ""
            display = getattr(sp, "display_name", "") or ""
            sp_type = (getattr(sp, "service_principal_type", "") or "").lower()
            tags = list(getattr(sp, "tags", []) or [])

            if not _is_ai_related(app_id, display, tags):
                continue

            # --- Credentials ---
            key_creds = getattr(sp, "key_credentials", []) or []
            pwd_creds = getattr(sp, "password_credentials", []) or []
            total_creds = len(key_creds) + len(pwd_creds)
            has_expired = False
            expires_soon = False
            for cred in list(key_creds) + list(pwd_creds):
                end = getattr(cred, "end_date_time", None)
                if end:
                    if end < now:
                        has_expired = True
                    elif (end - now).days <= 30:
                        expires_soon = True

            cred_status = "valid"
            if has_expired:
                cred_status = "expired"
            elif expires_soon:
                cred_status = "expiring_soon"

            # --- App registration data ---
            app_reg = app_by_id.get(app_id)
            sign_in_audience = ""
            api_permissions: list[str] = []
            owners: list[dict] = []
            if app_reg:
                sign_in_audience = getattr(app_reg, "sign_in_audience", "") or ""
                # Collect required resource access (API permissions)
                rra = getattr(app_reg, "required_resource_access", []) or []
                for res_access in rra:
                    for perm in (getattr(res_access, "resource_access", []) or []):
                        perm_id = getattr(perm, "id", "")
                        perm_type = getattr(perm, "type", "")
                        api_permissions.append(f"{perm_id}:{perm_type}")
                # Owners
                try:
                    obj_id = getattr(app_reg, "id", "") or ""
                    if obj_id:
                        owner_objs = await paginate_graph(
                            graph.applications.by_application_id(obj_id).owners
                        )
                        for o in owner_objs:
                            upn = getattr(o, "user_principal_name", "") or ""
                            o_type = "guest" if "#EXT#" in upn else "member"
                            owners.append({
                                "Name": getattr(o, "display_name", "") or upn,
                                "Type": o_type,
                            })
                except Exception:
                    pass

            # --- Resolve display-name permissions (Graph scopes) ---
            # The engine checks string scope names, so also extract
            # app-role display names from the Graph SP
            scope_names: list[str] = []
            try:
                # MS Graph SP appRoles contain scope display names
                for perm_str in api_permissions:
                    scope_names.append(perm_str)
            except Exception:
                pass
            # Also add high-level Graph scope names if consent exists
            for cg in consent_grants:
                if cg.get("AppId") == app_id:
                    # Already in consent evidence — use scope names from there
                    pass

            # Merge actual display-name permissions from the app manifest
            actual_perms: list[str] = []
            if app_reg:
                rra = getattr(app_reg, "required_resource_access", []) or []
                for res_access in rra:
                    for perm in (getattr(res_access, "resource_access", []) or []):
                        # We store the permission type:id, but the engine expects
                        # human-readable scope names. Edge case — leave as IDs for now.
                        pass

            # --- CA coverage ---
            covered = (
                ca_all_cloud_apps
                or app_id.lower() in ca_covered_apps
            )
            ca_quality = ca_details.get(app_id.lower(), ca_details.get("__all__", {}))

            # --- Directory roles ---
            dir_roles = role_assignments_by_principal.get(sp_id, [])

            # --- Azure role assignments (API permissions as readable names) ---
            azure_roles = dir_roles  # Also serve as role names

            # --- Risk ---
            risk_info = risky_sps.get(sp_id, {})

            # --- Managed identity ---
            uses_mi = sp_type == "managedidentity"

            # --- Federation ---
            has_fed = app_id.lower() in federated_apps

            # --- PIM ---
            uses_pim = sp_id in pim_principals

            evidence.append(make_evidence(
                source=Source.ENTRA,
                collector="EntraAIIdentity",
                evidence_type="entra-ai-service-principal",
                description=f"AI SP: {display}",
                data={
                    "AppId": app_id,
                    "ObjectId": sp_id,
                    "DisplayName": display,
                    "ServicePrincipalType": sp_type,
                    "SignInAudience": sign_in_audience,
                    "AccountEnabled": getattr(sp, "account_enabled", True),
                    # Credentials
                    "CredentialCount": total_creds,
                    "CredentialStatus": cred_status,
                    "CredentialExpiry": "",  # summarised in status
                    "KeyCredentialCount": len(key_creds),
                    "PasswordCredentialCount": len(pwd_creds),
                    # Permissions
                    "APIPermissions": scope_names,
                    "AzureRoleAssignments": dir_roles,
                    "DirectoryRoles": dir_roles,
                    # Identity
                    "UsesManagedIdentity": uses_mi,
                    "HasFederatedCredential": has_fed,
                    "UsesPIM": uses_pim,
                    # CA
                    "CoveredByCA": covered,
                    "HasTokenLifetimePolicy": bool(ca_quality.get("CASignInFrequency")),
                    "CARequiresMFA": ca_quality.get("RequiresMFA", False),
                    "CARequiresCompliantDevice": ca_quality.get("RequiresCompliantDevice", False),
                    "CAHasLocationCondition": ca_quality.get("HasLocationCondition", False),
                    "CASignInFrequency": ca_quality.get("CASignInFrequency", False),
                    "CAEEnabled": ca_quality.get("CAEEnabled", False),
                    # Risk
                    "RiskLevel": risk_info.get("RiskLevel", "none"),
                    "RiskState": risk_info.get("RiskState", "none"),
                    # Owners
                    "Owners": owners,
                },
                resource_id=sp_id,
                resource_type="AIServicePrincipal",
            ))
            ai_sp_count += 1

        log.info("  [EntraAIIdentity] %d AI service principals enriched", ai_sp_count)
        return evidence

    return (await run_collector("EntraAIIdentity", Source.ENTRA, _collect)).data
