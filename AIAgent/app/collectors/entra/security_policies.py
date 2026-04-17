"""
Entra Security Policies Collector
Security defaults, authorization policy, cross-tenant access.
"""

from __future__ import annotations
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="security_policies", plane="control", source="entra", priority=70)
async def collect_entra_security_policies(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()

        # Security Defaults
        try:
            sec_defaults = await graph.policies.identity_security_defaults_enforcement_policy.get()
            if sec_defaults:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraSecurityPolicies",
                    evidence_type="entra-security-defaults",
                    description="Security defaults policy",
                    data={
                        "IsEnabled": getattr(sec_defaults, "is_enabled", False),
                        "DisplayName": getattr(sec_defaults, "display_name", ""),
                    },
                    resource_type="SecurityDefaults",
                ))
        except Exception as exc:
            log.warning("  [EntraSecurityPolicies] Security defaults: %s", exc)

        # Authorization Policy
        try:
            auth_policy = await graph.policies.authorization_policy.get()
            if auth_policy:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraSecurityPolicies",
                    evidence_type="entra-authorization-policy",
                    description="Authorization policy",
                    data={
                        "AllowInvitesFrom": str(getattr(auth_policy, "allow_invites_from", "")),
                        "AllowEmailVerifiedUsersToJoinOrganization": getattr(
                            auth_policy, "allow_email_verified_users_to_join_organization", False
                        ),
                        "BlockMsolPowerShell": getattr(auth_policy, "block_msol_power_shell", False),
                        "GuestUserRoleId": str(getattr(auth_policy, "guest_user_role_id", "")),
                        "AllowedToSignUpEmailBasedSubscriptions": getattr(
                            auth_policy, "allowed_to_sign_up_email_based_subscriptions", False
                        ),
                    },
                    resource_type="AuthorizationPolicy",
                ))
        except Exception as exc:
            log.warning("  [EntraSecurityPolicies] Authorization policy: %s", exc)

        # Cross-Tenant Access Policy
        try:
            cta = await graph.policies.cross_tenant_access_policy.get()
            if cta:
                default = getattr(cta, "default_", None)
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraSecurityPolicies",
                    evidence_type="entra-cross-tenant-policy",
                    description="Cross-tenant access policy",
                    data={
                        "AllowedCloudEndpoints": [str(c) for c in (getattr(cta, "allowed_cloud_endpoints", []) or [])],
                        "HasDefault": default is not None,
                    },
                    resource_type="CrossTenantPolicy",
                ))

            # Partners
            try:
                partners = await graph.policies.cross_tenant_access_policy.partners.get()
                for p in (partners.value or []):
                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="EntraSecurityPolicies",
                        evidence_type="entra-cross-tenant-partner",
                        description=f"Cross-tenant partner: {getattr(p, 'tenant_id', '')}",
                        data={
                            "TenantId": getattr(p, "tenant_id", ""),
                            "IsServiceProvider": getattr(p, "is_service_provider", False),
                        },
                        resource_type="CrossTenantPartner",
                    ))
            except Exception:
                pass
        except Exception as exc:
            log.warning("  [EntraSecurityPolicies] Cross-tenant policy: %s", exc)

        # Password Methods Policy
        try:
            methods_policy = await graph.policies.authentication_methods_policy.get()
            if methods_policy:
                configs = getattr(methods_policy, "authentication_method_configurations", []) or []
                for config in configs:
                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="EntraSecurityPolicies",
                        evidence_type="entra-auth-method-config",
                        description=f"Auth method: {getattr(config, 'id', '')}",
                        data={
                            "Id": getattr(config, "id", ""),
                            "State": str(getattr(config, "state", "")),
                        },
                        resource_type="AuthMethodConfig",
                    ))
        except Exception as exc:
            log.warning("  [EntraSecurityPolicies] Auth methods: %s", exc)

        return evidence

    return (await run_collector("EntraSecurityPolicies", Source.ENTRA, _collect)).data
