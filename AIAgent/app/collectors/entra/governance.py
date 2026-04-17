"""
Entra Governance Collector
PIM settings, access reviews, entitlement management, terms of use.
"""

from __future__ import annotations
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence, AccessDeniedError
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="governance", plane="control", source="entra", priority=80)
async def collect_entra_governance(creds: ComplianceCredentials) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()
        graph_beta = creds.get_graph_beta_client()

        # PIM Role Management Policy Rules (activation settings)
        # Uses beta Graph API — PIM governance endpoints have better coverage on beta
        try:
            policies = await paginate_graph(
                graph_beta.policies.role_management_policies
            )
            for policy in policies:
                pid = getattr(policy, "id", "")
                scope = getattr(policy, "scope_id", "")
                scope_type = getattr(policy, "scope_type", "")

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraGovernance",
                    evidence_type="entra-pim-policy",
                    description=f"PIM policy: {pid}",
                    data={
                        "PolicyId": pid,
                        "ScopeId": scope,
                        "ScopeType": scope_type,
                        "DisplayName": getattr(policy, "display_name", ""),
                    },
                    resource_type="PimPolicy",
                ))

                # Policy rules (activation duration, MFA requirements)
                try:
                    rules = await graph_beta.policies.role_management_policies.by_unified_role_management_policy_id(pid).rules.get()
                    for rule in (rules.value or []):
                        rule_type = getattr(rule, "odata_type", "")
                        rule_id = getattr(rule, "id", "")

                        data = {
                            "PolicyId": pid,
                            "RuleId": rule_id,
                            "RuleType": rule_type,
                        }

                        # Extract activation duration if present
                        if hasattr(rule, "maximum_duration"):
                            data["MaximumDuration"] = str(getattr(rule, "maximum_duration", ""))
                        if hasattr(rule, "is_enabled"):
                            data["IsEnabled"] = getattr(rule, "is_enabled", False)
                        if hasattr(rule, "is_mfa_required"):
                            data["IsMfaRequired"] = getattr(rule, "is_mfa_required", False)

                        evidence.append(make_evidence(
                            source=Source.ENTRA, collector="EntraGovernance",
                            evidence_type="entra-pim-policy-rule",
                            description=f"PIM rule: {rule_id}",
                            data=data,
                            resource_type="PimPolicyRule",
                        ))
                except AccessDeniedError:
                    raise  # Let run_collector produce access-denied marker
                except Exception as exc:
                    log.warning("  [EntraGovernance] PIM policy rules for %s failed: %s", pid, exc)
            log.info("  [EntraGovernance] %d PIM policies", len(policies))
        except AccessDeniedError:
            raise  # Let run_collector produce access-denied marker
        except Exception as exc:
            log.warning("  [EntraGovernance] PIM policies failed: %s", exc)

        # Access Reviews
        try:
            reviews = await paginate_graph(
                graph.identity_governance.access_reviews.definitions
            )
            for rev in reviews:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraGovernance",
                    evidence_type="entra-access-review",
                    description=f"Review: {getattr(rev, 'display_name', '')}",
                    data={
                        "ReviewId": getattr(rev, "id", ""),
                        "DisplayName": getattr(rev, "display_name", ""),
                        "Status": getattr(rev, "status", ""),
                        "Scope": str(getattr(rev, "scope", "")),
                    },
                    resource_type="AccessReview",
                ))
            log.info("  [EntraGovernance] %d access reviews", len(reviews))
        except Exception as exc:
            log.warning("  [EntraGovernance] Access reviews failed: %s", exc)

        # Entitlement Management - Access Packages
        try:
            packages = await paginate_graph(
                graph.identity_governance.entitlement_management.access_packages
            )
            for pkg in packages:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraGovernance",
                    evidence_type="entra-access-package",
                    description=f"Package: {getattr(pkg, 'display_name', '')}",
                    data={
                        "PackageId": getattr(pkg, "id", ""),
                        "DisplayName": getattr(pkg, "display_name", ""),
                        "IsHidden": getattr(pkg, "is_hidden", False),
                    },
                    resource_type="AccessPackage",
                ))
            log.info("  [EntraGovernance] %d access packages", len(packages))
        except Exception as exc:
            log.warning("  [EntraGovernance] Access packages failed: %s", exc)

        # Terms of Use
        try:
            agreements = await paginate_graph(
                graph.identity_governance.terms_of_use.agreements
            )
            for a in agreements:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraGovernance",
                    evidence_type="entra-terms-of-use",
                    description=f"ToU: {getattr(a, 'display_name', '')}",
                    data={
                        "AgreementId": getattr(a, "id", ""),
                        "DisplayName": getattr(a, "display_name", ""),
                        "IsPerDeviceAcceptanceRequired": getattr(a, "is_per_device_acceptance_required", False),
                        "IsViewingBeforeAcceptanceRequired": getattr(a, "is_viewing_before_acceptance_required", False),
                    },
                    resource_type="TermsOfUse",
                ))
        except Exception as exc:
            log.warning("  [EntraGovernance] Terms of use failed: %s", exc)

        return evidence

    return (await run_collector("EntraGovernance", Source.ENTRA, _collect)).data
