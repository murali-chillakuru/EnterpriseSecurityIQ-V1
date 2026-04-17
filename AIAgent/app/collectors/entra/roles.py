"""
Entra Directory Roles Collector
Directory roles, role assignments, PIM eligibility.
"""

from __future__ import annotations
from msgraph import GraphServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence, AccessDeniedError
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

PRIVILEGED_ROLES = [
    "Global Administrator", "Privileged Role Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Exchange Administrator", "SharePoint Administrator",
    "User Administrator", "Authentication Administrator",
    "Security Administrator", "Conditional Access Administrator",
]


@register_collector(name="roles", plane="control", source="entra", priority=50)
async def collect_entra_roles(creds: ComplianceCredentials) -> list[dict]:
    # Progressive evidence list — survives timeout cancellation.
    # The orchestrator can recover this via _partial_evidence if the coroutine
    # is cancelled by asyncio.wait_for before _collect() returns.
    collect_entra_roles._partial_evidence = []

    async def _collect():
        evidence = collect_entra_roles._partial_evidence
        graph = creds.get_graph_client()

        # Stage 1: Role definitions (fast, essential for report rendering)
        try:
            role_defs = await paginate_graph(
                graph.role_management.directory.role_definitions
            )
            for rd in role_defs:
                rname = getattr(rd, "display_name", "")
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraRoles",
                    evidence_type="entra-role-definition",
                    description=f"Role: {rname}",
                    data={
                        "RoleId": getattr(rd, "id", ""),
                        "DisplayName": rname,
                        "IsBuiltIn": getattr(rd, "is_built_in", True),
                        "IsEnabled": getattr(rd, "is_enabled", True),
                        "IsPrivileged": rname in PRIVILEGED_ROLES,
                    },
                    resource_id=getattr(rd, "id", ""), resource_type="RoleDefinition",
                ))
            log.info("  [EntraRoles] %d role definitions", len(role_defs))
        except Exception as exc:
            log.warning("  [EntraRoles] Role definitions failed: %s", exc)

        # Stage 2: Active role assignments via roleManagement
        try:
            assignments = await paginate_graph(
                graph.role_management.directory.role_assignments
            )
            for a in assignments:
                role_def_id = getattr(a, "role_definition_id", "")
                principal_id = getattr(a, "principal_id", "")
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraRoles",
                    evidence_type="entra-role-assignment",
                    description=f"Role assignment: {principal_id}",
                    data={
                        "Id": getattr(a, "id", ""),
                        "RoleDefinitionId": role_def_id,
                        "PrincipalId": principal_id,
                        "DirectoryScopeId": getattr(a, "directory_scope_id", "/"),
                    },
                    resource_id=getattr(a, "id", ""), resource_type="RoleAssignment",
                ))
            log.info("  [EntraRoles] %d active role assignments", len(assignments))
        except Exception as exc:
            log.warning("  [EntraRoles] Role assignments failed: %s", exc)

        # Stage 3: PIM eligibility schedules
        try:
            elig = await paginate_graph(
                graph.role_management.directory.role_eligibility_schedule_instances
            )
            for e in elig:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraRoles",
                    evidence_type="entra-pim-eligible-assignment",
                    description=f"PIM eligible: {getattr(e, 'principal_id', '')}",
                    data={
                        "Id": getattr(e, "id", ""),
                        "RoleDefinitionId": getattr(e, "role_definition_id", ""),
                        "PrincipalId": getattr(e, "principal_id", ""),
                        "DirectoryScopeId": getattr(e, "directory_scope_id", "/"),
                        "StartDateTime": str(getattr(e, "start_date_time", "")),
                        "EndDateTime": str(getattr(e, "end_date_time", "")),
                    },
                    resource_type="PimEligibility",
                ))
            log.info("  [EntraRoles] %d PIM eligibility schedules", len(elig))
        except AccessDeniedError as ade:
            log.warning("  [EntraRoles] PIM eligibility access denied (HTTP %d) — skipping", ade.status)
        except Exception as exc:
            log.warning("  [EntraRoles] PIM eligibility failed: %s", exc)

        # Stage 4: Directory role members (slowest — N+1 queries, most likely to timeout)
        try:
            roles = await paginate_graph(graph.directory_roles)
            for role in roles:
                rname = getattr(role, "display_name", "")
                rid = getattr(role, "id", "")
                try:
                    members = await paginate_graph(graph.directory_roles.by_directory_role_id(rid).members)
                    for m in members:
                        evidence.append(make_evidence(
                            source=Source.ENTRA, collector="EntraRoles",
                            evidence_type="entra-directory-role-member",
                            description=f"Member of {rname}: {getattr(m, 'display_name', '')}",
                            data={
                                "RoleName": rname,
                                "RoleId": rid,
                                "MemberId": getattr(m, "id", ""),
                                "MemberDisplayName": getattr(m, "display_name", ""),
                                "MemberUPN": getattr(m, "user_principal_name", ""),
                                "IsPrivilegedRole": rname in PRIVILEGED_ROLES,
                            },
                            resource_id=getattr(m, "id", ""), resource_type="DirectoryRoleMember",
                        ))
                except Exception:
                    pass
        except Exception as exc:
            log.warning("  [EntraRoles] Directory roles failed: %s", exc)

        return evidence

    return (await run_collector("EntraRoles", Source.ENTRA, _collect)).data
