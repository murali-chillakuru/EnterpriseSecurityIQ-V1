"""Phase 7: RBAC risk identification and health scoring."""

from __future__ import annotations


def _count_tree(node: dict) -> dict:
    """Recursively count assignments and nodes in the tree."""
    c: dict = {
        "management_groups": 0,
        "subscriptions": 0,
        "resource_groups": 0,
        "resources": 0,
        "active": 0,
        "eligible": 0,
        "privileged_active": 0,
        "privileged_eligible": 0,
        "all_assignments": [],
    }
    if node["type"] == "ManagementGroup":
        c["management_groups"] += 1
    elif node["type"] == "Subscription":
        c["subscriptions"] += 1

    for a in node.get("assignments", []):
        c["active"] += 1
        c["all_assignments"].append(a)
        if a.get("is_privileged"):
            c["privileged_active"] += 1
    for a in node.get("eligible", []):
        c["eligible"] += 1
        c["all_assignments"].append(a)
        if a.get("is_privileged"):
            c["privileged_eligible"] += 1

    for rg in node.get("resource_groups", []):
        c["resource_groups"] += 1
        for a in rg.get("assignments", []):
            c["active"] += 1
            c["all_assignments"].append(a)
            if a.get("is_privileged"):
                c["privileged_active"] += 1
        for res in rg.get("resources", []):
            c["resources"] += 1
            for a in res.get("assignments", []):
                c["active"] += 1
                c["all_assignments"].append(a)
                if a.get("is_privileged"):
                    c["privileged_active"] += 1

    for child in node.get("children", []):
        cc = _count_tree(child)
        for k in ("management_groups", "subscriptions", "resource_groups", "resources",
                   "active", "eligible", "privileged_active", "privileged_eligible"):
            c[k] += cc[k]
        c["all_assignments"].extend(cc["all_assignments"])
    return c


def _count_principal_subtypes(principal_ids: set, principals: dict) -> dict[str, int]:
    """Count unique principals by sub_type."""
    counts: dict[str, int] = {}
    for pid in principal_ids:
        st = principals.get(pid, {}).get("sub_type", "Unknown")
        counts[st] = counts.get(st, 0) + 1
    return counts


def compute_stats(tree: dict, principals: dict) -> dict:
    """Compute summary statistics from the RBAC tree."""
    counts = _count_tree(tree)
    unique_principals = set()
    for a in counts["all_assignments"]:
        if a.get("principal_id"):
            unique_principals.add(a["principal_id"])
    groups_with_roles = sum(
        1 for pid in unique_principals
        if principals.get(pid, {}).get("type") == "Group"
    )
    custom_roles = sum(1 for a in counts["all_assignments"] if a.get("is_custom"))
    return {
        "management_groups": counts["management_groups"],
        "subscriptions": counts["subscriptions"],
        "resource_groups": counts["resource_groups"],
        "resources": counts["resources"],
        "total_assignments": counts["active"] + counts["eligible"],
        "active_assignments": counts["active"],
        "eligible_assignments": counts["eligible"],
        "privileged_active": counts["privileged_active"],
        "privileged_eligible": counts["privileged_eligible"],
        "unique_principals": len(unique_principals),
        "groups_with_roles": groups_with_roles,
        "custom_roles": custom_roles,
        "principal_sub_types": _count_principal_subtypes(unique_principals, principals),
    }


def compute_rbac_score(stats: dict, risks: list[dict]) -> int:
    """Compute an RBAC health score (0-100). Higher is better."""
    score = 100
    for r in risks:
        sev = r.get("severity", "medium")
        if sev == "critical":
            score -= 15
        elif sev == "high":
            score -= 8
        elif sev == "medium":
            score -= 4
        else:
            score -= 1
    total = stats.get("total_assignments", 0) or 1
    priv = stats.get("privileged_active", 0) + stats.get("privileged_eligible", 0)
    priv_ratio = priv / total
    if priv_ratio > 0.5:
        score -= 15
    elif priv_ratio > 0.3:
        score -= 8
    if stats.get("eligible_assignments", 0) == 0 and stats.get("privileged_active", 0) > 0:
        score -= 10
    return max(0, min(100, score))


def compute_risks(tree: dict, principals: dict) -> list[dict]:
    """Identify RBAC risk conditions across the tree."""
    risks: list[dict] = []
    all_a = _count_tree(tree)["all_assignments"]

    # Risk: Owner / User Access Admin at high scopes
    for a in all_a:
        if a["role_name"] in ("Owner", "User Access Administrator") and a["scope_level"] in ("ManagementGroup", "Subscription"):
            if a["status"] == "Active":
                risks.append({
                    "severity": "critical",
                    "title": f"Standing {a['role_name']} at {a['scope_level']} scope",
                    "detail": f"Principal {a['principal_id']} has active {a['role_name']} "
                              f"at {a['scope']}.",
                    "principal_id": a["principal_id"],
                    "scope": a["scope"],
                    "role_name": a["role_name"],
                    "remediation": (
                        f"Convert this standing {a['role_name']} assignment to PIM-eligible so it requires "
                        f"just-in-time activation. In Entra admin > Identity Governance > PIM > Azure resources, "
                        f"select the scope and convert the assignment to Eligible. Require MFA and justification for activation."
                    ),
                    "powershell": (
                        f"# Remove standing assignment and create PIM-eligible\n"
                        f"Remove-AzRoleAssignment -ObjectId {a['principal_id']} -RoleDefinitionName '{a['role_name']}' -Scope '{a['scope']}'\n"
                        f"New-AzRoleEligibilityScheduleRequest -Name (New-Guid) -Scope '{a['scope']}' "
                        f"-PrincipalId {a['principal_id']} -RoleDefinitionId '<role-def-id>' "
                        f"-RequestType AdminAssign -ScheduleInfoStartDateTime (Get-Date).ToUniversalTime().ToString('o')"
                    ),
                })

    # Risk: Contributor at MG scope
    for a in all_a:
        if a["role_name"] == "Contributor" and a["scope_level"] == "ManagementGroup" and a["status"] == "Active":
            risks.append({
                "severity": "high",
                "title": "Standing Contributor at Management Group scope",
                "detail": f"Principal {a['principal_id']} has active Contributor at {a['scope']}.",
                "principal_id": a["principal_id"],
                "scope": a["scope"],
                "role_name": a["role_name"],
                "remediation": (
                    "Move this Contributor assignment to a narrower scope (subscription or resource group) "
                    "or convert to PIM-eligible. Management group-level Contributor grants write access to "
                    "all child subscriptions and resources."
                ),
                "powershell": (
                    f"# Remove MG-scope Contributor\n"
                    f"Remove-AzRoleAssignment -ObjectId {a['principal_id']} -RoleDefinitionName 'Contributor' -Scope '{a['scope']}'"
                ),
            })

    # Risk: Service Principals with Owner
    for a in all_a:
        ptype = principals.get(a.get("principal_id", ""), {}).get("type", a.get("principal_type", ""))
        if ptype == "ServicePrincipal" and a["role_name"] == "Owner" and a["status"] == "Active":
            risks.append({
                "severity": "high",
                "title": "Service Principal with Owner role",
                "detail": f"SP {a['principal_id']} has Owner at {a['scope']}.",
                "principal_id": a["principal_id"],
                "scope": a["scope"],
                "role_name": a["role_name"],
                "remediation": (
                    "Replace the Owner role with a least-privilege custom role or Contributor. "
                    "Service principals with Owner can manage RBAC assignments and escalate privileges. "
                    "Review in Entra admin > Enterprise applications."
                ),
                "powershell": (
                    f"# Replace Owner with Contributor for service principal\n"
                    f"Remove-AzRoleAssignment -ObjectId {a['principal_id']} -RoleDefinitionName 'Owner' -Scope '{a['scope']}'\n"
                    f"New-AzRoleAssignment -ObjectId {a['principal_id']} -RoleDefinitionName 'Contributor' -Scope '{a['scope']}'"
                ),
            })

    # Risk: Large groups with privileged roles
    for a in all_a:
        if not a.get("is_privileged"):
            continue
        pinfo = principals.get(a.get("principal_id", ""), {})
        if pinfo.get("type") == "Group":
            members = pinfo.get("members", [])
            if len(members) > 20:
                risks.append({
                    "severity": "high",
                    "title": f"Large group ({len(members)} members) with {a['role_name']}",
                    "detail": f"Group '{pinfo.get('display_name', '')}' has {len(members)} members "
                              f"and holds {a['role_name']} at {a['scope']}.",
                    "principal_id": a["principal_id"],
                    "scope": a["scope"],
                    "role_name": a["role_name"],
                    "remediation": (
                        f"Break this large group into smaller, purpose-specific groups with fewer members. "
                        f"Consider using PIM for Groups so members must activate their group membership. "
                        f"Review membership in Entra admin > Groups."
                    ),
                    "powershell": (
                        f"# List group members for review\n"
                        f"Get-AzADGroupMember -GroupObjectId {a['principal_id']} | Select-Object DisplayName, UserPrincipalName, ObjectType"
                    ),
                })

    # Risk: Custom roles at high scopes
    for a in all_a:
        if a.get("is_custom") and a["scope_level"] in ("ManagementGroup", "Subscription") and a["status"] == "Active":
            risks.append({
                "severity": "medium",
                "title": f"Custom role '{a['role_name']}' at {a['scope_level']} scope",
                "detail": f"Custom role assigned to {a['principal_id']} at {a['scope']}. "
                          f"Custom roles may have overly broad permissions that bypass built-in guardrails.",
                "principal_id": a["principal_id"],
                "scope": a["scope"],
                "role_name": a["role_name"],
                "remediation": (
                    "Audit the custom role definition to confirm it follows least privilege. "
                    "Compare actions/dataActions with the closest built-in role. "
                    "Review in Azure Portal > Subscriptions > Access control > Roles > Custom."
                ),
                "powershell": (
                    f"# View custom role definition\n"
                    f"Get-AzRoleDefinition -Name '{a['role_name']}' | ConvertTo-Json -Depth 5"
                ),
            })

    # Risk: Service principals with Contributor at broad scopes
    for a in all_a:
        ptype = principals.get(a.get("principal_id", ""), {}).get("type", a.get("principal_type", ""))
        if ptype == "ServicePrincipal" and a["role_name"] == "Contributor" and a["scope_level"] in ("ManagementGroup", "Subscription") and a["status"] == "Active":
            risks.append({
                "severity": "medium",
                "title": f"Service Principal with Contributor at {a['scope_level']} scope",
                "detail": f"SP {a['principal_id']} has Contributor at {a['scope']}. "
                          f"Broad SP access increases blast radius if credentials are compromised.",
                "principal_id": a["principal_id"],
                "scope": a["scope"],
                "role_name": a["role_name"],
                "remediation": (
                    "Scope the service principal to specific resource groups. Use managed identities "
                    "where possible. Enable credential rotation and monitor sign-in activity."
                ),
                "powershell": (
                    f"# Move assignment to narrower scope\n"
                    f"Remove-AzRoleAssignment -ObjectId {a['principal_id']} -RoleDefinitionName 'Contributor' -Scope '{a['scope']}'\n"
                    f"New-AzRoleAssignment -ObjectId {a['principal_id']} -RoleDefinitionName 'Contributor' -Scope '/subscriptions/<sub>/resourceGroups/<rg>'"
                ),
            })

    # Deduplicate by (title, principal_id, scope)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for r in risks:
        key = (r["title"], r.get("principal_id", ""), r.get("scope", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    deduped.sort(key=lambda r: (
        order.get(r["severity"], 9),
        r.get("title", ""),
        r.get("principal_id", ""),
        r.get("scope", ""),
    ))
    return deduped
