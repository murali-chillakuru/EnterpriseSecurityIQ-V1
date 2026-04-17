"""Backward-compatibility shim — re-exports from modular rbac_evaluators / rbac_orchestrator.

All logic has moved to:
  app.rbac_evaluators.helpers        — PRIVILEGED_ROLES, scope_level, rg_from_scope, make_assignment
  app.rbac_evaluators.tree_builder   — build_mg_tree, attach_subs_to_tree
  app.rbac_evaluators.assignment_collector — collect_mg_assignments, collect_sub_data
  app.rbac_evaluators.principal_resolver   — resolve_principals, enrich/expand/backfill
  app.rbac_evaluators.risks          — compute_stats, compute_risks, compute_rbac_score
  app.rbac_evaluators.deterministic  — sort_tree_deterministic, sort_group_members_deterministic
  app.rbac_orchestrator              — collect_rbac_data  (public entry-point)
"""

from app.rbac_orchestrator import collect_rbac_data  # noqa: F401
from app.rbac_evaluators.helpers import PRIVILEGED_ROLES  # noqa: F401