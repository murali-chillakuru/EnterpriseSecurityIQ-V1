"""Query evaluators — modular split of query_engine.py."""

# Re-export public API
from .arg_queries import query_resource_graph, ARG_TEMPLATES  # noqa: F401
from .entra_queries import (  # noqa: F401
    query_entra_users, query_entra_groups, query_entra_apps,
    query_entra_service_principals, query_entra_directory_roles,
    query_entra_admin_users, query_entra_conditional_access,
    query_entra_risky_users, query_entra_named_locations,
    query_entra_auth_methods_policy, query_entra_role_assignments_pim,
)
from .resource_detail import get_resource_detail, get_entra_user_detail  # noqa: F401
from .cross_reference import cross_reference_findings  # noqa: F401
# dispatch_natural_language is accessed via query_evaluators.dispatcher (shim)
# or query_engine — NOT re-exported here to avoid circular import.
from .evidence_search import search_evidence, search_evidence_advanced  # noqa: F401
