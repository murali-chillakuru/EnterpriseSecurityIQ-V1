"""Backward-compat shim — delegates to modular query_evaluators/."""

# ARG queries
from app.query_evaluators.arg_queries import query_resource_graph, ARG_TEMPLATES  # noqa: F401

# Entra queries
from app.query_evaluators.entra_queries import (  # noqa: F401
    query_entra_users, query_entra_groups, query_entra_apps,
    query_entra_service_principals, query_entra_directory_roles,
    query_entra_admin_users, query_entra_conditional_access,
    query_entra_risky_users, query_entra_named_locations,
    query_entra_auth_methods_policy, query_entra_role_assignments_pim,
)

# Resource detail
from app.query_evaluators.resource_detail import (  # noqa: F401
    get_resource_detail, get_entra_user_detail,
)

# Cross-reference
from app.query_evaluators.cross_reference import cross_reference_findings  # noqa: F401

# NL dispatcher
from app.query_evaluators.dispatcher import dispatch_natural_language  # noqa: F401

# Evidence search
from app.query_evaluators.evidence_search import (  # noqa: F401
    search_evidence, search_evidence_advanced,
)

# Extended Entra helpers (used by collectors/orchestrators)
from app.query_evaluators.entra_extended import (  # noqa: F401
    _query_organization_info, _query_security_defaults,
    _query_risk_detections, _query_risky_service_principals,
    _query_access_reviews, _query_consent_grants,
    _query_federated_credentials, _query_cross_tenant_access,
    _query_sharepoint_sites, _query_sensitivity_labels,
    _query_dlp_policies,
)

# Entra dispatcher
from app.query_evaluators.entra_dispatcher import _run_entra_query  # noqa: F401
