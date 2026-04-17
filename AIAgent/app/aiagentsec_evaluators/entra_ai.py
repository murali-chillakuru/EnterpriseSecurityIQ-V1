"""Entra identity security evaluators for AI — service principals, conditional access, consent, workload identity, cross-tenant, privileged access."""

from __future__ import annotations

from .finding import _as_finding


def analyze_entra_ai_service_principals(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Entra service principal security for AI applications."""
    findings: list[dict] = []
    findings.extend(_check_sp_excessive_permissions(evidence_index))
    findings.extend(_check_sp_credential_expiry(evidence_index))
    findings.extend(_check_sp_no_credential_rotation(evidence_index))
    findings.extend(_check_sp_multi_tenant(evidence_index))
    findings.extend(_check_sp_no_managed_identity(evidence_index))
    findings.extend(_check_sp_ai_api_permissions(evidence_index))
    findings.extend(_check_sp_risky(evidence_index))
    findings.extend(_check_sp_privileged_roles(evidence_index))
    findings.extend(_check_sp_owner_governance(evidence_index))
    findings.extend(_check_sp_stale_disabled(evidence_index))
    return findings


def _check_sp_excessive_permissions(idx: dict) -> list[dict]:
    """Flag AI service principals with broad API permissions."""
    sps = idx.get("entra-ai-service-principal", [])
    excessive: list[dict] = []
    _HIGH_PRIV = {"directory.readwrite.all", "application.readwrite.all",
                  "user.readwrite.all", "mail.readwrite", "files.readwrite.all",
                  "sites.readwrite.all", "group.readwrite.all"}
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        perms = [p.lower() for p in data.get("APIPermissions", [])]
        high_perms = [p for p in perms if p in _HIGH_PRIV]
        if high_perms:
            excessive.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "HighPrivilegePermissions": str(high_perms),
            })
    if excessive:
        return [_as_finding(
            "entra_ai_service_principals", "sp_excessive_permissions",
            f"{len(excessive)} AI service principals have overly broad API permissions",
            "AI application service principals with high-privilege permissions "
            "(e.g., Directory.ReadWrite.All) can access and modify sensitive tenant data. "
            "Apply least-privilege principles.",
            "high", "entra_identity", excessive,
            {"Description": "Reduce API permissions to the minimum required.",
             "PortalSteps": ["Go to Entra ID > App registrations > Select the app",
                             "Go to API permissions",
                             "Remove high-privilege permissions",
                             "Add only the specific scopes required"]},
        )]
    return []


def _check_sp_credential_expiry(idx: dict) -> list[dict]:
    """Flag AI service principals with credentials expiring soon or already expired."""
    sps = idx.get("entra-ai-service-principal", [])
    expiring: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        cred_status = data.get("CredentialStatus", "")
        if cred_status in ("expired", "expiring_soon"):
            expiring.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "CredentialStatus": cred_status,
                "CredentialExpiry": data.get("CredentialExpiry", ""),
            })
    if expiring:
        return [_as_finding(
            "entra_ai_service_principals", "sp_credential_expiry",
            f"{len(expiring)} AI service principals have expired or expiring credentials",
            "AI applications with expired or soon-to-expire credentials may stop "
            "functioning or use stale secrets that have been compromised.",
            "high", "entra_identity", expiring,
            {"Description": "Rotate credentials before expiry. Use managed identity where possible.",
             "AzureCLI": "az ad app credential reset --id <app-id>",
             "PowerShell": "New-AzADAppCredential -ApplicationId <app-id> -EndDate (Get-Date).AddYears(1)",
             "PortalSteps": ["Go to Entra ID > App registrations > Select the app",
                             "Go to Certificates & secrets",
                             "Add new client secret or certificate",
                             "Remove the expired credential"]},
        )]
    return []


def _check_sp_no_credential_rotation(idx: dict) -> list[dict]:
    """Flag AI service principals with a single credential (no rotation strategy)."""
    sps = idx.get("entra-ai-service-principal", [])
    no_rotation: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        cred_count = data.get("CredentialCount", 0)
        if cred_count == 1 and not data.get("UsesManagedIdentity"):
            no_rotation.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
            })
    if no_rotation:
        return [_as_finding(
            "entra_ai_service_principals", "sp_no_credential_rotation",
            f"{len(no_rotation)} AI service principals have a single credential (no rotation)",
            "A single credential without rotation means a compromised secret cannot be "
            "replaced without downtime. Maintain overlapping credentials or use managed identity.",
            "medium", "entra_identity", no_rotation,
            {"Description": "Add a second credential for rotation or switch to managed identity.",
             "PortalSteps": ["Go to Entra ID > App registrations > Select the app",
                             "Go to Certificates & secrets",
                             "Add a second credential for zero-downtime rotation",
                             "Consider migrating to managed identity"]},
        )]
    return []


def _check_sp_multi_tenant(idx: dict) -> list[dict]:
    """Flag AI app registrations set to multi-tenant."""
    sps = idx.get("entra-ai-service-principal", [])
    multi_tenant: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("SignInAudience", "").lower() in ("azureadmultipleorgs", "azureadandpersonalmicrosoftaccount"):
            multi_tenant.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "SignInAudience": data.get("SignInAudience", ""),
            })
    if multi_tenant:
        return [_as_finding(
            "entra_ai_service_principals", "sp_multi_tenant_exposure",
            f"{len(multi_tenant)} AI apps are configured for multi-tenant sign-in",
            "Multi-tenant AI applications accept tokens from any Azure AD tenant, "
            "increasing the risk of unauthorized cross-tenant access to AI resources.",
            "medium", "entra_identity", multi_tenant,
            {"Description": "Restrict sign-in audience to single tenant unless multi-tenant is required.",
             "PortalSteps": ["Go to Entra ID > App registrations > Select the app",
                             "Go to Authentication",
                             "Under 'Supported account types', select 'Single tenant'",
                             "Save"]},
        )]
    return []


def _check_sp_no_managed_identity(idx: dict) -> list[dict]:
    """Flag AI service principals that could use managed identity but rely on credentials."""
    sps = idx.get("entra-ai-service-principal", [])
    no_mi: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("UsesManagedIdentity") and data.get("CredentialCount", 0) > 0:
            no_mi.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "CredentialCount": data.get("CredentialCount", 0),
            })
    if no_mi:
        return [_as_finding(
            "entra_ai_service_principals", "sp_no_managed_identity",
            f"{len(no_mi)} AI service principals use credentials instead of managed identity",
            "AI services with client secrets or certificates are vulnerable to credential "
            "leakage. Managed identity eliminates credential management overhead and "
            "reduces the attack surface for AI workloads.",
            "high", "entra_identity", no_mi,
            {"Description": "Migrate AI service authentication to managed identity.",
             "AzureCLI": "az ad sp update --id <sp-id> --set 'tags=[\"WindowsAzureActiveDirectoryIntegratedApp\"]'",
             "PortalSteps": ["Go to Azure portal > AI resource > Identity",
                             "Enable system-assigned managed identity",
                             "Grant RBAC roles to the managed identity",
                             "Remove client secret/certificate from app registration"]},
        )]
    return []


def _check_sp_ai_api_permissions(idx: dict) -> list[dict]:
    """Flag AI service principals with broad AI-specific resource permissions."""
    sps = idx.get("entra-ai-service-principal", [])
    over_scoped: list[dict] = []
    _AI_HIGH_PRIV = {
        "cognitiveservices.readwrite", "cognitiveservices.readwrite.all",
        "azure ai services.readwrite", "search.readwrite", "search.readwrite.all",
        "cognitiveservices contributor", "azure ai developer",
        "cognitive services contributor", "cognitive services openai contributor",
    }
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        perms = [p.lower() for p in data.get("APIPermissions", [])]
        roles = [r.lower() for r in data.get("AzureRoleAssignments", [])]
        combined = perms + roles
        ai_high = [p for p in combined if p in _AI_HIGH_PRIV]
        if ai_high:
            over_scoped.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "AIHighPrivilegePermissions": str(ai_high),
            })
    if over_scoped:
        return [_as_finding(
            "entra_ai_service_principals", "sp_ai_api_over_scoped",
            f"{len(over_scoped)} AI service principals have broad AI resource permissions",
            "Service principals with Cognitive Services Contributor or Azure AI Developer "
            "roles can deploy models, modify content filters, or exfiltrate training data. "
            "Use Cognitive Services User for inference-only workloads.",
            "high", "entra_identity", over_scoped,
            {"Description": "Reduce AI resource permissions to minimum required.",
             "PortalSteps": ["Go to Azure portal > AI resource > Access control (IAM)",
                             "Review role assignments for the service principal",
                             "Replace Contributor roles with User (read-only inference)",
                             "Apply least-privilege RBAC for AI resources"]},
        )]
    return []


def _check_sp_risky(idx: dict) -> list[dict]:
    """Flag AI service principals detected as risky by Identity Protection."""
    sps = idx.get("entra-ai-service-principal", [])
    risky: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        risk_level = data.get("RiskLevel", "none").lower()
        if risk_level in ("high", "medium"):
            risky.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "RiskLevel": data.get("RiskLevel", ""),
                "RiskState": data.get("RiskState", ""),
            })
    if risky:
        return [_as_finding(
            "entra_ai_service_principals", "sp_risky_identity_protection",
            f"{len(risky)} AI service principals flagged as risky by Identity Protection",
            "A compromised AI service principal can be used for model extraction, "
            "prompt injection at scale, or data exfiltration from the AI pipeline. "
            "Investigate and remediate immediately.",
            "critical", "entra_identity", risky,
            {"Description": "Investigate risky AI service principals and rotate credentials.",
             "PortalSteps": ["Go to Entra ID > Security > Identity Protection > Risky workload identities",
                             "Review the flagged service principals",
                             "Rotate credentials for compromised SPs",
                             "Revoke active sessions and tokens"]},
        )]
    return []


def _check_sp_privileged_roles(idx: dict) -> list[dict]:
    """Flag AI service principals holding privileged Entra directory roles."""
    sps = idx.get("entra-ai-service-principal", [])
    over_privileged: list[dict] = []
    _PRIV_ROLES = {"global administrator", "application administrator",
                   "cloud application administrator", "privileged role administrator",
                   "security administrator"}
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        directory_roles = [r.lower() for r in data.get("DirectoryRoles", [])]
        priv = [r for r in directory_roles if r in _PRIV_ROLES]
        if priv:
            over_privileged.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "PrivilegedRoles": str(priv),
            })
    if over_privileged:
        return [_as_finding(
            "entra_ai_service_principals", "sp_privileged_directory_roles",
            f"{len(over_privileged)} AI service principals hold privileged directory roles",
            "An AI SP with Application Administrator can create new app registrations, "
            "consent to scopes, and escalate its own permissions — a prime target for "
            "AI supply-chain attacks.",
            "critical", "entra_identity", over_privileged,
            {"Description": "Remove privileged directory roles from AI service principals.",
             "PortalSteps": ["Go to Entra ID > Roles and administrators",
                             "Find the role > Members > Remove AI SP",
                             "Use PIM for just-in-time access if needed",
                             "Assign least-privilege roles specific to AI workloads"]},
        )]
    return []


def _check_sp_owner_governance(idx: dict) -> list[dict]:
    """Flag AI app registrations with single owner or guest/external owners."""
    sps = idx.get("entra-ai-service-principal", [])
    poor_gov: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        owners = data.get("Owners", [])
        owner_count = len(owners) if isinstance(owners, list) else 0
        has_guest = any(
            o.get("Type", "").lower() == "guest" for o in owners
        ) if isinstance(owners, list) else False
        if owner_count == 1 or has_guest:
            poor_gov.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "OwnerCount": owner_count,
                "HasGuestOwner": has_guest,
            })
    if poor_gov:
        return [_as_finding(
            "entra_ai_service_principals", "sp_owner_governance_weak",
            f"{len(poor_gov)} AI app registrations have weak owner governance",
            "AI app registrations with a single owner create a single point of failure. "
            "Guest/external owners may lose access without notice, blocking credential "
            "rotation and permission management.",
            "medium", "entra_identity", poor_gov,
            {"Description": "Add group ownership to AI app registrations.",
             "PortalSteps": ["Go to Entra ID > App registrations > Select the app",
                             "Go to Owners > Add owners",
                             "Add a security group as owner for resilience",
                             "Remove guest/external owners"]},
        )]
    return []


def _check_sp_stale_disabled(idx: dict) -> list[dict]:
    """Flag disabled AI service principals that still have valid credentials or roles."""
    sps = idx.get("entra-ai-service-principal", [])
    stale: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("AccountEnabled") is False:
            has_creds = data.get("CredentialCount", 0) > 0
            has_roles = len(data.get("DirectoryRoles", [])) > 0 or len(data.get("AzureRoleAssignments", [])) > 0
            if has_creds or has_roles:
                stale.append({
                    "Type": "EntraServicePrincipal",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("AppId", ""),
                    "HasCredentials": has_creds,
                    "HasRoleAssignments": has_roles,
                })
    if stale:
        return [_as_finding(
            "entra_ai_service_principals", "sp_stale_disabled",
            f"{len(stale)} disabled AI service principals retain credentials or roles",
            "Disabled AI SPs with valid credentials are dormant backdoors. "
            "An attacker who re-enables the SP immediately gains access to AI resources.",
            "medium", "entra_identity", stale,
            {"Description": "Remove credentials and role assignments from disabled AI SPs.",
             "PortalSteps": ["Go to Entra ID > Enterprise applications > Filter disabled",
                             "Select the AI service principal",
                             "Remove all certificates & secrets",
                             "Remove all role assignments"]},
        )]
    return []

def analyze_entra_ai_conditional_access(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Conditional Access policy coverage for AI applications."""
    findings: list[dict] = []
    findings.extend(_check_no_ca_for_ai_apps(evidence_index))
    findings.extend(_check_no_token_lifetime_restriction(evidence_index))
    findings.extend(_check_ca_weak_policy_quality(evidence_index))
    findings.extend(_check_ca_no_session_controls(evidence_index))
    return findings


def _check_no_ca_for_ai_apps(idx: dict) -> list[dict]:
    """Flag AI app IDs not covered by any Conditional Access policy."""
    sps = idx.get("entra-ai-service-principal", [])
    uncovered: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("CoveredByCA"):
            uncovered.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
            })
    if uncovered:
        return [_as_finding(
            "entra_ai_conditional_access", "no_ca_for_ai_apps",
            f"{len(uncovered)} AI applications are not covered by Conditional Access",
            "AI applications without Conditional Access policies lack enforcement of "
            "MFA, device compliance, and location-based controls — tokens may be stolen and replayed.",
            "high", "entra_identity", uncovered,
            {"Description": "Create Conditional Access policies targeting AI application service principals.",
             "PortalSteps": ["Go to Entra ID > Security > Conditional Access",
                             "Create new policy > Target cloud apps",
                             "Add AI application IDs",
                             "Configure MFA, device compliance, and sign-in risk conditions"]},
        )]
    return []


def _check_no_token_lifetime_restriction(idx: dict) -> list[dict]:
    """Flag AI apps without token lifetime restrictions."""
    sps = idx.get("entra-ai-service-principal", [])
    no_restriction: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasTokenLifetimePolicy"):
            no_restriction.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
            })
    if no_restriction:
        return [_as_finding(
            "entra_ai_conditional_access", "no_token_lifetime_restriction",
            f"{len(no_restriction)} AI apps lack token lifetime restrictions",
            "AI application tokens without lifetime restrictions can remain valid for "
            "extended periods, increasing the window for token theft and replay attacks.",
            "medium", "entra_identity", no_restriction,
            {"Description": "Apply token lifetime policies to AI applications.",
             "PortalSteps": ["Go to Entra ID > Security > Conditional Access > Session controls",
                             "Configure sign-in frequency and persistent browser session",
                             "Or create a tokenLifetimePolicy via Graph API",
                             "Assign the policy to AI application service principals"]},
        )]
    return []


def _check_ca_weak_policy_quality(idx: dict) -> list[dict]:
    """Flag AI apps covered by CA but without MFA, device compliance, or location restrictions."""
    sps = idx.get("entra-ai-service-principal", [])
    weak_ca: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("CoveredByCA"):
            has_mfa = data.get("CARequiresMFA", False)
            has_compliant = data.get("CARequiresCompliantDevice", False)
            has_location = data.get("CAHasLocationCondition", False)
            if not has_mfa and not has_compliant and not has_location:
                weak_ca.append({
                    "Type": "EntraServicePrincipal",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("AppId", ""),
                    "CARequiresMFA": has_mfa,
                    "CARequiresCompliantDevice": has_compliant,
                    "CAHasLocationCondition": has_location,
                })
    if weak_ca:
        return [_as_finding(
            "entra_ai_conditional_access", "ca_weak_policy_quality",
            f"{len(weak_ca)} AI apps have Conditional Access without MFA, device compliance, or location restrictions",
            "CA policies targeting AI applications do not enforce MFA, device compliance, "
            "or location controls. A report-only or grant-all policy provides no real protection — "
            "stolen tokens can be replayed from any device or location.",
            "high", "entra_identity", weak_ca,
            {"Description": "Strengthen CA policies for AI apps with MFA and device compliance.",
             "PortalSteps": ["Go to Entra ID > Security > Conditional Access",
                             "Edit policies targeting AI applications",
                             "Add 'Require multifactor authentication' grant control",
                             "Add device compliance or trusted location conditions"]},
        )]
    return []


def _check_ca_no_session_controls(idx: dict) -> list[dict]:
    """Flag AI apps without Continuous Access Evaluation or sign-in frequency controls."""
    sps = idx.get("entra-ai-service-principal", [])
    no_session: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("CoveredByCA"):
            has_cae = data.get("CAEEnabled", False)
            has_signin_freq = data.get("CASignInFrequency", False)
            if not has_cae and not has_signin_freq:
                no_session.append({
                    "Type": "EntraServicePrincipal",
                    "Name": data.get("DisplayName", "Unknown"),
                    "ResourceId": data.get("AppId", ""),
                    "CAEEnabled": has_cae,
                    "CASignInFrequency": has_signin_freq,
                })
    if no_session:
        return [_as_finding(
            "entra_ai_conditional_access", "ca_no_session_controls",
            f"{len(no_session)} AI apps lack Continuous Access Evaluation or sign-in frequency controls",
            "AI apps with long-running operations (fine-tuning, RAG indexing) use tokens "
            "that remain valid until expiry. Without CAE, revoked tokens continue working — "
            "allowing continued AI access after a compromise is detected.",
            "medium", "entra_identity", no_session,
            {"Description": "Enable session controls and CAE for AI applications.",
             "PortalSteps": ["Go to Entra ID > Security > Conditional Access",
                             "Edit policies > Session > Sign-in frequency",
                             "Set sign-in frequency to 1 hour for AI apps",
                             "Enable Continuous Access Evaluation (CAE) for the tenant"]},
        )]
    return []

def analyze_entra_ai_consent(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess OAuth consent grants to AI applications."""
    findings: list[dict] = []
    findings.extend(_check_broad_user_consent(evidence_index))
    findings.extend(_check_admin_consent_high_privilege(evidence_index))
    findings.extend(_check_ai_specific_consent_scopes(evidence_index))
    return findings


def _check_broad_user_consent(idx: dict) -> list[dict]:
    """Flag user consent grants to AI apps with sensitive scopes."""
    grants = idx.get("entra-ai-consent-grant", [])
    broad: list[dict] = []
    _SENSITIVE = {"mail.read", "mail.readwrite", "files.readwrite.all",
                  "sites.readwrite.all", "user.readwrite.all", "directory.read.all"}
    for ev in grants:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("ConsentType", "").lower() == "user":
            scopes = [s.lower() for s in data.get("Scopes", [])]
            sensitive = [s for s in scopes if s in _SENSITIVE]
            if sensitive:
                broad.append({
                    "Type": "OAuthConsent",
                    "Name": data.get("AppDisplayName", "Unknown"),
                    "ResourceId": data.get("AppId", ""),
                    "ConsentedBy": data.get("UserPrincipalName", ""),
                    "SensitiveScopes": str(sensitive),
                })
    if broad:
        return [_as_finding(
            "entra_ai_consent", "broad_user_consent_to_ai_apps",
            f"{len(broad)} users granted OAuth consent to AI apps with sensitive scopes",
            "User-level consent to AI applications with mail, file, or directory access "
            "scopes may enable data exfiltration through AI agent integrations.",
            "high", "entra_identity", broad,
            {"Description": "Review and revoke excessive user consent grants.",
             "PortalSteps": ["Go to Entra ID > Enterprise applications > Consent & permissions",
                             "Review user consent grants",
                             "Revoke sensitive consents",
                             "Configure admin consent workflow to require approval"]},
        )]
    return []


def _check_admin_consent_high_privilege(idx: dict) -> list[dict]:
    """Flag admin-consented AI apps with high-privilege Graph permissions."""
    grants = idx.get("entra-ai-consent-grant", [])
    high_priv: list[dict] = []
    _HIGH_PRIV = {"directory.readwrite.all", "application.readwrite.all",
                  "rolemanagemenet.readwrite.directory", "approleassignment.readwrite.all"}
    for ev in grants:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("ConsentType", "").lower() == "admin":
            scopes = [s.lower() for s in data.get("Scopes", [])]
            high = [s for s in scopes if s in _HIGH_PRIV]
            if high:
                high_priv.append({
                    "Type": "OAuthConsent",
                    "Name": data.get("AppDisplayName", "Unknown"),
                    "ResourceId": data.get("AppId", ""),
                    "HighPrivilegeScopes": str(high),
                })
    if high_priv:
        return [_as_finding(
            "entra_ai_consent", "admin_consent_ai_high_privilege",
            f"{len(high_priv)} AI apps have admin-consented high-privilege permissions",
            "Admin-consented high-privilege permissions on AI applications provide "
            "broad tenant-level access that may be exploited through prompt injection.",
            "medium", "entra_identity", high_priv,
            {"Description": "Review admin consent grants and reduce to minimum required.",
             "PortalSteps": ["Go to Entra ID > Enterprise applications > Select the AI app",
                             "Go to Permissions > Review admin consent",
                             "Remove high-privilege permissions",
                             "Replace with delegated permissions where possible"]},
        )]
    return []


def _check_ai_specific_consent_scopes(idx: dict) -> list[dict]:
    """Flag consent grants with AI-specific scopes or to third-party AI apps."""
    grants = idx.get("entra-ai-consent-grant", [])
    ai_consent: list[dict] = []
    _AI_SCOPES = {
        "cognitiveservices.readwrite", "cognitiveservices.readwrite.all",
        "azure ai services.readwrite", "azureopenai.readwrite",
        "search.readwrite", "search.readwrite.all",
    }
    for ev in grants:
        data = ev.get("Data", ev.get("data", {}))
        scopes = [s.lower() for s in data.get("Scopes", [])]
        is_third_party = data.get("IsThirdParty", False)
        ai_scopes = [s for s in scopes if s in _AI_SCOPES]
        if ai_scopes or (is_third_party and data.get("ConsentType", "").lower() == "admin"):
            ai_consent.append({
                "Type": "OAuthConsent",
                "Name": data.get("AppDisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "AIScopes": str(ai_scopes) if ai_scopes else "tenant-wide third-party",
                "IsThirdParty": is_third_party,
                "ConsentType": data.get("ConsentType", ""),
            })
    if ai_consent:
        return [_as_finding(
            "entra_ai_consent", "ai_specific_consent_scopes",
            f"{len(ai_consent)} consent grants include AI-specific scopes or third-party AI apps",
            "Consent grants with CognitiveServices or Azure OpenAI scopes allow "
            "applications to interact with AI resources. Third-party AI apps with "
            "admin consent can exfiltrate corporate data through their AI backend — "
            "a growing shadow AI risk.",
            "high", "entra_identity", ai_consent,
            {"Description": "Review AI-specific consent grants and third-party AI app access.",
             "PortalSteps": ["Go to Entra ID > Enterprise applications > Consent & permissions",
                             "Filter for AI-related application names",
                             "Revoke consent grants with CognitiveServices scopes",
                             "Block third-party AI apps that lack corporate approval"]},
        )]
    return []


# ── 15b. AI Workload Identity ────────────────────────────────────────

def analyze_entra_ai_workload_identity(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Workload Identity Federation for AI CI/CD pipelines."""
    findings: list[dict] = []
    findings.extend(_check_wif_missing_federation(evidence_index))
    return findings


def _check_wif_missing_federation(idx: dict) -> list[dict]:
    """Flag AI service principals using password credentials without federated identity."""
    sps = idx.get("entra-ai-service-principal", [])
    no_federation: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        has_fed_cred = data.get("HasFederatedCredential", False)
        pwd_count = data.get("PasswordCredentialCount", 0)
        if pwd_count > 0 and not has_fed_cred and not data.get("UsesManagedIdentity"):
            no_federation.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "PasswordCredentialCount": pwd_count,
            })
    if no_federation:
        return [_as_finding(
            "entra_ai_workload_identity", "wif_missing_federation",
            f"{len(no_federation)} AI service principals use password secrets without Workload Identity Federation",
            "AI deployment pipelines with long-lived password secrets are vulnerable to "
            "credential theft. Workload Identity Federation (OIDC) eliminates stored secrets "
            "for CI/CD systems like GitHub Actions and Azure DevOps.",
            "medium", "entra_identity", no_federation,
            {"Description": "Migrate AI CI/CD authentication to Workload Identity Federation.",
             "AzureCLI": "az ad app federated-credential create --id <app-id> "
                         "--parameters '{\"name\":\"github-oidc\",\"issuer\":\"https://token.actions.githubusercontent.com\","
                         "\"subject\":\"repo:org/repo:ref:refs/heads/main\",\"audiences\":[\"api://AzureADTokenExchange\"]}'",
             "PortalSteps": ["Go to Entra ID > App registrations > Select the app",
                             "Go to Certificates & secrets > Federated credentials",
                             "Add credential for GitHub Actions or Azure DevOps",
                             "Remove the password credential after migration"]},
        )]
    return []


# ── 15c. AI Cross-Tenant Access ──────────────────────────────────────

def analyze_entra_ai_cross_tenant(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess cross-tenant access controls for AI service principals."""
    findings: list[dict] = []
    findings.extend(_check_cross_tenant_ai_exposure(evidence_index))
    return findings


def _check_cross_tenant_ai_exposure(idx: dict) -> list[dict]:
    """Flag multi-tenant AI SPs combined with permissive cross-tenant access policy."""
    sps = idx.get("entra-ai-service-principal", [])
    ct_policies = idx.get("entra-cross-tenant-policy", [])
    # Determine if cross-tenant policy is permissive (no default restrictions)
    policy_permissive = False
    for ev in ct_policies:
        data = ev.get("Data", ev.get("data", {}))
        # If no restrictions are configured, it's permissive
        if not data.get("HasInboundRestrictions", True):
            policy_permissive = True

    exposed: list[dict] = []
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        audience = data.get("SignInAudience", "").lower()
        is_multi = audience in ("azureadmultipleorgs", "azureadandpersonalmicrosoftaccount")
        if is_multi and policy_permissive:
            exposed.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "SignInAudience": data.get("SignInAudience", ""),
                "CrossTenantPolicyPermissive": True,
            })
    if exposed:
        return [_as_finding(
            "entra_ai_cross_tenant", "cross_tenant_ai_exposure",
            f"{len(exposed)} multi-tenant AI apps operate under permissive cross-tenant access policy",
            "Multi-tenant AI service principals combined with unrestricted cross-tenant "
            "access allow external tenants to access AI endpoints, model data, and inference "
            "results without additional controls.",
            "high", "entra_identity", exposed,
            {"Description": "Restrict cross-tenant access for AI applications.",
             "PortalSteps": ["Go to Entra ID > External identities > Cross-tenant access settings",
                             "Configure default inbound restrictions",
                             "Add partner-specific policies for approved tenants only",
                             "Or restrict AI apps to single-tenant sign-in audience"]},
        )]
    return []


# ── 15d. AI Privileged Access ────────────────────────────────────────

def analyze_entra_ai_privileged_access(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess PIM coverage for roles granting AI resource access."""
    findings: list[dict] = []
    findings.extend(_check_pim_missing_for_ai_roles(evidence_index))
    return findings


def _check_pim_missing_for_ai_roles(idx: dict) -> list[dict]:
    """Flag permanent (non-PIM) assignments of AI-privileged roles."""
    sps = idx.get("entra-ai-service-principal", [])
    no_pim: list[dict] = []
    _AI_ROLES = {"cognitive services contributor", "azure ai developer",
                 "cognitive services openai contributor",
                 "cognitive services openai user", "search service contributor",
                 "cognitive services user"}
    for ev in sps:
        data = ev.get("Data", ev.get("data", {}))
        roles = [r.lower() for r in data.get("AzureRoleAssignments", [])]
        ai_roles = [r for r in roles if r in _AI_ROLES]
        if ai_roles and not data.get("UsesPIM"):
            no_pim.append({
                "Type": "EntraServicePrincipal",
                "Name": data.get("DisplayName", "Unknown"),
                "ResourceId": data.get("AppId", ""),
                "PermanentAIRoles": str(ai_roles),
            })
    if no_pim:
        return [_as_finding(
            "entra_ai_privileged_access", "pim_missing_for_ai_roles",
            f"{len(no_pim)} AI identities have permanent role assignments without PIM",
            "Permanent standing access to AI resources means a compromised identity "
            "has continuous access to deploy models, read inference data, or modify "
            "content filters. Use PIM for just-in-time activation.",
            "high", "entra_identity", no_pim,
            {"Description": "Enable PIM for AI resource role assignments.",
             "PortalSteps": ["Go to Entra ID > Identity Governance > Privileged Identity Management",
                             "Select Azure resources > Find AI resource roles",
                             "Convert permanent assignments to PIM-eligible",
                             "Configure activation duration and MFA requirement"]},
        )]
    return []

