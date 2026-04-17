"""Zero Trust posture evaluator for M365 Copilot readiness."""

from __future__ import annotations

from .finding import _cr_finding


def analyze_zero_trust(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Zero Trust posture for Copilot deployment."""
    findings: list[dict] = []
    findings.extend(_check_continuous_access_evaluation(evidence_index))
    findings.extend(_check_token_protection(evidence_index))
    findings.extend(_check_phishing_resistant_mfa(evidence_index))
    findings.extend(_check_authentication_context(evidence_index))
    findings.extend(_check_workload_identity_protection(evidence_index))
    findings.extend(_check_compliant_network(evidence_index))
    return findings


def _check_continuous_access_evaluation(idx: dict) -> list[dict]:
    """Check if Continuous Access Evaluation (CAE) is enabled via CA policies."""
    ca_policies = idx.get("entra-conditional-access-policies", [])
    if not ca_policies:
        return [_cr_finding(
            "zero_trust", "no_continuous_access_evaluation",
            "Continuous Access Evaluation (CAE) not verified — no Conditional Access data",
            "CAE enforces near-real-time token revocation when user risk changes, "
            "session is revoked, or network location changes. Without CAE, Copilot "
            "sessions may persist even after credentials are compromised or the user "
            "is disabled, allowing continued access to sensitive data.",
            "high",
            [{"Type": "CAE", "Name": "Continuous Access Evaluation",
              "ResourceId": "entra-cae"}],
            {"Description": "Enable CAE for all users and Copilot-targeted CA policies.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Protection > Conditional Access",
                 "Edit each policy targeting M365 Copilot or all cloud apps",
                 "Under Session > Customize continuous access evaluation, select 'Disable' is NOT checked",
                 "CAE is enabled by default for tenants — verify no policy disables it",
                 "Test with 'What If' to confirm CAE is active for Copilot users",
             ]},
            compliance_status="gap",
        )]
    # Check if any policy explicitly disables CAE
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        session = data.get("SessionControls", {})
        if isinstance(session, str):
            continue
        cae_mode = ""
        if isinstance(session, dict):
            cae_mode = session.get("ContinuousAccessEvaluation", "")
            if isinstance(cae_mode, dict):
                cae_mode = cae_mode.get("Mode", "")
        if str(cae_mode).lower() == "disabled":
            return [_cr_finding(
                "zero_trust", "no_continuous_access_evaluation",
                "Continuous Access Evaluation is explicitly disabled in a Conditional Access policy",
                f"Policy '{data.get('DisplayName', 'Unknown')}' disables CAE. "
                "This allows stale sessions to persist after user risk changes, "
                "potentially allowing compromised accounts to access Copilot data.",
                "high",
                [{"Type": "CAPolicy", "Name": data.get("DisplayName", "Unknown"),
                  "ResourceId": data.get("PolicyId", "")}],
                {"Description": "Remove the CAE disable setting from this policy.",
                 "PortalSteps": [
                     "Go to Microsoft Entra admin center > Protection > Conditional Access",
                     f"Edit policy: {data.get('DisplayName', 'Unknown')}",
                     "Under Session, remove 'Disable continuous access evaluation'",
                     "Save and test the policy",
                 ]},
                compliance_status="gap",
            )]
    return []


def _check_token_protection(idx: dict) -> list[dict]:
    """Check if token protection (binding) is configured in CA policies."""
    ca_policies = idx.get("entra-conditional-access-policies", [])
    has_token_protection = False
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        session = data.get("SessionControls", {})
        if isinstance(session, dict):
            tp = session.get("SignInTokenProtection", session.get("TokenProtection", ""))
            if tp:
                has_token_protection = True
                break
        grant = data.get("GrantControls", "")
        if isinstance(grant, str) and "tokenProtection" in grant.lower():
            has_token_protection = True
            break
    if not has_token_protection:
        return [_cr_finding(
            "zero_trust", "no_token_protection",
            "Token protection (token binding) is not configured in Conditional Access",
            "Token protection binds sign-in tokens to the device, preventing token "
            "theft and replay attacks. Without token binding, a stolen token can be "
            "used from any device to access Copilot and all M365 data the user has "
            "permissions for.",
            "medium",
            [{"Type": "TokenProtection", "Name": "CA Token Binding",
              "ResourceId": "entra-token-protection"}],
            {"Description": "Configure token protection in a CA policy targeting Copilot users.",
             "PowerShell": "# Token protection is configured via Conditional Access policies in Entra portal",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Protection > Conditional Access",
                 "Create or edit a policy targeting M365 Copilot users",
                 "Under Session > Token protection (preview), enable 'Require token protection'",
                 "Note: Currently supports Windows 10/11 sign-in sessions",
                 "Start in Report-only mode before enforcing",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_phishing_resistant_mfa(idx: dict) -> list[dict]:
    """Check if phishing-resistant MFA methods are required (FIDO2, WHfB, CBA)."""
    ca_policies = idx.get("entra-conditional-access-policies", [])
    has_phishing_resistant = False
    phishing_resistant_terms = (
        "fido2", "windowshelloforbusiness", "x509certificate",
        "phishingresistant", "passwordless",
    )
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        state = str(data.get("State", "")).lower()
        if state not in ("enabled", "enabledforreportingbutntenforced"):
            continue
        grant = str(data.get("GrantControls", "")).lower()
        auth_strengths = str(data.get("AuthenticationStrength", "")).lower()
        combined = grant + " " + auth_strengths
        if any(t in combined for t in phishing_resistant_terms):
            has_phishing_resistant = True
            break
    if not has_phishing_resistant:
        return [_cr_finding(
            "zero_trust", "no_phishing_resistant_mfa",
            "No Conditional Access policy requires phishing-resistant MFA methods",
            "While MFA may be enforced, the tenant does not require phishing-resistant "
            "methods (FIDO2 security keys, Windows Hello for Business, or certificate-based "
            "authentication). SMS and phone-based MFA are vulnerable to SIM-swap, "
            "real-time phishing proxies, and MFA fatigue attacks that can compromise "
            "Copilot access.",
            "medium",
            [{"Type": "MFA", "Name": "Phishing-Resistant MFA",
              "ResourceId": "entra-phishing-resistant-mfa"}],
            {"Description": "Require phishing-resistant authentication strengths via CA policy.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Protection > Authentication methods",
                 "Enable FIDO2 security keys and/or Windows Hello for Business",
                 "Create a CA policy with Grant > Require authentication strength > Phishing-resistant MFA",
                 "Target the policy to Copilot-licensed users",
                 "Gradually expand scope after pilot rollout",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_authentication_context(idx: dict) -> list[dict]:
    """Check if authentication contexts are used with sensitivity labels for step-up auth."""
    labels = idx.get("m365-sensitivity-labels", [])
    ca_policies = idx.get("entra-conditional-access-policies", [])
    # Check if any CA policy uses authentication context
    has_auth_context = False
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        conditions = data.get("Conditions", "")
        if isinstance(conditions, dict):
            auth_ctx = conditions.get("AuthenticationContext", conditions.get("authenticationContextClassReferences", ""))
            if auth_ctx:
                has_auth_context = True
                break
        cond_str = str(conditions).lower()
        if "authenticationcontext" in cond_str or "authenticationcontextclassreference" in cond_str:
            has_auth_context = True
            break
    if not has_auth_context and labels:
        return [_cr_finding(
            "zero_trust", "no_authentication_context",
            "No Conditional Access policy uses authentication context for step-up authentication",
            "Authentication contexts allow requiring stronger authentication when users "
            "access content protected by specific sensitivity labels. Without this, "
            "Copilot can surface Highly Confidential content using the same authentication "
            "level as General content.",
            "medium",
            [{"Type": "AuthContext", "Name": "Authentication Context",
              "ResourceId": "entra-auth-context"}],
            {"Description": "Create authentication contexts and link them to sensitivity labels.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Protection > Conditional Access > Authentication context",
                 "Create a context (e.g., 'Access highly confidential content')",
                 "Create a CA policy targeting the authentication context with stronger grant controls",
                 "In Microsoft Purview > Information Protection, edit the sensitivity label",
                 "Under 'Access control', assign the authentication context to the label",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_workload_identity_protection(idx: dict) -> list[dict]:
    """Check if workload identity risk policies are configured for service principals."""
    sps = idx.get("entra-service-principals", [])
    risk_policies = idx.get("entra-risk-based-ca-policies", [])
    # Check if any risk policy targets workload identities
    has_workload_risk = False
    for ev in risk_policies:
        data = ev.get("Data", ev.get("data", {}))
        # Workload identity protection uses servicePrincipalRiskLevels
        if data.get("ServicePrincipalRiskLevels"):
            has_workload_risk = True
            break
    if not has_workload_risk and sps:
        sp_count = len(sps)
        return [_cr_finding(
            "zero_trust", "workload_identity_unprotected",
            f"No workload identity risk policies detected for {sp_count} service principals",
            "Workload Identity Protection detects anomalous service principal sign-ins, "
            "credential changes, and suspicious activity. Without it, compromised service "
            "principals with Graph API access can exfiltrate organizational data that "
            "Copilot indexes.",
            "medium",
            [{"Type": "WorkloadIdentity", "Name": "Workload Identity Protection",
              "ResourceId": "entra-workload-identity",
              "ServicePrincipalCount": sp_count}],
            {"Description": "Enable workload identity risk policies in Entra ID Protection.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Protection > Identity Protection",
                 "Under 'Workload identity risk policy', configure risk-based policies",
                 "Set actions for medium and high risk detections",
                 "Note: Requires Entra Workload ID Premium license",
                 "Review workload identity risk detections regularly",
             ]},
            compliance_status="gap",
        )]
    return []


def _check_compliant_network(idx: dict) -> list[dict]:
    """Check if compliant network checks are configured via Global Secure Access."""
    ca_policies = idx.get("entra-conditional-access-policies", [])
    has_compliant_network = False
    for ev in ca_policies:
        data = ev.get("Data", ev.get("data", {}))
        grant = str(data.get("GrantControls", "")).lower()
        conditions = data.get("Conditions", "")
        cond_str = str(conditions).lower()
        if "compliantnetwork" in grant or "compliantnetwork" in cond_str:
            has_compliant_network = True
            break
    if not has_compliant_network:
        return [_cr_finding(
            "zero_trust", "no_compliant_network_check",
            "No Conditional Access policy enforces compliant network requirements",
            "Global Secure Access enables compliant network checks in Conditional Access "
            "to verify that connections to Copilot originate from managed network endpoints. "
            "Without this, Copilot can be accessed from any network including compromised "
            "or untrusted environments.",
            "low",
            [{"Type": "CompliantNetwork", "Name": "Compliant Network Check",
              "ResourceId": "entra-compliant-network"}],
            {"Description": "Configure compliant network via Global Secure Access.",
             "PortalSteps": [
                 "Go to Microsoft Entra admin center > Global Secure Access > Connect",
                 "Deploy the Global Secure Access client to managed devices",
                 "Create a CA policy with Grant > Require compliant network",
                 "Target the policy to Copilot-licensed users",
                 "Note: Requires Microsoft Entra Private Access or Internet Access license",
             ]},
            compliance_status="gap",
        )]
    return []

