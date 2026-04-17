"""Apply Phase G changes to the codebase files on disk."""
import re


def patch_file(path, old, new):
    content = open(path, encoding="utf-8").read()
    if old not in content:
        print(f"  WARNING: patch target not found in {path}")
        print(f"    Looking for: {old[:80]}...")
        return False
    count = content.count(old)
    if count > 1:
        print(f"  WARNING: {count} matches in {path}, replacing first")
    content = content.replace(old, new, 1)
    open(path, "w", encoding="utf-8").write(content)
    print(f"  OK: patched {path}")
    return True


# ============ 1. ENGINE: Add docstring entries ============
ENGINE = "app/ai_agent_security_engine.py"

patch_file(ENGINE,
    '     9e. Registry Security              — public access, RBAC\n\n  C. Custom Agent Security  (cross-cutting)',
    '     9e. Registry Security              — public access, RBAC\n     9f. Connection Security            — connection auth types\n     9g. Serverless Endpoints           — serverless endpoint security\n     9h. Workspace Diagnostics          — diagnostic settings on workspaces\n     9i. Prompt Shield Security         — prompt injection protection\n     9j. Model Catalog Governance       — model catalog security\n     9k. Data Exfiltration Prevention   — data exfiltration controls\n     9L. Agent Identity Security        — Entra Agent ID, shared vs distinct identity\n     9m. Agent Application Security     — published agent audit, auth policy\n\n  C. Custom Agent Security  (cross-cutting)')

# ============ 2. ENGINE: Add new analyze functions ============
NEW_FUNCTIONS = '''

# ── 9L. Agent Identity Security ──────────────────────────────────────

def analyze_foundry_agent_identity(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Entra Agent ID and identity posture for Foundry projects."""
    findings: list[dict] = []
    findings.extend(_check_project_no_managed_identity(evidence_index))
    findings.extend(_check_project_shared_identity(evidence_index))
    findings.extend(_check_agent_identity_permission_drift(evidence_index))
    return findings


def _check_project_no_managed_identity(idx: dict) -> list[dict]:
    """Flag Foundry projects without a managed identity configured."""
    projects = idx.get("foundry-project", [])
    no_mi: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasManagedIdentity"):
            no_mi.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_mi:
        return [_as_finding(
            "foundry_agent_identity", "project_no_managed_identity",
            f"{len(no_mi)} Foundry projects lack managed identity",
            "Foundry projects require a system-assigned managed identity to issue "
            "federated credentials for Entra Agent ID. Without it, agents cannot "
            "obtain scoped tokens for downstream resources.",
            "high", "foundry", no_mi,
            {"Description": "Enable system-assigned managed identity on Foundry projects.",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Select the project",
                             "Go to Settings > Identity",
                             "Enable system-assigned managed identity",
                             "Grant necessary RBAC roles to the identity"]},
        )]
    return []


def _check_project_shared_identity(idx: dict) -> list[dict]:
    """Flag projects where multiple agents share a single project identity."""
    projects = idx.get("foundry-project", [])
    apps = idx.get("foundry-agent-application", [])
    shared: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        project_id = data.get("ProjectId", "")
        published = [
            a for a in apps
            if (a.get("Data", a.get("data", {})).get("ProjectId", "") == project_id)
        ]
        unpublished_count = data.get("AgentCount", 0) - len(published)
        if unpublished_count > 1:
            shared.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": project_id,
                "UnpublishedAgents": unpublished_count,
                "PublishedAgents": len(published),
            })
    if shared:
        return [_as_finding(
            "foundry_agent_identity", "shared_project_identity",
            f"{len(shared)} projects have multiple agents sharing a single identity",
            "Unpublished agents in a Foundry project share one project-level identity. "
            "This means all agents get the same permissions, preventing least-privilege "
            "isolation. Publishing agents creates distinct Entra Agent IDs.",
            "medium", "foundry", shared,
            {"Description": "Publish agents to create distinct Entra Agent IDs.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Select each agent and click \'Publish\'",
                             "Each published agent receives a unique Entra Agent Identity",
                             "Assign RBAC roles per-agent on their Agent Application scope"]},
        )]
    return []


def _check_agent_identity_permission_drift(idx: dict) -> list[dict]:
    """Flag published agent apps without RBAC assignments (permission drift risk)."""
    apps = idx.get("foundry-agent-application", [])
    no_rbac: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasRBACAssignments"):
            no_rbac.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "ProjectName": data.get("ProjectName", ""),
            })
    if no_rbac:
        return [_as_finding(
            "foundry_agent_identity", "agent_permission_drift",
            f"{len(no_rbac)} published agent applications lack RBAC assignments",
            "Published agents with distinct Entra Agent IDs but no explicit RBAC "
            "assignments may inherit overly broad permissions from the project identity, "
            "violating least-privilege. Assign scoped roles on the Agent Application resource.",
            "high", "foundry", no_rbac,
            {"Description": "Assign Azure AI User role on each Agent Application scope.",
             "AzureCLI": "az role assignment create --assignee <agent-identity-object-id> "
                         "--role \'Azure AI User\' --scope <agent-application-resource-id>",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Projects > Agent Applications",
                             "Select the agent application",
                             "Go to Access Control (IAM)",
                             "Add role assignment with minimum required permissions"]},
        )]
    return []


# ── 9m. Agent Application Security ──────────────────────────────────

def analyze_foundry_agent_application(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess published agent applications and their deployment posture."""
    findings: list[dict] = []
    findings.extend(_check_agent_app_public_endpoint(evidence_index))
    findings.extend(_check_agent_app_no_auth(evidence_index))
    findings.extend(_check_agent_deployment_unhealthy(evidence_index))
    return findings


def _check_agent_app_public_endpoint(idx: dict) -> list[dict]:
    """Flag agent applications with public endpoint exposure."""
    apps = idx.get("foundry-agent-application", [])
    public: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsPublicEndpoint", True):
            public.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "EndpointUrl": data.get("EndpointUrl", ""),
                "Protocol": data.get("Protocol", ""),
            })
    if public:
        return [_as_finding(
            "foundry_agent_application", "public_endpoint_exposure",
            f"{len(public)} agent applications expose public endpoints",
            "Published agents with public endpoints can be reached from the internet. "
            "For agents handling sensitive data, restrict access via private endpoints "
            "or IP restrictions and apply RBAC-based authentication.",
            "high", "foundry", public,
            {"Description": "Restrict agent application endpoints to private networks.",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Agent Applications",
                             "Select the agent application",
                             "Configure network restrictions or private endpoints",
                             "Ensure RBAC authentication is enforced at the endpoint"]},
        )]
    return []


def _check_agent_app_no_auth(idx: dict) -> list[dict]:
    """Flag agent applications without RBAC or authentication policy."""
    apps = idx.get("foundry-agent-application", [])
    no_auth: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        auth_type = str(data.get("AuthenticationType", "")).lower()
        if not auth_type or auth_type in ("none", "anonymous"):
            no_auth.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "AuthenticationType": data.get("AuthenticationType", "None"),
            })
    if no_auth:
        return [_as_finding(
            "foundry_agent_application", "no_auth_policy",
            f"{len(no_auth)} agent applications lack authentication policies",
            "Agent applications without authentication allow unauthenticated callers. "
            "Configure RBAC-based auth (Azure AI User role) or Bot Service channel auth.",
            "critical", "foundry", no_auth,
            {"Description": "Configure authentication on agent applications.",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Agent Applications",
                             "Select the agent application",
                             "Configure authentication to require Azure AI User RBAC role",
                             "Alternatively, configure Bot Service channel authentication"]},
        )]
    return []


def _check_agent_deployment_unhealthy(idx: dict) -> list[dict]:
    """Flag agent deployments in non-running/unhealthy state."""
    deployments = idx.get("foundry-agent-deployment", [])
    unhealthy: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        state = str(data.get("ProvisioningState", "")).lower()
        if state and state not in ("succeeded", "running"):
            unhealthy.append({
                "Type": "AgentDeployment",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "ApplicationName": data.get("ApplicationName", ""),
                "ProvisioningState": data.get("ProvisioningState", ""),
            })
    if unhealthy:
        return [_as_finding(
            "foundry_agent_application", "deployment_unhealthy",
            f"{len(unhealthy)} agent deployments are in unhealthy state",
            "Agent deployments not in Succeeded/Running state may indicate failed "
            "provisioning, resource constraints, or configuration issues that affect "
            "agent availability and security posture monitoring.",
            "medium", "foundry", unhealthy,
            {"Description": "Investigate and remediate unhealthy agent deployments.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Agent Applications > Deployments",
                             "Check provisioning state and error details",
                             "Remediate configuration issues and redeploy"]},
        )]
    return []

'''

patch_file(ENGINE,
    '    return []\n\n\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================',
    '    return []\n' + NEW_FUNCTIONS + '\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================')

# ============ 3. ENGINE: Wire into orchestrator ============
patch_file(ENGINE,
    '    foundry_data_exfil_findings = analyze_foundry_data_exfiltration(evidence_index)\n\n    # C. Custom Agent Security',
    '    foundry_data_exfil_findings = analyze_foundry_data_exfiltration(evidence_index)\n\n    log.info("Running Foundry agent identity analysis …")\n    foundry_agent_identity_findings = analyze_foundry_agent_identity(evidence_index)\n\n    log.info("Running Foundry agent application analysis …")\n    foundry_agent_app_findings = analyze_foundry_agent_application(evidence_index)\n\n    # C. Custom Agent Security')

# ============ 4. ENGINE: Update all_findings ============
patch_file(ENGINE,
    '        + foundry_data_exfil_findings\n        + custom_api_findings',
    '        + foundry_data_exfil_findings\n        + foundry_agent_identity_findings + foundry_agent_app_findings\n        + custom_api_findings')

# ============ 5. ENGINE: Update EvidenceSummary ============
patch_file(ENGINE,
    '            "Serverless": fs.get("ServerlessEndpoints", 0),\n            "AccessDeniedErrors": fs.get("AccessDeniedErrors", 0),',
    '            "Serverless": fs.get("ServerlessEndpoints", 0),\n            "FoundryProjects_New": fs.get("FoundryProjectsNew", 0),\n            "AgentApplications": fs.get("AgentApplications", 0),\n            "AgentDeployments": fs.get("AgentDeployments", 0),\n            "AccessDeniedErrors": fs.get("AccessDeniedErrors", 0),')

# ============ 6. ENGINE: Update Categories ============
patch_file(ENGINE,
    '            "foundry_data_exfiltration": foundry_data_exfil_findings,\n            "custom_api_security": custom_api_findings,',
    '            "foundry_data_exfiltration": foundry_data_exfil_findings,\n            "foundry_agent_identity": foundry_agent_identity_findings,\n            "foundry_agent_application": foundry_agent_app_findings,\n            "custom_api_security": custom_api_findings,')

# ============ 7. ENGINE: Update CategoryCounts ============
patch_file(ENGINE,
    '            "foundry_data_exfiltration": len(foundry_data_exfil_findings),\n            "custom_api_security": len(custom_api_findings),',
    '            "foundry_data_exfiltration": len(foundry_data_exfil_findings),\n            "foundry_agent_identity": len(foundry_agent_identity_findings),\n            "foundry_agent_application": len(foundry_agent_app_findings),\n            "custom_api_security": len(custom_api_findings),')

print("\n=== Engine patches done ===\n")

# ============ 8. COLLECTOR: Add new evidence collection ============
COLLECTOR = "app/collectors/azure/foundry_config.py"

COLLECTOR_INSERT = '''
            # ── 12. Foundry projects (CognitiveServices subresources) ─
            ai_services_accounts = [
                ev for ev in evidence
                if ev.get("EvidenceType") == "azure-ai-service"
                and (ev.get("Data", ev.get("data", {})).get("SubscriptionId") == sub_id)
                and str(ev.get("Data", ev.get("data", {})).get("Kind", "")).lower() in ("aiservices", "openai", "azureopenai")
            ]

            for acct_ev in ai_services_accounts:
                acct_data = acct_ev.get("Data", acct_ev.get("data", {}))
                acct_id = acct_data.get("AccountId", "")
                acct_name = acct_data.get("Name", "")
                if not acct_id:
                    continue

                # ── 12a. List projects under this account ────────────
                async with _CONCURRENCY:
                    try:
                        proj_url = (
                            f"https://management.azure.com{acct_id}"
                            f"/projects?api-version=2025-04-01-preview"
                        )
                        proj_resp = await _arm_get(creds, proj_url)
                        projects = (proj_resp or {}).get("value", [])

                        for proj in projects:
                            proj_props = proj.get("properties", {})
                            proj_identity = proj.get("identity", {})
                            identity_type = (proj_identity.get("type", "") or "") if proj_identity else ""

                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="FoundryConfig",
                                evidence_type="foundry-project",
                                description=f"Foundry project: {proj.get(\'name\', \'\')} on {acct_name}",
                                data={
                                    "ProjectId": proj.get("id", ""),
                                    "Name": proj.get("name", ""),
                                    "AccountId": acct_id,
                                    "AccountName": acct_name,
                                    "Location": proj.get("location", ""),
                                    "IdentityType": identity_type,
                                    "HasManagedIdentity": "systemassigned" in identity_type.lower() if identity_type else False,
                                    "ProvisioningState": proj_props.get("provisioningState", ""),
                                    "AgentCount": proj_props.get("agentCount", 0),
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=proj.get("id", ""), resource_type="FoundryProject",
                            ))

                            # ── 12b. Agent Applications under project ─
                            proj_id = proj.get("id", "")
                            if proj_id:
                                try:
                                    app_url = (
                                        f"https://management.azure.com{proj_id}"
                                        f"/applications?api-version=2025-04-01-preview"
                                    )
                                    app_resp = await _arm_get(creds, app_url)
                                    applications = (app_resp or {}).get("value", [])

                                    for app in applications:
                                        app_props = app.get("properties", {})

                                        # Check RBAC on application
                                        has_rbac = False
                                        app_id = app.get("id", "")
                                        if app_id:
                                            try:
                                                rbac_url = (
                                                    f"https://management.azure.com{app_id}"
                                                    f"/providers/Microsoft.Authorization/roleAssignments"
                                                    f"?api-version=2022-04-01"
                                                )
                                                rbac_resp = await _arm_get(creds, rbac_url)
                                                rbac_assignments = (rbac_resp or {}).get("value", [])
                                                has_rbac = len(rbac_assignments) > 0
                                            except Exception:
                                                pass

                                        evidence.append(make_evidence(
                                            source=Source.AZURE, collector="FoundryConfig",
                                            evidence_type="foundry-agent-application",
                                            description=f"Agent app: {app.get(\'name\', \'\')} in {proj.get(\'name\', \'\')}",
                                            data={
                                                "ApplicationId": app_id,
                                                "Name": app.get("name", ""),
                                                "ProjectId": proj_id,
                                                "ProjectName": proj.get("name", ""),
                                                "AccountName": acct_name,
                                                "EndpointUrl": app_props.get("endpointUrl", ""),
                                                "Protocol": app_props.get("protocol", ""),
                                                "AuthenticationType": app_props.get("authenticationType", ""),
                                                "IsPublicEndpoint": str(app_props.get("publicNetworkAccess", "Enabled")).lower() != "disabled",
                                                "HasRBACAssignments": has_rbac,
                                                "ProvisioningState": app_props.get("provisioningState", ""),
                                                "SubscriptionId": sub_id,
                                            },
                                            resource_id=app_id, resource_type="AgentApplication",
                                        ))

                                        # ── 12c. Agent Deployments ───
                                        if app_id:
                                            try:
                                                dep_url = (
                                                    f"https://management.azure.com{app_id}"
                                                    f"/agentDeployments?api-version=2025-04-01-preview"
                                                )
                                                dep_resp = await _arm_get(creds, dep_url)
                                                agent_deploys = (dep_resp or {}).get("value", [])

                                                for adep in agent_deploys:
                                                    adep_props = adep.get("properties", {})
                                                    evidence.append(make_evidence(
                                                        source=Source.AZURE, collector="FoundryConfig",
                                                        evidence_type="foundry-agent-deployment",
                                                        description=f"Agent deployment: {adep.get(\'name\', \'\')} in {app.get(\'name\', \'\')}",
                                                        data={
                                                            "DeploymentId": adep.get("id", ""),
                                                            "Name": adep.get("name", ""),
                                                            "ApplicationId": app_id,
                                                            "ApplicationName": app.get("name", ""),
                                                            "ProjectId": proj_id,
                                                            "ProvisioningState": adep_props.get("provisioningState", ""),
                                                            "SubscriptionId": sub_id,
                                                        },
                                                        resource_id=adep.get("id", ""), resource_type="AgentDeployment",
                                                    ))
                                            except AccessDeniedError:
                                                access_denied_count += 1
                                                log.warning("  [FoundryConfig] Agent deployments access denied for %s/%s", proj.get("name", ""), app.get("name", ""))
                                            except Exception as exc:
                                                log.warning("  [FoundryConfig] Agent deployments for %s/%s failed: %s", proj.get("name", ""), app.get("name", ""), exc)

                                except AccessDeniedError:
                                    access_denied_count += 1
                                    log.warning("  [FoundryConfig] Agent apps access denied for %s/%s", acct_name, proj.get("name", ""))
                                except Exception as exc:
                                    log.warning("  [FoundryConfig] Agent apps for %s/%s failed: %s", acct_name, proj.get("name", ""), exc)

                        log.info(
                            "  [FoundryConfig] %s/%s: %d Foundry projects",
                            sub_name, acct_name, len(projects),
                        )
                    except AccessDeniedError:
                        access_denied_count += 1
                        log.warning("  [FoundryConfig] Foundry projects access denied for %s/%s", sub_name, acct_name)
                    except Exception as exc:
                        log.warning("  [FoundryConfig] Foundry projects for %s/%s failed: %s", sub_name, acct_name, exc)

'''

patch_file(COLLECTOR,
    '        # ── Summary ──',
    COLLECTOR_INSERT + '        # ── Summary ──')

# ============ 9. COLLECTOR: Update summary counts ============
patch_file(COLLECTOR,
    '        serverless_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-serverless-endpoint")\n',
    '        serverless_count = sum(1 for e in evidence if e.get("EvidenceType") == "azure-ai-serverless-endpoint")\n        foundry_proj_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-project")\n        agent_app_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-application")\n        agent_deploy_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-deployment")\n')

patch_file(COLLECTOR,
    '                "ServerlessEndpoints": serverless_count,\n                "AccessDeniedErrors": access_denied_count,',
    '                "ServerlessEndpoints": serverless_count,\n                "FoundryProjectsNew": foundry_proj_count,\n                "AgentApplications": agent_app_count,\n                "AgentDeployments": agent_deploy_count,\n                "AccessDeniedErrors": access_denied_count,')

print("=== Collector patches done ===\n")

# ============ 10. TESTS: Add evidence helpers and test classes ============
TESTS = "tests/test_ai_agent_security_engine.py"

# Add helpers
patch_file(TESTS,
    'def _ai_ws_diag_ev(data: dict) -> dict:\n    return {"EvidenceType": "azure-ai-workspace-diagnostics", "Data": data, "ResourceId": data.get("WorkspaceId", "")}\n\ndef _entra_sp_ev',
    'def _ai_ws_diag_ev(data: dict) -> dict:\n    return {"EvidenceType": "azure-ai-workspace-diagnostics", "Data": data, "ResourceId": data.get("WorkspaceId", "")}\n\ndef _foundry_project_ev(data: dict) -> dict:\n    return {"EvidenceType": "foundry-project", "Data": data, "ResourceId": data.get("ProjectId", "")}\n\ndef _foundry_agent_app_ev(data: dict) -> dict:\n    return {"EvidenceType": "foundry-agent-application", "Data": data, "ResourceId": data.get("ApplicationId", "")}\n\ndef _foundry_agent_deploy_ev(data: dict) -> dict:\n    return {"EvidenceType": "foundry-agent-deployment", "Data": data, "ResourceId": data.get("DeploymentId", "")}\n\ndef _entra_sp_ev')

# Add test classes
TEST_CLASSES = '''

# ====================================================================
# B16. Foundry — Agent Identity Security
# ====================================================================

class TestFoundryAgentIdentity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_agent_identity
        self.analyze = analyze_foundry_agent_identity

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_project_no_managed_identity_detected(self):
        """Foundry project without MI triggers project_no_managed_identity."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "proj-1", "Name": "my-project",
            "AccountName": "my-account",
            "HasManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "project_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_project_with_mi_no_finding(self):
        """Project with MI does not trigger finding."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "proj-2", "Name": "secure-project",
            "AccountName": "my-account",
            "HasManagedIdentity": True,
            "AgentCount": 1,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "project_no_managed_identity"]
        self.assertEqual(len(mi), 0)

    def test_shared_identity_detected(self):
        """Multiple unpublished agents sharing project identity triggers finding."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "proj-3", "Name": "busy-project",
                "AccountName": "acct",
                "HasManagedIdentity": True,
                "AgentCount": 5,
            }),
        ])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "shared_project_identity"]
        self.assertGreater(len(shared), 0)

    def test_agent_permission_drift_detected(self):
        """Published app without RBAC triggers agent_permission_drift."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-1", "Name": "my-agent-app",
            "ProjectName": "proj",
            "HasRBACAssignments": False,
        })])
        findings = self.analyze(idx)
        drift = [f for f in findings if f["Subcategory"] == "agent_permission_drift"]
        self.assertGreater(len(drift), 0)

    def test_agent_with_rbac_no_drift(self):
        """Published app with RBAC does not trigger drift finding."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-2", "Name": "rbac-agent",
            "ProjectName": "proj",
            "HasRBACAssignments": True,
        })])
        findings = self.analyze(idx)
        drift = [f for f in findings if f["Subcategory"] == "agent_permission_drift"]
        self.assertEqual(len(drift), 0)


# ====================================================================
# B17. Foundry — Agent Application Security
# ====================================================================

class TestFoundryAgentApplication(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_agent_application
        self.analyze = analyze_foundry_agent_application

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_endpoint_detected(self):
        """Agent app with public endpoint triggers public_endpoint_exposure."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-pub", "Name": "public-agent",
            "IsPublicEndpoint": True,
            "Protocol": "ResponsesAPI",
            "AuthenticationType": "RBAC",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_endpoint_exposure"]
        self.assertGreater(len(pub), 0)

    def test_private_endpoint_no_finding(self):
        """Agent app with private endpoint (IsPublicEndpoint=False) is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-priv", "Name": "private-agent",
            "IsPublicEndpoint": False,
            "AuthenticationType": "RBAC",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_endpoint_exposure"]
        self.assertEqual(len(pub), 0)

    def test_no_auth_detected(self):
        """Agent app without auth triggers no_auth_policy."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-noauth", "Name": "unauth-agent",
            "AuthenticationType": "None",
            "IsPublicEndpoint": True,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "no_auth_policy"]
        self.assertGreater(len(auth), 0)

    def test_rbac_auth_no_finding(self):
        """Agent app with RBAC auth is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-rbac", "Name": "secure-agent",
            "AuthenticationType": "RBAC",
            "IsPublicEndpoint": False,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "no_auth_policy"]
        self.assertEqual(len(auth), 0)

    def test_unhealthy_deployment_detected(self):
        """Agent deployment not succeeded triggers deployment_unhealthy."""
        idx = _build_index([_foundry_agent_deploy_ev({
            "DeploymentId": "dep-1", "Name": "broken-deploy",
            "ApplicationName": "my-app",
            "ProvisioningState": "Failed",
        })])
        findings = self.analyze(idx)
        bad = [f for f in findings if f["Subcategory"] == "deployment_unhealthy"]
        self.assertGreater(len(bad), 0)

    def test_healthy_deployment_no_finding(self):
        """Succeeded deployment is clean."""
        idx = _build_index([_foundry_agent_deploy_ev({
            "DeploymentId": "dep-2", "Name": "good-deploy",
            "ApplicationName": "my-app",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        bad = [f for f in findings if f["Subcategory"] == "deployment_unhealthy"]
        self.assertEqual(len(bad), 0)

'''

patch_file(TESTS,
    '\n# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================',
    TEST_CLASSES + '# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================')

# Add import assertions
patch_file(TESTS,
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_registry"))\n        # C – Cross-cutting',
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_registry"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_agent_identity"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_agent_application"))\n        # C – Cross-cutting')

print("=== Test patches done ===\n")
print("All Phase G patches applied successfully!")
