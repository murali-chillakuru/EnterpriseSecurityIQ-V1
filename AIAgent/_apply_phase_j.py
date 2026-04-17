"""Apply Phase J changes: Data Resources & Observability."""


def patch_file(path, old, new):
    content = open(path, encoding="utf-8").read()
    if old not in content:
        print(f"  SKIP: target not found in {path}")
        return False
    content = content.replace(old, new, 1)
    open(path, "w", encoding="utf-8").write(content)
    print(f"  OK: patched {path}")
    return True


ENGINE = "app/ai_agent_security_engine.py"
TESTS = "tests/test_ai_agent_security_engine.py"

# ============================================================
# 1. ENGINE: Update docstring
# ============================================================
patch_file(ENGINE,
    '     9q. Hosted Agent Security            — capability hosts, ACR, container security\n\n  C. Custom Agent Security  (cross-cutting)',
    '     9q. Hosted Agent Security            — capability hosts, ACR, container security\n     9r. Agent Data Resources             — Cosmos DB, AI Search, Storage security\n     9s. Agent Observability              — tracing, App Insights, log coverage\n\n  C. Custom Agent Security  (cross-cutting)')

# ============================================================
# 2. ENGINE: Add new analyze functions
# ============================================================
NEW_FUNCTIONS = '''

# ── 9r. Agent Data Resources ─────────────────────────────────────────

def analyze_foundry_data_resources(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data resource connections used by agents (Cosmos DB, AI Search, Storage)."""
    findings: list[dict] = []
    findings.extend(_check_data_connection_no_mi(evidence_index))
    findings.extend(_check_storage_no_encryption(evidence_index))
    findings.extend(_check_data_connection_shared(evidence_index))
    return findings


def _get_data_connections(idx: dict) -> list[dict]:
    """Extract data-resource connections (Cosmos, AI Search, Storage) from evidence."""
    connections = idx.get("azure-ai-connection", [])
    _DATA_CATEGORIES = {
        "cosmosdb", "cosmos", "azurecosmosdb",
        "cognitivesearch", "azureaisearch", "aisearch",
        "azureblobstorage", "azureblob", "blob", "storage", "azurestorage",
        "azuredatalake", "datalake",
    }
    return [
        ev for ev in connections
        if str(ev.get("Data", ev.get("data", {})).get("Category", "")).lower().replace(" ", "").replace("-", "").replace("_", "") in _DATA_CATEGORIES
    ]


def _check_data_connection_no_mi(idx: dict) -> list[dict]:
    """Flag data connections using credential-based auth instead of managed identity."""
    data_conns = _get_data_connections(idx)
    _MI_AUTH = {"managedidentity", "aad", "entra", "identity", "serviceprincipal"}
    no_mi: list[dict] = []
    for ev in data_conns:
        data = ev.get("Data", ev.get("data", {}))
        auth = str(data.get("AuthType", "")).lower().replace(" ", "").replace("-", "")
        if auth not in _MI_AUTH:
            no_mi.append({
                "Type": "DataConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
                "AuthType": data.get("AuthType", ""),
                "Target": data.get("Target", ""),
            })
    if no_mi:
        return [_as_finding(
            "foundry_data_resources", "data_connection_no_managed_identity",
            f"{len(no_mi)} agent data connections use credential-based authentication",
            "Data resource connections (Cosmos DB, AI Search, Storage) used by agents "
            "should use managed identity authentication. Credential-based access creates "
            "key rotation burden and increases risk of leaked secrets.",
            "high", "foundry", no_mi,
            {"Description": "Switch data connections to managed identity authentication.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Data connections",
                             "Edit each connection using API keys",
                             "Switch to managed identity authentication",
                             "Ensure the workspace MI has appropriate RBAC on the data resource"]},
        )]
    return []


def _check_storage_no_encryption(idx: dict) -> list[dict]:
    """Flag AI service accounts without customer-managed key encryption."""
    services = idx.get("azure-ai-service", [])
    no_cmk: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        kind = str(data.get("Kind", "")).lower()
        if kind in ("aiservices", "openai", "azureopenai") and not data.get("HasCMK"):
            no_cmk.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
                "Kind": data.get("Kind", ""),
            })
    if no_cmk:
        return [_as_finding(
            "foundry_data_resources", "no_customer_managed_key",
            f"{len(no_cmk)} Foundry accounts lack customer-managed key encryption",
            "Agent conversation state, uploaded files, and cached data stored in "
            "Foundry-managed resources are encrypted with Microsoft-managed keys by default. "
            "Configure customer-managed keys (CMK) via Azure Key Vault for data sovereignty "
            "and compliance requirements.",
            "medium", "foundry", no_cmk,
            {"Description": "Enable customer-managed key encryption on Foundry accounts.",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the account",
                             "Go to Encryption > Customer-managed keys",
                             "Select or create a Key Vault with the encryption key",
                             "Assign Key Vault access to the AI service managed identity"]},
        )]
    return []


def _check_data_connection_shared(idx: dict) -> list[dict]:
    """Flag data connections shared to all workspace users."""
    data_conns = _get_data_connections(idx)
    shared: list[dict] = []
    for ev in data_conns:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsSharedToAll"):
            shared.append({
                "Type": "DataConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
            })
    if shared:
        return [_as_finding(
            "foundry_data_resources", "data_connection_shared_to_all",
            f"{len(shared)} agent data connections are shared to all workspace users",
            "Data connections (Cosmos DB, AI Search, Storage) shared to all users "
            "allow any agent or user in the workspace to access the data resource. "
            "Restrict data connections to specific agents for least-privilege data access.",
            "medium", "foundry", shared,
            {"Description": "Restrict data connection sharing to specific users.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Data connections",
                             "Edit shared connections",
                             "Disable 'Shared to all users'",
                             "Assign per-agent or per-user access to data resources"]},
        )]
    return []


# ── 9s. Agent Observability ──────────────────────────────────────────

def analyze_foundry_observability(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent observability coverage: tracing, diagnostics, App Insights."""
    findings: list[dict] = []
    findings.extend(_check_workspace_no_diagnostics(evidence_index))
    findings.extend(_check_project_no_tracing(evidence_index))
    findings.extend(_check_workspace_limited_log_coverage(evidence_index))
    return findings


def _check_workspace_no_diagnostics(idx: dict) -> list[dict]:
    """Flag workspaces with no diagnostic settings configured."""
    ws_diags = idx.get("azure-ai-workspace-diagnostics", [])
    no_diag: list[dict] = []
    for ev in ws_diags:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasDiagnostics"):
            no_diag.append({
                "Type": "AIWorkspace",
                "Name": data.get("WorkspaceName", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
            })
    if no_diag:
        return [_as_finding(
            "foundry_observability", "workspace_no_diagnostics",
            f"{len(no_diag)} AI workspaces have no diagnostic settings",
            "Without diagnostic settings, agent interactions, errors, and tool calls "
            "are not logged. Enable diagnostic settings with Log Analytics for "
            "comprehensive agent activity monitoring and incident response.",
            "high", "foundry", no_diag,
            {"Description": "Enable diagnostic settings on AI workspaces.",
             "PortalSteps": ["Go to Azure portal > AI workspace > Diagnostic settings",
                             "Add diagnostic setting",
                             "Enable all log categories",
                             "Select Log Analytics workspace as destination"]},
        )]
    return []


def _check_project_no_tracing(idx: dict) -> list[dict]:
    """Flag Foundry projects without Application Insights for agent tracing."""
    projects = idx.get("foundry-project", [])
    ws_diags = idx.get("azure-ai-workspace-diagnostics", [])
    if not projects:
        return []
    # Collect workspaces that have App Insights / Log Analytics enabled
    monitored_workspaces = set()
    for ev in ws_diags:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasLogAnalytics") or data.get("HasDiagnostics"):
            ws_name = str(data.get("WorkspaceName", "")).lower()
            if ws_name:
                monitored_workspaces.add(ws_name)
    no_trace: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        acct = str(data.get("AccountName", "")).lower()
        proj = str(data.get("Name", "")).lower()
        # Check if the parent account or project name matches any monitored workspace
        if acct not in monitored_workspaces and proj not in monitored_workspaces:
            no_trace.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_trace:
        return [_as_finding(
            "foundry_observability", "project_no_tracing",
            f"{len(no_trace)} Foundry projects lack Application Insights tracing",
            "Foundry agent tracing via Application Insights provides end-to-end "
            "visibility into agent reasoning, tool calls, and guardrail interventions. "
            "Without tracing, debugging agent behavior and detecting anomalies is limited.",
            "medium", "foundry", no_trace,
            {"Description": "Enable Application Insights tracing for Foundry projects.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Tracing > Configure",
                             "Connect Application Insights resource",
                             "Enable OpenTelemetry-based agent tracing",
                             "Verify trace data appears in App Insights"]},
        )]
    return []


def _check_workspace_limited_log_coverage(idx: dict) -> list[dict]:
    """Flag workspaces with diagnostics but incomplete log categories."""
    ws_diags = idx.get("azure-ai-workspace-diagnostics", [])
    limited: list[dict] = []
    _REQUIRED = {"audit", "requestresponse", "allmetrics"}
    for ev in ws_diags:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasDiagnostics"):
            continue
        enabled = set(c.lower() for c in (data.get("EnabledLogs", []) + data.get("EnabledMetrics", [])))
        missing = _REQUIRED - enabled
        if missing:
            limited.append({
                "Type": "AIWorkspace",
                "Name": data.get("WorkspaceName", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "EnabledCategories": str(data.get("EnabledLogs", []) + data.get("EnabledMetrics", [])),
                "MissingCategories": str(sorted(missing)),
            })
    if limited:
        return [_as_finding(
            "foundry_observability", "workspace_limited_log_coverage",
            f"{len(limited)} AI workspaces have incomplete diagnostic log coverage",
            "Diagnostic settings exist but not all required log categories are enabled. "
            "Enable Audit, RequestResponse, and AllMetrics for comprehensive "
            "agent activity monitoring.",
            "medium", "foundry", limited,
            {"Description": "Enable all required diagnostic log categories.",
             "PortalSteps": ["Go to Azure portal > AI workspace > Diagnostic settings",
                             "Edit existing diagnostic setting",
                             "Enable missing log categories (Audit, RequestResponse)",
                             "Enable all metric categories",
                             "Save"]},
        )]
    return []

'''

patch_file(ENGINE,
    '    return []\n\n\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================',
    '    return []\n' + NEW_FUNCTIONS + '\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================')

# ============================================================
# 3. ENGINE: Wire into orchestrator
# ============================================================
patch_file(ENGINE,
    '    foundry_hosted_findings = analyze_foundry_hosted_agents(evidence_index)\n\n    # C. Custom Agent Security',
    '    foundry_hosted_findings = analyze_foundry_hosted_agents(evidence_index)\n\n    log.info("Running Foundry data resources analysis …")\n    foundry_data_findings = analyze_foundry_data_resources(evidence_index)\n\n    log.info("Running Foundry observability analysis …")\n    foundry_obs_findings = analyze_foundry_observability(evidence_index)\n\n    # C. Custom Agent Security')

# ============================================================
# 4. ENGINE: Update all_findings
# ============================================================
patch_file(ENGINE,
    '        + foundry_guardrail_findings + foundry_hosted_findings\n        + custom_api_findings',
    '        + foundry_guardrail_findings + foundry_hosted_findings\n        + foundry_data_findings + foundry_obs_findings\n        + custom_api_findings')

# ============================================================
# 5. ENGINE: Update Categories
# ============================================================
patch_file(ENGINE,
    '            "foundry_hosted_agents": foundry_hosted_findings,\n            "custom_api_security": custom_api_findings,',
    '            "foundry_hosted_agents": foundry_hosted_findings,\n            "foundry_data_resources": foundry_data_findings,\n            "foundry_observability": foundry_obs_findings,\n            "custom_api_security": custom_api_findings,')

# ============================================================
# 6. ENGINE: Update CategoryCounts
# ============================================================
patch_file(ENGINE,
    '            "foundry_hosted_agents": len(foundry_hosted_findings),\n            "custom_api_security": len(custom_api_findings),',
    '            "foundry_hosted_agents": len(foundry_hosted_findings),\n            "foundry_data_resources": len(foundry_data_findings),\n            "foundry_observability": len(foundry_obs_findings),\n            "custom_api_security": len(custom_api_findings),')

print("=== Engine patches done ===\n")

# ============================================================
# 7. TESTS: Add test classes
# ============================================================
TEST_CLASSES = '''

# ====================================================================
# B22. Foundry — Agent Data Resources
# ====================================================================

class TestFoundryDataResources(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_data_resources
        self.analyze = analyze_foundry_data_resources

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_cosmos_no_mi_detected(self):
        """Cosmos DB connection with API key triggers data_connection_no_managed_identity."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-cosmos-1", "Name": "cosmos-state",
            "WorkspaceName": "ws1",
            "Category": "CosmosDB",
            "AuthType": "ApiKey",
            "Target": "https://myagent.documents.azure.com",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "data_connection_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_cosmos_mi_no_finding(self):
        """Cosmos DB connection with managed identity is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-cosmos-2", "Name": "cosmos-mi",
            "WorkspaceName": "ws1",
            "Category": "CosmosDB",
            "AuthType": "ManagedIdentity",
            "Target": "https://myagent.documents.azure.com",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "data_connection_no_managed_identity"]
        self.assertEqual(len(mi), 0)

    def test_aisearch_no_mi_detected(self):
        """AI Search connection with API key triggers finding."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-search-1", "Name": "search-conn",
            "WorkspaceName": "ws1",
            "Category": "CognitiveSearch",
            "AuthType": "ApiKey",
            "Target": "https://mysearch.search.windows.net",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "data_connection_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_no_cmk_detected(self):
        """AI service account without CMK triggers no_customer_managed_key."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "/sub/acct1", "Name": "myai",
            "Kind": "AIServices", "HasCMK": False,
        })])
        findings = self.analyze(idx)
        cmk = [f for f in findings if f["Subcategory"] == "no_customer_managed_key"]
        self.assertGreater(len(cmk), 0)

    def test_cmk_no_finding(self):
        """AI service account with CMK is clean."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "/sub/acct2", "Name": "myai-cmk",
            "Kind": "AIServices", "HasCMK": True,
        })])
        findings = self.analyze(idx)
        cmk = [f for f in findings if f["Subcategory"] == "no_customer_managed_key"]
        self.assertEqual(len(cmk), 0)

    def test_data_shared_to_all_detected(self):
        """Data connection shared to all triggers data_connection_shared_to_all."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-blob-1", "Name": "blob-store",
            "WorkspaceName": "ws1",
            "Category": "AzureBlobStorage",
            "AuthType": "ManagedIdentity",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "data_connection_shared_to_all"]
        self.assertGreater(len(shared), 0)

    def test_non_data_connection_ignored(self):
        """Non-data connections (e.g., Git) should not trigger findings."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-git-1", "Name": "github-repo",
            "WorkspaceName": "ws1",
            "Category": "GitHub",
            "AuthType": "PAT",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B23. Foundry — Agent Observability
# ====================================================================

class TestFoundryObservability(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_observability
        self.analyze = analyze_foundry_observability

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_workspace_no_diagnostics_detected(self):
        """Workspace without diagnostics triggers workspace_no_diagnostics."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws1", "WorkspaceName": "ws1",
            "HasDiagnostics": False,
        })])
        findings = self.analyze(idx)
        diag = [f for f in findings if f["Subcategory"] == "workspace_no_diagnostics"]
        self.assertGreater(len(diag), 0)

    def test_workspace_with_diagnostics_no_finding(self):
        """Workspace with diagnostics is clean for workspace_no_diagnostics."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws2", "WorkspaceName": "ws2",
            "HasDiagnostics": True,
            "HasLogAnalytics": True,
            "EnabledLogs": ["Audit", "RequestResponse"],
            "EnabledMetrics": ["AllMetrics"],
        })])
        findings = self.analyze(idx)
        diag = [f for f in findings if f["Subcategory"] == "workspace_no_diagnostics"]
        self.assertEqual(len(diag), 0)

    def test_project_no_tracing_detected(self):
        """Foundry project without linked diagnostics triggers project_no_tracing."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "/sub/proj1", "Name": "my-project",
            "AccountName": "my-account",
        })])
        findings = self.analyze(idx)
        trace = [f for f in findings if f["Subcategory"] == "project_no_tracing"]
        self.assertGreater(len(trace), 0)

    def test_project_with_tracing_no_finding(self):
        """Foundry project with matching monitored workspace is clean."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj2", "Name": "my-project",
                "AccountName": "my-account",
            }),
            _ai_ws_diag_ev({
                "WorkspaceId": "/sub/ws-acct", "WorkspaceName": "my-account",
                "HasDiagnostics": True, "HasLogAnalytics": True,
            }),
        ])
        findings = self.analyze(idx)
        trace = [f for f in findings if f["Subcategory"] == "project_no_tracing"]
        self.assertEqual(len(trace), 0)

    def test_workspace_limited_logs_detected(self):
        """Workspace with incomplete log coverage triggers finding."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws3", "WorkspaceName": "ws3",
            "HasDiagnostics": True,
            "EnabledLogs": ["Audit"],
            "EnabledMetrics": [],
        })])
        findings = self.analyze(idx)
        limited = [f for f in findings if f["Subcategory"] == "workspace_limited_log_coverage"]
        self.assertGreater(len(limited), 0)

    def test_workspace_full_logs_no_finding(self):
        """Workspace with all required log categories is clean."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws4", "WorkspaceName": "ws4",
            "HasDiagnostics": True,
            "EnabledLogs": ["Audit", "RequestResponse"],
            "EnabledMetrics": ["AllMetrics"],
        })])
        findings = self.analyze(idx)
        limited = [f for f in findings if f["Subcategory"] == "workspace_limited_log_coverage"]
        self.assertEqual(len(limited), 0)

'''

patch_file(TESTS,
    '\n# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================',
    TEST_CLASSES + '# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================')

# Add import assertions
patch_file(TESTS,
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_hosted_agents"))\n        # C – Cross-cutting',
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_hosted_agents"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_data_resources"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_observability"))\n        # C – Cross-cutting')

print("=== Test patches done ===\n")
print("All Phase J patches applied!")
