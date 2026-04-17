"""Apply Phase H changes: MCP & Tool Security."""


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

# ============ 1. ENGINE: Update docstring ============
patch_file(ENGINE,
    '     9m. Agent Application Security     — published agent audit, auth policy\n\n  C. Custom Agent Security  (cross-cutting)',
    '     9m. Agent Application Security     — published agent audit, auth policy\n     9n. MCP Tool Security              — MCP server auth, approval policies, endpoint exposure\n     9o. Tool Connection Security       — A2A auth, non-Microsoft tools, shared access\n\n  C. Custom Agent Security  (cross-cutting)')

# ============ 2. ENGINE: Add new analyze functions ============
NEW_FUNCTIONS = '''

# ── 9n. MCP Tool Security ───────────────────────────────────────────

def analyze_foundry_mcp_tools(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess MCP (Model Context Protocol) tool connections for security risks."""
    findings: list[dict] = []
    findings.extend(_check_mcp_no_auth(evidence_index))
    findings.extend(_check_mcp_public_endpoint(evidence_index))
    findings.extend(_check_mcp_shared_to_all(evidence_index))
    return findings


def _get_mcp_connections(idx: dict) -> list[dict]:
    """Extract MCP/RemoteTool connections from evidence."""
    connections = idx.get("azure-ai-connection", [])
    mcp_categories = {"mcp", "remotetool", "remote_tool", "mcpserver"}
    return [
        ev for ev in connections
        if str(ev.get("Data", ev.get("data", {})).get("Category", "")).lower().replace(" ", "").replace("-", "") in mcp_categories
    ]


def _check_mcp_no_auth(idx: dict) -> list[dict]:
    """Flag MCP connections without secure authentication."""
    mcp_conns = _get_mcp_connections(idx)
    no_auth: list[dict] = []
    _WEAK_AUTH = {"none", "", "apikey", "pat", "customkeys"}
    for ev in mcp_conns:
        data = ev.get("Data", ev.get("data", {}))
        auth = str(data.get("AuthType", "")).lower()
        if auth in _WEAK_AUTH:
            no_auth.append({
                "Type": "MCPConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "AuthType": data.get("AuthType", "None"),
                "Target": data.get("Target", ""),
            })
    if no_auth:
        return [_as_finding(
            "foundry_mcp_tools", "mcp_no_secure_auth",
            f"{len(no_auth)} MCP tool connections lack secure authentication",
            "MCP server connections using API keys or no authentication are vulnerable "
            "to credential theft and replay attacks. Use Entra ID or OAuth passthrough "
            "authentication for MCP tools to benefit from token scoping and rotation.",
            "high", "foundry", no_auth,
            {"Description": "Configure Entra ID authentication on MCP connections.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Connections",
                             "Edit the MCP server connection",
                             "Change authentication to Entra ID or OAuth passthrough",
                             "Rotate any exposed API keys"]},
        )]
    return []


def _check_mcp_public_endpoint(idx: dict) -> list[dict]:
    """Flag MCP connections targeting public (non-private) endpoints."""
    mcp_conns = _get_mcp_connections(idx)
    public: list[dict] = []
    _PRIVATE_PATTERNS = (".privatelink.", ".internal.", "10.", "172.", "192.168.")
    for ev in mcp_conns:
        data = ev.get("Data", ev.get("data", {}))
        target = str(data.get("Target", "")).lower()
        if target and not any(p in target for p in _PRIVATE_PATTERNS):
            public.append({
                "Type": "MCPConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Target": data.get("Target", ""),
            })
    if public:
        return [_as_finding(
            "foundry_mcp_tools", "mcp_public_endpoint",
            f"{len(public)} MCP tool connections use public endpoints",
            "MCP servers on public endpoints expose agent tool traffic to the internet. "
            "Use private endpoints for MCP servers when handling sensitive data to keep "
            "traffic on the Microsoft backbone network.",
            "medium", "foundry", public,
            {"Description": "Configure private endpoints for MCP tool servers.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > MCP server connections",
                             "Update the target URL to use private endpoint",
                             "Ensure VNet integration allows private connectivity"]},
        )]
    return []


def _check_mcp_shared_to_all(idx: dict) -> list[dict]:
    """Flag MCP connections shared to all users in the workspace."""
    mcp_conns = _get_mcp_connections(idx)
    shared: list[dict] = []
    for ev in mcp_conns:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsSharedToAll"):
            shared.append({
                "Type": "MCPConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if shared:
        return [_as_finding(
            "foundry_mcp_tools", "mcp_shared_to_all",
            f"{len(shared)} MCP tool connections are shared to all workspace users",
            "MCP connections shared to all users allow any agent in the workspace to "
            "invoke these tools. Restrict MCP connections to specific agents or users "
            "to enforce least-privilege tool access.",
            "medium", "foundry", shared,
            {"Description": "Restrict MCP connection sharing to specific users.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Connections",
                             "Edit the MCP connection",
                             "Disable 'Shared to all users'",
                             "Configure per-agent or per-user access"]},
        )]
    return []


# ── 9o. Tool Connection Security ─────────────────────────────────────

def analyze_foundry_tool_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess tool and agent-to-agent connection security posture."""
    findings: list[dict] = []
    findings.extend(_check_a2a_no_auth(evidence_index))
    findings.extend(_check_non_microsoft_tools(evidence_index))
    findings.extend(_check_tool_connections_credential_based(evidence_index))
    return findings


def _get_a2a_connections(idx: dict) -> list[dict]:
    """Extract Agent-to-Agent connections from evidence."""
    connections = idx.get("azure-ai-connection", [])
    a2a_categories = {"agent", "a2a", "remotea2a", "agenttoagent", "remote_a2a"}
    return [
        ev for ev in connections
        if str(ev.get("Data", ev.get("data", {})).get("Category", "")).lower().replace(" ", "").replace("-", "") in a2a_categories
    ]


def _check_a2a_no_auth(idx: dict) -> list[dict]:
    """Flag Agent-to-Agent connections without identity-based authentication."""
    a2a_conns = _get_a2a_connections(idx)
    no_auth: list[dict] = []
    _IDENTITY_AUTH = {"aad", "managedidentity", "entra", "oauth2", "serviceprincipal"}
    for ev in a2a_conns:
        data = ev.get("Data", ev.get("data", {}))
        auth = str(data.get("AuthType", "")).lower().replace(" ", "").replace("-", "")
        if auth not in _IDENTITY_AUTH:
            no_auth.append({
                "Type": "A2AConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "AuthType": data.get("AuthType", "None"),
                "Target": data.get("Target", ""),
            })
    if no_auth:
        return [_as_finding(
            "foundry_tool_security", "a2a_no_identity_auth",
            f"{len(no_auth)} Agent-to-Agent connections lack identity-based authentication",
            "A2A connections should use Entra ID or managed identity authentication "
            "to verify the calling agent's identity. API key or no authentication "
            "allows any caller to invoke the target agent.",
            "high", "foundry", no_auth,
            {"Description": "Configure Entra ID authentication for A2A connections.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Agent connections",
                             "Edit the A2A connection",
                             "Configure Entra ID authentication with proper audience",
                             "Set the target agent application's resource ID as audience"]},
        )]
    return []


def _check_non_microsoft_tools(idx: dict) -> list[dict]:
    """Flag connections to non-Microsoft external tool services."""
    connections = idx.get("azure-ai-connection", [])
    _TOOL_CATEGORIES = {"mcp", "remotetool", "remote_tool", "mcpserver",
                        "agent", "a2a", "remotea2a", "openapi", "custom"}
    _MICROSOFT_PATTERNS = (".azure.com", ".microsoft.com", ".windows.net",
                           ".azure-api.net", ".cognitiveservices.azure.com",
                           ".openai.azure.com", ".search.windows.net")
    non_ms: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        cat = str(data.get("Category", "")).lower().replace(" ", "").replace("-", "")
        if cat not in _TOOL_CATEGORIES:
            continue
        target = str(data.get("Target", "")).lower()
        if target and not any(p in target for p in _MICROSOFT_PATTERNS):
            non_ms.append({
                "Type": "ExternalConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
                "Target": data.get("Target", ""),
            })
    if non_ms:
        return [_as_finding(
            "foundry_tool_security", "non_microsoft_tool_connection",
            f"{len(non_ms)} tool connections target non-Microsoft external services",
            "Non-Microsoft MCP servers and tool endpoints have no data processing "
            "guarantees under Microsoft's terms. Ensure data governance policies "
            "cover data sent to external tool services and that approval policies "
            "are configured.",
            "medium", "foundry", non_ms,
            {"Description": "Review and govern non-Microsoft tool connections.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Review all external tool/MCP connections",
                             "Verify data governance and privacy agreements",
                             "Configure approval policies for external tools",
                             "Restrict allowed_tools list to minimize data exposure"]},
        )]
    return []


def _check_tool_connections_credential_based(idx: dict) -> list[dict]:
    """Flag tool connections using credential-based (non-MI) authentication."""
    connections = idx.get("azure-ai-connection", [])
    _TOOL_CATEGORIES = {"mcp", "remotetool", "remote_tool", "mcpserver",
                        "azurefunction", "azure_function", "cognitivesearch",
                        "azureaisearch", "openapi", "custom"}
    _CRED_AUTH = {"apikey", "pat", "customkeys", "accountkey", "accesskey"}
    cred_based: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        cat = str(data.get("Category", "")).lower().replace(" ", "").replace("-", "")
        if cat not in _TOOL_CATEGORIES:
            continue
        auth = str(data.get("AuthType", "")).lower()
        if auth in _CRED_AUTH:
            cred_based.append({
                "Type": "ToolConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
                "AuthType": data.get("AuthType", ""),
            })
    if cred_based:
        return [_as_finding(
            "foundry_tool_security", "tool_credential_based_auth",
            f"{len(cred_based)} tool connections use credential-based authentication",
            "Tool connections using API keys or access keys are harder to rotate "
            "and audit. Prefer managed identity or Entra ID authentication for "
            "tool connections to enable automatic credential rotation and RBAC.",
            "medium", "foundry", cred_based,
            {"Description": "Migrate tool connections to identity-based authentication.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Connections",
                             "Edit each tool connection using API key auth",
                             "Switch to Entra ID or managed identity authentication",
                             "Rotate and revoke old API keys"]},
        )]
    return []

'''

patch_file(ENGINE,
    '    return []\n\n\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================',
    '    return []\n' + NEW_FUNCTIONS + '\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================')

# ============ 3. ENGINE: Wire into orchestrator ============
patch_file(ENGINE,
    '    foundry_agent_app_findings = analyze_foundry_agent_application(evidence_index)\n\n    # C. Custom Agent Security',
    '    foundry_agent_app_findings = analyze_foundry_agent_application(evidence_index)\n\n    log.info("Running Foundry MCP tool security analysis …")\n    foundry_mcp_findings = analyze_foundry_mcp_tools(evidence_index)\n\n    log.info("Running Foundry tool connection security analysis …")\n    foundry_tool_findings = analyze_foundry_tool_security(evidence_index)\n\n    # C. Custom Agent Security')

# ============ 4. ENGINE: Update all_findings ============
patch_file(ENGINE,
    '        + foundry_agent_identity_findings + foundry_agent_app_findings\n        + custom_api_findings',
    '        + foundry_agent_identity_findings + foundry_agent_app_findings\n        + foundry_mcp_findings + foundry_tool_findings\n        + custom_api_findings')

# ============ 5. ENGINE: Update Categories ============
patch_file(ENGINE,
    '            "foundry_agent_application": foundry_agent_app_findings,\n            "custom_api_security": custom_api_findings,',
    '            "foundry_agent_application": foundry_agent_app_findings,\n            "foundry_mcp_tools": foundry_mcp_findings,\n            "foundry_tool_security": foundry_tool_findings,\n            "custom_api_security": custom_api_findings,')

# ============ 6. ENGINE: Update CategoryCounts ============
patch_file(ENGINE,
    '            "foundry_agent_application": len(foundry_agent_app_findings),\n            "custom_api_security": len(custom_api_findings),',
    '            "foundry_agent_application": len(foundry_agent_app_findings),\n            "foundry_mcp_tools": len(foundry_mcp_findings),\n            "foundry_tool_security": len(foundry_tool_findings),\n            "custom_api_security": len(custom_api_findings),')

print("\n=== Engine patches done ===\n")

# ============ 7. TESTS: Add test classes ============
TEST_CLASSES = '''

# ====================================================================
# B18. Foundry — MCP Tool Security
# ====================================================================

class TestFoundryMCPTools(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_mcp_tools
        self.analyze = analyze_foundry_mcp_tools

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_mcp_no_auth_detected(self):
        """MCP connection with apikey auth triggers mcp_no_secure_auth."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-1", "Name": "my-mcp-server",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "ApiKey",
            "Target": "https://mcp.example.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "mcp_no_secure_auth"]
        self.assertGreater(len(auth), 0)

    def test_mcp_entra_auth_no_finding(self):
        """MCP connection with Entra auth is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-2", "Name": "secure-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mcp.internal.azure.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "mcp_no_secure_auth"]
        self.assertEqual(len(auth), 0)

    def test_mcp_public_endpoint_detected(self):
        """MCP connection on public URL triggers mcp_public_endpoint."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-3", "Name": "public-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mcp.example.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "mcp_public_endpoint"]
        self.assertGreater(len(pub), 0)

    def test_mcp_private_endpoint_no_finding(self):
        """MCP connection on privatelink URL is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-4", "Name": "private-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://myserver.privatelink.azure.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "mcp_public_endpoint"]
        self.assertEqual(len(pub), 0)

    def test_mcp_shared_to_all_detected(self):
        """MCP connection shared to all triggers mcp_shared_to_all."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-5", "Name": "shared-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mcp.internal.azure.com/sse",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "mcp_shared_to_all"]
        self.assertGreater(len(shared), 0)

    def test_non_mcp_connection_no_finding(self):
        """Non-MCP connection should not trigger MCP findings."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-other", "Name": "storage-conn",
            "WorkspaceName": "ws1",
            "Category": "AzureBlob",
            "AuthType": "ApiKey",
            "Target": "https://storage.blob.core.windows.net",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B19. Foundry — Tool Connection Security
# ====================================================================

class TestFoundryToolSecurity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_tool_security
        self.analyze = analyze_foundry_tool_security

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_a2a_no_auth_detected(self):
        """A2A connection without identity auth triggers a2a_no_identity_auth."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-a2a-1", "Name": "agent-link",
            "WorkspaceName": "ws1",
            "Category": "A2A",
            "AuthType": "ApiKey",
            "Target": "https://other-agent.azure.com/api",
        })])
        findings = self.analyze(idx)
        a2a = [f for f in findings if f["Subcategory"] == "a2a_no_identity_auth"]
        self.assertGreater(len(a2a), 0)

    def test_a2a_entra_auth_no_finding(self):
        """A2A connection with Entra ID auth is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-a2a-2", "Name": "secure-agent-link",
            "WorkspaceName": "ws1",
            "Category": "A2A",
            "AuthType": "AAD",
            "Target": "https://agent.azure.com/api",
        })])
        findings = self.analyze(idx)
        a2a = [f for f in findings if f["Subcategory"] == "a2a_no_identity_auth"]
        self.assertEqual(len(a2a), 0)

    def test_non_microsoft_tool_detected(self):
        """MCP to non-MS endpoint triggers non_microsoft_tool_connection."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-ext-1", "Name": "external-tool",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://tools.thirdparty.io/api",
        })])
        findings = self.analyze(idx)
        ext = [f for f in findings if f["Subcategory"] == "non_microsoft_tool_connection"]
        self.assertGreater(len(ext), 0)

    def test_microsoft_tool_no_finding(self):
        """MCP to Azure endpoint does not trigger non-MS finding."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-az-1", "Name": "azure-tool",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mymcp.azure.com/sse",
        })])
        findings = self.analyze(idx)
        ext = [f for f in findings if f["Subcategory"] == "non_microsoft_tool_connection"]
        self.assertEqual(len(ext), 0)

    def test_credential_based_tool_detected(self):
        """Tool connection with API key triggers tool_credential_based_auth."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-func-1", "Name": "my-function",
            "WorkspaceName": "ws1",
            "Category": "AzureFunction",
            "AuthType": "ApiKey",
            "Target": "https://func.azurewebsites.net",
        })])
        findings = self.analyze(idx)
        cred = [f for f in findings if f["Subcategory"] == "tool_credential_based_auth"]
        self.assertGreater(len(cred), 0)

    def test_mi_tool_no_credential_finding(self):
        """Tool connection with managed identity has no credential finding."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-func-2", "Name": "mi-function",
            "WorkspaceName": "ws1",
            "Category": "AzureFunction",
            "AuthType": "ManagedIdentity",
            "Target": "https://func.azurewebsites.net",
        })])
        findings = self.analyze(idx)
        cred = [f for f in findings if f["Subcategory"] == "tool_credential_based_auth"]
        self.assertEqual(len(cred), 0)

'''

patch_file(TESTS,
    '\n# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================',
    TEST_CLASSES + '# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================')

# Add import assertions
patch_file(TESTS,
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_agent_application"))\n        # C – Cross-cutting',
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_agent_application"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_mcp_tools"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_tool_security"))\n        # C – Cross-cutting')

print("=== Test patches done ===\n")
print("All Phase H patches applied!")
