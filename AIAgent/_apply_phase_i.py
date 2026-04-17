"""Apply Phase I changes: Guardrails & Hosted Agents."""


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
COLLECTOR = "app/collectors/azure/foundry_config.py"
TESTS = "tests/test_ai_agent_security_engine.py"

# ============================================================
# 1. COLLECTOR: Add Capability Host collection (Section 13)
# ============================================================
patch_file(COLLECTOR,
    '        # ── Summary ──────────────────────────────────────────────────',
    '''        # ── 13. Capability Hosts (Hosted Agent infrastructure) ───────
        for sub_id, sub_name, acct_name, acct_id in ai_accounts:
            if not acct_id:
                continue
            try:
                ch_url = (
                    f"https://management.azure.com{acct_id}"
                    f"/capabilityHosts?api-version=2025-04-01-preview"
                )
                ch_resp = await _arm_get(creds, ch_url)
                cap_hosts = (ch_resp or {}).get("value", [])
                for ch in cap_hosts:
                    ch_props = ch.get("properties", {})
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="FoundryConfig",
                        evidence_type="foundry-capability-host",
                        description=f"Capability host: {ch.get('name', '')} in {acct_name}",
                        data={
                            "CapabilityHostId": ch.get("id", ""),
                            "Name": ch.get("name", ""),
                            "AccountName": acct_name,
                            "AccountId": acct_id,
                            "ProvisioningState": ch_props.get("provisioningState", ""),
                            "ContainerRegistryId": ch_props.get("containerRegistryId", ""),
                            "AcrRegistryName": ch_props.get("acrRegistryName", ""),
                            "StorageAccountId": ch_props.get("storageAccountId", ""),
                            "HasVNetConfig": bool(ch_props.get("virtualNetworkConfiguration")),
                            "ComputeType": ch_props.get("computeType", ""),
                            "ReplicaCount": ch_props.get("replicaCount"),
                            "SubscriptionId": sub_id,
                        },
                        resource_id=ch.get("id", ""), resource_type="CapabilityHost",
                    ))
                log.info(
                    "  [FoundryConfig] %s/%s: %d capability hosts",
                    sub_name, acct_name, len(cap_hosts),
                )
            except AccessDeniedError:
                access_denied_count += 1
                log.warning("  [FoundryConfig] Capability hosts access denied for %s/%s", sub_name, acct_name)
            except Exception as exc:
                log.warning("  [FoundryConfig] Capability hosts for %s/%s failed: %s", sub_name, acct_name, exc)

        # ── Summary ──────────────────────────────────────────────────''')

# Add capability host count to summary
patch_file(COLLECTOR,
    '        agent_deploy_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-deployment")',
    '        agent_deploy_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-agent-deployment")\n        cap_host_count = sum(1 for e in evidence if e.get("EvidenceType") == "foundry-capability-host")')

patch_file(COLLECTOR,
    '                "AgentDeployments": agent_deploy_count,\n                "AccessDeniedErrors": access_denied_count,',
    '                "AgentDeployments": agent_deploy_count,\n                "CapabilityHosts": cap_host_count,\n                "AccessDeniedErrors": access_denied_count,')

print("=== Collector patches done ===\n")

# ============================================================
# 2. ENGINE: Update docstring
# ============================================================
patch_file(ENGINE,
    '     9o. Tool Connection Security       — A2A auth, non-Microsoft tools, shared access\n\n  C. Custom Agent Security  (cross-cutting)',
    '     9o. Tool Connection Security       — A2A auth, non-Microsoft tools, shared access\n     9p. Guardrails Configuration        — agent guardrails, intervention points, PII/safety\n     9q. Hosted Agent Security            — capability hosts, ACR, container security\n\n  C. Custom Agent Security  (cross-cutting)')

# ============================================================
# 3. ENGINE: Add new analyze functions before D. ENTRA section
# ============================================================
NEW_FUNCTIONS = '''

# ── 9p. Guardrails Configuration ─────────────────────────────────────

def analyze_foundry_guardrails(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent guardrail configuration and safety interventions."""
    findings: list[dict] = []
    findings.extend(_check_agent_no_custom_guardrail(evidence_index))
    findings.extend(_check_agent_no_content_safety(evidence_index))
    findings.extend(_check_guardrail_default_only(evidence_index))
    return findings


def _check_agent_no_custom_guardrail(idx: dict) -> list[dict]:
    """Flag published agent applications without a custom guardrail assigned."""
    apps = idx.get("foundry-agent-application", [])
    no_guard: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        guardrail = str(data.get("GuardrailCollection", "") or "").strip()
        if not guardrail or guardrail.lower() in ("", "none", "default", "microsoft.defaultv2"):
            no_guard.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "ProjectName": data.get("ProjectName", ""),
                "GuardrailCollection": guardrail or "None",
            })
    if no_guard:
        return [_as_finding(
            "foundry_guardrails", "agent_no_custom_guardrail",
            f"{len(no_guard)} agent applications use default or no custom guardrails",
            "Agent-level guardrails override model guardrails entirely. When agents "
            "have no custom guardrail collection, they rely on the default Microsoft.DefaultV2 "
            "guardrail which may not cover domain-specific risks like PII exposure, "
            "task adherence violations, or tool-call injection.",
            "medium", "foundry", no_guard,
            {"Description": "Assign custom guardrail collections to agent applications.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Open the agent application > Safety & Security tab",
                             "Create a custom guardrail collection with relevant controls",
                             "Enable tool-call and tool-response intervention points",
                             "Assign the collection to the agent"]},
        )]
    return []


def _check_agent_no_content_safety(idx: dict) -> list[dict]:
    """Flag agent applications in projects that have no content safety filters configured."""
    apps = idx.get("foundry-agent-application", [])
    filters = idx.get("azure-openai-content-filter", [])
    if not apps:
        return []
    # Collect accounts that have content filters
    accounts_with_filters = set()
    for f_ev in filters:
        f_data = f_ev.get("Data", f_ev.get("data", {}))
        acct = f_data.get("AccountName", "")
        if acct:
            accounts_with_filters.add(acct.lower())
    no_safety: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        acct = str(data.get("AccountName", "")).lower()
        if acct and acct not in accounts_with_filters:
            no_safety.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "AccountName": data.get("AccountName", ""),
                "ProjectName": data.get("ProjectName", ""),
            })
    if no_safety:
        return [_as_finding(
            "foundry_guardrails", "agent_account_no_content_safety",
            f"{len(no_safety)} agent applications are in accounts with no content safety filters",
            "Agent applications in Foundry accounts that lack content safety filters "
            "have no guardrails against harmful content generation. Configure both "
            "model-level content filters and agent-level guardrails for defense in depth.",
            "high", "foundry", no_safety,
            {"Description": "Configure content safety filters on the Foundry account.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Content Safety > Filters",
                             "Create content filter policies for model deployments",
                             "Also configure agent-level guardrails for additional protection"]},
        )]
    return []


def _check_guardrail_default_only(idx: dict) -> list[dict]:
    """Flag when all content filters in an account use minimum severity thresholds."""
    filters = idx.get("azure-openai-content-filter", [])
    if not filters:
        return []
    weak_accounts: dict[str, list] = {}
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        # Check if all categories are set to low/allow thresholds
        props = data.get("Properties", data.get("properties", {}))
        if not props:
            continue
        categories = props.get("contentFilters", [])
        all_permissive = True
        for cat in categories:
            sev = str(cat.get("severityThreshold", "")).lower()
            if sev not in ("low", ""):
                all_permissive = False
                break
        if all_permissive and categories:
            acct = data.get("AccountName", "unknown")
            if acct not in weak_accounts:
                weak_accounts[acct] = []
            weak_accounts[acct].append({
                "Type": "ContentFilter",
                "Name": data.get("Name", data.get("FilterName", "Unknown")),
                "AccountName": acct,
            })
    if weak_accounts:
        affected = []
        for acct, items in weak_accounts.items():
            affected.extend(items)
        return [_as_finding(
            "foundry_guardrails", "permissive_content_filters",
            f"{len(affected)} content filters use minimum severity thresholds",
            "Content filters with 'low' severity thresholds allow most harmful content "
            "through. For agents with tool access, use 'medium' or 'high' thresholds "
            "to mitigate prompt injection and content safety risks.",
            "medium", "foundry", affected,
            {"Description": "Increase content filter severity thresholds.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Content Safety > Filters",
                             "Increase severity thresholds from 'Low' to 'Medium' or 'High'",
                             "Apply to all model deployments used by agents"]},
        )]
    return []


# ── 9q. Hosted Agent Security ────────────────────────────────────────

def analyze_foundry_hosted_agents(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess hosted agent capability hosts for security posture."""
    findings: list[dict] = []
    findings.extend(_check_hosted_no_vnet(evidence_index))
    findings.extend(_check_hosted_no_acr(evidence_index))
    findings.extend(_check_hosted_unhealthy(evidence_index))
    return findings


def _check_hosted_no_vnet(idx: dict) -> list[dict]:
    """Flag hosted agent capability hosts without VNet integration."""
    cap_hosts = idx.get("foundry-capability-host", [])
    no_vnet: list[dict] = []
    for ev in cap_hosts:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasVNetConfig"):
            no_vnet.append({
                "Type": "CapabilityHost",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("CapabilityHostId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_vnet:
        return [_as_finding(
            "foundry_hosted_agents", "hosted_no_vnet",
            f"{len(no_vnet)} hosted agent capability hosts lack VNet integration",
            "Hosted agents without VNet integration have their container traffic "
            "routed over public networks. Configure VNet integration with a delegated "
            "subnet (Microsoft.App/environments) to keep agent execution traffic private.",
            "high", "foundry", no_vnet,
            {"Description": "Configure VNet integration for hosted agent capability hosts.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Networking > Hosted Agents",
                             "Configure a delegated subnet (Microsoft.App/environments)",
                             "Enable VNet integration for the capability host",
                             "Note: Some features may not support VNet in preview"]},
        )]
    return []


def _check_hosted_no_acr(idx: dict) -> list[dict]:
    """Flag hosted agent capability hosts without a container registry configured."""
    cap_hosts = idx.get("foundry-capability-host", [])
    no_acr: list[dict] = []
    for ev in cap_hosts:
        data = ev.get("Data", ev.get("data", {}))
        acr_id = data.get("ContainerRegistryId", "") or ""
        acr_name = data.get("AcrRegistryName", "") or ""
        if not acr_id and not acr_name:
            no_acr.append({
                "Type": "CapabilityHost",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("CapabilityHostId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_acr:
        return [_as_finding(
            "foundry_hosted_agents", "hosted_no_acr",
            f"{len(no_acr)} hosted agent capability hosts have no container registry configured",
            "Hosted agents require an Azure Container Registry to store and pull "
            "Docker images. Without a configured ACR, the capability host cannot "
            "deploy hosted agent containers securely.",
            "high", "foundry", no_acr,
            {"Description": "Configure Azure Container Registry for capability hosts.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Hosted Agents > Capability Hosts",
                             "Associate an Azure Container Registry",
                             "Ensure ACR has RBAC (Container Registry Repository Reader)",
                             "Enable private endpoint on ACR for network isolation"]},
        )]
    return []


def _check_hosted_unhealthy(idx: dict) -> list[dict]:
    """Flag hosted agent capability hosts with failed provisioning."""
    cap_hosts = idx.get("foundry-capability-host", [])
    unhealthy: list[dict] = []
    _HEALTHY = {"succeeded", "running", "creating"}
    for ev in cap_hosts:
        data = ev.get("Data", ev.get("data", {}))
        state = str(data.get("ProvisioningState", "")).lower()
        if state and state not in _HEALTHY:
            unhealthy.append({
                "Type": "CapabilityHost",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("CapabilityHostId", ""),
                "AccountName": data.get("AccountName", ""),
                "ProvisioningState": data.get("ProvisioningState", ""),
            })
    if unhealthy:
        return [_as_finding(
            "foundry_hosted_agents", "hosted_unhealthy",
            f"{len(unhealthy)} hosted agent capability hosts are in unhealthy state",
            "Capability hosts with failed provisioning indicate misconfiguration "
            "or resource issues. Investigate and resolve provisioning errors to "
            "ensure hosted agents can be deployed and managed properly.",
            "high", "foundry", unhealthy,
            {"Description": "Investigate and fix unhealthy capability hosts.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Hosted Agents > Capability Hosts",
                             "Check provisioning state and error details",
                             "Resolve configuration issues (ACR access, VNet, etc.)",
                             "Re-provision the capability host"]},
        )]
    return []

'''

patch_file(ENGINE,
    '    return []\n\n\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================',
    '    return []\n' + NEW_FUNCTIONS + '\n# ====================================================================\n# D. ENTRA IDENTITY SECURITY FOR AI\n# ====================================================================')

# ============================================================
# 4. ENGINE: Wire into orchestrator
# ============================================================
patch_file(ENGINE,
    '    foundry_tool_findings = analyze_foundry_tool_security(evidence_index)\n\n    # C. Custom Agent Security',
    '    foundry_tool_findings = analyze_foundry_tool_security(evidence_index)\n\n    log.info("Running Foundry guardrails analysis …")\n    foundry_guardrail_findings = analyze_foundry_guardrails(evidence_index)\n\n    log.info("Running Foundry hosted agent security analysis …")\n    foundry_hosted_findings = analyze_foundry_hosted_agents(evidence_index)\n\n    # C. Custom Agent Security')

# ============================================================
# 5. ENGINE: Update all_findings
# ============================================================
patch_file(ENGINE,
    '        + foundry_mcp_findings + foundry_tool_findings\n        + custom_api_findings',
    '        + foundry_mcp_findings + foundry_tool_findings\n        + foundry_guardrail_findings + foundry_hosted_findings\n        + custom_api_findings')

# ============================================================
# 6. ENGINE: Update Categories
# ============================================================
patch_file(ENGINE,
    '            "foundry_tool_security": foundry_tool_findings,\n            "custom_api_security": custom_api_findings,',
    '            "foundry_tool_security": foundry_tool_findings,\n            "foundry_guardrails": foundry_guardrail_findings,\n            "foundry_hosted_agents": foundry_hosted_findings,\n            "custom_api_security": custom_api_findings,')

# ============================================================
# 7. ENGINE: Update CategoryCounts
# ============================================================
patch_file(ENGINE,
    '            "foundry_tool_security": len(foundry_tool_findings),\n            "custom_api_security": len(custom_api_findings),',
    '            "foundry_tool_security": len(foundry_tool_findings),\n            "foundry_guardrails": len(foundry_guardrail_findings),\n            "foundry_hosted_agents": len(foundry_hosted_findings),\n            "custom_api_security": len(custom_api_findings),')

# ============================================================
# 8. ENGINE: Update EvidenceSummary
# ============================================================
patch_file(ENGINE,
    '            "AgentDeployments": fs.get("AgentDeployments", 0),\n            "AccessDeniedErrors": fs.get("AccessDeniedErrors", 0),',
    '            "AgentDeployments": fs.get("AgentDeployments", 0),\n            "CapabilityHosts": fs.get("CapabilityHosts", 0),\n            "AccessDeniedErrors": fs.get("AccessDeniedErrors", 0),')

print("=== Engine patches done ===\n")

# ============================================================
# 9. TESTS: Add evidence helper + test classes
# ============================================================

# Add evidence helper for capability hosts
patch_file(TESTS,
    'def _foundry_agent_deploy_ev(data: dict) -> dict:',
    'def _foundry_capability_host_ev(data: dict) -> dict:\n    return {"EvidenceType": "foundry-capability-host", "Data": data, "ResourceId": data.get("CapabilityHostId", "")}\n\ndef _foundry_agent_deploy_ev(data: dict) -> dict:')

# Add test classes before D1. Entra
TEST_CLASSES = '''

# ====================================================================
# B20. Foundry — Guardrails Configuration
# ====================================================================

class TestFoundryGuardrails(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_guardrails
        self.analyze = analyze_foundry_guardrails

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_custom_guardrail_detected(self):
        """Agent app with no guardrail triggers agent_no_custom_guardrail."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app1", "Name": "agent-1",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "GuardrailCollection": "",
        })])
        findings = self.analyze(idx)
        guard = [f for f in findings if f["Subcategory"] == "agent_no_custom_guardrail"]
        self.assertGreater(len(guard), 0)

    def test_default_guardrail_detected(self):
        """Agent app with Microsoft.DefaultV2 guardrail triggers finding."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app2", "Name": "agent-2",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "GuardrailCollection": "Microsoft.DefaultV2",
        })])
        findings = self.analyze(idx)
        guard = [f for f in findings if f["Subcategory"] == "agent_no_custom_guardrail"]
        self.assertGreater(len(guard), 0)

    def test_custom_guardrail_no_finding(self):
        """Agent app with custom guardrail is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app3", "Name": "agent-3",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "GuardrailCollection": "MyCustomGuardrails",
        })])
        findings = self.analyze(idx)
        guard = [f for f in findings if f["Subcategory"] == "agent_no_custom_guardrail"]
        self.assertEqual(len(guard), 0)

    def test_agent_account_no_content_safety(self):
        """Agent in account with no content filters triggers finding."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app4", "Name": "agent-4",
            "ProjectName": "proj-1", "AccountName": "acct-no-filters",
        })])
        findings = self.analyze(idx)
        safety = [f for f in findings if f["Subcategory"] == "agent_account_no_content_safety"]
        self.assertGreater(len(safety), 0)

    def test_agent_account_with_content_safety_no_finding(self):
        """Agent in account that has content filters is clean."""
        idx = _build_index([
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app5", "Name": "agent-5",
                "ProjectName": "proj-1", "AccountName": "acct-safe",
            }),
            _ai_filter_ev({"AccountName": "acct-safe", "Name": "filter-1"}),
        ])
        findings = self.analyze(idx)
        safety = [f for f in findings if f["Subcategory"] == "agent_account_no_content_safety"]
        self.assertEqual(len(safety), 0)


# ====================================================================
# B21. Foundry — Hosted Agent Security
# ====================================================================

class TestFoundryHostedAgents(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_hosted_agents
        self.analyze = analyze_foundry_hosted_agents

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_hosted_no_vnet_detected(self):
        """Capability host without VNet triggers hosted_no_vnet."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch1", "Name": "cap-host-1",
            "AccountName": "acct-1",
            "HasVNetConfig": False,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        vnet = [f for f in findings if f["Subcategory"] == "hosted_no_vnet"]
        self.assertGreater(len(vnet), 0)

    def test_hosted_with_vnet_no_finding(self):
        """Capability host with VNet is clean."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch2", "Name": "cap-host-2",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        vnet = [f for f in findings if f["Subcategory"] == "hosted_no_vnet"]
        self.assertEqual(len(vnet), 0)

    def test_hosted_no_acr_detected(self):
        """Capability host without ACR triggers hosted_no_acr."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch3", "Name": "cap-host-3",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "",
            "AcrRegistryName": "",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        acr = [f for f in findings if f["Subcategory"] == "hosted_no_acr"]
        self.assertGreater(len(acr), 0)

    def test_hosted_with_acr_no_finding(self):
        """Capability host with ACR configured is clean."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch4", "Name": "cap-host-4",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        acr = [f for f in findings if f["Subcategory"] == "hosted_no_acr"]
        self.assertEqual(len(acr), 0)

    def test_hosted_unhealthy_detected(self):
        """Capability host with failed state triggers hosted_unhealthy."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch5", "Name": "cap-host-5",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Failed",
        })])
        findings = self.analyze(idx)
        unhealthy = [f for f in findings if f["Subcategory"] == "hosted_unhealthy"]
        self.assertGreater(len(unhealthy), 0)

    def test_hosted_succeeded_no_unhealthy_finding(self):
        """Capability host with Succeeded state is clean."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch6", "Name": "cap-host-6",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        unhealthy = [f for f in findings if f["Subcategory"] == "hosted_unhealthy"]
        self.assertEqual(len(unhealthy), 0)

'''

patch_file(TESTS,
    '\n# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================',
    TEST_CLASSES + '# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================')

# Add import assertions
patch_file(TESTS,
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_tool_security"))\n        # C – Cross-cutting',
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_tool_security"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_guardrails"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_hosted_agents"))\n        # C – Cross-cutting')

print("=== Test patches done ===\n")
print("All Phase I patches applied!")
