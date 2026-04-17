"""Apply Phase K changes: Lifecycle Governance."""


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
    '     9s. Agent Observability              — tracing, App Insights, log coverage\n\n  C. Custom Agent Security  (cross-cutting)',
    '     9s. Agent Observability              — tracing, App Insights, log coverage\n     9t. Agent Lifecycle Governance       — versioning, shadow agents, publishing controls\n\n  C. Custom Agent Security  (cross-cutting)')

# ============================================================
# 2. ENGINE: Add new analyze functions
# ============================================================
NEW_FUNCTIONS = '''

# ── 9t. Agent Lifecycle Governance ───────────────────────────────────

def analyze_foundry_lifecycle(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent lifecycle governance: versioning, shadow agents, publishing."""
    findings: list[dict] = []
    findings.extend(_check_projects_no_agents(evidence_index))
    findings.extend(_check_unpublished_agents(evidence_index))
    findings.extend(_check_agent_no_rbac(evidence_index))
    return findings


def _check_projects_no_agents(idx: dict) -> list[dict]:
    """Flag Foundry projects with agent capacity but no published applications."""
    projects = idx.get("foundry-project", [])
    apps = idx.get("foundry-agent-application", [])
    if not projects:
        return []
    # Collect project IDs that have published applications
    published_projects = set()
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        if proj_id:
            published_projects.add(proj_id)
    no_apps: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        agent_count = data.get("AgentCount", 0) or 0
        # Projects with agents but no published applications indicate shadow/unmanaged agents
        if agent_count > 0 and proj_id not in published_projects:
            no_apps.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
                "AgentCount": agent_count,
            })
    if no_apps:
        return [_as_finding(
            "foundry_lifecycle", "shadow_agents_unpublished",
            f"{len(no_apps)} projects have agents but no published applications (potential shadow agents)",
            "These projects contain active agents that have not been published as "
            "formal Agent Applications. Unpublished agents bypass lifecycle controls, "
            "RBAC scoping, and audit trails. Publish agents to formalize governance "
            "and enable identity-scoped access control.",
            "medium", "foundry", no_apps,
            {"Description": "Review and publish or decommission shadow agents.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Review all agents under the 'Agents' tab",
                             "Publish production-ready agents as Agent Applications",
                             "Decommission or delete unused development agents",
                             "Set up Azure Policy to require agent publishing"]},
        )]
    return []


def _check_unpublished_agents(idx: dict) -> list[dict]:
    """Flag projects with high agent counts relative to published applications."""
    projects = idx.get("foundry-project", [])
    apps = idx.get("foundry-agent-application", [])
    if not projects:
        return []
    # Count published apps per project
    project_app_count: dict[str, int] = {}
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        if proj_id:
            project_app_count[proj_id] = project_app_count.get(proj_id, 0) + 1
    excess: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        agent_count = data.get("AgentCount", 0) or 0
        published = project_app_count.get(proj_id, 0)
        # If agent count significantly exceeds published count, signal governance gap
        if agent_count > 3 and published > 0 and agent_count > published * 3:
            excess.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
                "AgentCount": agent_count,
                "PublishedApplications": published,
            })
    if excess:
        return [_as_finding(
            "foundry_lifecycle", "excess_unpublished_agents",
            f"{len(excess)} projects have disproportionately more agents than published applications",
            "A large number of unpublished agents relative to published applications "
            "suggests development sprawl or abandoned experiments. Review and clean up "
            "unused agents to reduce attack surface and manage resource costs.",
            "low", "foundry", excess,
            {"Description": "Audit and clean up excess unpublished agents.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Review agent inventory under the 'Agents' tab",
                             "Identify and delete unused or duplicate agents",
                             "Establish naming conventions and cleanup policies"]},
        )]
    return []


def _check_agent_no_rbac(idx: dict) -> list[dict]:
    """Flag published agent applications without explicit RBAC assignments."""
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
                "AccountName": data.get("AccountName", ""),
            })
    if no_rbac:
        return [_as_finding(
            "foundry_lifecycle", "agent_no_rbac",
            f"{len(no_rbac)} published agent applications have no explicit RBAC assignments",
            "Published Agent Applications without RBAC assignments may be accessible "
            "only via inherited permissions, making access control opaque. Assign "
            "explicit Azure AI User role assignments on each Agent Application "
            "resource to enforce least-privilege access.",
            "medium", "foundry", no_rbac,
            {"Description": "Assign explicit RBAC to Agent Application resources.",
             "PortalSteps": ["Go to Azure portal > Agent Application resource",
                             "Go to Access control (IAM) > Add role assignment",
                             "Assign 'Azure AI User' to authorized principals",
                             "Remove broad inherited role assignments if possible"]},
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
    '    foundry_obs_findings = analyze_foundry_observability(evidence_index)\n\n    # C. Custom Agent Security',
    '    foundry_obs_findings = analyze_foundry_observability(evidence_index)\n\n    log.info("Running Foundry lifecycle governance analysis …")\n    foundry_lifecycle_findings = analyze_foundry_lifecycle(evidence_index)\n\n    # C. Custom Agent Security')

# ============================================================
# 4. ENGINE: Update all_findings
# ============================================================
patch_file(ENGINE,
    '        + foundry_data_findings + foundry_obs_findings\n        + custom_api_findings',
    '        + foundry_data_findings + foundry_obs_findings\n        + foundry_lifecycle_findings\n        + custom_api_findings')

# ============================================================
# 5. ENGINE: Update Categories
# ============================================================
patch_file(ENGINE,
    '            "foundry_observability": foundry_obs_findings,\n            "custom_api_security": custom_api_findings,',
    '            "foundry_observability": foundry_obs_findings,\n            "foundry_lifecycle": foundry_lifecycle_findings,\n            "custom_api_security": custom_api_findings,')

# ============================================================
# 6. ENGINE: Update CategoryCounts
# ============================================================
patch_file(ENGINE,
    '            "foundry_observability": len(foundry_obs_findings),\n            "custom_api_security": len(custom_api_findings),',
    '            "foundry_observability": len(foundry_obs_findings),\n            "foundry_lifecycle": len(foundry_lifecycle_findings),\n            "custom_api_security": len(custom_api_findings),')

print("=== Engine patches done ===\n")

# ============================================================
# 7. TESTS: Add test classes
# ============================================================
TEST_CLASSES = '''

# ====================================================================
# B24. Foundry — Agent Lifecycle Governance
# ====================================================================

class TestFoundryLifecycle(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_lifecycle
        self.analyze = analyze_foundry_lifecycle

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_shadow_agents_detected(self):
        """Project with agents but no published apps triggers shadow finding."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "/sub/proj1", "Name": "dev-project",
            "AccountName": "acct-1", "AgentCount": 5,
        })])
        findings = self.analyze(idx)
        shadow = [f for f in findings if f["Subcategory"] == "shadow_agents_unpublished"]
        self.assertGreater(len(shadow), 0)

    def test_no_shadow_agents_when_published(self):
        """Project with agents and published apps is clean."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj2", "Name": "prod-project",
                "AccountName": "acct-1", "AgentCount": 3,
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app1", "Name": "agent-1",
                "ProjectId": "/sub/proj2", "ProjectName": "prod-project",
            }),
        ])
        findings = self.analyze(idx)
        shadow = [f for f in findings if f["Subcategory"] == "shadow_agents_unpublished"]
        self.assertEqual(len(shadow), 0)

    def test_no_shadow_when_zero_agents(self):
        """Project with zero agents count does not trigger shadow finding."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "/sub/proj3", "Name": "empty-project",
            "AccountName": "acct-1", "AgentCount": 0,
        })])
        findings = self.analyze(idx)
        shadow = [f for f in findings if f["Subcategory"] == "shadow_agents_unpublished"]
        self.assertEqual(len(shadow), 0)

    def test_excess_unpublished_detected(self):
        """Project with many more agents than published apps triggers excess finding."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj4", "Name": "sprawl-project",
                "AccountName": "acct-1", "AgentCount": 20,
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app2", "Name": "only-app",
                "ProjectId": "/sub/proj4", "ProjectName": "sprawl-project",
            }),
        ])
        findings = self.analyze(idx)
        excess = [f for f in findings if f["Subcategory"] == "excess_unpublished_agents"]
        self.assertGreater(len(excess), 0)

    def test_balanced_agents_no_excess(self):
        """Project with balanced agent/app ratio is clean."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj5", "Name": "balanced-project",
                "AccountName": "acct-1", "AgentCount": 3,
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app3", "Name": "app-1",
                "ProjectId": "/sub/proj5", "ProjectName": "balanced-project",
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app4", "Name": "app-2",
                "ProjectId": "/sub/proj5", "ProjectName": "balanced-project",
            }),
        ])
        findings = self.analyze(idx)
        excess = [f for f in findings if f["Subcategory"] == "excess_unpublished_agents"]
        self.assertEqual(len(excess), 0)

    def test_agent_no_rbac_detected(self):
        """Published agent without RBAC triggers agent_no_rbac."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app5", "Name": "no-rbac-agent",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "HasRBACAssignments": False,
        })])
        findings = self.analyze(idx)
        rbac = [f for f in findings if f["Subcategory"] == "agent_no_rbac"]
        self.assertGreater(len(rbac), 0)

    def test_agent_with_rbac_no_finding(self):
        """Published agent with explicit RBAC is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app6", "Name": "rbac-agent",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "HasRBACAssignments": True,
        })])
        findings = self.analyze(idx)
        rbac = [f for f in findings if f["Subcategory"] == "agent_no_rbac"]
        self.assertEqual(len(rbac), 0)

'''

patch_file(TESTS,
    '\n# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================',
    TEST_CLASSES + '# ====================================================================\n# D1. Entra — AI Service Principals\n# ====================================================================')

# Add import assertions
patch_file(TESTS,
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_observability"))\n        # C – Cross-cutting',
    '        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_observability"))\n        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_lifecycle"))\n        # C – Cross-cutting')

print("=== Test patches done ===\n")
print("All Phase K patches applied!")
