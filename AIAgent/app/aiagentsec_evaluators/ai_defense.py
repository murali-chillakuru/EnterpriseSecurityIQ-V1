"""AI defense and governance evaluators — Defender for AI, Azure Policy, agent communication, agent governance."""

from __future__ import annotations

from .finding import _as_finding


def analyze_ai_defender_coverage(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Microsoft Defender for AI coverage."""
    findings: list[dict] = []
    findings.extend(_check_no_defender_for_ai(evidence_index))
    findings.extend(_check_defender_ai_alerts_suppressed(evidence_index))
    return findings


def _check_no_defender_for_ai(idx: dict) -> list[dict]:
    """Flag subscriptions without Defender for AI enabled."""
    defender = idx.get("azure-defender-plan", [])
    ai_services = idx.get("azure-ai-service", [])
    if not ai_services:
        return []

    subs_with_ai = {
        ev.get("Data", ev.get("data", {})).get("SubscriptionId", "")
        for ev in ai_services
        if ev.get("Data", ev.get("data", {})).get("SubscriptionId")
    }

    subs_with_defender = set()
    for ev in defender:
        data = ev.get("Data", ev.get("data", {}))
        plan_name = str(data.get("PlanName", "")).lower()
        if "ai" in plan_name and data.get("PricingTier", "").lower() == "standard":
            subs_with_defender.add(data.get("SubscriptionId", ""))

    unprotected = subs_with_ai - subs_with_defender
    if unprotected:
        resources = [{"Type": "Subscription", "Name": sid, "ResourceId": sid}
                     for sid in sorted(unprotected)]
        return [_as_finding(
            "ai_defender_coverage", "no_defender_for_ai",
            f"{len(unprotected)} subscriptions with AI services lack Defender for AI",
            "Microsoft Defender for AI provides threat detection for AI workloads, "
            "including prompt injection, credential theft, and anomalous usage patterns.",
            "high", "agent_orchestration", resources,
            {"Description": "Enable Defender for AI on subscriptions with AI resources.",
             "AzureCLI": "az security pricing create --name AI --tier Standard",
             "PortalSteps": ["Go to Azure portal > Microsoft Defender for Cloud",
                             "Go to Environment settings > Select subscription",
                             "Enable 'AI' plan",
                             "Save"]},
        )]
    return []


def _check_defender_ai_alerts_suppressed(idx: dict) -> list[dict]:
    """Flag subscriptions with Defender for AI alert suppression rules."""
    defender = idx.get("azure-defender-plan", [])
    suppressed: list[dict] = []
    for ev in defender:
        data = ev.get("Data", ev.get("data", {}))
        plan_name = str(data.get("PlanName", "")).lower()
        if "ai" in plan_name and data.get("HasSuppressionRules"):
            suppressed.append({
                "Type": "DefenderPlan",
                "Name": data.get("PlanName", ""),
                "ResourceId": data.get("SubscriptionId", ""),
                "SuppressionRuleCount": data.get("SuppressionRuleCount", 0),
            })
    if suppressed:
        return [_as_finding(
            "ai_defender_coverage", "defender_ai_alerts_suppressed",
            f"{len(suppressed)} subscriptions have Defender for AI alert suppressions",
            "Alert suppression rules may hide legitimate security threats targeting "
            "AI workloads — review and remove unnecessary suppressions.",
            "medium", "agent_orchestration", suppressed,
            {"Description": "Review and remove unnecessary alert suppressions.",
             "PortalSteps": ["Go to Microsoft Defender for Cloud > Alerts",
                             "Click 'Suppression rules'",
                             "Review AI-related suppression rules",
                             "Remove rules that are no longer justified"]},
        )]
    return []


# ── 21. Azure Policy for AI ─────────────────────────────────────────

def analyze_ai_policy_compliance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Azure Policy coverage for AI resources."""
    findings: list[dict] = []
    findings.extend(_check_no_ai_policies(evidence_index))
    findings.extend(_check_ai_policy_non_compliant(evidence_index))
    return findings


def _check_no_ai_policies(idx: dict) -> list[dict]:
    """Flag when no Azure Policy assignments govern AI resources."""
    policies = idx.get("azure-policy-assignment", [])
    ai_services = idx.get("azure-ai-service", [])
    if not ai_services:
        return []

    _AI_POLICY_KEYWORDS = {"cognitiveservices", "openai", "machinelearning",
                           "aiservices", "content safety", "responsible ai"}
    ai_policies = [
        ev for ev in policies
        if any(kw in str(ev.get("Data", ev.get("data", {})).get("PolicyDefinitionId", "")).lower()
               or kw in str(ev.get("Data", ev.get("data", {})).get("DisplayName", "")).lower()
               for kw in _AI_POLICY_KEYWORDS)
    ]

    if not ai_policies:
        return [_as_finding(
            "ai_policy_compliance", "no_ai_azure_policies",
            "No Azure Policy assignments found governing AI resources",
            "Azure Policies for AI resources enforce guardrails like denying public access, "
            "requiring CMK encryption, and mandating diagnostic settings.",
            "high", "agent_orchestration",
            [{"Type": "PolicyGap", "Name": "AI Policy Coverage",
              "ResourceId": "ai-policy-governance"}],
            {"Description": "Assign built-in Azure Policies for AI services.",
             "AzureCLI": "az policy assignment create --name 'deny-ai-public-access' "
                         "--policy '/providers/Microsoft.Authorization/policyDefinitions/<built-in-id>' "
                         "--scope /subscriptions/<sub-id>",
             "PortalSteps": ["Go to Azure portal > Policy > Definitions",
                             "Filter by 'Cognitive Services' category",
                             "Assign policies: deny public access, require CMK, enable diagnostics",
                             "Apply to subscriptions with AI resources"]},
        )]
    return []


def _check_ai_policy_non_compliant(idx: dict) -> list[dict]:
    """Flag AI resources in non-compliant state against assigned policies."""
    compliance = idx.get("azure-policy-compliance", [])
    non_compliant: list[dict] = []
    _AI_TYPES = {"microsoft.cognitiveservices/accounts", "microsoft.machinelearningservices/workspaces"}
    for ev in compliance:
        data = ev.get("Data", ev.get("data", {}))
        resource_type = str(data.get("ResourceType", "")).lower()
        if resource_type in _AI_TYPES and data.get("ComplianceState", "").lower() == "noncompliant":
            non_compliant.append({
                "Type": "PolicyNonCompliance",
                "Name": data.get("ResourceName", "Unknown"),
                "ResourceId": data.get("ResourceId", ""),
                "PolicyName": data.get("PolicyDefinitionName", ""),
            })
    if non_compliant:
        return [_as_finding(
            "ai_policy_compliance", "ai_policy_non_compliant",
            f"{len(non_compliant)} AI resources are non-compliant with assigned Azure Policies",
            "Non-compliant AI resources violate organizational governance guardrails, "
            "indicating configuration drift or policy evasion.",
            "medium", "agent_orchestration", non_compliant,
            {"Description": "Remediate non-compliant AI resources or create exemptions if justified.",
             "PortalSteps": ["Go to Azure portal > Policy > Compliance",
                             "Filter by non-compliant Cognitive Services/ML resources",
                             "Review each non-compliant resource",
                             "Remediate or create documented exemptions"]},
        )]
    return []


# ── 22. Agent Communication Security ────────────────────────────────

def analyze_agent_communication(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent-to-agent communication security."""
    findings: list[dict] = []
    findings.extend(_check_agent_no_auth_between_agents(evidence_index))
    findings.extend(_check_agent_unrestricted_tool_access(evidence_index))
    findings.extend(_check_agent_memory_encryption(evidence_index))
    return findings


def _check_agent_no_auth_between_agents(idx: dict) -> list[dict]:
    """Flag multi-agent setups without inter-agent authentication."""
    agents = idx.get("agent-orchestration-config", [])
    no_auth: list[dict] = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsMultiAgent") and not data.get("HasInterAgentAuth"):
            no_auth.append({
                "Type": "AgentConfig",
                "Name": data.get("AgentName", "Unknown"),
                "ResourceId": data.get("AgentId", ""),
                "OrchestrationType": data.get("OrchestrationType", ""),
            })
    if no_auth:
        return [_as_finding(
            "agent_communication", "agent_no_auth_between_agents",
            f"{len(no_auth)} multi-agent setups lack inter-agent authentication",
            "Multi-agent systems without mutual authentication allow any agent to invoke "
            "another, enabling privilege escalation and unauthorized data access.",
            "critical", "agent_orchestration", no_auth,
            {"Description": "Implement mutual authentication between agents.",
             "PortalSteps": ["Review agent orchestration configuration",
                             "Enable managed identity for each agent",
                             "Configure AAD token-based auth between agent calls",
                             "Restrict agent-to-agent communication via network policies"]},
        )]
    return []


def _check_agent_unrestricted_tool_access(idx: dict) -> list[dict]:
    """Flag agents with unrestricted tool access."""
    agents = idx.get("agent-orchestration-config", [])
    unrestricted: list[dict] = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasUnrestrictedToolAccess"):
            unrestricted.append({
                "Type": "AgentConfig",
                "Name": data.get("AgentName", "Unknown"),
                "ResourceId": data.get("AgentId", ""),
                "ToolCount": data.get("ToolCount", 0),
            })
    if unrestricted:
        return [_as_finding(
            "agent_communication", "agent_unrestricted_tool_access",
            f"{len(unrestricted)} agents have unrestricted access to all available tools",
            "Agents with access to all tools without least-privilege scoping can "
            "perform unintended write/delete operations when manipulated.",
            "high", "agent_orchestration", unrestricted,
            {"Description": "Restrict each agent to only the tools required for its function.",
             "PortalSteps": ["Review agent tool configuration",
                             "Create tool allow-lists per agent role",
                             "Remove unnecessary tool bindings",
                             "Implement tool-level RBAC"]},
        )]
    return []


def _check_agent_memory_encryption(idx: dict) -> list[dict]:
    """Flag agents with unencrypted memory/state stores."""
    agents = idx.get("agent-orchestration-config", [])
    unencrypted: list[dict] = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasMemoryStore") and not data.get("MemoryEncrypted"):
            unencrypted.append({
                "Type": "AgentConfig",
                "Name": data.get("AgentName", "Unknown"),
                "ResourceId": data.get("AgentId", ""),
            })
    if unencrypted:
        return [_as_finding(
            "agent_communication", "agent_memory_no_encryption",
            f"{len(unencrypted)} agents have unencrypted memory/state stores",
            "Agent memory stores may contain conversation history and sensitive data. "
            "Without encryption, this data is vulnerable to extraction.",
            "medium", "agent_orchestration", unencrypted,
            {"Description": "Encrypt agent memory and state stores.",
             "PortalSteps": ["Review agent state storage configuration",
                             "Enable encryption at rest for memory stores",
                             "Use Azure Key Vault for encryption key management",
                             "Rotate encryption keys on schedule"]},
        )]
    return []


# ── 23. Agent Governance ────────────────────────────────────────────

def analyze_agent_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent governance and inventory controls."""
    findings: list[dict] = []
    findings.extend(_check_no_agent_inventory(evidence_index))
    findings.extend(_check_agent_no_human_in_loop(evidence_index))
    findings.extend(_check_shadow_ai_agents(evidence_index))
    return findings


def _check_no_agent_inventory(idx: dict) -> list[dict]:
    """Flag when no centralized agent inventory exists."""
    agents = idx.get("agent-orchestration-config", [])
    cs_bots = idx.get("copilot-studio-bot", [])
    workspaces = idx.get("azure-ai-workspace", [])

    has_agents = bool(agents or cs_bots or workspaces)
    has_inventory = any(
        ev.get("Data", ev.get("data", {})).get("IsPartOfInventory")
        for ev in agents
    )

    if has_agents and not has_inventory:
        total = len(agents) + len(cs_bots)
        return [_as_finding(
            "agent_governance", "no_agent_inventory",
            f"No centralized agent inventory found ({total} agents detected)",
            "Without a centralized registry of deployed agents, organizations cannot "
            "track agent capabilities, data access, or security posture.",
            "medium", "agent_orchestration",
            [{"Type": "GovernanceGap", "Name": "Agent Inventory",
              "ResourceId": "agent-governance", "DetectedAgents": total}],
            {"Description": "Create a centralized agent registry.",
             "PortalSteps": ["Document all deployed AI agents across platforms",
                             "Record agent capabilities, data access, and ownership",
                             "Establish an agent lifecycle management process",
                             "Integrate with CMDB or asset management system"]},
        )]
    return []


def _check_agent_no_human_in_loop(idx: dict) -> list[dict]:
    """Flag agents performing write/delete operations without human approval."""
    agents = idx.get("agent-orchestration-config", [])
    no_hitl: list[dict] = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasWriteOperations") and not data.get("HasHumanInLoop"):
            no_hitl.append({
                "Type": "AgentConfig",
                "Name": data.get("AgentName", "Unknown"),
                "ResourceId": data.get("AgentId", ""),
                "WriteOperations": str(data.get("WriteOperations", [])),
            })
    if no_hitl:
        return [_as_finding(
            "agent_governance", "agent_no_human_in_loop",
            f"{len(no_hitl)} agents perform write operations without human approval",
            "Agents that can create, modify, or delete resources without human-in-the-loop "
            "approval gates pose significant risk of unintended or malicious actions.",
            "high", "agent_orchestration", no_hitl,
            {"Description": "Implement human-in-the-loop approval for destructive operations.",
             "PortalSteps": ["Review agent action configurations",
                             "Identify write/delete/create operations",
                             "Add human approval gates for high-risk actions",
                             "Configure notification and approval workflows"]},
        )]
    return []


def _check_shadow_ai_agents(idx: dict) -> list[dict]:
    """Flag agents deployed outside governed platforms."""
    agents = idx.get("agent-orchestration-config", [])
    shadow: list[dict] = []
    for ev in agents:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsUngoverned"):
            shadow.append({
                "Type": "AgentConfig",
                "Name": data.get("AgentName", "Unknown"),
                "ResourceId": data.get("AgentId", ""),
                "DeploymentType": data.get("DeploymentType", ""),
            })
    if shadow:
        return [_as_finding(
            "agent_governance", "shadow_ai_agents",
            f"{len(shadow)} shadow AI agents detected outside governed platforms",
            "Agents deployed directly on VMs, containers, or App Service with direct "
            "API keys bypass organizational AI governance, content safety, and audit controls.",
            "high", "agent_orchestration", shadow,
            {"Description": "Migrate shadow agents to governed AI platforms.",
             "PortalSteps": ["Identify agents running outside Copilot Studio or AI Foundry",
                             "Assess migration to governed platforms",
                             "Apply content safety and audit controls",
                             "Block ungoverned AI deployments via Azure Policy"]},
        )]
    return []

