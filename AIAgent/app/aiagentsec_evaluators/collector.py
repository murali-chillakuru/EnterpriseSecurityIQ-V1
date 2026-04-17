"""Targeted evidence collector for AI Agent Security assessment."""

from __future__ import annotations

import logging

from app.auth import ComplianceCredentials

log = logging.getLogger(__name__)


def _synthesize_agent_orchestration_config(
    index: dict[str, list[dict]],
) -> list[dict]:
    """Derive agent-orchestration-config evidence from Foundry agent apps and
    Copilot Studio bots already present in the evidence index."""
    from app.collectors.base import Source, make_evidence

    records: list[dict] = []

    # Build project-level agent count lookup to infer IsMultiAgent
    project_agent_counts: dict[str, int] = {}
    for ev in index.get("foundry-project", []):
        d = ev.get("Data", ev.get("data", {}))
        pid = d.get("ProjectId", "")
        if pid:
            project_agent_counts[pid] = d.get("AgentCount", 0)

    # -- Foundry Agent Applications -----------------------------------
    for ev in index.get("foundry-agent-application", []):
        d = ev.get("Data", ev.get("data", {}))
        app_id = d.get("ApplicationId", "")
        proj_id = d.get("ProjectId", "")
        agent_count = project_agent_counts.get(proj_id, 1)
        auth_type = (d.get("AuthenticationType", "") or "").lower()

        records.append(make_evidence(
            source=Source.AZURE,
            collector="AgentOrchestrationSynthesizer",
            evidence_type="agent-orchestration-config",
            description=f"Agent orchestration: {d.get('Name', '')}",
            data={
                "AgentId": app_id,
                "AgentName": d.get("Name", ""),
                "Platform": "foundry",
                "IsMultiAgent": agent_count > 1,
                "HasInterAgentAuth": auth_type not in ("", "none"),
                "OrchestrationType": d.get("Protocol", ""),
                "HasUnrestrictedToolAccess": not d.get("HasRBACAssignments", False),
                "ToolCount": 0,
                "HasMemoryStore": bool(index.get("foundry-capability-host")),
                "MemoryEncrypted": True,
                "IsPartOfInventory": True,
                "HasWriteOperations": False,
                "HasHumanInLoop": False,
                "WriteOperations": [],
                "IsUngoverned": False,
                "DeploymentType": "foundry",
            },
            resource_id=app_id,
            resource_type="AgentOrchestrationConfig",
        ))

    # -- Copilot Studio Bots ------------------------------------------
    for ev in index.get("copilot-studio-bot", []):
        d = ev.get("Data", ev.get("data", {}))
        bot_id = d.get("BotId", "")
        has_connectors = (
            bool(d.get("HasConfiguredConnectors"))
            or bool(d.get("CustomConnectors"))
            or bool(d.get("PremiumConnectors"))
        )
        custom_ct = d.get("CustomConnectors", 0) or 0
        premium_ct = d.get("PremiumConnectors", 0) or 0

        records.append(make_evidence(
            source=Source.AZURE,
            collector="AgentOrchestrationSynthesizer",
            evidence_type="agent-orchestration-config",
            description=f"Agent orchestration: {d.get('DisplayName', '')}",
            data={
                "AgentId": bot_id,
                "AgentName": d.get("DisplayName", ""),
                "Platform": "copilot-studio",
                "IsMultiAgent": bool(d.get("OrchestratorEnabled")),
                "HasInterAgentAuth": bool(d.get("RequiresAuthentication")),
                "OrchestrationType": "orchestrator" if d.get("OrchestratorEnabled") else "single",
                "HasUnrestrictedToolAccess": has_connectors and not bool(d.get("TopicRestrictionEnabled")),
                "ToolCount": custom_ct + premium_ct,
                "HasMemoryStore": bool(d.get("HasConversationLogging")),
                "MemoryEncrypted": True,
                "IsPartOfInventory": True,
                "HasWriteOperations": has_connectors,
                "HasHumanInLoop": False,
                "WriteOperations": [],
                "IsUngoverned": False,
                "DeploymentType": "copilot-studio",
            },
            resource_id=bot_id,
            resource_type="AgentOrchestrationConfig",
        ))

    return records


async def _as_collect(
    creds: ComplianceCredentials,
    subscriptions: list[dict],
) -> dict[str, list[dict]]:
    """Run targeted collection for AI agent security assessment."""
    from app.collectors.azure.copilot_studio import collect_copilot_studio
    from app.collectors.azure.foundry_config import collect_foundry_config
    from app.collectors.entra.ai_identity import collect_entra_ai_identity

    index: dict[str, list[dict]] = {}

    collectors = [
        ("Copilot Studio", collect_copilot_studio(creds, subscriptions)),
        ("Foundry Config", collect_foundry_config(creds, subscriptions)),
        ("Entra AI Identity", collect_entra_ai_identity(creds)),
    ]

    for name, coro in collectors:
        try:
            log.info("  Collecting %s …", name)
            records = await coro
            for ev in records:
                etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
                if etype:
                    index.setdefault(etype, []).append(ev)
            log.info("  %s: %d evidence records", name, len(records))
        except Exception as exc:
            log.warning("  %s collection failed: %s", name, exc)


    # -- Synthesize agent-orchestration-config from collected evidence --
    synth = _synthesize_agent_orchestration_config(index)
    if synth:
        for ev in synth:
            index.setdefault("agent-orchestration-config", []).append(ev)
        log.info("  Agent Orchestration Synthesizer: %d evidence records", len(synth))

    return index

