"""
Azure Policy Compliance Collector
"""

from __future__ import annotations
from azure.mgmt.policyinsights.aio import PolicyInsightsClient
from app.models import Source
from app.collectors.base import run_collector, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="policy_compliance", plane="control", source="azure", priority=80)
async def collect_azure_policy_compliance(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = PolicyInsightsClient(creds.credential, sub_id)
                scope = f"/subscriptions/{sub_id}"
                compliant = 0
                non_compliant = 0
                count = 0
                async for state in client.policy_states.list_query_results_for_subscription(
                    "latest", sub_id
                ):
                    count += 1
                    is_compliant = state.compliance_state == "Compliant"
                    if is_compliant:
                        compliant += 1
                    else:
                        non_compliant += 1
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzurePolicyCompliance",
                        evidence_type="azure-policy-compliance",
                        description=f"Policy state: {state.policy_definition_name}",
                        data={
                            "ComplianceState": state.compliance_state or "Unknown",
                            "IsCompliant": is_compliant,
                            "PolicyAssignmentId": state.policy_assignment_id or "",
                            "PolicyDefinitionId": state.policy_definition_id or "",
                            "PolicyDefinitionName": state.policy_definition_name or "",
                            "ResourceId": state.resource_id or "",
                            "ResourceType": state.resource_type or "",
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=state.resource_id or "", resource_type="PolicyCompliance",
                    ))
                    if count >= 10000:
                        break
                await client.close()
                log.info("  [AzurePolicyCompliance] %s: %d compliant, %d non-compliant",
                         sub_name, compliant, non_compliant)
            except Exception as exc:
                log.warning("  [AzurePolicyCompliance] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzurePolicyCompliance", Source.AZURE, _collect)).data
