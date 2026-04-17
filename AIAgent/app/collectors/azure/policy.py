"""
Azure Policy Collector
Collects policy assignments per subscription.
"""

from __future__ import annotations
import re
from azure.mgmt.resource.policy.aio import PolicyClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="policy", plane="control", source="azure", priority=30)
async def collect_azure_policy(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = PolicyClient(creds.credential, sub_id)
                assignments = await paginate_arm(client.policy_assignments.list())
                for pa in assignments:
                    defn_id = pa.policy_definition_id or ""
                    is_set = bool(re.search(r"/policySetDefinitions/", defn_id, re.IGNORECASE))
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzurePolicy",
                        evidence_type="azure-policy-assignment",
                        description=f"Policy: {pa.display_name or pa.name}",
                        data={
                            "PolicyAssignmentId": pa.id,
                            "Name": pa.name,
                            "DisplayName": pa.display_name or pa.name,
                            "PolicyDefinitionId": defn_id,
                            "Scope": pa.scope or "",
                            "EnforcementMode": _v(pa.enforcement_mode, "Default"),
                            "IsPolicySet": is_set,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=pa.id or "", resource_type="PolicyAssignment",
                    ))

                # Custom policy definitions (referenced in framework mappings but not previously collected)
                custom_defs = []
                try:
                    all_defs = await paginate_arm(client.policy_definitions.list())
                    custom_defs = [d for d in all_defs if _v(d.policy_type) == "Custom"]
                except Exception as def_exc:
                    log.warning("  [AzurePolicy] %s policy definitions failed: %s", sub_name, def_exc)

                for pd in custom_defs:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzurePolicy",
                        evidence_type="azure-policy-definition",
                        description=f"Custom Policy: {pd.display_name or pd.name}",
                        data={
                            "PolicyDefinitionId": pd.id,
                            "Name": pd.name,
                            "DisplayName": pd.display_name or pd.name,
                            "PolicyType": _v(pd.policy_type),
                            "Mode": pd.mode or "",
                            "Description": pd.description or "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=pd.id or "", resource_type="PolicyDefinition",
                    ))

                await client.close()
                log.info("  [AzurePolicy] %s: %d assignments, %d custom definitions",
                         sub_name, len(assignments), len(custom_defs))
            except Exception as exc:
                log.warning("  [AzurePolicy] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzurePolicy", Source.AZURE, _collect)).data
