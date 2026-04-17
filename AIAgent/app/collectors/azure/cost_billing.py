"""
Azure Cost Management & Billing Collector
Cost data, budgets, and advisor cost recommendations.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timedelta, timezone
from azure.mgmt.costmanagement.aio import CostManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="cost_billing", plane="control", source="azure", priority=190)
async def collect_azure_cost_billing(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            scope = f"/subscriptions/{sub_id}"

            # --- Budgets ---
            try:
                client = CostManagementClient(creds.credential)
                budgets = []
                async for b in client.budgets.list(scope):
                    budgets.append(b)

                for b in budgets:
                    props = b or type("B", (), {})()
                    notifications = getattr(props, "notifications", {}) or {}
                    current_spend = getattr(props, "current_spend", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureCostBilling",
                        evidence_type="azure-budget",
                        description=f"Budget: {b.name}",
                        data={
                            "BudgetId": b.id,
                            "Name": b.name,
                            "Amount": getattr(props, "amount", 0),
                            "TimeGrain": _v(getattr(props, "time_grain", None)),
                            "Category": _v(getattr(props, "category", None)),
                            "CurrentSpendAmount": getattr(current_spend, "amount", 0) if current_spend else 0,
                            "CurrentSpendUnit": getattr(current_spend, "unit", "") if current_spend else "",
                            "NotificationCount": len(notifications),
                            "NotificationThresholds": [
                                getattr(v, "threshold", 0) for v in notifications.values()
                            ] if isinstance(notifications, dict) else [],
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=b.id or "", resource_type="Budget",
                    ))
                log.info("  [CostBilling] %s: %d budgets", sub_name, len(budgets))
                await client.close()
            except Exception as exc:
                log.warning("  [CostBilling] %s budgets failed: %s", sub_name, exc)

            # --- Advisor Cost Recommendations ---
            try:
                from azure.mgmt.advisor.aio import AdvisorManagementClient
                adv_client = AdvisorManagementClient(creds.credential, sub_id)
                recs = []
                async for r in adv_client.recommendations.list(filter="Category eq 'Cost'"):
                    recs.append(r)

                for r in recs:
                    props = r.properties if hasattr(r, "properties") else r
                    short_desc = getattr(props, "short_description", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureCostBilling",
                        evidence_type="azure-advisor-cost-recommendation",
                        description=f"Cost recommendation: {getattr(short_desc, 'problem', '') if short_desc else r.name}",
                        data={
                            "RecommendationId": r.id,
                            "Name": r.name,
                            "Category": _v(getattr(props, "category", None)),
                            "Impact": _v(getattr(props, "impact", None)),
                            "Problem": getattr(short_desc, "problem", "") if short_desc else "",
                            "Solution": getattr(short_desc, "solution", "") if short_desc else "",
                            "ImpactedField": getattr(props, "impacted_field", ""),
                            "ImpactedValue": getattr(props, "impacted_value", ""),
                            "LastUpdated": str(getattr(props, "last_updated", "")),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=r.id or "", resource_type="AdvisorRecommendation",
                    ))
                log.info("  [CostBilling] %s: %d cost recommendations", sub_name, len(recs))
                await adv_client.close()
            except Exception as exc:
                log.warning("  [CostBilling] %s advisor failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureCostBilling", Source.AZURE, _collect)).data
