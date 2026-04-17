"""
Azure Defender Plans Collector
Defender pricing, auto-provisioning, security contacts.
"""

from __future__ import annotations
from azure.mgmt.security.aio import SecurityCenter
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="defender_plans", plane="control", source="azure", priority=90)
async def collect_azure_defender_plans(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = SecurityCenter(creds.credential, sub_id, asc_location="centralus")

                # Defender pricing plans (SDK v7+ requires scope_id)
                scope_id = f"/subscriptions/{sub_id}"
                pricing_list = await client.pricings.list(scope_id=scope_id)
                plans = pricing_list.value or []
                for plan in plans:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDefenderPlans",
                        evidence_type="azure-defender-pricing",
                        description=f"Defender: {plan.name}",
                        data={
                            "PlanName": plan.name,
                            "PricingTier": _v(plan.pricing_tier, "Free"),
                            "IsEnabled": (plan.pricing_tier and _v(plan.pricing_tier) == "Standard"),
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=plan.id or "", resource_type="DefenderPlan",
                    ))

                # Auto-provisioning
                try:
                    autoprov = await paginate_arm(client.auto_provisioning_settings.list())
                    for ap in autoprov:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDefenderPlans",
                            evidence_type="azure-auto-provisioning",
                            description=f"Auto-provisioning: {ap.name}",
                            data={
                                "Name": ap.name,
                                "AutoProvision": _v(ap.auto_provision, "Off"),
                                "IsEnabled": (ap.auto_provision and _v(ap.auto_provision) == "On"),
                                "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                            },
                            resource_id=ap.id or "", resource_type="AutoProvisioning",
                        ))
                except Exception as exc:
                    log.warning("  [DefenderPlans] Auto-provisioning for %s failed: %s", sub_name, exc)

                # Security contacts
                try:
                    contacts = await paginate_arm(client.security_contacts.list())
                    for sc in contacts:
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureDefenderPlans",
                            evidence_type="azure-security-contact",
                            description=f"Security contact: {sc.name}",
                            data={
                                "Name": sc.name,
                                "Emails": sc.emails or "",
                                "Phone": sc.phone or "",
                                "AlertNotifications": (
                                    _v(sc.alert_notifications.state, "Off")
                                    if sc.alert_notifications and sc.alert_notifications.state else "Off"
                                ),
                                "NotificationsByRole": (
                                    _v(sc.notifications_by_role.state, "Off")
                                    if sc.notifications_by_role and sc.notifications_by_role.state else "Off"
                                ),
                                "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                            },
                            resource_id=sc.id or "", resource_type="SecurityContact",
                        ))
                except Exception as exc:
                    log.warning("  [DefenderPlans] Security contacts for %s failed: %s", sub_name, exc)

                await client.close()
                log.info("  [AzureDefenderPlans] %s: %d plans", sub_name, len(plans))
            except Exception as exc:
                log.warning("  [AzureDefenderPlans] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureDefenderPlans", Source.AZURE, _collect)).data
