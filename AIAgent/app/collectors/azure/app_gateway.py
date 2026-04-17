"""
Azure Application Gateway & WAF Collector
Application Gateways and WAF Policy configuration.
"""

from __future__ import annotations
from azure.mgmt.network.aio import NetworkManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="app_gateway", plane="control", source="azure", priority=170)
async def collect_azure_app_gateway(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = NetworkManagementClient(creds.credential, sub_id)

                # Application Gateways
                gateways = await paginate_arm(client.application_gateways.list_all())
                for gw in gateways:
                    ssl_policy = getattr(gw, "ssl_policy", None)
                    waf_cfg = getattr(gw, "web_application_firewall_configuration", None)
                    fw_policy = getattr(gw, "firewall_policy", None)

                    listeners = getattr(gw, "http_listeners", None) or []
                    https_listeners = sum(1 for l in listeners if _v(getattr(l, "protocol", None), "").lower() == "https")

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAppGateway",
                        evidence_type="azure-app-gateway",
                        description=f"Application Gateway: {gw.name}",
                        data={
                            "GatewayId": gw.id,
                            "Name": gw.name,
                            "Location": gw.location,
                            "SkuName": _v(gw.sku.name, "Unknown") if gw.sku else "Unknown",
                            "SkuTier": _v(gw.sku.tier, "Unknown") if gw.sku else "Unknown",
                            "SslPolicyType": _v(getattr(ssl_policy, "policy_type", None), "Predefined") if ssl_policy else "None",
                            "SslPolicyName": _v(getattr(ssl_policy, "policy_name", None), "") if ssl_policy else "",
                            "MinProtocolVersion": _v(getattr(ssl_policy, "min_protocol_version", None), "") if ssl_policy else "",
                            "WafEnabled": bool(waf_cfg and getattr(waf_cfg, "enabled", False)),
                            "WafMode": _v(getattr(waf_cfg, "firewall_mode", None), "Detection") if waf_cfg else "None",
                            "WafRuleSetType": _v(getattr(waf_cfg, "rule_set_type", None), "") if waf_cfg else "",
                            "WafRuleSetVersion": _v(getattr(waf_cfg, "rule_set_version", None), "") if waf_cfg else "",
                            "FirewallPolicyId": getattr(fw_policy, "id", "") if fw_policy else "",
                            "HttpListenerCount": len(listeners),
                            "HttpsListenerCount": https_listeners,
                            "BackendPoolCount": len(getattr(gw, "backend_address_pools", None) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=gw.id or "", resource_type="Microsoft.Network/applicationGateways",
                    ))
                log.info("  [AzureAppGateway] %s: %d application gateways", sub_name, len(gateways))

                # WAF Policies
                waf_policies = await paginate_arm(client.web_application_firewall_policies.list_all())
                for pol in waf_policies:
                    managed_rules = getattr(pol, "managed_rules", None)
                    policy_settings = getattr(pol, "policy_settings", None)
                    custom_rules = getattr(pol, "custom_rules", None) or []
                    managed_rule_sets = getattr(managed_rules, "managed_rule_sets", None) or [] if managed_rules else []
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureAppGateway",
                        evidence_type="azure-waf-policy",
                        description=f"WAF Policy: {pol.name}",
                        data={
                            "PolicyId": pol.id,
                            "Name": pol.name,
                            "Location": pol.location,
                            "PolicyMode": _v(getattr(policy_settings, "mode", None), "Detection") if policy_settings else "Unknown",
                            "PolicyState": _v(getattr(policy_settings, "state", None), "Enabled") if policy_settings else "Unknown",
                            "RequestBodyCheck": getattr(policy_settings, "request_body_check", True) if policy_settings else True,
                            "MaxRequestBodySizeInKb": getattr(policy_settings, "max_request_body_size_in_kb", 128) if policy_settings else 128,
                            "ManagedRuleSetCount": len(managed_rule_sets),
                            "ManagedRuleSets": [
                                {"Type": _v(getattr(rs, "rule_set_type", None), ""),
                                 "Version": _v(getattr(rs, "rule_set_version", None), "")}
                                for rs in managed_rule_sets
                            ],
                            "CustomRuleCount": len(custom_rules),
                            "AssociatedGatewayCount": len(getattr(pol, "application_gateways", None) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=pol.id or "", resource_type="Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
                    ))
                log.info("  [AzureAppGateway] %s: %d WAF policies", sub_name, len(waf_policies))

                await client.close()
            except Exception as exc:
                log.warning("  [AzureAppGateway] %s failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("AzureAppGateway", Source.AZURE, _collect)
    return result.data
