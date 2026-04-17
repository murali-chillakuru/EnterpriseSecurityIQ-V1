"""
Azure Front Door & CDN Collector
Front Door profiles, CDN profiles, endpoints, WAF policies, custom domains.
"""

from __future__ import annotations
from azure.mgmt.cdn.aio import CdnManagementClient
from azure.mgmt.frontdoor.aio import FrontDoorManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="frontdoor_cdn", plane="control", source="azure", priority=142)
async def collect_azure_frontdoor_cdn(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Front Door Classic ---
            try:
                fd_client = FrontDoorManagementClient(creds.credential, sub_id)
                doors = await paginate_arm(fd_client.front_doors.list())
                for fd in doors:
                    props = fd.properties if hasattr(fd, "properties") else fd
                    frontend_endpoints = getattr(props, "frontend_endpoints", []) or []
                    routing_rules = getattr(props, "routing_rules", []) or []
                    backend_pools = getattr(props, "backend_pools", []) or []
                    health_probes = getattr(props, "health_probe_settings", []) or []

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureFrontDoorCDN",
                        evidence_type="azure-front-door",
                        description=f"Front Door: {fd.name}",
                        data={
                            "FrontDoorId": fd.id,
                            "Name": fd.name,
                            "Location": getattr(fd, "location", "global"),
                            "ProvisioningState": _v(getattr(props, "provisioning_state", None)),
                            "EnabledState": _v(getattr(props, "enabled_state", None)),
                            "FriendlyName": getattr(props, "friendly_name", ""),
                            "FrontendEndpointCount": len(frontend_endpoints),
                            "RoutingRuleCount": len(routing_rules),
                            "BackendPoolCount": len(backend_pools),
                            "HealthProbeCount": len(health_probes),
                            "EnforceHTTPS": any(
                                _v(getattr(rr, "redirect_protocol", None)) == "HttpsOnly"
                                for rr in routing_rules
                            ),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=fd.id or "", resource_type="FrontDoor",
                    ))
                await fd_client.close()
                log.info("  [FrontDoorCDN] %s: %d front doors", sub_name, len(doors))
            except Exception as exc:
                log.warning("  [FrontDoorCDN] %s Front Door failed: %s", sub_name, exc)

            # --- Front Door WAF Policies ---
            try:
                fd_client = FrontDoorManagementClient(creds.credential, sub_id)
                policies = await paginate_arm(fd_client.policies.list_by_subscription())
                for pol in policies:
                    managed_rules = getattr(pol, "managed_rules", None)
                    custom_rules = getattr(pol, "custom_rules", None)
                    policy_settings = getattr(pol, "policy_settings", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureFrontDoorCDN",
                        evidence_type="azure-waf-policy",
                        description=f"WAF Policy: {pol.name}",
                        data={
                            "PolicyId": pol.id,
                            "Name": pol.name,
                            "Location": getattr(pol, "location", "global"),
                            "ProvisioningState": _v(getattr(pol, "provisioning_state", None)),
                            "PolicyMode": _v(getattr(policy_settings, "mode", None)) if policy_settings else "",
                            "EnabledState": _v(getattr(policy_settings, "enabled_state", None)) if policy_settings else "",
                            "RedirectUrl": getattr(policy_settings, "redirect_url", "") if policy_settings else "",
                            "ManagedRuleSetCount": len(getattr(managed_rules, "managed_rule_sets", []) or []) if managed_rules else 0,
                            "CustomRuleCount": len(getattr(custom_rules, "rules", []) or []) if custom_rules else 0,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=pol.id or "", resource_type="FrontDoorWafPolicy",
                    ))
                await fd_client.close()
                log.info("  [FrontDoorCDN] %s: %d WAF policies", sub_name, len(policies))
            except Exception as exc:
                log.warning("  [FrontDoorCDN] %s WAF Policies failed: %s", sub_name, exc)

            # --- CDN Profiles & Endpoints ---
            try:
                cdn_client = CdnManagementClient(creds.credential, sub_id)
                profiles = await paginate_arm(cdn_client.profiles.list())
                for profile in profiles:
                    rg = (profile.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (profile.id or "") else ""
                    endpoints = []
                    if rg:
                        try:
                            endpoints = await paginate_arm(cdn_client.endpoints.list_by_profile(rg, profile.name))
                        except Exception:
                            pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureFrontDoorCDN",
                        evidence_type="azure-cdn-profile",
                        description=f"CDN Profile: {profile.name}",
                        data={
                            "ProfileId": profile.id,
                            "Name": profile.name,
                            "Location": profile.location,
                            "SkuName": profile.sku.name if profile.sku else "",
                            "ProvisioningState": _v(getattr(profile, "provisioning_state", None)),
                            "FrontDoorId": getattr(profile, "front_door_id", ""),
                            "EndpointCount": len(endpoints),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=profile.id or "", resource_type="CdnProfile",
                    ))

                    for ep in endpoints:
                        origins = getattr(ep, "origins", []) or []
                        custom_domains = getattr(ep, "custom_domains", []) or []
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureFrontDoorCDN",
                            evidence_type="azure-cdn-endpoint",
                            description=f"CDN Endpoint: {ep.name}",
                            data={
                                "EndpointId": ep.id,
                                "Name": ep.name,
                                "HostName": getattr(ep, "host_name", ""),
                                "IsHttpAllowed": getattr(ep, "is_http_allowed", True),
                                "IsHttpsAllowed": getattr(ep, "is_https_allowed", True),
                                "IsCompressionEnabled": getattr(ep, "is_compression_enabled", False),
                                "OriginCount": len(origins),
                                "CustomDomainCount": len(custom_domains),
                                "ProvisioningState": _v(getattr(ep, "provisioning_state", None)),
                                "QueryStringCachingBehavior": _v(getattr(ep, "query_string_caching_behavior", None)),
                                "SubscriptionId": sub_id,
                                "SubscriptionName": sub_name,
                            },
                            resource_id=ep.id or "", resource_type="CdnEndpoint",
                        ))

                await cdn_client.close()
                log.info("  [FrontDoorCDN] %s: %d CDN profiles", sub_name, len(profiles))
            except Exception as exc:
                log.warning("  [FrontDoorCDN] %s CDN failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureFrontDoorCDN", Source.AZURE, _collect)).data
