"""
Network Domain Evaluator
Controls: SC-7, SC-7(5), SC-7(8), SC-7(11), SC-7(13).
"""

from __future__ import annotations
import re
from app.models import FindingRecord, Status, Severity


def _tls_below(version: str, target: str = "1.2") -> bool:
    """Compare TLS versions numerically. Handles '1.0', '1.2', 'TLS1_0', 'TLS1_2' formats."""
    def _parse(v: str) -> tuple[int, int]:
        m = re.search(r'(\d+)[._](\d+)', v)
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return _parse(version) < _parse(target)


from app.config import ThresholdConfig


def evaluate_network(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_network_segmentation": _check_network_segmentation,
        "check_nsg_rules": _check_nsg_rules,
        "check_storage_security": _check_storage_security,
        "check_firewall_protection": _check_firewall_protection,
        "check_route_table_security": _check_route_table_security,
        "check_conditional_access": _check_network_segmentation,
        "check_ml_network_security": _check_ml_network_security,
        "check_app_gateway_security": _check_app_gateway_security,
        "check_waf_policy": _check_waf_policy,
        "check_container_app_network": _check_container_app_network,
        "check_apim_network_security": _check_apim_network_security,
        "check_webapp_detailed_security": _check_webapp_detailed_security,
        "check_acr_repository_security": _check_acr_repository_security,
        "check_dns_security": _check_dns_security,
        "check_aks_advanced_security": _check_aks_advanced_security,
        "check_apim_advanced_security": _check_apim_advanced_security,
        "check_frontdoor_cdn_security": _check_frontdoor_cdn_security,
        "check_private_endpoint_adoption": _check_private_endpoint_adoption,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", "FedRAMP"),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="network", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[{"ResourceId": resource_id, "ResourceName": resource_name,
                              "ResourceType": resource_type}] if resource_name else (evidence_items or []),
    ).to_dict()


def _res(item, rtype=""):
    """Extract resource context from an evidence item."""
    d = item.get("Data", {})
    ctx = item.get("Context", {})
    return dict(
        resource_id=d.get("ResourceId") or ctx.get("ResourceId") or item.get("ResourceId", ""),
        resource_name=d.get("Name") or d.get("NsgName") or d.get("DisplayName") or ctx.get("ResourceName", ""),
        resource_type=rtype or d.get("ResourceType") or ctx.get("ResourceType", ""),
    )


def _check_network_segmentation(cid, ctrl, evidence, idx):
    findings = []
    vnets = idx.get("azure-virtual-network", [])
    nsgs = idx.get("azure-nsg-rule", [])
    firewalls = idx.get("azure-firewall", [])

    if vnets and nsgs:
        # Deeper check: verify NSGs have deny-by-default or non-wildcard rules
        allow_all_inbound = [
            r for r in nsgs
            if r.get("Data", {}).get("Direction") == "Inbound"
            and r.get("Data", {}).get("Access") == "Allow"
            and r.get("Data", {}).get("SourceAddressPrefix") in ("*", "0.0.0.0/0", "Internet", "Any")
            and r.get("Data", {}).get("DestinationPortRange") == "*"
        ]
        if allow_all_inbound:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Network segmentation weak: {len(allow_all_inbound)} NSG rules allow all inbound traffic."))
        else:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"Network segmentation: {len(vnets)} VNets, {len(nsgs)} NSG rules with no open-all inbound."))
    elif vnets and not nsgs:
        if firewalls:
            findings.append(_f(cid, ctrl, Status.COMPLIANT,
                              f"VNets ({len(vnets)}) with Azure Firewall ({len(firewalls)}) but no NSGs."))
        else:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"VNets ({len(vnets)}) exist but no NSGs or firewalls configured."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          "No VNets detected (may be PaaS-only workload)."))

    return findings


def _check_nsg_rules(cid, ctrl, evidence, idx):
    findings = []
    nsgs = idx.get("azure-nsg-rule", [])
    vnets = idx.get("azure-virtual-network", [])

    # Each evidence record IS a single NSG rule (flat model)
    for nsg_rule in nsgs:
        d = nsg_rule.get("Data", {})
        nsg_name = d.get("NsgName", "unknown")
        r = _res(nsg_rule, "Microsoft.Network/networkSecurityGroups")

        if d.get("Direction") != "Inbound" or d.get("Access") != "Allow":
            continue

        src = d.get("SourceAddressPrefix", "")
        src_prefixes = d.get("SourceAddressPrefixes", [])
        dest_port = str(d.get("DestinationPortRange", ""))
        dest_ports = d.get("DestinationPortRanges", [])

        is_open_source = src in ("*", "0.0.0.0/0", "Internet", "Any") or any(
            s in ("*", "0.0.0.0/0", "Internet", "Any") for s in src_prefixes
        )

        if is_open_source:
            all_ports = [dest_port] + list(dest_ports)
            for port in all_ports:
                if port == "*":
                    findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                      f"CRITICAL: All ports exposed to internet on NSG '{nsg_name}'.",
                                      recommendation="Remove or restrict the NSG rule allowing all inbound ports from the internet.", **r))
                elif port == "3389":
                    findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                      f"CRITICAL: RDP (3389) exposed to internet on NSG '{nsg_name}'.",
                                      recommendation="Restrict RDP (3389) to specific IP ranges or use Azure Bastion for secure access.", **r))
                elif port == "22":
                    findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                                      f"CRITICAL: SSH (22) exposed to internet on NSG '{nsg_name}'.",
                                      recommendation="Restrict SSH (22) to specific IP ranges or use Azure Bastion for secure access.", **r))

    # VNets without DDoS
    for vnet in vnets:
        d = vnet.get("Data", {})
        r = _res(vnet, "Microsoft.Network/virtualNetworks")
        if not d.get("DdosProtectionEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"VNet '{d.get('Name', 'unknown')}' without DDoS protection.",
                              recommendation="Enable Azure DDoS Protection on the virtual network.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "NSG rules properly configured."))
    return findings


def _check_storage_security(cid, ctrl, evidence, idx):
    findings = []
    storage = idx.get("azure-storage-security", [])

    for s in storage:
        d = s.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(s, "Microsoft.Storage/storageAccounts")
        if not d.get("EnableHttpsTrafficOnly"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' allows HTTP traffic.",
                              recommendation="Enable 'Secure transfer required' on the storage account to enforce HTTPS.", **r))
        if _tls_below(d.get("MinimumTlsVersion", "TLS1_0")):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' TLS below 1.2.",
                              recommendation="Set minimum TLS version to TLS 1.2 on the storage account.", **r))
        if d.get("AllowBlobPublicAccess"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' public blob access enabled.",
                              recommendation="Disable public blob access on the storage account.", **r))
        if d.get("AllowSharedKeyAccess"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' shared key access enabled.",
                              recommendation="Disable shared key access. Use Azure AD authentication instead.", **r))
        fw = d.get("NetworkDefaultAction", "Allow")
        if fw == "Allow":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Storage '{name}' has no network firewall (allows all).",
                              recommendation="Configure the storage account firewall to deny all public access.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Storage security checks passed."))
    return findings


def _check_firewall_protection(cid, ctrl, evidence, idx):
    findings = []
    firewalls = idx.get("azure-firewall", [])

    if not firewalls:
        return [_f(cid, ctrl, Status.COMPLIANT,
                   "No Azure Firewalls detected (may use alternative WAF/NVA).")]

    for fw in firewalls:
        d = fw.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(fw, "Microsoft.Network/azureFirewalls")
        threat_mode = d.get("ThreatIntelMode", "")
        if threat_mode not in ("Deny", "Alert"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Firewall '{name}' threat intelligence not in Deny/Alert mode.",
                              recommendation="Set threat intelligence mode to 'Deny' on the Azure Firewall.", **r))
        total_rules = (d.get("NetworkRuleCollectionCount", 0) +
                       d.get("ApplicationRuleCollectionCount", 0) +
                       d.get("NatRuleCollectionCount", 0))
        if total_rules == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Firewall '{name}' has no rule collections.",
                              recommendation="Configure network and application rule collections on the Azure Firewall.", **r))
        if d.get("SkuTier", "") == "Basic":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Firewall '{name}' using Basic SKU (limited features).",
                              recommendation="Upgrade the Azure Firewall from Basic to Standard or Premium SKU.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Firewall protection adequate."))
    return findings


def _check_route_table_security(cid, ctrl, evidence, idx):
    findings = []
    routes = idx.get("azure-route-table", [])
    flow_logs = idx.get("azure-nsg-flow-log", [])

    for rt in routes:
        d = rt.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(rt, "Microsoft.Network/routeTables")
        if not d.get("HasDefaultRouteToNVA"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Route table '{name}' no default route to firewall/NVA.",
                              recommendation="Add a default route (0.0.0.0/0) pointing to the firewall or NVA.", **r))
        if d.get("DisableBgpRoutePropagation") is False:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Route table '{name}' BGP propagation enabled (can bypass routes).",
                              recommendation="Disable BGP route propagation to prevent route bypasses.", **r))

    for fl in flow_logs:
        d = fl.get("Data", {})
        r = _res(fl, "Microsoft.Network/networkWatchers/flowLogs")
        if not d.get("Enabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"NSG flow log '{d.get('Name', '')}' disabled.",
                              recommendation="Enable the NSG flow log for network traffic monitoring.", **r))
        if not d.get("TrafficAnalyticsEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"NSG flow log '{d.get('Name', '')}' traffic analytics disabled.",
                              recommendation="Enable Traffic Analytics on the NSG flow log for visibility.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT, "Route table security passed."))
    return findings


def _default(cid, ctrl, evidence, idx):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for network control ({len(evidence)} items).")]


def _check_ml_network_security(cid, ctrl, evidence, idx):
    """Check ML workspace network isolation — private endpoints, public access, HBI."""
    findings = []
    workspaces = idx.get("azure-ml-workspace", [])

    if not workspaces:
        return [_f(cid, ctrl, Status.COMPLIANT, "No ML workspaces to evaluate.")]

    for ws in workspaces:
        d = ws.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(ws, "Microsoft.MachineLearningServices/workspaces")

        # Check public network access
        if d.get("PublicNetworkAccess", "Enabled") != "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ML workspace '{name}' public network access enabled.",
                              recommendation="Disable public network access on the ML workspace. Use private endpoints.", **r))
        # Check private endpoints
        pe_count = d.get("PrivateEndpoints", 0)
        if pe_count == 0 and d.get("PublicNetworkAccess", "Enabled") != "Disabled":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ML workspace '{name}' has no private endpoints and public access enabled.",
                              recommendation="Configure private endpoints for the ML workspace.", **r))
        # Check managed identity
        mi_type = d.get("ManagedIdentityType", "")
        if not mi_type or mi_type == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ML workspace '{name}' has no managed identity.",
                              recommendation="Enable a managed identity on the ML workspace.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(workspaces)} ML workspaces pass network security checks."))
    return findings


def _check_app_gateway_security(cid, ctrl, evidence, idx):
    """Check Application Gateway security: WAF, SSL policy, HTTPS listeners."""
    findings = []
    gateways = idx.get("azure-app-gateway", [])

    if not gateways:
        return [_f(cid, ctrl, Status.COMPLIANT, "No Application Gateways to evaluate.")]

    for gw in gateways:
        d = gw.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(gw, "Microsoft.Network/applicationGateways")

        if not d.get("WafEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"App Gateway '{name}' WAF not enabled.",
                              recommendation="Enable WAF on the Application Gateway for web application protection.", **r))
        elif d.get("WafMode") == "Detection":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"App Gateway '{name}' WAF in Detection mode (not Prevention).",
                              recommendation="Switch WAF to Prevention mode on the Application Gateway.", **r))

        min_proto = d.get("MinProtocolVersion", "")
        if min_proto and _tls_below(min_proto):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"App Gateway '{name}' SSL policy allows TLS < 1.2.",
                              recommendation="Set minimum TLS version to 1.2 on the Application Gateway SSL policy.", **r))

        total_listeners = d.get("HttpListenerCount", 0)
        https_listeners = d.get("HttpsListenerCount", 0)
        if total_listeners > 0 and https_listeners < total_listeners:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"App Gateway '{name}' has {total_listeners - https_listeners} non-HTTPS listeners.",
                              recommendation="Configure all listeners to use HTTPS on the Application Gateway.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(gateways)} Application Gateways pass security checks."))
    return findings


def _check_waf_policy(cid, ctrl, evidence, idx):
    """Check WAF policy configuration: prevention mode, managed rules."""
    findings = []
    policies = idx.get("azure-waf-policy", [])

    if not policies:
        return [_f(cid, ctrl, Status.COMPLIANT, "No WAF policies to evaluate.")]

    for pol in policies:
        d = pol.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(pol, "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies")

        if d.get("PolicyMode") != "Prevention":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"WAF policy '{name}' not in Prevention mode.",
                              recommendation="Set WAF policy mode to Prevention.", **r))
        if d.get("ManagedRuleSetCount", 0) == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"WAF policy '{name}' has no managed rule sets.",
                              recommendation="Configure managed rule sets (OWASP) on the WAF policy.", **r))
        if not d.get("RequestBodyCheck", True):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"WAF policy '{name}' request body inspection disabled.",
                              recommendation="Enable request body check on the WAF policy.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(policies)} WAF policies pass security checks."))
    return findings


def _check_container_app_network(cid, ctrl, evidence, idx):
    """Check Container App network security: ingress, TLS, managed identity."""
    findings = []
    apps = idx.get("azure-container-app", [])

    if not apps:
        return [_f(cid, ctrl, Status.COMPLIANT, "No Container Apps to evaluate.")]

    for app in apps:
        d = app.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(app, "Microsoft.App/containerApps")

        if d.get("IngressEnabled") and d.get("IngressAllowInsecure"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Container App '{name}' allows insecure (HTTP) ingress.",
                              recommendation="Disable insecure connections. Enforce HTTPS-only ingress.", **r))
        mi_type = d.get("ManagedIdentityType", "None")
        if not mi_type or mi_type == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Container App '{name}' has no managed identity.",
                              recommendation="Enable a managed identity for the Container App.", **r))
        if d.get("IngressEnabled") and d.get("IngressExternal"):
            if d.get("IngressTransport", "auto") not in ("http2", "auto"):
                pass  # TCP transport is fine for some workloads
            # Flag external ingress as informational — it may be intentional
        if d.get("ScaleMinReplicas", 0) == 0 and d.get("ScaleMaxReplicas", 10) > 0:
            pass  # Scale-to-zero is valid for event-driven apps

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(apps)} Container Apps pass network security checks."))
    return findings


def _check_apim_network_security(cid, ctrl, evidence, idx):
    """Check APIM network security: TLS, VNet, managed identity."""
    findings = []
    instances = idx.get("azure-apim-instance", [])

    if not instances:
        return [_f(cid, ctrl, Status.COMPLIANT, "No API Management instances to evaluate.")]

    for apim in instances:
        d = apim.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(apim, "Microsoft.ApiManagement/service")

        if d.get("Tls10Enabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM '{name}' TLS 1.0 enabled on frontend.",
                              recommendation="Disable TLS 1.0 on the APIM gateway.", **r))
        if d.get("Tls11Enabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM '{name}' TLS 1.1 enabled on frontend.",
                              recommendation="Disable TLS 1.1 on the APIM gateway.", **r))
        if d.get("Ssl30Enabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM '{name}' SSL 3.0 enabled.",
                              recommendation="Disable SSL 3.0 on the APIM gateway.", **r))
        if d.get("BackendTls10Enabled") or d.get("BackendTls11Enabled") or d.get("BackendSsl30Enabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM '{name}' legacy TLS/SSL enabled on backend.",
                              recommendation="Disable TLS 1.0/1.1 and SSL 3.0 on APIM backend connections.", **r))
        vnet_type = d.get("VirtualNetworkType", "None")
        if vnet_type == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM '{name}' not connected to VNet.",
                              recommendation="Configure VNet integration (Internal or External) for the APIM instance.", **r))
        mi_type = d.get("ManagedIdentityType", "None")
        if not mi_type or mi_type == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM '{name}' has no managed identity.",
                              recommendation="Enable a managed identity on the APIM instance.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(instances)} APIM instances pass network security checks."))
    return findings


def _check_webapp_detailed_security(cid, ctrl, evidence, idx):
    """Check Web App authentication, IP restrictions, CORS, and logging."""
    findings = []
    apps = idx.get("azure-webapp-detailed", [])

    if not apps:
        return [_f(cid, ctrl, Status.COMPLIANT, "No Web App detailed data to evaluate.")]

    for app in apps:
        d = app.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(app, "Microsoft.Web/sites")

        if not d.get("AuthEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Web App '{name}' App Service Authentication disabled.",
                              recommendation="Enable App Service Authentication (EasyAuth) or integrate with Entra ID.", **r))
        if d.get("CorsAllowAll"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Web App '{name}' CORS allows all origins (*).",
                              recommendation="Restrict CORS allowed origins to specific trusted domains.", **r))
        if d.get("IpRestrictionCount", 0) == 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Web App '{name}' has no IP access restrictions.",
                              recommendation="Configure IP security restrictions to limit access.", **r))
        if not d.get("ApplicationLogsEnabled") and not d.get("HttpLogsEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Web App '{name}' has no diagnostic logging enabled.",
                              recommendation="Enable application and/or HTTP logging for the Web App.", **r))
        if not d.get("Http20Enabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Web App '{name}' HTTP/2 not enabled.",
                              recommendation="Enable HTTP/2 for improved performance and security.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(apps)} Web Apps pass detailed security checks."))
    return findings


def _check_acr_repository_security(cid, ctrl, evidence, idx):
    """Check ACR repository tag mutability and stale images."""
    findings = []
    repos = idx.get("azure-acr-repository", [])

    if not repos:
        return [_f(cid, ctrl, Status.COMPLIANT, "No ACR repository data to evaluate.")]

    for item in repos:
        d = item.get("Data", {})
        name = d.get("RegistryName", "unknown")
        r = _res(item, "Microsoft.ContainerRegistry/registries")

        no_immutable = d.get("ReposWithoutTagImmutability", 0)
        total = d.get("RepositoryCount", 0)
        if total > 0 and no_immutable == total:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ACR '{name}' — all {total} repositories have mutable tags.",
                              recommendation="Configure tag immutability to prevent image tag overwriting.", **r))
        elif no_immutable > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ACR '{name}' — {no_immutable}/{total} repositories have mutable tags.",
                              recommendation="Enable tag immutability on repositories to prevent tag overwriting.", **r))
        stale = d.get("StaleRepositories", 0)
        if stale > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"ACR '{name}' has {stale} stale repository(ies) with no tags.",
                              recommendation="Clean up stale repositories with no tagged images.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(repos)} ACR registries pass repository security checks."))
    return findings


# ---------------------------------------------------------------------------
# DNS security
# ---------------------------------------------------------------------------
def _check_dns_security(cid, ctrl, evidence, idx):
    findings = []
    public_zones = idx.get("azure-dns-zone", [])
    private_zones = idx.get("azure-private-dns-zone", [])
    traffic_mgrs = idx.get("azure-traffic-manager", [])

    for item in traffic_mgrs:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Network/trafficManagerProfiles")
        status_val = d.get("ProfileStatus", "")
        monitoring = d.get("MonitorProtocol", "")
        if monitoring and monitoring.upper() == "HTTP":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Traffic Manager '{name}' uses HTTP monitoring instead of HTTPS.",
                              recommendation="Switch Traffic Manager health monitoring to HTTPS.", **r))

    if not findings:
        total = len(public_zones) + len(private_zones) + len(traffic_mgrs)
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {total} DNS resources pass security checks."))
    return findings


# ---------------------------------------------------------------------------
# AKS advanced security (using deep config)
# ---------------------------------------------------------------------------
def _check_aks_advanced_security(cid, ctrl, evidence, idx):
    findings = []
    clusters = idx.get("azure-aks-cluster-config", [])
    node_pools = idx.get("azure-aks-node-pool", [])

    for item in clusters:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.ContainerService/managedClusters")

        if not d.get("AadManaged"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AKS '{name}' does not use AAD-managed RBAC.",
                              recommendation="Enable AAD-managed RBAC on the AKS cluster.", **r))
        if not d.get("NetworkPolicy"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AKS '{name}' has no network policy configured.",
                              recommendation="Enable Calico or Azure network policy.", **r))
        if not d.get("PrivateCluster") and not d.get("AuthorizedIpRanges"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AKS '{name}' API server is publicly accessible without IP restrictions.",
                              recommendation="Enable private cluster or configure authorized IP ranges.", **r))
        if not d.get("DefenderEnabled"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AKS '{name}' does not have Defender for Containers enabled.",
                              recommendation="Enable Microsoft Defender for Containers.", **r))

    for item in node_pools:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        cluster = d.get("ClusterName", "")
        r = _res(item, "Microsoft.ContainerService/managedClusters/agentPools")
        if d.get("EnableNodePublicIP"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"AKS node pool '{cluster}/{name}' has public IPs on nodes.",
                              recommendation="Disable node public IPs for AKS node pools.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(clusters)} AKS clusters pass advanced security checks."))
    return findings


# ---------------------------------------------------------------------------
# APIM advanced security
# ---------------------------------------------------------------------------
def _check_apim_advanced_security(cid, ctrl, evidence, idx):
    findings = []
    services = idx.get("azure-apim-service", [])
    certs = idx.get("azure-apim-certificate", [])
    named_vals = idx.get("azure-apim-named-value", [])

    for item in services:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.ApiManagement/service")
        vnet_type = d.get("VirtualNetworkType", "None")
        if vnet_type == "None":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM '{name}' is not connected to a VNet.",
                              recommendation="Deploy APIM in Internal or External VNet mode.", **r))
        if not d.get("EnableClientCertificate"):
            findings.append(_f(cid, ctrl, Status.INFO,
                              f"APIM '{name}' does not require client certificates.",
                              recommendation="Consider enabling client certificate authentication.", **r))

    for item in named_vals:
        d = item.get("Data", {})
        name = d.get("DisplayName", d.get("Name", "unknown"))
        svc = d.get("ServiceName", "")
        r = _res(item, "Microsoft.ApiManagement/service/namedValues")
        if d.get("Secret") and not d.get("KeyVaultId"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"APIM named value '{svc}/{name}' is a secret not backed by Key Vault.",
                              recommendation="Store secrets in Key Vault and reference them from APIM.", **r))

    if not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {len(services)} APIM services pass advanced security checks."))
    return findings


# ---------------------------------------------------------------------------
# Front Door & CDN security
# ---------------------------------------------------------------------------
def _check_frontdoor_cdn_security(cid, ctrl, evidence, idx):
    findings = []
    fd = idx.get("azure-front-door", [])
    waf = idx.get("azure-waf-policy", [])
    cdn = idx.get("azure-cdn-profile", [])

    for item in fd:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Network/frontDoors")
        if not d.get("WafPolicyId"):
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"Front Door '{name}' has no WAF policy attached.",
                              recommendation="Attach a WAF policy to the Front Door profile.", **r))

    for item in waf:
        d = item.get("Data", {})
        name = d.get("Name", "unknown")
        r = _res(item, "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies")
        mode = d.get("PolicyMode", "")
        if mode and mode.lower() != "prevention":
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"WAF policy '{name}' is in {mode} mode, not Prevention.",
                              recommendation="Set WAF policy mode to Prevention.", **r))

    if not findings:
        total = len(fd) + len(waf) + len(cdn)
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"All {total} Front Door/CDN resources pass security checks."))
    return findings


# ---------------------------------------------------------------------------
# Private Endpoint Adoption Analysis
# ---------------------------------------------------------------------------
# PaaS services that should use private endpoints for secure connectivity.
_PE_PAAS_TYPES = {
    "azure-storage-account":   ("Microsoft.Storage/storageAccounts", "Storage Accounts"),
    "azure-sql-server":        ("Microsoft.Sql/servers", "SQL Servers"),
    "azure-cosmosdb":          ("Microsoft.DocumentDB/databaseAccounts", "Cosmos DB"),
    "azure-keyvault":          ("Microsoft.KeyVault/vaults", "Key Vaults"),
    "azure-acr":               ("Microsoft.ContainerRegistry/registries", "Container Registries"),
    "azure-app-service":       ("Microsoft.Web/sites", "App Services"),
    "azure-function-app":      ("Microsoft.Web/sites", "Function Apps"),
    "azure-cognitive-service":  ("Microsoft.CognitiveServices/accounts", "AI Services"),
    "azure-eventhub-namespace": ("Microsoft.EventHub/namespaces", "Event Hubs"),
    "azure-servicebus-namespace": ("Microsoft.ServiceBus/namespaces", "Service Bus"),
}


def _check_private_endpoint_adoption(cid, ctrl, evidence, idx):
    """Measure private endpoint adoption across all PaaS services.

    For each PaaS resource type, checks:
    - Whether private endpoints are configured
    - Whether public network access is disabled
    Reports adoption % and flags resources with public exposure.
    """
    findings = []
    pe_items = idx.get("azure-private-endpoint", [])

    # Build set of resource IDs that have private endpoints
    pe_targets: set[str] = set()
    for item in pe_items:
        d = item.get("Data", {})
        for conn in d.get("PrivateLinkServiceConnections", []) or []:
            target_id = conn.get("PrivateLinkServiceId", "")
            if target_id:
                pe_targets.add(target_id.lower())

    total_paas = 0
    total_with_pe = 0
    total_public_disabled = 0
    per_type_stats = []

    for etype, (rtype, friendly_name) in _PE_PAAS_TYPES.items():
        items = idx.get(etype, [])
        if not items:
            continue
        type_total = len(items)
        type_with_pe = 0
        type_public_disabled = 0

        for item in items:
            d = item.get("Data", {})
            r = _res(item, rtype)
            rid = (d.get("ResourceId") or r["resource_id"]).lower()
            name = r["resource_name"] or "unknown"

            has_pe = rid in pe_targets
            # Check various forms of "public network access" property
            public_access = (
                d.get("PublicNetworkAccess", "")
                or d.get("publicNetworkAccess", "")
                or d.get("Properties", {}).get("publicNetworkAccess", "")
            )
            public_disabled = public_access.lower() in ("disabled", "false", "deny")

            if has_pe:
                type_with_pe += 1
            if public_disabled:
                type_public_disabled += 1

            if not has_pe and not public_disabled:
                findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                    f"{friendly_name}: '{name}' has no private endpoint and public access is enabled.",
                    recommendation=f"Configure a private endpoint for '{name}' and disable public network access.",
                    **r))

        total_paas += type_total
        total_with_pe += type_with_pe
        total_public_disabled += type_public_disabled
        pe_pct = round(type_with_pe / type_total * 100, 1) if type_total else 0
        per_type_stats.append({
            "ResourceType": friendly_name,
            "Total": type_total,
            "WithPrivateEndpoint": type_with_pe,
            "PublicDisabled": type_public_disabled,
            "AdoptionPct": pe_pct,
        })

    # Compute overall adoption
    adoption_pct = round(total_with_pe / total_paas * 100, 1) if total_paas else 100
    public_disabled_pct = round(total_public_disabled / total_paas * 100, 1) if total_paas else 100

    # Summary finding
    if adoption_pct >= 90 and not findings:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
            f"Private endpoint adoption: {adoption_pct}% ({total_with_pe}/{total_paas} PaaS resources). "
            f"Public access disabled: {public_disabled_pct}%.",
            evidence_items=[{"PerTypeStats": per_type_stats, "AdoptionPct": adoption_pct}]))
    elif not findings:
        findings.append(_f(cid, ctrl, Status.PARTIAL,
            f"Private endpoint adoption: {adoption_pct}% ({total_with_pe}/{total_paas} PaaS resources). "
            f"Consider enabling private endpoints for remaining services.",
            evidence_items=[{"PerTypeStats": per_type_stats, "AdoptionPct": adoption_pct}]))

    return findings
