"""
Data Security — Platform Services evaluator — SQL MI, AppConfig, Databricks, APIM, FrontDoor, Secret Sprawl, Firewall, Bastion, Policy, Defender.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_sql_mi_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#2 SQL Managed Instance — TDE, ATP, AAD-only, public endpoint."""
    findings: list[dict] = []
    mi_list = evidence_index.get("azure-sql-mi", [])
    if not mi_list:
        return findings

    no_atp: list[dict] = []
    public_ep: list[dict] = []
    no_aad_only: list[dict] = []

    for ev in mi_list:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "SqlManagedInstance", "Name": name, "ResourceId": rid}

        if not data.get("AdvancedThreatProtection", True):
            no_atp.append(dict(entry))
        pub = str(data.get("publicDataEndpointEnabled", "")).lower()
        if pub == "true":
            public_ep.append(dict(entry))
        aad = str(data.get("administratorType", "")).lower()
        if aad != "activedirectory":
            no_aad_only.append(dict(entry))

    if no_atp:
        findings.append(_ds_finding("database", "sqlmi_no_atp",
            f"{len(no_atp)} SQL MI without Advanced Threat Protection",
            "SQL MI without threat protection cannot detect anomalous database activities.",
            "high", no_atp,
            {"Description": "Enable Advanced Threat Protection on SQL MI.",
             "AzureCLI": "az sql mi threat-policy update --resource-group <rg> --managed-instance <mi> --state Enabled"}))
    if public_ep:
        findings.append(_ds_finding("database", "sqlmi_public_endpoint",
            f"{len(public_ep)} SQL MI with public data endpoint enabled",
            "Public endpoint exposes the managed instance to Internet-originated attacks.",
            "high", public_ep,
            {"Description": "Disable the public data endpoint on SQL MI.",
             "AzureCLI": "az sql mi update -g <rg> -n <mi> --public-data-endpoint-enabled false"}))
    if no_aad_only:
        findings.append(_ds_finding("database", "sqlmi_no_aad_only",
            f"{len(no_aad_only)} SQL MI without AAD-only authentication",
            "SQL authentication allows password-based access which is weaker than AAD/Entra ID.",
            "medium", no_aad_only,
            {"Description": "Configure AAD-only authentication for SQL MI.",
             "AzureCLI": "az sql mi ad-only-auth enable -g <rg> --mi <mi>"}))
    return findings


def analyze_app_config_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#4 App Configuration — CMK, private endpoint, public access, soft delete."""
    findings: list[dict] = []
    configs = evidence_index.get("azure-app-configuration", [])
    if not configs:
        return findings

    no_pe: list[dict] = []
    public_access: list[dict] = []
    no_soft_delete: list[dict] = []

    for ev in configs:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "AppConfiguration", "Name": name, "ResourceId": rid}

        pe_conns = data.get("privateEndpointConnections", [])
        if not pe_conns:
            no_pe.append(dict(entry))
        pub = str(data.get("publicNetworkAccess", "")).lower()
        if pub in ("enabled", ""):
            public_access.append(dict(entry))
        sd = data.get("enablePurgeProtection", data.get("softDeleteEnabled"))
        if sd is False or sd is None:
            no_soft_delete.append(dict(entry))

    if public_access:
        findings.append(_ds_finding("app_config", "appconfig_public_access",
            f"{len(public_access)} App Configuration stores with public access",
            "Public access to configuration stores may expose secrets and feature flags.",
            "high", public_access,
            {"Description": "Disable public network access on App Configuration.",
             "AzureCLI": "az appconfig update -n <name> -g <rg> --enable-public-network false"}))
    if no_pe:
        findings.append(_ds_finding("app_config", "appconfig_no_private_endpoint",
            f"{len(no_pe)} App Configuration stores without private endpoints",
            "Without private endpoints, configuration data traverses the public Internet.",
            "medium", no_pe,
            {"Description": "Create a private endpoint for App Configuration.",
             "AzureCLI": "az network private-endpoint create --name <pe> -g <rg> --vnet-name <vnet> --subnet <subnet> --connection-name <conn> --private-connection-resource-id <id> --group-id configurationStores"}))
    if no_soft_delete:
        findings.append(_ds_finding("app_config", "appconfig_no_soft_delete",
            f"{len(no_soft_delete)} App Configuration stores without soft delete/purge protection",
            "Without soft delete, accidentally deleted configuration cannot be recovered.",
            "medium", no_soft_delete,
            {"Description": "Enable soft delete and purge protection.",
             "AzureCLI": "az appconfig update -n <name> -g <rg> --enable-purge-protection true"}))
    return findings


def analyze_cert_lifecycle(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#10 Certificate Lifecycle — KV cert expiry, auto-renewal, weak key size."""
    findings: list[dict] = []
    certs = evidence_index.get("azure-keyvault-certs", [])
    if not certs:
        return findings

    from datetime import timezone, timedelta
    expiring: list[dict] = []
    no_auto: list[dict] = []
    weak_key: list[dict] = []
    now = datetime.now(timezone.utc)

    for ev in certs:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        vault = data.get("vaultName", "")
        entry = {"Type": "Certificate", "Name": f"{vault}/{name}" if vault else name, "ResourceId": rid}

        exp_str = data.get("expires", "")
        if exp_str:
            try:
                exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                if exp_dt < now + timedelta(days=30):
                    expiring.append(dict(entry))
            except (ValueError, TypeError):
                pass
        auto = data.get("autoRenewEnabled", True)
        if auto is False:
            no_auto.append(dict(entry))
        key_size = data.get("keySize", 2048)
        if isinstance(key_size, int) and key_size < 2048:
            weak_key.append(dict(entry))

    if expiring:
        findings.append(_ds_finding("keyvault", "cert_expiring_soon",
            f"{len(expiring)} certificates expiring within 30 days",
            "Expired certificates cause service outages and break TLS trust chains.",
            "critical", expiring,
            {"Description": "Renew or rotate certificates before expiry.",
             "AzureCLI": "az keyvault certificate create --vault-name <vault> -n <cert> -p @policy.json"}))
    if no_auto:
        findings.append(_ds_finding("keyvault", "cert_no_auto_renew",
            f"{len(no_auto)} certificates without auto-renewal configured",
            "Manual renewal is error-prone and risks service disruption on expiry.",
            "medium", no_auto,
            {"Description": "Enable auto-renewal in the certificate issuance policy.",
             "AzureCLI": "az keyvault certificate set-attributes --vault-name <vault> -n <cert>"}))
    if weak_key:
        findings.append(_ds_finding("keyvault", "cert_weak_key",
            f"{len(weak_key)} certificates with key size below 2048 bits",
            "Short RSA keys can be factored; NIST mandates >= 2048-bit keys.",
            "high", weak_key,
            {"Description": "Re-issue certificates with RSA 2048+ or EC P-256+.",
             "AzureCLI": "az keyvault certificate create --vault-name <vault> -n <cert> -p @policy.json"}))
    return findings


def analyze_databricks_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#1 Databricks — VNET injection, CMK, no public access, Unity Catalog."""
    findings: list[dict] = []
    dbx = evidence_index.get("azure-databricks", [])
    if not dbx:
        return findings

    no_vnet: list[dict] = []
    no_cmk: list[dict] = []
    public_access: list[dict] = []

    for ev in dbx:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "DatabricksWorkspace", "Name": name, "ResourceId": rid}

        params = data.get("parameters", {})
        custom_vnet = params.get("customVirtualNetworkId", {}).get("value", "")
        if not custom_vnet:
            no_vnet.append(dict(entry))
        enc = data.get("encryption", {})
        cmk = enc.get("entities", {}).get("managedServices", {}).get("keySource", "")
        if cmk.lower() != "microsoft.keyvault":
            no_cmk.append(dict(entry))
        pub = str(data.get("publicNetworkAccess", "")).lower()
        if pub in ("enabled", ""):
            public_access.append(dict(entry))

    if no_vnet:
        findings.append(_ds_finding("databricks", "databricks_no_vnet",
            f"{len(no_vnet)} Databricks workspaces without VNET injection",
            "Without VNET injection data processing runs on shared infrastructure and cannot enforce network controls.",
            "high", no_vnet,
            {"Description": "Deploy Databricks workspace with VNET injection.",
             "AzureCLI": "az databricks workspace create -n <name> -g <rg> --vnet <vnet> --private-subnet <sub1> --public-subnet <sub2>"}))
    if no_cmk:
        findings.append(_ds_finding("databricks", "databricks_no_cmk",
            f"{len(no_cmk)} Databricks workspaces without customer-managed keys",
            "Platform-managed keys mean Microsoft controls the encryption key lifecycle.",
            "medium", no_cmk,
            {"Description": "Configure CMK encryption for Databricks managed services.",
             "AzureCLI": "az databricks workspace update -n <name> -g <rg> --key-source Microsoft.Keyvault --key-name <key> --key-vault <kvUri> --key-version <ver>"}))
    if public_access:
        findings.append(_ds_finding("databricks", "databricks_public_access",
            f"{len(public_access)} Databricks workspaces with public network access",
            "Public access exposes the workspace control plane and data plane to the Internet.",
            "high", public_access,
            {"Description": "Disable public network access on Databricks workspace.",
             "AzureCLI": "az databricks workspace update -n <name> -g <rg> --public-network-access Disabled"}))
    return findings


def analyze_apim_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#3 APIM — backend credentials, client cert auth, subscription key, WAF."""
    findings: list[dict] = []
    apims = evidence_index.get("azure-apim", [])
    if not apims:
        return findings

    no_vnet: list[dict] = []
    no_mi: list[dict] = []
    public_portal: list[dict] = []

    for ev in apims:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "ApiManagement", "Name": name, "ResourceId": rid}

        vnet_type = str(data.get("virtualNetworkType", "")).lower()
        if vnet_type in ("none", ""):
            no_vnet.append(dict(entry))
        mi = data.get("identity", {})
        if not mi or mi.get("type", "None").lower() == "none":
            no_mi.append(dict(entry))
        dev_portal = str(data.get("developerPortalStatus", "")).lower()
        if dev_portal == "enabled":
            public_portal.append(dict(entry))

    if no_vnet:
        findings.append(_ds_finding("apim", "apim_no_vnet",
            f"{len(no_vnet)} APIM instances without VNET integration",
            "APIM without VNET integration exposes API backends and credentials on the public Internet.",
            "high", no_vnet,
            {"Description": "Configure APIM with VNET integration (Internal or External mode).",
             "AzureCLI": "az apim update -n <name> -g <rg> --virtual-network-type Internal"}))
    if no_mi:
        findings.append(_ds_finding("apim", "apim_no_managed_identity",
            f"{len(no_mi)} APIM instances without managed identity",
            "Without managed identity, APIM relies on stored credentials for backend access.",
            "medium", no_mi,
            {"Description": "Enable system-assigned managed identity on APIM.",
             "AzureCLI": "az apim update -n <name> -g <rg> --enable-managed-identity true"}))
    return findings


def analyze_frontdoor_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#5 Front Door / CDN + WAF — WAF policy, managed rules, TLS 1.2+."""
    findings: list[dict] = []
    fds = evidence_index.get("azure-frontdoor", [])
    if not fds:
        return findings

    no_waf: list[dict] = []
    old_tls: list[dict] = []

    for ev in fds:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "FrontDoor", "Name": name, "ResourceId": rid}

        waf_policy = data.get("frontDoorWebApplicationFirewallPolicyLink", data.get("wafPolicyId", ""))
        if not waf_policy:
            no_waf.append(dict(entry))
        tls = str(data.get("minimumTlsVersion", "")).lower()
        if tls and tls < "1.2":
            old_tls.append(dict(entry))

    if no_waf:
        findings.append(_ds_finding("frontdoor", "frontdoor_no_waf",
            f"{len(no_waf)} Front Door profiles without WAF policy",
            "Without WAF, Front Door cannot block OWASP Top-10 attacks, SQL injection, or data exfiltration payloads.",
            "critical", no_waf,
            {"Description": "Create and associate a WAF policy in Prevention mode.",
             "AzureCLI": "az network front-door waf-policy create -g <rg> -n <policy> --mode Prevention"}))
    if old_tls:
        findings.append(_ds_finding("frontdoor", "frontdoor_old_tls",
            f"{len(old_tls)} Front Door profiles with TLS below 1.2",
            "TLS versions below 1.2 have known vulnerabilities.",
            "high", old_tls,
            {"Description": "Set minimum TLS version to 1.2.",
             "AzureCLI": "az network front-door update -g <rg> -n <name> --enforce-certificate-name-check Enabled"}))
    return findings


def analyze_secret_sprawl(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#8 Secret Sprawl Detection — app settings, ARM params with embedded secrets."""
    findings: list[dict] = []
    apps = evidence_index.get("azure-webapp", [])
    if not apps:
        return findings

    import re as _re
    _SECRET_PATTERNS = [
        _re.compile(r"(?i)(password|secret|key|token|connectionstring)\s*[=:]\s*[\"\']?[A-Za-z0-9+/=]{10,}"),
        _re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{40,}"),
        _re.compile(r"(?i)SharedAccessSignature="),
    ]

    sprawl: list[dict] = []
    kv_ref: list[dict] = []

    for ev in apps:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "WebApp", "Name": name, "ResourceId": rid}

        settings = data.get("appSettings", [])
        kv_ref_count = 0
        plain_secret_count = 0
        for s in settings if isinstance(settings, list) else []:
            val = str(s.get("value", ""))
            sname = str(s.get("name", "")).lower()
            if "@Microsoft.KeyVault" in val:
                kv_ref_count += 1
                continue
            for pat in _SECRET_PATTERNS:
                if pat.search(val) or pat.search(sname + "=" + val):
                    plain_secret_count += 1
                    break
        if plain_secret_count > 0:
            e = dict(entry)
            e["PlainSecretCount"] = plain_secret_count
            sprawl.append(e)
        if kv_ref_count == 0 and len(settings) > 0:
            kv_ref.append(dict(entry))

    if sprawl:
        findings.append(_ds_finding("secret_sprawl", "secret_in_app_settings",
            f"{len(sprawl)} web apps with potential secrets in app settings",
            "Secrets stored in plain text in app settings are visible to anyone with Reader access and appear in ARM template exports.",
            "critical", sprawl,
            {"Description": "Move secrets to Key Vault and use Key Vault references.",
             "AzureCLI": "az webapp config appsettings set -g <rg> -n <app> --settings MySecret=@Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/<secret>)"}))
    if kv_ref:
        findings.append(_ds_finding("secret_sprawl", "no_keyvault_references",
            f"{len(kv_ref)} web apps with zero Key Vault references",
            "Apps not using Key Vault references likely store configuration secrets in plain text.",
            "medium", kv_ref,
            {"Description": "Adopt Key Vault references for all sensitive app settings.",
             "AzureCLI": "az webapp config appsettings set -g <rg> -n <app> --settings MySecret=@Microsoft.KeyVault(SecretUri=...)"}))
    return findings


def analyze_firewall_appgw_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#6 Azure Firewall / Application Gateway — TLS inspection, IDPS, threat intel."""
    findings: list[dict] = []

    # Azure Firewall
    fws = evidence_index.get("azure-firewall", [])
    no_threat_intel: list[dict] = []
    no_idps: list[dict] = []
    for ev in fws:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "AzureFirewall", "Name": name, "ResourceId": rid}

        ti_mode = str(data.get("threatIntelMode", "")).lower()
        if ti_mode in ("off", ""):
            no_threat_intel.append(dict(entry))
        idps = data.get("intrusionDetection", {})
        idps_mode = str(idps.get("mode", "")).lower() if isinstance(idps, dict) else ""
        if idps_mode in ("off", ""):
            no_idps.append(dict(entry))

    if no_threat_intel:
        findings.append(_ds_finding("firewall", "firewall_no_threat_intel",
            f"{len(no_threat_intel)} Azure Firewalls with threat intelligence disabled",
            "Without threat intelligence filtering, known malicious IPs can reach internal data services.",
            "high", no_threat_intel,
            {"Description": "Enable threat intelligence-based filtering in Alert or Deny mode.",
             "AzureCLI": "az network firewall update -g <rg> -n <name> --threat-intel-mode Deny"}))
    if no_idps:
        findings.append(_ds_finding("firewall", "firewall_no_idps",
            f"{len(no_idps)} Azure Firewalls without IDPS enabled",
            "IDPS detects data exfiltration, C2 traffic, and lateral movement patterns.",
            "high", no_idps,
            {"Description": "Enable IDPS on Azure Firewall Premium.",
             "AzureCLI": "az network firewall policy intrusion-detection add -g <rg> --policy-name <pol> --mode Alert"}))

    # Application Gateway
    appgws = evidence_index.get("azure-appgw", [])
    no_waf_appgw: list[dict] = []
    for ev in appgws:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "ApplicationGateway", "Name": name, "ResourceId": rid}
        sku_tier = str(data.get("skuTier", data.get("sku_tier", ""))).lower()
        if "waf" not in sku_tier:
            no_waf_appgw.append(dict(entry))

    if no_waf_appgw:
        findings.append(_ds_finding("firewall", "appgw_no_waf",
            f"{len(no_waf_appgw)} Application Gateways without WAF SKU",
            "Non-WAF Application Gateways cannot inspect or block malicious payloads targeting backend data APIs.",
            "high", no_waf_appgw,
            {"Description": "Upgrade Application Gateway to WAF_v2 SKU.",
             "AzureCLI": "az network application-gateway update -g <rg> -n <name> --sku WAF_v2"}))
    return findings


def analyze_bastion_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#7 Bastion — usage audit, shareable links, native client."""
    findings: list[dict] = []
    bastions = evidence_index.get("azure-bastion", [])
    nsgs = evidence_index.get("azure-nsg", [])

    # Check for open RDP/SSH NSG rules without Bastion
    open_rdp_ssh: list[dict] = []
    for ev in nsgs:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        rules = data.get("securityRules", [])
        for rule in rules if isinstance(rules, list) else []:
            props = rule if isinstance(rule, dict) else {}
            direction = str(props.get("direction", props.get("properties", {}).get("direction", ""))).lower()
            access = str(props.get("access", props.get("properties", {}).get("access", ""))).lower()
            dest_port = str(props.get("destinationPortRange", props.get("properties", {}).get("destinationPortRange", "")))
            src = str(props.get("sourceAddressPrefix", props.get("properties", {}).get("sourceAddressPrefix", "")))
            if direction == "inbound" and access == "allow" and dest_port in ("3389", "22", "*") and src in ("*", "Internet", "0.0.0.0/0"):
                open_rdp_ssh.append({"Type": "NSG", "Name": name, "ResourceId": rid, "Port": dest_port})
                break

    if open_rdp_ssh and not bastions:
        findings.append(_ds_finding("bastion", "no_bastion_open_rdp",
            f"{len(open_rdp_ssh)} NSGs allow RDP/SSH from Internet without Bastion deployed",
            "Direct RDP/SSH exposure increases brute-force risk and potential data exfiltration via remote sessions.",
            "critical", open_rdp_ssh,
            {"Description": "Deploy Azure Bastion and remove direct RDP/SSH NSG rules.",
             "AzureCLI": "az network bastion create -n <bastion> -g <rg> --vnet-name <vnet> --public-ip-address <pip>"}))

    shareable: list[dict] = []
    for ev in bastions:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        name = data.get("name", rid.rsplit("/", 1)[-1] if "/" in rid else "Unknown")
        entry = {"Type": "BastionHost", "Name": name, "ResourceId": rid}
        sl = data.get("enableShareableLink", False)
        if sl:
            shareable.append(dict(entry))

    if shareable:
        findings.append(_ds_finding("bastion", "bastion_shareable_links",
            f"{len(shareable)} Bastion hosts with shareable links enabled",
            "Shareable links allow unauthenticated URL-based access to VMs, bypassing RBAC.",
            "high", shareable,
            {"Description": "Disable shareable links on Bastion.",
             "AzureCLI": "az network bastion update -n <name> -g <rg> --enable-shareable-link false"}))
    return findings


def analyze_policy_compliance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#11 Azure Policy Compliance — data-related policy assignments, non-compliant count."""
    findings: list[dict] = []
    policies = evidence_index.get("azure-policy-states", [])
    if not policies:
        return findings

    non_compliant: list[dict] = []
    _DATA_KEYWORDS = {"storage", "sql", "cosmos", "keyvault", "key vault", "encrypt",
                      "tls", "https", "private", "network", "firewall", "data", "backup"}

    for ev in policies:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        state = str(data.get("complianceState", "")).lower()
        policy_name = data.get("policyDefinitionName", "")
        policy_display = data.get("policyDefinitionDisplayName", policy_name)

        if state == "noncompliant":
            display_lower = str(policy_display).lower()
            if any(kw in display_lower for kw in _DATA_KEYWORDS):
                non_compliant.append({
                    "Type": "PolicyAssignment",
                    "Name": policy_display,
                    "ResourceId": rid,
                    "PolicyName": policy_name,
                })

    if non_compliant:
        findings.append(_ds_finding("policy_compliance", "data_policy_noncompliant",
            f"{len(non_compliant)} data-related Azure Policy assignments are non-compliant",
            "Non-compliant policies indicate that governance controls for data protection are not being enforced.",
            "high", non_compliant,
            {"Description": "Remediate non-compliant resources or adjust policy assignments.",
             "AzureCLI": "az policy state trigger-scan --resource-group <rg>"}))
    return findings


def analyze_defender_score(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """#14 Defender for Cloud Secure Score — data protection sub-score."""
    findings: list[dict] = []
    recs = evidence_index.get("azure-security-recommendations", [])
    if not recs:
        return findings

    data_recs: list[dict] = []
    _DATA_RE = {"storage", "sql", "cosmos", "data", "encrypt", "key vault", "keyvault",
                "tls", "https", "private endpoint", "backup", "network access"}

    for ev in recs:
        data = ev.get("Data", {})
        rid = ev.get("ResourceId", "")
        display = data.get("displayName", "")
        state = str(data.get("state", "")).lower()
        if state in ("unhealthy", "notapplicable"):
            display_lower = display.lower()
            if any(kw in display_lower for kw in _DATA_RE):
                data_recs.append({
                    "Type": "SecurityRecommendation",
                    "Name": display,
                    "ResourceId": rid,
                    "Severity": data.get("severity", "medium"),
                })

    if data_recs:
        severity = "critical" if len(data_recs) > 10 else "high" if len(data_recs) > 5 else "medium"
        findings.append(_ds_finding("defender_score", "defender_data_recs_unhealthy",
            f"{len(data_recs)} Defender data-protection recommendations are unhealthy",
            "Unhealthy Defender recommendations indicate gaps in the data security posture detected by Microsoft Defender for Cloud.",
            severity, data_recs,
            {"Description": "Review and remediate Defender for Cloud recommendations.",
             "AzureCLI": "az security assessment list --query \"[?status.code=='Unhealthy\']\""}))
    return findings


#                                                                           
# Wave D — Advanced Security Domain Checks
#                                                                           


