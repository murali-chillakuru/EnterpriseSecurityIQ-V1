"""
Data Security — Key Vault Hygiene evaluator — 10 checks.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_keyvault_hygiene(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_keyvault_access_policies(evidence_index))
    findings.extend(_check_keyvault_purge_protection(evidence_index))
    findings.extend(_check_keyvault_expiring_items(evidence_index))
    findings.extend(_check_keyvault_rbac_model(evidence_index))
    findings.extend(_check_keyvault_network_restrictions(evidence_index))
    findings.extend(_check_keyvault_soft_delete(evidence_index))
    findings.extend(_check_keyvault_no_expiry_secrets(evidence_index))
    findings.extend(_check_keyvault_cert_auto_renewal(evidence_index))
    findings.extend(_check_keyvault_hsm_backed(evidence_index))
    return findings


def _check_keyvault_access_policies(idx: dict) -> list[dict]:
    kvs = idx.get("azure-keyvault", [])
    broad: list[dict] = []
    for ev in kvs:
        data = ev.get("Data", ev.get("data", {}))
        rbac = data.get("EnableRbacAuthorization", data.get("enable_rbac_authorization"))
        if rbac is False:
            policies = data.get("AccessPolicies", data.get("access_policies", []))
            if len(policies) > 10:
                broad.append({
                    "Type": "KeyVault",
                    "Name": data.get("VaultName", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "PolicyCount": len(policies),
                })
    if broad:
        return [_ds_finding(
            "keyvault", "broad_access_policies",
            f"{len(broad)} Key Vaults with excessive access policies",
            "Key Vaults using legacy access policies with many entries are hard to govern. Migrate to RBAC.",
            "medium", broad,
            {"Description": "Enable RBAC authorization on Key Vaults.",
             "AzureCLI": "az keyvault update -n <vault> -g <rg> --enable-rbac-authorization true"},
        )]
    return []


def _check_keyvault_purge_protection(idx: dict) -> list[dict]:
    kvs = idx.get("azure-keyvault", [])
    no_purge: list[dict] = []
    for ev in kvs:
        data = ev.get("Data", ev.get("data", {}))
        purge = data.get("EnablePurgeProtection", data.get("enable_purge_protection"))
        if purge is not True:
            no_purge.append({
                "Type": "KeyVault",
                "Name": data.get("VaultName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_purge:
        return [_ds_finding(
            "keyvault", "purge_protection_disabled",
            f"{len(no_purge)} Key Vaults without purge protection",
            "Without purge protection, deleted keys/secrets/certs can be permanently lost.",
            "high", no_purge,
            {"Description": "Enable purge protection (irreversible once enabled).",
             "AzureCLI": "az keyvault update -n <vault> -g <rg> --enable-purge-protection true"},
        )]
    return []


def _check_keyvault_expiring_items(idx: dict) -> list[dict]:
    kvs = idx.get("azure-keyvault", [])
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=30)
    expired: list[dict] = []
    expiring: list[dict] = []

    for ev in kvs:
        data = ev.get("Data", ev.get("data", {}))
        vault_name = data.get("VaultName", data.get("name", "Unknown"))
        for item_list_key in ("Secrets", "Keys", "Certificates",
                              "secrets", "keys", "certificates"):
            for item in data.get(item_list_key, []):
                exp_raw = item.get("Expiry", item.get("expiry",
                          item.get("ExpiresOn", item.get("expires_on"))))
                if not exp_raw:
                    continue
                try:
                    exp_dt = (
                        datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
                        if isinstance(exp_raw, str) else exp_raw
                    )
                    entry = {"Type": "KeyVaultItem", "Vault": vault_name,
                             "ItemName": item.get("Name", item.get("name", "Unknown")),
                             "Expiry": str(exp_dt)}
                    if exp_dt < now:
                        expired.append(entry)
                    elif exp_dt < soon:
                        expiring.append(entry)
                except (ValueError, TypeError):
                    continue

    findings: list[dict] = []
    if expired:
        findings.append(_ds_finding(
            "keyvault", "expired_items",
            f"{len(expired)} expired Key Vault items",
            "Expired keys/secrets/certificates may cause service outages or indicate abandoned resources.",
            "high", expired,
            {"Description": "Rotate or remove expired items.",
             "AzureCLI": "az keyvault secret set --vault-name <vault> -n <name> --value <new-value>"},
        ))
    if expiring:
        findings.append(_ds_finding(
            "keyvault", "expiring_items",
            f"{len(expiring)} Key Vault items expiring within 30 days",
            "Proactively rotate items before expiry to prevent service disruptions.",
            "medium", expiring,
            {"Description": "Rotate items before expiry. Consider auto-rotation.",
             "PortalSteps": [
                 "Navigate to Key Vault > Secrets/Keys/Certificates",
                 "Set up rotation policies for auto-renewal",
             ]},
        ))
    return findings


def _check_keyvault_rbac_model(idx: dict) -> list[dict]:
    """Flag Key Vaults still using legacy access-policy model instead of Azure RBAC."""
    kvs = idx.get("azure-keyvault", [])
    legacy: list[dict] = []
    for ev in kvs:
        data = ev.get("Data", ev.get("data", {}))
        rbac = data.get("EnableRbacAuthorization", data.get("enable_rbac_authorization"))
        if rbac is not True:
            legacy.append({
                "Type": "KeyVault",
                "Name": data.get("VaultName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "AuthorizationModel": "Access Policy",
            })
    if legacy:
        return [_ds_finding(
            "keyvault", "legacy_access_policy_model",
            f"{len(legacy)} Key Vaults using legacy access-policy model",
            "Azure RBAC provides fine-grained, centrally managed permissions. "
            "Legacy access policies are harder to audit and lack conditional access integration.",
            "medium", legacy,
            {"Description": "Migrate Key Vaults to RBAC authorization model.",
             "AzureCLI": "az keyvault update -n <vault> -g <rg> --enable-rbac-authorization true",
             "PortalSteps": [
                 "Navigate to Key Vault > Access configuration",
                 "Select 'Azure role-based access control' under Permission model",
                 "Click Save",
             ]},
        )]
    return []


def _check_keyvault_network_restrictions(idx: dict) -> list[dict]:
    """Flag Key Vaults without network restrictions (public access)."""
    kvs = idx.get("azure-keyvault", [])
    open_vaults: list[dict] = []
    for ev in kvs:
        data = ev.get("Data", ev.get("data", {}))
        network_acls = data.get("NetworkAcls", data.get("networkAcls", {})) or {}
        default_action = (network_acls.get("defaultAction", "") or "").lower()
        ip_rules = network_acls.get("ipRules", []) or []
        vnet_rules = network_acls.get("virtualNetworkRules", []) or []
        pe_conns = data.get("PrivateEndpointConnections",
                   data.get("privateEndpointConnections", [])) or []

        # If default action is not "deny" AND no private endpoints → publicly open
        if default_action != "deny" and not pe_conns:
            open_vaults.append({
                "Type": "KeyVault",
                "Name": data.get("VaultName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "DefaultAction": default_action or "Allow",
                "IpRuleCount": len(ip_rules),
                "VNetRuleCount": len(vnet_rules),
            })
    if open_vaults:
        return [_ds_finding(
            "keyvault", "no_network_restrictions",
            f"{len(open_vaults)} Key Vaults without network restrictions",
            "Key Vaults accessible from all networks are exposed to potential brute-force "
            "and credential-stuffing attacks. Restrict access via firewall rules or private endpoints.",
            "high", open_vaults,
            {"Description": "Configure Key Vault firewall to deny public access and use private endpoints.",
             "AzureCLI": "az keyvault update -n <vault> -g <rg> --default-action Deny",
             "PortalSteps": [
                 "Navigate to Key Vault > Networking",
                 "Under Firewalls and virtual networks, select 'Allow access from: Selected networks'",
                 "Add permitted IP ranges or VNet service endpoints",
                 "Consider adding a Private Endpoint under Private endpoint connections",
             ]},
        )]
    return []


def _check_keyvault_soft_delete(idx: dict) -> list[dict]:
    """Flag Key Vaults without soft-delete enabled (CIS 8.4)."""
    kvs = idx.get("azure-keyvault", [])
    no_soft: list[dict] = []
    for ev in kvs:
        data = ev.get("Data", ev.get("data", {}))
        soft = data.get("enableSoftDelete", data.get("EnableSoftDelete"))
        if soft is False:
            no_soft.append({
                "Type": "KeyVault",
                "Name": data.get("VaultName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_soft:
        return [_ds_finding(
            "keyvault", "soft_delete_disabled",
            f"{len(no_soft)} Key Vaults without soft-delete",
            "Without soft-delete, deleted keys, secrets, and certificates are "
            "permanently lost immediately. Soft-delete provides a recovery window.",
            "high", no_soft,
            {"Description": "Enable soft-delete on Key Vaults (enabled by default on new vaults).",
             "AzureCLI": "az keyvault update -n <vault> -g <rg> --enable-soft-delete true"},
        )]
    return []


def _check_keyvault_no_expiry_secrets(idx: dict) -> list[dict]:
    """Flag Key Vault secrets and keys that have no expiration date set."""
    kvs = idx.get("azure-keyvault", [])
    no_expiry: list[dict] = []
    for ev in kvs:
        data = ev.get("Data", ev.get("data", {}))
        vault_name = data.get("VaultName", data.get("name", "Unknown"))
        for item_list_key in ("Secrets", "Keys", "secrets", "keys"):
            for item in data.get(item_list_key, []):
                exp_raw = item.get("Expiry", item.get("expiry",
                          item.get("ExpiresOn", item.get("expires_on"))))
                if exp_raw is None or exp_raw == "":
                    no_expiry.append({
                        "Type": "KeyVaultItem",
                        "Vault": vault_name,
                        "ItemName": item.get("Name", item.get("name", "Unknown")),
                        "ItemType": "Key" if item_list_key.lower().startswith("key") else "Secret",
                    })
    if no_expiry:
        return [_ds_finding(
            "keyvault", "no_expiry_set",
            f"{len(no_expiry)} Key Vault items without expiration dates",
            "Secrets and keys without expiration dates are never forced into rotation, "
            "increasing the risk of compromised credentials persisting indefinitely.",
            "medium", no_expiry,
            {"Description": "Set expiration dates on all secrets and keys; enable auto-rotation.",
             "AzureCLI": "az keyvault secret set-attributes --vault-name <vault> -n <name> --expires <YYYY-MM-DDTHH:MM:SSZ>"},
        )]
    return []


def _check_keyvault_cert_auto_renewal(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Flag certificates without auto-renewal configured."""
    no_renewal: list[dict] = []
    for ev in evidence_index.get("azure-keyvault", []):
        data = ev.get("Data", ev.get("data", {}))
        vault_name = data.get("VaultName", data.get("name", "Unknown"))
        for cert in data.get("Certificates", data.get("certificates", [])):
            policy = cert.get("Policy", cert.get("policy", {}))
            lifetime_actions = policy.get("LifetimeActions", policy.get("lifetime_actions", []))
            has_auto_renew = any(
                (a.get("Action", a.get("action", {})) or {}).get("ActionType", "").lower() == "autorenew"
                or (a.get("Action", a.get("action", {})) or {}).get("action_type", "").lower() == "autorenew"
                for a in lifetime_actions
            )
            if not has_auto_renew:
                no_renewal.append({
                    "Type": "KeyVaultCertificate",
                    "Vault": vault_name,
                    "CertificateName": cert.get("Name", cert.get("name", "Unknown")),
                })
    if no_renewal:
        return [_ds_finding(
            "keyvault", "cert_no_auto_renewal",
            f"{len(no_renewal)} certificates without auto-renewal configured",
            "Certificates without auto-renewal risk expiration-related outages "
            "and manual rotation burden, increasing the chance of missed renewals.",
            "medium", no_renewal,
            {"Description": "Enable auto-renewal in certificate issuance policies.",
             "AzureCLI": "az keyvault certificate set-attributes --vault-name <vault> -n <cert> "
                         "--policy '{\"lifetime_actions\":[{\"action\":{\"action_type\":\"AutoRenew\"},"
                         "\"trigger\":{\"days_before_expiry\":30}}]}'"},
        )]
    return []


def _check_keyvault_hsm_backed(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Flag keys not using HSM-backed protection."""
    software_keys: list[dict] = []
    for ev in evidence_index.get("azure-keyvault", []):
        data = ev.get("Data", ev.get("data", {}))
        vault_name = data.get("VaultName", data.get("name", "Unknown"))
        for key in data.get("Keys", data.get("keys", [])):
            key_type = key.get("KeyType", key.get("kty", ""))
            # RSA/EC without -HSM suffix means software-protected
            if key_type and not key_type.upper().endswith("-HSM"):
                software_keys.append({
                    "Type": "KeyVaultKey",
                    "Vault": vault_name,
                    "KeyName": key.get("Name", key.get("name", "Unknown")),
                    "KeyType": key_type,
                })
    if software_keys:
        return [_ds_finding(
            "keyvault", "keys_not_hsm_backed",
            f"{len(software_keys)} keys using software protection instead of HSM",
            "Software-protected keys store key material in software, which offers "
            "lower assurance than HSM-backed keys (FIPS 140-2 Level 2/3).",
            "low", software_keys,
            {"Description": "Recreate keys with HSM-backed protection (RSA-HSM or EC-HSM) "
                           "or migrate to Azure Key Vault Managed HSM for highest assurance.",
             "AzureCLI": "az keyvault key create --vault-name <vault> -n <key> --kty RSA-HSM"},
        )]
    return []


