"""
Data Security — Storage Exposure evaluator — 16 checks.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_storage_exposure(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_blob_public_access(evidence_index))
    findings.extend(_check_storage_https(evidence_index))
    findings.extend(_check_storage_network_rules(evidence_index))
    findings.extend(_check_storage_soft_delete(evidence_index))
    # Phase 3 — deeper storage checks
    findings.extend(_check_storage_min_tls(evidence_index))
    findings.extend(_check_storage_shared_key(evidence_index))
    findings.extend(_check_storage_infra_encryption(evidence_index))
    findings.extend(_check_storage_anonymous_containers(evidence_index))
    findings.extend(_check_storage_sas_policy(evidence_index))
    findings.extend(_check_storage_immutability(evidence_index))
    # Phase 4 — additional storage checks
    findings.extend(_check_storage_lifecycle_management(evidence_index))
    findings.extend(_check_storage_cors_policy(evidence_index))
    findings.extend(_check_storage_network_bypass(evidence_index))
    findings.extend(_check_storage_logging(evidence_index))
    # Phase 5 — versioning & change-feed
    findings.extend(_check_storage_blob_versioning(evidence_index))
    findings.extend(_check_storage_change_feed(evidence_index))
    return findings


def _check_blob_public_access(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    public: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("AllowBlobPublicAccess", data.get("allow_blob_public_access")) is True:
            public.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "storage", "blob_public_access",
            f"{len(public)} storage accounts allow public blob access",
            "Public blob access may expose sensitive data to the Internet.",
            "high", public,
            {"Description": "Disable public blob access.",
             "AzureCLI": "az storage account update -n <name> -g <rg> --allow-blob-public-access false",
             "PowerShell": "Set-AzStorageAccount -ResourceGroupName <rg> -Name <name> -AllowBlobPublicAccess $false"},
        )]
    return []


def _check_storage_https(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    insecure: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        https = data.get("HttpsOnly", data.get("https_only", data.get("supportsHttpsTrafficOnly")))
        if https is False:
            insecure.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if insecure:
        return [_ds_finding(
            "storage", "https_not_enforced",
            f"{len(insecure)} storage accounts without HTTPS enforcement",
            "Storage accounts accepting HTTP traffic expose data to interception.",
            "high", insecure,
            {"Description": "Enable HTTPS-only on all storage accounts.",
             "AzureCLI": "az storage account update -n <name> -g <rg> --https-only true"},
        )]
    return []


def _check_storage_network_rules(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    open_accounts: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        default_action = data.get("NetworkDefaultAction",
                         data.get("network_default_action",
                         data.get("DefaultAction", ""))).lower()
        if default_action == "allow":
            open_accounts.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if open_accounts:
        return [_ds_finding(
            "storage", "network_unrestricted",
            f"{len(open_accounts)} storage accounts with unrestricted network access",
            "Default 'Allow' network rule permits access from any network.",
            "medium", open_accounts,
            {"Description": "Set default network rule to Deny and add virtual network / IP rules.",
             "AzureCLI": "az storage account update -n <name> -g <rg> --default-action Deny"},
        )]
    return []


def _check_storage_soft_delete(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    no_soft_del: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        soft_del = data.get("BlobSoftDeleteEnabled",
                   data.get("blob_soft_delete_enabled",
                   data.get("SoftDeleteEnabled")))
        if soft_del is False:
            no_soft_del.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_soft_del:
        return [_ds_finding(
            "storage", "soft_delete_disabled",
            f"{len(no_soft_del)} storage accounts without soft delete",
            "Without soft delete, accidentally or maliciously deleted data cannot be recovered.",
            "medium", no_soft_del,
            {"Description": "Enable blob soft delete with a 7+ day retention.",
             "AzureCLI": "az storage account blob-service-properties update -n <name> -g <rg> "
                         "--enable-delete-retention true --delete-retention-days 7"},
        )]
    return []


# -- Phase 3: deeper storage checks --

def _check_storage_min_tls(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    weak_tls: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        tls = data.get("minimumTlsVersion", data.get("MinimumTlsVersion", ""))
        if tls and tls not in ("TLS1_2", "TLS1_3"):
            weak_tls.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "CurrentTLS": tls,
            })
    if weak_tls:
        return [_ds_finding(
            "storage", "weak_tls",
            f"{len(weak_tls)} storage accounts with TLS below 1.2",
            "Older TLS versions are vulnerable to downgrade attacks.",
            "high", weak_tls,
            {"Description": "Set minimum TLS version to 1.2.",
             "AzureCLI": "az storage account update -n <name> -g <rg> --min-tls-version TLS1_2"},
        )]
    return []


def _check_storage_shared_key(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    shared_key: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        allow_shared = data.get("allowSharedKeyAccess", data.get("AllowSharedKeyAccess"))
        if allow_shared is True:
            shared_key.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if shared_key:
        return [_ds_finding(
            "storage", "shared_key_enabled",
            f"{len(shared_key)} storage accounts with shared key access enabled",
            "Shared key access bypasses Azure AD RBAC controls — prefer Entra ID auth.",
            "medium", shared_key,
            {"Description": "Disable shared key access and use Entra ID (RBAC) authentication.",
             "AzureCLI": "az storage account update -n <name> -g <rg> --allow-shared-key-access false"},
        )]
    return []


def _check_storage_infra_encryption(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    no_infra: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        infra_enc = data.get("infrastructureEncryption",
                    data.get("InfrastructureEncryption",
                    data.get("requireInfrastructureEncryption")))
        if infra_enc is False:
            no_infra.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_infra:
        return [_ds_finding(
            "storage", "no_infrastructure_encryption",
            f"{len(no_infra)} storage accounts without infrastructure (double) encryption",
            "Infrastructure encryption adds a second layer of encryption at the storage service level.",
            "low", no_infra,
            {"Description": "Enable infrastructure encryption (requires account recreation or new account).",
             "AzureCLI": "az storage account create -n <name> -g <rg> --require-infrastructure-encryption"},
        )]
    return []


def _check_storage_anonymous_containers(idx: dict) -> list[dict]:
    """Flag storage accounts where ARG-enriched container data shows anonymous access."""
    containers = idx.get("azure-storage-containers", [])
    anon: list[dict] = []
    for ev in containers:
        data = ev.get("Data", ev.get("data", {}))
        access = data.get("publicAccess", data.get("PublicAccess", "")).lower()
        if access in ("blob", "container"):
            anon.append({
                "Type": "BlobContainer",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "PublicAccess": access,
            })
    if anon:
        return [_ds_finding(
            "storage", "anonymous_containers",
            f"{len(anon)} blob containers with anonymous public access",
            "Individual containers allowing anonymous reads can leak sensitive data.",
            "critical", anon,
            {"Description": "Set container public access level to Private.",
             "AzureCLI": "az storage container set-permission -n <container> --account-name <acct> --public-access off"},
        )]
    return []


def _check_storage_sas_policy(idx: dict) -> list[dict]:
    """Flag storage accounts without a SAS expiration policy."""
    storage = idx.get("azure-storage-security", [])
    no_policy: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        sas_policy = data.get("SasPolicy", data.get("properties_sasPolicy", data.get("sasPolicy", "")))
        has_policy = bool(sas_policy) if isinstance(sas_policy, (dict, str)) and sas_policy != "" else False
        if not has_policy:
            no_policy.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_policy:
        return [_ds_finding(
            "storage", "no_sas_expiration_policy",
            f"{len(no_policy)} storage accounts without SAS expiration policy",
            "Without a SAS expiration policy, shared access signatures can be created "
            "with excessively long validity periods, increasing the risk of token theft.",
            "medium", no_policy,
            {"Description": "Configure a SAS expiration policy on each storage account.",
             "AzureCLI": (
                 "az storage account update -n <acct> -g <rg> "
                 "--sas-expiration-period 1.00:00:00"
             ),
             "PortalSteps": [
                 "Azure Portal → Storage account → Configuration",
                 "Set 'SAS expiration policy' to a reasonable period (e.g. 24 hours)",
             ]},
        )]
    return []


def _check_storage_immutability(idx: dict) -> list[dict]:
    """Flag storage accounts without an account-level immutability policy."""
    storage = idx.get("azure-storage-security", [])
    no_immutable: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        immutable = data.get("ImmutableStorageWithVersioning",
                   data.get("properties_immutableStorageWithVersioning",
                   data.get("immutableStorageWithVersioning", "")))
        has_immutable = bool(immutable) and immutable != ""
        if not has_immutable:
            no_immutable.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_immutable:
        return [_ds_finding(
            "storage", "no_immutability_policy",
            f"{len(no_immutable)} storage accounts without immutability policy",
            "Immutable storage protects critical data from modification or deletion. "
            "Without it, ransomware or accidental deletion can destroy compliance-critical data.",
            "low", no_immutable,
            {"Description": "Enable account-level immutability with versioning for compliance data.",
             "AzureCLI": (
                 "az storage account update -n <acct> -g <rg> "
                 "--immutability-period-since-creation-in-days 365 "
                 "--immutability-policy-state unlocked"
             ),
             "PortalSteps": [
                 "Azure Portal → Storage account → Data protection",
                 "Enable version-level immutability support",
                 "Set immutability policies on containers holding compliance data",
             ]},
        )]
    return []


def _check_storage_lifecycle_management(idx: dict) -> list[dict]:
    """Flag storage accounts without lifecycle management policies (CIS 7.2)."""
    storage = idx.get("azure-storage-security", [])
    no_lifecycle: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        lifecycle = data.get("LifecycleManagementEnabled",
                   data.get("lifecycleManagementEnabled"))
        if lifecycle is False:
            no_lifecycle.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_lifecycle:
        return [_ds_finding(
            "storage", "no_lifecycle_management",
            f"{len(no_lifecycle)} storage accounts without lifecycle management policies",
            "Without lifecycle management, data grows indefinitely. Stale data increases "
            "the blast radius in a breach and raises storage costs.",
            "low", no_lifecycle,
            {"Description": "Configure lifecycle management to transition old data to cool/archive tiers.",
             "AzureCLI": (
                 "az storage account management-policy create --account-name <acct> -g <rg> "
                 "--policy @lifecycle-policy.json"
             )},
        )]
    return []


def _check_storage_cors_policy(idx: dict) -> list[dict]:
    """Flag storage accounts with wildcard CORS origins (CIS 5.1)."""
    storage = idx.get("azure-storage-security", [])
    wildcard_cors: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        cors_rules = data.get("CorsRules", data.get("corsRules", []))
        if not isinstance(cors_rules, list):
            continue
        for rule in cors_rules:
            origins = rule.get("allowedOrigins", rule.get("AllowedOrigins", []))
            if isinstance(origins, list) and "*" in origins:
                wildcard_cors.append({
                    "Type": "StorageAccount",
                    "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "AllowedOrigins": ", ".join(origins),
                })
                break
            elif isinstance(origins, str) and origins == "*":
                wildcard_cors.append({
                    "Type": "StorageAccount",
                    "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "AllowedOrigins": origins,
                })
                break
    if wildcard_cors:
        return [_ds_finding(
            "storage", "wildcard_cors_origin",
            f"{len(wildcard_cors)} storage accounts with wildcard (*) CORS origins",
            "Overly permissive CORS (AllowedOrigins: *) exposes data to cross-origin "
            "script injection from any domain.",
            "medium", wildcard_cors,
            {"Description": "Restrict CORS allowed origins to specific trusted domains.",
             "AzureCLI": (
                 "az storage cors clear --account-name <acct> --services b ; "
                 "az storage cors add --account-name <acct> --services b "
                 "--origins https://trusted.example.com --methods GET"
             )},
        )]
    return []


def _check_storage_network_bypass(idx: dict) -> list[dict]:
    """Flag storage accounts with overly permissive network bypass rules."""
    storage = idx.get("azure-storage-security", [])
    permissive: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        network_acls = data.get("NetworkAcls", data.get("networkAcls", {})) or {}
        bypass = (network_acls.get("bypass", "") or "").lower()
        default_action = (network_acls.get("defaultAction", "") or "").lower()
        # Only relevant if default is Deny but bypass is too broad
        if default_action == "deny" and bypass:
            # "Logging, Metrics, AzureServices" = too permissive
            # Acceptable: "AzureServices" alone or "None"
            parts = {p.strip() for p in bypass.split(",")}
            overly_broad = parts - {"azureservices", "none", ""}
            if overly_broad:
                permissive.append({
                    "Type": "StorageAccount",
                    "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                    "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                    "Bypass": bypass,
                })
    if permissive:
        return [_ds_finding(
            "storage", "overly_permissive_bypass",
            f"{len(permissive)} storage accounts with overly permissive network bypass",
            "Network bypass rules allowing 'Logging' and 'Metrics' services create "
            "additional access paths beyond AzureServices.",
            "low", permissive,
            {"Description": "Restrict bypass to 'AzureServices' only or 'None'.",
             "AzureCLI": "az storage account update -n <name> -g <rg> --bypass AzureServices"},
        )]
    return []


def _check_storage_logging(idx: dict) -> list[dict]:
    """Flag storage accounts without diagnostic/audit logging to Log Analytics."""
    storage = idx.get("azure-storage-security", [])
    diag = idx.get("azure-diagnostic-settings", [])
    resources_with_diag = {
        ev.get("Data", ev.get("data", {})).get("resourceId", ev.get("ResourceId", "")).lower()
        for ev in diag
    }
    no_logging: list[dict] = []
    for ev in storage:
        rid = ev.get("ResourceId", ev.get("resource_id", "")).lower()
        if rid and rid not in resources_with_diag:
            data = ev.get("Data", ev.get("data", {}))
            blob_logging = data.get("BlobLoggingEnabled", data.get("blobLoggingEnabled"))
            if blob_logging is False:
                no_logging.append({
                    "Type": "StorageAccount",
                    "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                    "ResourceId": rid,
                })
    if no_logging:
        return [_ds_finding(
            "storage", "no_blob_logging",
            f"{len(no_logging)} storage accounts without blob audit logging",
            "Without diagnostic or storage analytics logging, read/write/delete operations "
            "on blobs are not tracked for audit or anomaly detection (CIS 5.1.2).",
            "medium", no_logging,
            {"Description": "Enable diagnostic settings to send blob logs to Log Analytics.",
             "AzureCLI": (
                 "az monitor diagnostic-settings create -n blob-audit "
                 "--resource <storage-id>/blobServices/default "
                 "--workspace <log-analytics-id> "
                 "--logs '[{\"category\":\"StorageRead\",\"enabled\":true},"
                 "{\"category\":\"StorageWrite\",\"enabled\":true},"
                 "{\"category\":\"StorageDelete\",\"enabled\":true}]'"
             )},
        )]
    return []


def _check_storage_blob_versioning(idx: dict) -> list[dict]:
    """Flag storage accounts without blob versioning enabled."""
    storage = idx.get("azure-storage-security", [])
    no_versioning: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        versioning = data.get("IsBlobVersioningEnabled",
                              data.get("isBlobVersioningEnabled",
                              data.get("is_blob_versioning_enabled")))
        if versioning is not True:
            no_versioning.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_versioning:
        return [_ds_finding(
            "storage", "blob_versioning_disabled",
            f"{len(no_versioning)} storage accounts without blob versioning",
            "Without blob versioning, accidental overwrites or deletions cannot be "
            "recovered from previous versions, reducing data protection and compliance posture.",
            "medium", no_versioning,
            {"Description": "Enable blob versioning for data recovery and audit trails.",
             "AzureCLI": "az storage account blob-service-properties update "
                         "--account-name <account> -g <rg> --enable-versioning true"},
        )]
    return []


def _check_storage_change_feed(idx: dict) -> list[dict]:
    """Flag storage accounts without change feed monitoring."""
    storage = idx.get("azure-storage-security", [])
    no_feed: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        change_feed = data.get("IsChangeFeedEnabled",
                               data.get("isChangeFeedEnabled",
                               data.get("is_change_feed_enabled")))
        if change_feed is not True:
            no_feed.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_feed:
        return [_ds_finding(
            "storage", "change_feed_disabled",
            f"{len(no_feed)} storage accounts without change feed",
            "Change feed provides an ordered, guaranteed log of changes to blobs in a storage account. "
            "Without it, audit requirements for data mutation tracking may not be met.",
            "low", no_feed,
            {"Description": "Enable change feed for blob change tracking and audit compliance.",
             "AzureCLI": "az storage account blob-service-properties update "
                         "--account-name <account> -g <rg> --enable-change-feed true"},
        )]
    return []


