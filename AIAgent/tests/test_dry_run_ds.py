"""Dry-run test for enhanced data security engine (all 11 categories)."""
import sys, os, tempfile, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# -------------------------------------------------------------------
# Test 1: import all analyzers
# -------------------------------------------------------------------
from app.data_security_engine import (
    analyze_storage_exposure,
    analyze_database_security,
    analyze_cosmosdb_security,
    analyze_postgres_mysql_security,
    analyze_keyvault_hygiene,
    analyze_encryption_posture,
    analyze_data_access_controls,
    analyze_private_endpoints,
    analyze_purview_security,
    analyze_file_sync_security,
    analyze_m365_dlp,
    compute_data_security_scores,
)
print("OK: all 11 analyzers imported")

# -------------------------------------------------------------------
# Test 2: build sample evidence for every category
# -------------------------------------------------------------------
sample_idx = {
    "azure-storage-security": [
        {
            "EvidenceType": "azure-storage-security",
            "ResourceId": "/sub/1/rg/st1",
            "Data": {
                "name": "stor1",
                "type": "microsoft.storage/storageaccounts",
                "supportsHttpsTrafficOnly": True,
                "allowBlobPublicAccess": True,
                "DefaultAction": "Allow",
                "minimumTlsVersion": "TLS1_0",
                "allowSharedKeyAccess": True,
                "requireInfrastructureEncryption": False,
                "encryption": {"keySource": "Microsoft.Storage"},
            },
        },
    ],
    "azure-storage-containers": [
        {
            "EvidenceType": "azure-storage-containers",
            "ResourceId": "/sub/1/rg/st1/c1",
            "Data": {
                "name": "public-container",
                "publicAccess": "blob",
            },
        },
    ],
    "azure-sql-server": [
        {
            "EvidenceType": "azure-sql-server",
            "ResourceId": "/sub/1/rg/sql1",
            "Data": {
                "name": "sql-prod",
                "type": "microsoft.sql/servers",
                "TransparentDataEncryption": False,
                "AuditingEnabled": False,
                "AdvancedThreatProtection": False,
                "FirewallRules": [
                    {"Name": "AllowAll", "StartIpAddress": "0.0.0.0", "EndIpAddress": "255.255.255.255"}
                ],
            },
        },
    ],
    "azure-cosmosdb": [
        {
            "EvidenceType": "azure-cosmosdb",
            "ResourceId": "/sub/1/rg/cosmos1",
            "Data": {
                "name": "cosmos-prod",
                "type": "microsoft.documentdb/databaseaccounts",
                "publicNetworkAccess": "Enabled",
                "ipRules": [],
                "virtualNetworkRules": [],
                "disableLocalAuth": False,
                "backupPolicy": {"type": "Periodic"},
            },
        },
    ],
    "azure-dbforpostgresql": [
        {
            "EvidenceType": "azure-dbforpostgresql",
            "ResourceId": "/sub/1/rg/pg1",
            "Data": {
                "name": "pg-prod",
                "type": "microsoft.dbforpostgresql/flexibleservers",
                "requireSecureTransport": "off",
                "publicNetworkAccess": "Enabled",
                "geoRedundantBackup": "Disabled",
                "FirewallRules": [
                    {"name": "AllowAll", "startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}
                ],
            },
        },
    ],
    "azure-dbformysql": [],
    "azure-keyvault": [
        {
            "EvidenceType": "azure-keyvault",
            "ResourceId": "/sub/1/rg/kv1",
            "Data": {
                "name": "kv-prod",
                "VaultName": "kv-prod",
                "enable_purge_protection": None,
                "enable_rbac_authorization": False,
            },
        },
    ],
    "azure-compute-instance": [
        {
            "EvidenceType": "azure-compute-instance",
            "ResourceId": "/sub/1/rg/vm1",
            "Data": {
                "name": "vm-prod",
                "DiskEncryptionEnabled": False,
            },
        },
    ],
    "azure-resource": [
        {
            "EvidenceType": "azure-resource",
            "ResourceId": "/sub/1/rg/r1",
            "Data": {
                "name": "secret-data",
                "type": "microsoft.storage/storageaccounts",
                "tags": {"DataClassification": "PII"},
            },
        },
    ],
    "azure-role-assignments": [
        {
            "EvidenceType": "azure-role-assignments",
            "ResourceId": "/sub/1/ra1",
            "Data": {
                "roleDefinitionName": "storage blob data owner",
                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                "principalType": "User",
                "principalName": "admin@contoso.com",
            },
        },
    ],
    "azure-defender-plans": [
        {
            "EvidenceType": "azure-defender-plans",
            "ResourceId": "/sub/1/def/storage",
            "Data": {"name": "StorageAccounts", "pricingTier": "Free", "subscriptionId": "0eb177bd"},
        },
        {
            "EvidenceType": "azure-defender-plans",
            "ResourceId": "/sub/1/def/sql",
            "Data": {"name": "SqlServers", "pricingTier": "Free", "subscriptionId": "0eb177bd"},
        },
        {
            "EvidenceType": "azure-defender-plans",
            "ResourceId": "/sub/1/def/kv",
            "Data": {"name": "KeyVaults", "pricingTier": "Free", "subscriptionId": "0eb177bd"},
        },
    ],
    "azure-diagnostic-settings": [],
    "azure-private-endpoint-connections": [],
    "azure-purview": [
        {
            "EvidenceType": "azure-purview",
            "ResourceId": "/sub/1/rg/purview1",
            "Data": {
                "name": "purview-prod",
                "type": "microsoft.purview/accounts",
                "publicNetworkAccess": "Enabled",
                "privateEndpointConnections": [],
                "identity": {"type": "SystemAssigned"},
            },
        },
    ],
    "azure-storagesync": [
        {
            "EvidenceType": "azure-storagesync",
            "ResourceId": "/sub/1/rg/sync1",
            "Data": {
                "name": "sync-onprem",
                "type": "microsoft.storagesync/storagesyncservices",
                "location": "eastus",
                "incomingTrafficPolicy": "AllowAllTraffic",
                "privateEndpointConnections": [],
            },
        },
    ],
    "m365-dlp-policies": [
        {
            "EvidenceType": "m365-dlp-policies",
            "ResourceId": "/m365/dlp/policy1",
            "Data": {
                "name": "PII Detection Policy",
                "state": "disabled",
                "locations": [
                    {"workload": "Exchange"},
                    {"workload": "SharePoint"},
                ],
            },
        },
    ],
}

all_findings = []
all_findings.extend(analyze_storage_exposure(sample_idx))
all_findings.extend(analyze_database_security(sample_idx))
all_findings.extend(analyze_cosmosdb_security(sample_idx))
all_findings.extend(analyze_postgres_mysql_security(sample_idx))
all_findings.extend(analyze_keyvault_hygiene(sample_idx))
all_findings.extend(analyze_encryption_posture(sample_idx))
all_findings.extend(analyze_data_access_controls(sample_idx))
all_findings.extend(analyze_private_endpoints(sample_idx))
all_findings.extend(analyze_purview_security(sample_idx))
all_findings.extend(analyze_file_sync_security(sample_idx))
all_findings.extend(analyze_m365_dlp(sample_idx))

print(f"OK: {len(all_findings)} findings from sample data")
for f in all_findings:
    sev = f["Severity"].upper()
    cat = f["Category"]
    title = f["Title"]
    print(f"  [{sev:12s}] {cat:20s} -> {title}")

scores = compute_data_security_scores(all_findings)
print(f"\nOK: Overall score = {scores['OverallScore']}/100 ({scores['OverallLevel'].upper()})")
cats = list(scores["CategoryScores"].keys())
print(f"    Category scores ({len(cats)}): {cats}")
for c in cats:
    s = scores["CategoryScores"][c]
    print(f"      {c:20s}: {s['Score']}/100 ({s['Level'].upper()})")

# -------------------------------------------------------------------
# Test 3: report generation
# -------------------------------------------------------------------
from app.reports.data_security_report import generate_data_security_report

results = {
    "DataSecurityScores": scores,
    "Findings": all_findings,
    "FindingCount": len(all_findings),
    "SubscriptionCount": 4,
    "EvidenceSource": "sample_test",
    "AssessedAt": "2026-04-01T22:00:00+00:00",
}
tmp = tempfile.mkdtemp()
out = generate_data_security_report(results, tmp)
size_kb = os.path.getsize(out) // 1024
print(f"\nOK: Report generated ({size_kb} KB) at {out}")

# Quick HTML sanity: check that all 8 categories appear
html = open(out, encoding="utf-8").read()
expected_cats = ["storage", "database", "cosmosdb", "pgmysql", "keyvault", "encryption", "data_access", "private_endpoints", "purview", "file_sync", "m365_dlp"]
for ec in expected_cats:
    if ec in html:
        print(f"  HTML contains '{ec}' category card ✓")
    else:
        print(f"  HTML MISSING '{ec}' category card ✗")

print("\n=== DRY-RUN COMPLETE ===")
