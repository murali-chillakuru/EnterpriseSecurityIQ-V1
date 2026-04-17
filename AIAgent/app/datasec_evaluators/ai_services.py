"""
Data Security — AI Services Security evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_ai_services_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Azure AI/Cognitive Services security posture beyond network isolation."""
    findings: list[dict] = []
    findings.extend(_check_ai_key_auth_enabled(evidence_index))
    findings.extend(_check_ai_no_managed_identity(evidence_index))
    findings.extend(_check_ai_no_cmk(evidence_index))
    return findings


def _check_ai_key_auth_enabled(idx: dict) -> list[dict]:
    """Flag AI Services accounts that allow key-based authentication."""
    accounts = idx.get("azure-cognitive-account", [])
    key_auth: list[dict] = []
    for ev in accounts:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        disable_local = props.get("disableLocalAuth",
                       props.get("DisableLocalAuth", False))
        if not disable_local:
            key_auth.append({
                "Type": "CognitiveServicesAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if key_auth:
        return [_ds_finding(
            "ai_services", "ai_key_auth_enabled",
            f"{len(key_auth)} AI Services accounts allow key-based authentication",
            "Key-based authentication uses static shared secrets that cannot be "
            "scoped, rotated automatically, or audited per-caller. Disable local "
            "auth and use Azure AD / managed identity instead.",
            "high", key_auth,
            {"Description": "Disable local (key) authentication on AI Services.",
             "AzureCLI": "az cognitiveservices account update -n <name> -g <rg> "
                         "--custom-domain <domain> --disable-local-auth true"},
        )]
    return []


def _check_ai_no_managed_identity(idx: dict) -> list[dict]:
    """Flag AI Services accounts without a managed identity assigned."""
    accounts = idx.get("azure-cognitive-account", [])
    no_mi: list[dict] = []
    for ev in accounts:
        data = ev.get("Data", ev.get("data", {}))
        identity = data.get("identity", {})
        id_type = ""
        if isinstance(identity, dict):
            id_type = identity.get("type", identity.get("Type", "")).lower()
        has_mi = id_type in ("systemassigned", "userassigned",
                             "systemassigned,userassigned",
                             "systemassigned, userassigned")
        if not has_mi:
            no_mi.append({
                "Type": "CognitiveServicesAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_mi:
        return [_ds_finding(
            "ai_services", "ai_no_managed_identity",
            f"{len(no_mi)} AI Services accounts without managed identity",
            "Without a managed identity, AI services rely on connection strings "
            "and API keys for downstream access, increasing credential exposure risk.",
            "medium", no_mi,
            {"Description": "Enable system-assigned managed identity on AI Services.",
             "AzureCLI": "az cognitiveservices account identity assign -n <name> -g <rg>"},
        )]
    return []


def _check_ai_no_cmk(idx: dict) -> list[dict]:
    """Flag AI Services accounts not using customer-managed keys."""
    accounts = idx.get("azure-cognitive-account", [])
    no_cmk: list[dict] = []
    for ev in accounts:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        encryption = props.get("encryption", props.get("Encryption", {}))
        key_source = ""
        if isinstance(encryption, dict):
            key_source = encryption.get("keySource",
                        encryption.get("KeySource", "")).lower()
        if key_source != "microsoft.keyvault":
            no_cmk.append({
                "Type": "CognitiveServicesAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_cmk:
        return [_ds_finding(
            "ai_services", "ai_no_cmk",
            f"{len(no_cmk)} AI Services accounts without customer-managed key encryption",
            "AI Services store custom models, training data, and inference logs. "
            "Without CMK, Microsoft manages the encryption keys, limiting "
            "organizational control over data-at-rest protection.",
            "medium", no_cmk,
            {"Description": "Configure customer-managed key encryption for AI Services.",
             "AzureCLI": "az cognitiveservices account update -n <name> -g <rg> "
                         "--encryption-key-source Microsoft.KeyVault "
                         "--encryption-key-name <key> --encryption-key-vault <vault-uri>"},
        )]
    return []


# ── Enhanced Data Factory / Synapse ──────────────────────────────────

