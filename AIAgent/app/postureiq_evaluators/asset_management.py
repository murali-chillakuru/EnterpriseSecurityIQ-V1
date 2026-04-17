"""
Asset Management Domain Evaluator
Controls: CM-8, PM-5 (NIST), PCI 2.4, ISO A.5.9, CIS asset management.
Evaluates asset inventory completeness, classification tagging,
authorized software policies, and application inventory.
"""

from __future__ import annotations
from app.models import FindingRecord, Status, Severity
from app.config import ThresholdConfig


def evaluate_asset_management(
    control_id: str, control: dict, evidence: list[dict], evidence_index: dict,
    thresholds: ThresholdConfig | None = None,
) -> list[dict]:
    if thresholds is None:
        thresholds = ThresholdConfig()
    func = control.get("evaluation_logic", "")
    dispatch = {
        "check_asset_inventory": _check_asset_inventory,
        "check_classification_tagging": _check_classification_tagging,
        "check_authorized_software_policy": _check_authorized_software,
        "check_application_inventory": _check_application_inventory,
    }
    return dispatch.get(func, _default)(control_id, control, evidence, evidence_index, thresholds)


def _f(cid, ctrl, status, desc, *, recommendation=None, resource_id="", resource_name="", resource_type="",
       evidence_items=None):
    return FindingRecord(
        control_id=cid, framework=ctrl.get("_framework", ""),
        control_title=ctrl.get("title", ""),
        status=status, severity=Severity(ctrl.get("severity", "high")),
        domain="asset_management", description=desc,
        recommendation=recommendation or ctrl.get("recommendation", ""),
        resource_id=resource_id, resource_type=resource_type,
        supporting_evidence=[{"ResourceId": resource_id, "ResourceName": resource_name,
                              "ResourceType": resource_type}] if resource_name else (evidence_items or []),
    ).to_dict()


def _check_asset_inventory(cid, ctrl, evidence, idx, thresholds=None):
    """Verify resource inventory is comprehensive and discoverable."""
    findings = []
    resources = idx.get("azure-resource", [])
    resource_groups = idx.get("azure-resource-group", [])
    managed_ids = idx.get("azure-managed-identity", [])

    if not resources:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No Azure resource inventory collected.",
                   recommendation="Ensure resource inventory collection is enabled in PostureIQ configuration.")]

    # Inventory completeness: resources in groups
    findings.append(_f(cid, ctrl, Status.COMPLIANT,
                       f"Asset inventory: {len(resources)} resources across {len(resource_groups)} resource groups."))

    # Check for managed identities (identity inventory component)
    if managed_ids:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(managed_ids)} managed identities inventoried."))

    # Resource diversity check — a healthy inventory has multiple resource types
    resource_types = {r.get("Data", {}).get("ResourceType", "").lower() for r in resources}
    if len(resource_types) < 3 and len(resources) > 10:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Low resource type diversity ({len(resource_types)} types for {len(resources)} resources) — inventory may be incomplete.",
                          recommendation="Review resource collection scope to ensure all resource types are discovered."))

    return findings


def _check_classification_tagging(cid, ctrl, evidence, idx, thresholds=None):
    """Verify resources have classification tags for data sensitivity."""
    findings = []
    resources = idx.get("azure-resource", [])
    resource_groups = idx.get("azure-resource-group", [])
    all_items = resources + resource_groups

    if not all_items:
        return [_f(cid, ctrl, Status.COMPLIANT, "No resources to evaluate for classification tagging.")]

    tagged = sum(1 for r in all_items if r.get("Data", {}).get("Tags"))
    pct = (tagged / len(all_items)) * 100 if all_items else 0

    if pct < 50:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Resource tagging {pct:.0f}% (<50%) — data classification is inadequate.",
                          recommendation="Implement mandatory tagging policy with tags: environment, data-classification, owner, cost-center."))
    elif pct < 80:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          f"Resource tagging {pct:.0f}% (50-79%) — data classification needs improvement.",
                          recommendation="Increase tagging coverage to ≥80%. Use Azure Policy to enforce mandatory tags."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"Resource tagging {pct:.0f}% (≥80%) — classification tagging meets threshold."))

    # Check for specific classification tags
    classification_keys = {"data-classification", "dataclassification", "classification",
                           "sensitivity", "data_classification", "confidentiality"}
    classified = sum(1 for r in all_items
                     if any(k.lower() in classification_keys
                            for k in (r.get("Data", {}).get("Tags") or {}).keys()))
    if classified == 0 and len(all_items) > 0:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No resources have data classification tags (e.g., 'data-classification', 'sensitivity').",
                          recommendation="Add data classification tags to identify resources handling sensitive data."))

    return findings


def _check_authorized_software(cid, ctrl, evidence, idx, thresholds=None):
    """Verify policies control authorized resource types and services."""
    findings = []
    policies = idx.get("azure-policy-assignment", [])

    if not policies:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No Azure policies assigned for authorized resource control.",
                   recommendation="Assign 'Allowed resource types' or 'Not allowed resource types' policies.")]

    # Check for resource type restriction policies
    restrict_keywords = ("allowed resource", "not allowed resource", "allowed location",
                         "restrict", "deny", "whitelist", "allowlist")
    restricting = [p for p in policies
                   if any(k in str(p.get("Data", {}).get("DisplayName", "")).lower()
                          for k in restrict_keywords)]

    if not restricting:
        findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                          "No policies restricting resource types or locations found.",
                          recommendation="Deploy 'Allowed resource types' and 'Allowed locations' policies."))
    else:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(restricting)} policies controlling authorized resources/locations."))

    # Initiatives (policy sets) indicate mature governance
    initiatives = [p for p in policies if p.get("Data", {}).get("IsPolicySet")]
    if initiatives:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(initiatives)} policy initiative(s) for comprehensive resource governance."))

    return findings


def _check_application_inventory(cid, ctrl, evidence, idx, thresholds=None):
    """Verify application and service principal inventory is maintained."""
    findings = []
    apps = idx.get("entra-application", [])
    sps = idx.get("entra-service-principal", [])

    if not apps and not sps:
        return [_f(cid, ctrl, Status.NON_COMPLIANT,
                   "No application or service principal inventory available.",
                   recommendation="Enable Entra ID application collection to maintain software asset inventory.")]

    if apps:
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(apps)} Entra ID application registrations inventoried."))

    if sps:
        # Check for service principals without owners (orphaned)
        no_owner_count = sum(1 for sp in sps
                             if not sp.get("Data", {}).get("Owners")
                             and not sp.get("Data", {}).get("OwnerCount"))
        if no_owner_count > 0:
            findings.append(_f(cid, ctrl, Status.NON_COMPLIANT,
                              f"{no_owner_count} service principals without assigned owners.",
                              recommendation="Assign owners to all service principals for accountability and lifecycle management."))
        findings.append(_f(cid, ctrl, Status.COMPLIANT,
                          f"{len(sps)} service principals inventoried."))

    return findings


def _default(cid, ctrl, evidence, idx, thresholds=None):
    return [_f(cid, ctrl, Status.NOT_ASSESSED,
               f"No evaluation logic for asset management control ({len(evidence)} items).")]
