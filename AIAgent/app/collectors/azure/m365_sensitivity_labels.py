"""
M365 Sensitivity Labels & Label Policies Collector
Collects: sensitivity label definitions, label policies, auto-labeling rules,
label usage summary, DLP policies with sensitivity-label conditions.

Uses Microsoft Graph API (primarily informationProtection endpoints).
"""

from __future__ import annotations
from app.models import Source
from app.collectors.base import run_collector, paginate_graph, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="m365_sensitivity_labels", plane="control", source="azure", priority=182)
async def collect_m365_sensitivity_labels(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:  # noqa: ARG001
    """Collect M365 sensitivity label definitions, policies, and usage data."""

    async def _collect():
        evidence: list[dict] = []
        graph = creds.get_graph_client()
        beta = creds.get_graph_beta_client()

        # ── 1. Sensitivity label definitions ─────────────────────────
        labels = []
        labels_collected = False
        try:
            labels = await paginate_graph(
                beta.security.information_protection.sensitivity_labels
            )
            labels_collected = True
        except Exception as exc:
            log.warning("  [M365Labels] Beta sensitivity labels API failed: %s", exc)

        # Fallback: delegated /me/informationProtection/policy/labels
        if not labels_collected:
            try:
                labels = await paginate_graph(
                    graph.me.information_protection.policy.labels
                )
                labels_collected = True
                log.info("  [M365Labels] Used delegated /me fallback for labels")
            except Exception as exc2:
                log.warning("  [M365Labels] Delegated label fallback also failed: %s", exc2)

        if labels_collected:
            parent_labels = []
            sub_labels = []

            for label in labels:
                lid = getattr(label, "id", "") or ""
                name = getattr(label, "name", "") or ""
                desc = getattr(label, "description", "") or ""
                color = getattr(label, "color", "") or ""
                is_active = getattr(label, "is_active", True)
                parent_id = getattr(label, "parent", None)
                parent_id = getattr(parent_id, "id", "") if parent_id else ""
                tooltip = getattr(label, "tooltip", "") or ""

                lbl_data = {
                    "LabelId": lid,
                    "Name": name,
                    "Description": desc,
                    "Color": color,
                    "IsActive": is_active,
                    "ParentLabelId": parent_id,
                    "IsSubLabel": bool(parent_id),
                    "Tooltip": tooltip,
                }

                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="M365SensitivityLabels",
                    evidence_type="m365-sensitivity-label-definition",
                    description=f"Sensitivity label: {name}",
                    data=lbl_data,
                    resource_id=lid, resource_type="SensitivityLabel",
                ))

                if parent_id:
                    sub_labels.append(lbl_data)
                else:
                    parent_labels.append(lbl_data)

            # Summary evidence
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="M365SensitivityLabels",
                evidence_type="m365-label-summary",
                description="Sensitivity label inventory summary",
                data={
                    "TotalLabels": len(labels),
                    "ParentLabels": len(parent_labels),
                    "SubLabels": len(sub_labels),
                    "ActiveLabels": sum(1 for l in labels if getattr(l, "is_active", True)),
                    "InactiveLabels": sum(1 for l in labels if not getattr(l, "is_active", True)),
                },
                resource_id="m365-label-summary", resource_type="LabelSummary",
            ))
            log.info("  [M365Labels] Collected %d sensitivity labels", len(labels))
        else:
            # Both endpoints failed — emit a collection warning so the engine
            # can distinguish "no labels exist" from "API inaccessible".
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="M365SensitivityLabels",
                evidence_type="m365-label-collection-warning",
                description="Sensitivity label APIs are inaccessible — cannot determine label status",
                data={
                    "Warning": "LabelAPIInaccessible",
                    "Impact": "Cannot determine whether sensitivity labels are defined. "
                              "The tenant may have labels but the current user lacks permission "
                              "or the required license (E5 / Information Protection P2) is missing.",
                    "Recommendation": "Assign the Information Protection Reader role or "
                                      "run with a service principal that has InformationProtection.Read.All.",
                },
                resource_id="m365-label-api-warning", resource_type="CollectionWarning",
            ))
            log.warning("  [M365Labels] All label APIs failed — emitting collection warning")

        # ── 2. Label policies (beta) ─────────────────────────────────
        try:
            policy_settings = await beta.security.information_protection.label_policy_settings.get()
            has_mandatory = False
            has_default = False
            has_auto = False
            if policy_settings:
                has_mandatory = getattr(policy_settings, "is_mandatory_labeling_enabled", False) or False
                has_default = bool(getattr(policy_settings, "default_label_id", None))
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="M365SensitivityLabels",
                evidence_type="m365-label-policy-summary",
                description="Label policy configuration summary",
                data={
                    "TotalPolicies": 1 if policy_settings else 0,
                    "MandatoryLabelingPolicies": 1 if has_mandatory else 0,
                    "DefaultLabelPolicies": 1 if has_default else 0,
                    "AutoLabelingPolicies": 0,
                    "HasMandatoryLabeling": has_mandatory,
                    "HasDefaultLabel": has_default,
                    "HasAutoLabeling": has_auto,
                },
                resource_id="m365-label-policy-summary", resource_type="LabelPolicySummary",
            ))
            log.info("  [M365Labels] Collected label policy summary")
        except Exception:
            pass

        # Fallback: infer policy info from label objects themselves
        try:
            if not any(e.get("EvidenceType") == "m365-label-policy-summary" for e in evidence):
                # Use labels already collected to build a best-effort policy summary
                auto_label_count = sum(
                    1 for lbl in labels
                    if getattr(lbl, "auto_labeling", None)
                )
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="M365SensitivityLabels",
                    evidence_type="m365-label-policy-summary",
                    description="Label policy configuration summary (inferred from labels)",
                    data={
                        "TotalPolicies": 0,
                        "MandatoryLabelingPolicies": 0,
                        "DefaultLabelPolicies": 0,
                        "AutoLabelingPolicies": auto_label_count,
                        "HasMandatoryLabeling": False,
                        "HasDefaultLabel": False,
                        "HasAutoLabeling": auto_label_count > 0,
                    },
                    resource_id="m365-label-policy-summary", resource_type="LabelPolicySummary",
                ))
                log.info("  [M365Labels] Label policy summary inferred from labels")
        except Exception as exc:
            log.warning("  [M365Labels] Label policies failed: %s", exc)

        # ── 3. DLP label-integration indicator ────────────────────────
        # NOTE: Purview DLP policies are not directly accessible via Graph.
        # We record a placeholder so the engine can flag the gap explicitly.
        try:
            evidence.append(make_evidence(
                source=Source.ENTRA, collector="M365SensitivityLabels",
                evidence_type="m365-dlp-label-integration",
                description="DLP policy assessment (Graph API limitation)",
                data={
                    "DLPPoliciesWithLabelConditions": 0,
                    "HasLabelBasedDLP": False,
                    "Note": "Purview DLP policies are not accessible via Microsoft Graph. "
                            "Use Security & Compliance PowerShell for full DLP assessment.",
                },
                resource_id="m365-dlp-label-integration", resource_type="DLPLabelIntegration",
            ))
        except Exception as exc:
            log.debug("  [M365Labels] DLP label integration check failed: %s", exc)

        log.info(
            "  [M365Labels] Collection complete: %d total evidence records",
            len(evidence),
        )
        return evidence

    return (await run_collector("M365SensitivityLabels", Source.ENTRA, _collect)).data
