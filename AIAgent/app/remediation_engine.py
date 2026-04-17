"""
EnterpriseSecurityIQ — Remediation Engine
Automated remediation suggestions with ARM/CLI commands for non-compliant findings.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RemediationStep:
    """A single actionable remediation step."""
    step_number: int
    title: str
    description: str
    az_cli_command: str = ""
    arm_template_snippet: dict[str, Any] | None = None
    powershell_command: str = ""
    risk_level: str = "low"          # low | medium | high
    requires_downtime: bool = False
    estimated_impact: str = ""


@dataclass
class RemediationPlan:
    """Full remediation plan for a finding."""
    finding_id: str
    control_id: str
    framework: str
    resource_id: str
    resource_type: str
    severity: str
    title: str
    steps: list[RemediationStep] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    rollback_steps: list[str] = field(default_factory=list)
    estimated_effort: str = ""       # e.g. "5 minutes", "1 hour"

    def to_dict(self) -> dict:
        return {
            "FindingId": self.finding_id,
            "ControlId": self.control_id,
            "Framework": self.framework,
            "ResourceId": self.resource_id,
            "ResourceType": self.resource_type,
            "Severity": self.severity,
            "Title": self.title,
            "Prerequisites": self.prerequisites,
            "Steps": [
                {
                    "StepNumber": s.step_number,
                    "Title": s.title,
                    "Description": s.description,
                    "AzCliCommand": s.az_cli_command,
                    "ArmTemplateSnippet": s.arm_template_snippet,
                    "PowerShellCommand": s.powershell_command,
                    "RiskLevel": s.risk_level,
                    "RequiresDowntime": s.requires_downtime,
                    "EstimatedImpact": s.estimated_impact,
                }
                for s in self.steps
            ],
            "RollbackSteps": self.rollback_steps,
            "EstimatedEffort": self.estimated_effort,
        }


# ── Remediation rule registry ────────────────────────────────────────────

_REMEDIATION_RULES: dict[str, callable] = {}


def _rule(evaluation_logic: str):
    """Decorator to register a remediation rule by evaluation_logic key."""
    def decorator(fn):
        _REMEDIATION_RULES[evaluation_logic] = fn
        return fn
    return decorator


def generate_remediation(finding: dict, evidence_index: dict[str, list[dict]]) -> RemediationPlan | None:
    """
    Generate a remediation plan for a non-compliant finding.
    Returns None if no rule matches or finding is compliant.
    """
    status = finding.get("Status", "")
    if status not in ("non_compliant", "partial"):
        return None

    eval_logic = finding.get("EvaluationLogic", "")
    rule_fn = _REMEDIATION_RULES.get(eval_logic)
    if not rule_fn:
        return None

    return rule_fn(finding, evidence_index)


def generate_remediation_report(findings: list[dict], evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Generate remediation plans for all non-compliant findings."""
    plans = []
    for f in findings:
        plan = generate_remediation(f, evidence_index)
        if plan:
            plans.append(plan.to_dict())
    return plans


# ── Built-in remediation rules ───────────────────────────────────────────

def _extract_resource_id(finding: dict, evidence_index: dict, evidence_type: str) -> str:
    """Helper to get first resource ID from evidence matching a type."""
    for ev in evidence_index.get(evidence_type, []):
        rid = ev.get("Data", {}).get("ResourceId") or ev.get("ResourceId", "")
        if rid:
            return rid
    return finding.get("ResourceId", "")


@_rule("check_encryption_at_rest")
def _remediate_encryption(finding: dict, evidence_index: dict) -> RemediationPlan:
    resource_id = _extract_resource_id(finding, evidence_index, "azure-storage-account")
    rg = resource_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in resource_id else "<rg>"
    name = resource_id.rsplit("/", 1)[-1] if resource_id else "<storage-account>"

    return RemediationPlan(
        finding_id=finding.get("FindingId", ""),
        control_id=finding.get("ControlId", ""),
        framework=finding.get("Framework", ""),
        resource_id=resource_id,
        resource_type="StorageAccount",
        severity=finding.get("Severity", "high"),
        title="Enable encryption at rest with customer-managed keys",
        prerequisites=["Azure Key Vault with key created", "Storage account managed identity"],
        steps=[
            RemediationStep(
                step_number=1,
                title="Enable infrastructure encryption",
                description="Enable double encryption (infrastructure + service) for storage account.",
                az_cli_command=f"az storage account update --name {name} --resource-group {rg} --require-infrastructure-encryption true",
                risk_level="low",
            ),
        ],
        rollback_steps=["Infrastructure encryption cannot be disabled after enabling — plan accordingly."],
        estimated_effort="10 minutes",
    )


@_rule("check_tls_config")
def _remediate_tls(finding: dict, evidence_index: dict) -> RemediationPlan:
    resource_id = _extract_resource_id(finding, evidence_index, "azure-storage-account")
    rg = resource_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in resource_id else "<rg>"
    name = resource_id.rsplit("/", 1)[-1] if resource_id else "<storage-account>"

    return RemediationPlan(
        finding_id=finding.get("FindingId", ""),
        control_id=finding.get("ControlId", ""),
        framework=finding.get("Framework", ""),
        resource_id=resource_id,
        resource_type="StorageAccount",
        severity=finding.get("Severity", "high"),
        title="Enforce minimum TLS 1.2",
        steps=[
            RemediationStep(
                step_number=1,
                title="Set minimum TLS version to 1.2",
                description="Update storage account to require TLS 1.2 for all connections.",
                az_cli_command=f"az storage account update --name {name} --resource-group {rg} --min-tls-version TLS1_2",
                risk_level="medium",
                estimated_impact="Clients using TLS < 1.2 will be unable to connect.",
            ),
        ],
        rollback_steps=[f"az storage account update --name {name} --resource-group {rg} --min-tls-version TLS1_0"],
        estimated_effort="5 minutes",
    )


@_rule("check_network_security")
def _remediate_network_security(finding: dict, evidence_index: dict) -> RemediationPlan:
    resource_id = _extract_resource_id(finding, evidence_index, "azure-nsg")
    rg = resource_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in resource_id else "<rg>"

    return RemediationPlan(
        finding_id=finding.get("FindingId", ""),
        control_id=finding.get("ControlId", ""),
        framework=finding.get("Framework", ""),
        resource_id=resource_id,
        resource_type="NetworkSecurityGroup",
        severity=finding.get("Severity", "high"),
        title="Restrict overly permissive NSG rules",
        steps=[
            RemediationStep(
                step_number=1,
                title="Review and restrict inbound Any rules",
                description="Identify NSG rules allowing inbound traffic from Any source on sensitive ports (22, 3389, 445).",
                az_cli_command=f"az network nsg rule list --resource-group {rg} --nsg-name <nsg-name> --query \"[?sourceAddressPrefix=='*']\"",
                risk_level="high",
                requires_downtime=False,
                estimated_impact="May block legitimate traffic if source ranges are not correctly scoped.",
            ),
            RemediationStep(
                step_number=2,
                title="Update rule to restrict source",
                description="Replace wildcard source with specific IP ranges or service tags.",
                az_cli_command=f"az network nsg rule update --resource-group {rg} --nsg-name <nsg-name> --name <rule-name> --source-address-prefixes <allowed-cidr>",
                risk_level="high",
                requires_downtime=False,
            ),
        ],
        rollback_steps=["Revert NSG rule source to previous value if connectivity issues arise."],
        estimated_effort="15 minutes per rule",
    )


@_rule("check_mfa_enforcement")
def _remediate_mfa(finding: dict, evidence_index: dict) -> RemediationPlan:
    return RemediationPlan(
        finding_id=finding.get("FindingId", ""),
        control_id=finding.get("ControlId", ""),
        framework=finding.get("Framework", ""),
        resource_id="",
        resource_type="ConditionalAccessPolicy",
        severity=finding.get("Severity", "critical"),
        title="Enforce MFA via Conditional Access",
        prerequisites=["Entra ID P1/P2 license", "Security Defaults disabled if using CA policies"],
        steps=[
            RemediationStep(
                step_number=1,
                title="Create Conditional Access policy requiring MFA",
                description="Create a CA policy targeting all users requiring MFA for all cloud apps.",
                az_cli_command="az rest --method POST --uri https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies --body @ca-mfa-policy.json",
                risk_level="medium",
                estimated_impact="All users will be prompted for MFA; ensure users have registered MFA methods.",
            ),
        ],
        rollback_steps=["Disable or delete the Conditional Access policy."],
        estimated_effort="30 minutes",
    )


@_rule("check_diagnostic_settings")
def _remediate_diagnostics(finding: dict, evidence_index: dict) -> RemediationPlan:
    resource_id = finding.get("ResourceId", "")
    name = resource_id.rsplit("/", 1)[-1] if resource_id else "<resource>"

    return RemediationPlan(
        finding_id=finding.get("FindingId", ""),
        control_id=finding.get("ControlId", ""),
        framework=finding.get("Framework", ""),
        resource_id=resource_id,
        resource_type="DiagnosticSettings",
        severity=finding.get("Severity", "medium"),
        title="Enable diagnostic logging",
        steps=[
            RemediationStep(
                step_number=1,
                title="Create diagnostic setting",
                description=f"Enable diagnostic logs for {name} to Log Analytics workspace.",
                az_cli_command=f"az monitor diagnostic-settings create --resource {resource_id} --name enterprisesecurityiq-diag --workspace <la-workspace-id> --logs '[{{\"category\":\"allLogs\",\"enabled\":true}}]'",
                risk_level="low",
            ),
        ],
        rollback_steps=[f"az monitor diagnostic-settings delete --resource {resource_id} --name enterprisesecurityiq-diag"],
        estimated_effort="5 minutes",
    )


@_rule("check_database_config_security")
def _remediate_database_security(finding: dict, evidence_index: dict) -> RemediationPlan:
    resource_id = _extract_resource_id(finding, evidence_index, "azure-sql-server")
    rg = resource_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in resource_id else "<rg>"
    name = resource_id.rsplit("/", 1)[-1] if resource_id else "<sql-server>"

    return RemediationPlan(
        finding_id=finding.get("FindingId", ""),
        control_id=finding.get("ControlId", ""),
        framework=finding.get("Framework", ""),
        resource_id=resource_id,
        resource_type="SqlServer",
        severity=finding.get("Severity", "high"),
        title="Harden SQL Server configuration",
        steps=[
            RemediationStep(
                step_number=1,
                title="Enable Azure AD-only authentication",
                description="Disable SQL auth and enforce Azure AD authentication only.",
                az_cli_command=f"az sql server ad-only-auth enable --resource-group {rg} --name {name}",
                risk_level="high",
                requires_downtime=False,
                estimated_impact="Applications using SQL auth will lose access. Update connection strings first.",
            ),
            RemediationStep(
                step_number=2,
                title="Enable auditing",
                description="Enable SQL server auditing to a Log Analytics workspace.",
                az_cli_command=f"az sql server audit-policy update --resource-group {rg} --name {name} --state Enabled --lats Enabled --lawri <la-workspace-resource-id>",
                risk_level="low",
            ),
        ],
        rollback_steps=[f"az sql server ad-only-auth disable --resource-group {rg} --name {name}"],
        estimated_effort="20 minutes",
    )


@_rule("check_key_vault_security")
def _remediate_keyvault(finding: dict, evidence_index: dict) -> RemediationPlan:
    resource_id = _extract_resource_id(finding, evidence_index, "azure-keyvault")
    rg = resource_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in resource_id else "<rg>"
    name = resource_id.rsplit("/", 1)[-1] if resource_id else "<keyvault>"

    return RemediationPlan(
        finding_id=finding.get("FindingId", ""),
        control_id=finding.get("ControlId", ""),
        framework=finding.get("Framework", ""),
        resource_id=resource_id,
        resource_type="KeyVault",
        severity=finding.get("Severity", "high"),
        title="Harden Key Vault configuration",
        steps=[
            RemediationStep(
                step_number=1,
                title="Enable purge protection",
                description="Prevent permanent deletion of Key Vault secrets and keys.",
                az_cli_command=f"az keyvault update --name {name} --resource-group {rg} --enable-purge-protection true",
                risk_level="low",
                estimated_impact="Purge protection cannot be disabled once enabled.",
            ),
            RemediationStep(
                step_number=2,
                title="Enable RBAC authorization",
                description="Switch from access policies to Azure RBAC for Key Vault.",
                az_cli_command=f"az keyvault update --name {name} --resource-group {rg} --enable-rbac-authorization true",
                risk_level="medium",
                estimated_impact="Existing access policies will stop working; ensure RBAC roles are assigned.",
            ),
        ],
        rollback_steps=[f"az keyvault update --name {name} --resource-group {rg} --enable-rbac-authorization false"],
        estimated_effort="15 minutes",
    )
