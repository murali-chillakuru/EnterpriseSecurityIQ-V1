"""
EnterpriseSecurityIQ — Data Models
Mirrors the PowerShell Models.ps1 (ResourceContext, EvidenceRecord, FindingRecord, etc.)
"""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Namespace UUID for deterministic (UUID5) IDs across all models.
ENTERPRISESECURITYIQ_NS = uuid.UUID("c0a80164-dead-beef-cafe-000000000001")


def deterministic_id(*parts: str) -> str:
    """Generate a deterministic UUID5 from one or more string parts."""
    return str(uuid.uuid5(ENTERPRISESECURITYIQ_NS, "|".join(str(p) for p in parts)))


# ── Enums ────────────────────────────────────────────────────────────────

class Source(str, Enum):
    AZURE = "Azure"
    ENTRA = "Entra"


class Status(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"
    MISSING_EVIDENCE = "missing_evidence"
    PARTIAL = "partial"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ── Helpers ──────────────────────────────────────────────────────────────

def _to_pascal(name: str) -> str:
    """Convert snake_case to PascalCase."""
    return "".join(word.capitalize() for word in name.split("_"))


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass
class ResourceContext:
    resource_id: str = ""
    resource_name: str = ""
    resource_type: str = ""
    subscription_id: str = ""
    subscription_name: str = ""
    resource_group: str = ""
    location: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    source: str = Source.AZURE

    def to_dict(self) -> dict:
        return {_to_pascal(k): (v.value if isinstance(v, Enum) else v)
                for k, v in self.__dict__.items()}


@dataclass
class EvidenceRecord:
    source: str
    collector: str
    evidence_type: str
    description: str
    data: dict[str, Any]
    evidence_id: str = ""
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resource_id: str = ""
    resource_type: str = ""
    raw_reference: Any = None
    context: ResourceContext | None = None

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = deterministic_id(
                "evidence", self.source, self.collector,
                self.evidence_type, self.resource_id,
            )

    def to_dict(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if k == "context":
                continue
            d[_to_pascal(k)] = v.value if isinstance(v, Enum) else v
        if self.context:
            d["Context"] = self.context.to_dict()
        return d


@dataclass
class FindingRecord:
    control_id: str
    framework: str
    control_title: str
    status: str
    severity: str
    domain: str
    description: str = ""
    rationale: str = ""
    recommendation: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    supporting_evidence: list[dict] = field(default_factory=list)
    resource_id: str = ""
    resource_type: str = ""
    finding_id: str = ""
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = deterministic_id(
                "finding", self.control_id, self.framework,
                self.domain, self.description, self.resource_id,
            )

    def to_dict(self) -> dict:
        return {_to_pascal(k): (v.value if isinstance(v, Enum) else v)
                for k, v in self.__dict__.items()}


@dataclass
class ComplianceControlResult:
    control_id: str
    framework: str
    control_title: str
    domain: str
    overall_status: str = Status.NOT_ASSESSED
    compliant_count: int = 0
    non_compliant_count: int = 0
    not_assessed_count: int = 0
    missing_evidence_count: int = 0
    findings: list[FindingRecord] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if k == "findings":
                continue
            d[_to_pascal(k)] = v.value if isinstance(v, Enum) else v
        d["Findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class MissingEvidenceRecord:
    control_id: str
    framework: str
    control_title: str
    reason: str
    collector: str = ""
    domain: str = ""
    recommendation: str = ""
    record_id: str = ""
    recorded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if not self.record_id:
            self.record_id = deterministic_id(
                "missing", self.control_id, self.framework, self.reason,
            )

    def to_dict(self) -> dict:
        return {_to_pascal(k): (v.value if isinstance(v, Enum) else v)
                for k, v in self.__dict__.items()}


@dataclass
class CollectorResult:
    collector: str
    source: str
    success: bool
    data: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    duration_seconds: float = 0.0
    record_count: int = 0
    access_denied: bool = False
    access_denied_apis: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {_to_pascal(k): (v.value if isinstance(v, Enum) else v)
                for k, v in self.__dict__.items()}


@dataclass
class AssessmentSummary:
    assessment_id: str = ""
    tenant_id: str = ""
    tenant_name: str = ""
    assessor: str = ""
    started_at: str = ""
    completed_at: str = ""
    frameworks: list[str] = field(default_factory=list)
    total_controls: int = 0
    compliant: int = 0
    non_compliant: int = 0
    not_assessed: int = 0
    missing_evidence: int = 0
    compliance_percentage: float = 0.0
    domain_summaries: dict[str, dict] = field(default_factory=dict)
    framework_summaries: dict[str, dict] = field(default_factory=dict)
    evidence_count: int = 0
    collector_results: list[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.assessment_id:
            self.assessment_id = deterministic_id(
                "assessment", self.tenant_id, ",".join(self.frameworks),
            )

    def to_dict(self) -> dict:
        return {_to_pascal(k): (v.value if isinstance(v, Enum) else v)
                for k, v in self.__dict__.items()}


@dataclass
class CheckpointState:
    assessment_id: str
    completed_collectors: list[str] = field(default_factory=list)
    failed_collectors: list[str] = field(default_factory=list)
    evidence_file: str = ""
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {_to_pascal(k): (v.value if isinstance(v, Enum) else v)
                for k, v in self.__dict__.items()}
