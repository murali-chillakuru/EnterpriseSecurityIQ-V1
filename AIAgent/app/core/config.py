"""
EnterpriseSecurityIQ — Configuration
Loads assessment config from JSON file, environment variables, or defaults.
"""

from __future__ import annotations
import os
import json
import pathlib
from dataclasses import dataclass, field


@dataclass
class AuthConfig:
    tenant_id: str = ""
    auth_mode: str = "auto"  # auto | serviceprincipal
    subscription_filter: list[str] = field(default_factory=list)


@dataclass
class CollectorConfig:
    azure_enabled: bool = True
    entra_enabled: bool = True
    subscription_filter: list[str] = field(default_factory=list)
    azure_batch_size: int = 8       # Max concurrent Azure collectors
    entra_batch_size: int = 6       # Max concurrent Entra collectors
    collector_timeout: int = 600    # Per-collector timeout in seconds (0=no timeout)
    user_sample_limit: int = 200   # Max users for detail collection (0=all)


@dataclass
class ThresholdConfig:
    """Configurable evaluation thresholds — avoids hardcoded magic numbers in evaluators."""
    # Access domain
    max_subscription_owners: int = 3
    max_privileged_percent: float = 0.20
    max_global_admins: int = 5
    max_subscription_contributors: int = 10
    max_entra_privileged_roles: int = 10

    # Identity domain
    min_mfa_percent: float = 90.0
    max_no_default_mfa_percent: float = 30.0
    max_stale_percent: float = 20.0
    max_stale_guests: int = 10
    max_high_priv_oauth: int = 5
    max_admin_grants: int = 20
    max_not_mfa_registered: int = 10

    # Logging domain
    diagnostic_coverage_target: float = 80.0
    diagnostic_coverage_minimum: float = 50.0

    # Governance domain
    min_policies_for_baseline: int = 5
    min_tagging_percent: float = 80.0
    policy_compliance_target: float = 80.0


@dataclass
class AssessmentConfig:
    name: str = "EnterpriseSecurityIQ Assessment"
    frameworks: list[str] = field(default_factory=lambda: ["FedRAMP"])
    log_level: str = "INFO"
    auth: AuthConfig = field(default_factory=AuthConfig)
    collectors: CollectorConfig = field(default_factory=CollectorConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    output_formats: list[str] = field(default_factory=lambda: ["json", "html"])
    output_dir: str = "output"
    checkpoint_enabled: bool = True
    additional_tenants: list[str] = field(default_factory=list)  # extra tenant IDs for multi-tenant

    @classmethod
    def from_env(cls) -> AssessmentConfig:
        """Build config from environment variables (overridden by config file if present)."""
        cfg = cls()
        # Check for config file first
        config_path = os.getenv("ENTERPRISESECURITYIQ_CONFIG", "")
        if config_path and pathlib.Path(config_path).is_file():
            cfg = cls.from_file(config_path)
        # Environment overrides
        if os.getenv("AZURE_TENANT_ID"):
            cfg.auth.tenant_id = os.getenv("AZURE_TENANT_ID", "")
        if os.getenv("ENTERPRISESECURITYIQ_AUTH_MODE"):
            cfg.auth.auth_mode = os.getenv("ENTERPRISESECURITYIQ_AUTH_MODE", "auto")
        sub_filter = os.getenv("AZURE_SUBSCRIPTION_FILTER", "")
        if sub_filter:
            cfg.collectors.subscription_filter = [s.strip() for s in sub_filter.split(",")]
        fw = os.getenv("ENTERPRISESECURITYIQ_FRAMEWORKS")
        if fw:
            cfg.frameworks = [f.strip() for f in fw.split(",")]
        if os.getenv("ENTERPRISESECURITYIQ_LOG_LEVEL"):
            cfg.log_level = os.getenv("ENTERPRISESECURITYIQ_LOG_LEVEL", "INFO")
        return cfg

    @classmethod
    def from_file(cls, path: str) -> AssessmentConfig:
        """Load config from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = cls()
        cfg.name = data.get("name", cfg.name)
        cfg.frameworks = data.get("frameworks", cfg.frameworks)
        cfg.log_level = data.get("logLevel", cfg.log_level)
        cfg.output_formats = data.get("outputFormats", cfg.output_formats)
        cfg.output_dir = data.get("outputDir", cfg.output_dir)
        cfg.checkpoint_enabled = data.get("checkpointEnabled", cfg.checkpoint_enabled)
        cfg.additional_tenants = data.get("additionalTenants", cfg.additional_tenants)
        # Auth section
        auth = data.get("auth", {})
        if auth:
            cfg.auth.tenant_id = auth.get("tenantId", cfg.auth.tenant_id)
            cfg.auth.auth_mode = auth.get("authMode", cfg.auth.auth_mode)
            cfg.auth.subscription_filter = auth.get("subscriptionFilter", cfg.auth.subscription_filter)
        # Collectors section
        coll = data.get("collectors", {})
        if coll:
            cfg.collectors.azure_enabled = coll.get("azureEnabled", cfg.collectors.azure_enabled)
            cfg.collectors.entra_enabled = coll.get("entraEnabled", cfg.collectors.entra_enabled)
            cfg.collectors.subscription_filter = coll.get("subscriptionFilter", cfg.collectors.subscription_filter)
            cfg.collectors.azure_batch_size = coll.get("azureBatchSize", cfg.collectors.azure_batch_size)
            cfg.collectors.entra_batch_size = coll.get("entraBatchSize", cfg.collectors.entra_batch_size)
            cfg.collectors.collector_timeout = coll.get("collectorTimeout", cfg.collectors.collector_timeout)
            cfg.collectors.user_sample_limit = coll.get("userSampleLimit", cfg.collectors.user_sample_limit)
        # Thresholds section
        th = data.get("thresholds", {})
        if th:
            for fld in ThresholdConfig.__dataclass_fields__:
                if fld in th:
                    setattr(cfg.thresholds, fld, th[fld])
        return cfg
