"""
PostureIQ Core — shared infrastructure used by all assessment engines.

Modules:
    auth        – Authentication (ComplianceCredentials, UserTokenCredential)
    logger      – Structured logging
    config      – Assessment configuration (AssessmentConfig, ThresholdConfig)
    models      – Data models (FindingRecord, EvidenceRecord, Status, Severity, Source, etc.)

Engines depend ONLY on core/ + collectors/ — never on each other.
"""
