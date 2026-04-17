"""Re-export Copilot Readiness report generators from their canonical location."""

from app.reports.copilot_readiness_report import generate_copilot_readiness_report  # noqa: F401

__all__ = ["generate_copilot_readiness_report"]
