"""Re-export RBAC report generators from their canonical location."""

from app.reports.rbac_report import generate_rbac_report  # noqa: F401

__all__ = ["generate_rbac_report"]
