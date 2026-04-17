"""
Internationalization (i18n) Support
Loads locale-specific strings from JSON files for report labels and messages.
"""

from __future__ import annotations
import json, pathlib
from typing import Any
from app.logger import log

_DEFAULT_LOCALE = "en"
_LOCALE_DIR = pathlib.Path(__file__).parent / "locales"
_strings: dict[str, str] = {}
_current_locale: str = _DEFAULT_LOCALE


def load_locale(locale: str = "en") -> None:
    """Load strings for the given locale.  Falls back to English."""
    global _strings, _current_locale
    _current_locale = locale
    path = _LOCALE_DIR / f"{locale}.json"
    if not path.is_file():
        if locale != _DEFAULT_LOCALE:
            log.warning("Locale '%s' not found, falling back to 'en'", locale)
            path = _LOCALE_DIR / f"{_DEFAULT_LOCALE}.json"
        if not path.is_file():
            _strings = _default_strings()
            return
    try:
        _strings = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        _strings = _default_strings()


def t(key: str, **kwargs: Any) -> str:
    """Translate a key, with optional format substitution."""
    template = _strings.get(key, key)
    try:
        return template.format(**kwargs) if kwargs else template
    except (KeyError, IndexError):
        return template


def _default_strings() -> dict[str, str]:
    """Built-in English fallback strings."""
    return {
        "report.title": "EnterpriseSecurityIQ Compliance Report",
        "report.executive_summary": "Executive Summary",
        "report.score": "Compliance Score",
        "report.total_controls": "Total Controls",
        "report.compliant": "Compliant",
        "report.non_compliant": "Non-Compliant",
        "report.not_assessed": "Not Assessed",
        "report.findings": "Findings",
        "report.missing_evidence": "Missing Evidence",
        "report.domain_scores": "Domain Scores",
        "report.framework_results": "Framework Results",
        "report.generated_at": "Generated at {timestamp}",
        "report.severity.critical": "Critical",
        "report.severity.high": "High",
        "report.severity.medium": "Medium",
        "report.severity.low": "Low",
        "status.compliant": "Compliant",
        "status.non_compliant": "Non-Compliant",
        "status.not_assessed": "Not Assessed",
    }


# Auto-load default locale on import
load_locale(_DEFAULT_LOCALE)
