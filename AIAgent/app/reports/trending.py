"""
Compliance Trending
Stores and retrieves historical compliance scores for trend analysis over time.
"""

from __future__ import annotations
import json, pathlib
from datetime import datetime, timezone
from typing import Any
from app.logger import log

_TREND_FILE = "compliance-trend.json"


def record_score(
    results: dict[str, Any],
    output_dir: str = "output",
) -> None:
    """Append the current assessment scores to the trend history file."""
    path = pathlib.Path(output_dir) / _TREND_FILE
    history: list[dict] = []
    if path.is_file():
        try:
            history = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            history = []

    summary = results.get("summary", {})
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "compliance_score": summary.get("ComplianceScore", 0),
        "total_controls": summary.get("TotalControls", 0),
        "compliant": summary.get("Compliant", 0),
        "non_compliant": summary.get("NonCompliant", 0),
        "not_assessed": summary.get("NotAssessed", 0),
        "findings_count": len(results.get("findings", [])),
        "framework_scores": summary.get("framework_scores", {}),
    }
    history.append(entry)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history, indent=2, default=str), encoding="utf-8")
    log.info("Trend data recorded (%d entries)", len(history))


def get_trend(output_dir: str = "output", last_n: int = 30) -> list[dict]:
    """Retrieve the last *last_n* trend entries."""
    path = pathlib.Path(output_dir) / _TREND_FILE
    if not path.is_file():
        return []
    try:
        history = json.loads(path.read_text(encoding="utf-8"))
        return history[-last_n:]
    except (json.JSONDecodeError, OSError):
        return []
