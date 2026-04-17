"""
JSON Report Generator
Structured JSON output of the full assessment.
"""

from __future__ import annotations
import json, pathlib
from datetime import datetime, timezone
from typing import Any
from app.logger import log


def generate_json_report(
    results: dict[str, Any],
    tenant_info: dict | None = None,
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> str:
    """Generate a JSON report and return the file path."""
    if not results:
        raise ValueError("Cannot generate JSON report: results dict is empty")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"PostureIQ-Report-{ts}.json"

    report = {
        "metadata": {
            "frameworks": results.get("summary", {}).get("Frameworks", ["FedRAMP"]),
            "generated": datetime.now(timezone.utc).isoformat(),
            "generator": "PostureIQ AI Agent v1.0",
            "tenant": tenant_info or {},
        },
        "summary": results.get("summary", {}),
        "control_results": results.get("control_results", []),
        "findings": results.get("findings", []),
        "missing_evidence": results.get("missing_evidence", []),
        "access_denied": access_denied or [],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    log.info("JSON report: %s", path)
    return str(path)
