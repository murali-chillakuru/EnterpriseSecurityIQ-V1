"""
Data Exports — CSV and JSON
Produces structured data exports for control results, findings,
missing evidence, and raw evidence inventory.
"""

from __future__ import annotations
import csv
import json
import pathlib
from typing import Any
from app.logger import log


def export_data_files(
    results: dict[str, Any],
    evidence: list[dict],
    output_dir: str = "output",
    access_denied: list[dict] | None = None,
) -> list[str]:
    """Export compliance-data.json (combined report data for delta/CI). Returns list of created file paths."""
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    created: list[str] = []

    # Full JSON report (combined) — used by delta/comparison mode and CI/CD pipelines
    summary_report = {
        "summary": results.get("summary", {}),
        "control_results": results.get("control_results", []),
        "findings": results.get("findings", []),
        "missing_evidence": results.get("missing_evidence", []),
        "access_denied": access_denied or [],
    }
    created.append(_write_json(out / "compliance-data.json", summary_report))

    log.info("Data exports: %d files in %s", len(created), out)
    return created


def save_raw_evidence(evidence: list[dict], output_dir: str) -> str:
    """Save raw evidence to raw/ subdirectory as JSON files grouped by evidence type."""
    raw_dir = pathlib.Path(output_dir) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    by_type: dict[str, list[dict]] = {}
    for e in evidence:
        etype = e.get("EvidenceType") or e.get("evidence_type", "unknown")
        by_type.setdefault(etype, []).append(e)

    for etype, records in sorted(by_type.items()):
        safe_name = etype.replace("/", "-").replace("\\", "-")
        path = raw_dir / f"{safe_name}.json"
        records.sort(key=lambda r: r.get("ResourceId", ""))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, default=str, sort_keys=True)

    log.info("Raw evidence: %d types, %d records in %s", len(by_type), len(evidence), raw_dir)
    return str(raw_dir)


def _write_csv(path: pathlib.Path, rows: list[dict], fields: list[str]) -> str:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return str(path)


def _write_json(path: pathlib.Path, data: Any) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, sort_keys=True)
    return str(path)
