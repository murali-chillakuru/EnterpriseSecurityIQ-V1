"""
PostureIQ Historic Evidence Tracking — blob-backed assessment history.

Stores each assessment run as a timestamped JSON in blob storage under
``history/{tenant_id}/{timestamp}/postureiq-results.json`` and maintains
an index file at ``history/{tenant_id}/_index.json`` for fast enumeration.

Used for:
  - Auditing / change tracking across assessments
  - Trend analysis and compliance drift detection
  - Comparing any two historical runs
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from app.blob_store import _get_container
from app.logger import log

_HISTORY_CONTAINER = os.getenv("HISTORY_STORAGE_CONTAINER", "")  # empty = use reports container


def _container():
    """Return the blob container client (same as reports unless overridden)."""
    return _get_container()


# ── Save ────────────────────────────────────────────────────────

def save_run(tenant_id: str, results: dict[str, Any]) -> str:
    """Persist an assessment run to blob history and update the index.

    Returns the blob prefix (e.g. ``history/<tenant>/<ts>/``).
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = f"history/{tenant_id}/{ts}"
    blob_name = f"{prefix}/postureiq-results.json"

    summary = results.get("summary", {})
    meta = {
        "timestamp": ts,
        "prefix": prefix,
        "score": summary.get("ComplianceScore", 0),
        "total_findings": summary.get("TotalFindings", 0),
        "critical_findings": summary.get("CriticalFindings", 0),
        "frameworks": summary.get("Frameworks", []),
    }

    container = _container()
    try:
        # Upload full results
        container.upload_blob(
            name=blob_name,
            data=json.dumps(results, default=str).encode("utf-8"),
            overwrite=True,
        )
        log.info("History saved: %s", blob_name)

        # Update index
        _update_index(container, tenant_id, meta)

        return prefix
    except Exception as exc:
        log.warning("History save failed: %s", exc)
        return ""


def _update_index(container, tenant_id: str, meta: dict) -> None:
    """Append to the tenant's _index.json (create if missing)."""
    index_blob = f"history/{tenant_id}/_index.json"
    entries: list[dict] = []

    try:
        blob = container.get_blob_client(index_blob)
        data = blob.download_blob().readall()
        entries = json.loads(data)
    except Exception:
        pass  # index doesn't exist yet

    entries.append(meta)

    # Keep last 500 entries
    entries = entries[-500:]

    container.upload_blob(
        name=index_blob,
        data=json.dumps(entries, default=str).encode("utf-8"),
        overwrite=True,
    )
    log.info("History index updated: %d entries for tenant %s", len(entries), tenant_id)


# ── List ────────────────────────────────────────────────────────

def list_runs(tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return metadata for the most recent *limit* runs (newest first)."""
    index_blob = f"history/{tenant_id}/_index.json"
    try:
        container = _container()
        blob = container.get_blob_client(index_blob)
        data = blob.download_blob().readall()
        entries: list[dict] = json.loads(data)
        return list(reversed(entries[-limit:]))
    except Exception as exc:
        log.debug("History list failed: %s", exc)
        return []


# ── Load ────────────────────────────────────────────────────────

def load_run(tenant_id: str, timestamp: str) -> dict[str, Any] | None:
    """Load full results for a specific run by timestamp."""
    blob_name = f"history/{tenant_id}/{timestamp}/postureiq-results.json"
    try:
        container = _container()
        blob = container.get_blob_client(blob_name)
        data = blob.download_blob().readall()
        return json.loads(data)
    except Exception as exc:
        log.debug("History load failed for %s: %s", blob_name, exc)
        return None


# ── Query ───────────────────────────────────────────────────────

def query_history(
    tenant_id: str,
    last_n: int = 10,
    min_score: float | None = None,
    max_score: float | None = None,
) -> list[dict[str, Any]]:
    """Query run history with optional score filters.

    Returns lightweight metadata (no full results) for matching runs.
    """
    runs = list_runs(tenant_id, limit=last_n * 3)  # fetch extra to allow filtering
    filtered = []
    for r in runs:
        score = r.get("score", 0)
        if min_score is not None and score < min_score:
            continue
        if max_score is not None and score > max_score:
            continue
        filtered.append(r)
        if len(filtered) >= last_n:
            break
    return filtered


def get_score_trend(tenant_id: str, last_n: int = 20) -> list[dict[str, Any]]:
    """Return score trend data for charting — timestamp + score pairs."""
    runs = list_runs(tenant_id, limit=last_n)
    return [{"timestamp": r["timestamp"], "score": r.get("score", 0),
             "findings": r.get("total_findings", 0)} for r in reversed(runs)]
