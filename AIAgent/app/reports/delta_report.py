"""
Delta / Incremental Report
Compares the current assessment results against a previous run to show
what changed: new findings, resolved findings, status changes, and score drift.
"""

from __future__ import annotations
import json
import pathlib
from typing import Any
from app.logger import log


def find_previous_results(output_dir: str) -> dict | None:
    """Locate the most recent previous results JSON in the output directory."""
    out = pathlib.Path(output_dir)
    if not out.exists():
        return None
    # Find all results JSON files, sorted by name (timestamp-based) descending
    candidates = sorted(out.glob("**/assessment-results*.json"), reverse=True)
    # Skip the first one (current run) if there are at least two
    for cand in candidates:
        try:
            data = json.loads(cand.read_text(encoding="utf-8"))
            if "control_results" in data:
                return data
        except (json.JSONDecodeError, OSError):
            continue
    return None


def compute_delta(
    current: dict[str, Any],
    previous: dict[str, Any],
) -> dict[str, Any]:
    """Compute the differences between current and previous assessment results.

    Returns a dict with:
        - score_change: dict with old/new/delta per framework
        - new_findings: list of findings not in previous run
        - resolved_findings: list of findings in previous but not current
        - status_changes: list of controls whose status changed
        - summary: human-readable summary string
    """
    # Index previous controls by (framework, control_id)
    prev_controls: dict[tuple[str, str], dict] = {}
    for ctrl in previous.get("control_results", []):
        key = (ctrl.get("framework", ""), ctrl.get("control_id", ""))
        prev_controls[key] = ctrl

    curr_controls: dict[tuple[str, str], dict] = {}
    for ctrl in current.get("control_results", []):
        key = (ctrl.get("framework", ""), ctrl.get("control_id", ""))
        curr_controls[key] = ctrl

    # Status changes
    status_changes: list[dict] = []
    for key, ctrl in curr_controls.items():
        prev = prev_controls.get(key)
        if prev and prev.get("status") != ctrl.get("status"):
            status_changes.append({
                "framework": key[0],
                "control_id": key[1],
                "title": ctrl.get("title", ""),
                "old_status": prev.get("status"),
                "new_status": ctrl.get("status"),
            })

    # New vs resolved findings
    def _finding_key(f: dict) -> str:
        return f"{f.get('control_id', '')}|{f.get('resource', '')}|{f.get('check', '')}"

    prev_findings_set = {_finding_key(f) for f in previous.get("findings", [])}
    curr_findings_set = {_finding_key(f) for f in current.get("findings", [])}

    new_findings = [f for f in current.get("findings", [])
                    if _finding_key(f) not in prev_findings_set]
    resolved_findings = [f for f in previous.get("findings", [])
                         if _finding_key(f) not in curr_findings_set]

    # Score drift per framework
    prev_summary = previous.get("summary", {})
    curr_summary = current.get("summary", {})
    score_change: dict[str, dict] = {}
    for fw in set(list(prev_summary.get("framework_scores", {})) +
                  list(curr_summary.get("framework_scores", {}))):
        old = prev_summary.get("framework_scores", {}).get(fw, 0)
        new = curr_summary.get("framework_scores", {}).get(fw, 0)
        score_change[fw] = {"old": old, "new": new, "delta": round(new - old, 2)}

    # Summary text
    improved = sum(1 for s in status_changes if s["new_status"] == "COMPLIANT")
    regressed = sum(1 for s in status_changes
                    if s["old_status"] == "COMPLIANT" and s["new_status"] != "COMPLIANT")
    summary_text = (
        f"{len(new_findings)} new finding(s), "
        f"{len(resolved_findings)} resolved, "
        f"{improved} control(s) improved, "
        f"{regressed} regressed."
    )

    return {
        "score_change": score_change,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "status_changes": status_changes,
        "summary": summary_text,
    }


def generate_delta_section(delta: dict[str, Any]) -> str:
    """Return Markdown text summarizing the delta for inclusion in reports."""
    lines: list[str] = ["## Delta from Previous Assessment", ""]
    lines.append(f"**Summary:** {delta['summary']}")
    lines.append("")

    if delta.get("score_change"):
        lines.append("### Score Changes")
        lines.append("| Framework | Previous | Current | Change |")
        lines.append("|-----------|----------|---------|--------|")
        for fw, sc in delta["score_change"].items():
            sign = "+" if sc["delta"] >= 0 else ""
            lines.append(f"| {fw} | {sc['old']}% | {sc['new']}% | {sign}{sc['delta']}% |")
        lines.append("")

    if delta.get("status_changes"):
        lines.append("### Control Status Changes")
        lines.append("| Control | Old Status | New Status |")
        lines.append("|---------|-----------|-----------|")
        for ch in delta["status_changes"]:
            lines.append(f"| {ch['control_id']} | {ch['old_status']} | {ch['new_status']} |")
        lines.append("")

    if delta.get("new_findings"):
        lines.append(f"### New Findings ({len(delta['new_findings'])})")
        for f in delta["new_findings"][:20]:
            lines.append(f"- **{f.get('control_id', 'N/A')}** — {f.get('detail', 'N/A')}")
        lines.append("")

    if delta.get("resolved_findings"):
        lines.append(f"### Resolved Findings ({len(delta['resolved_findings'])})")
        for f in delta["resolved_findings"][:20]:
            lines.append(f"- ~~{f.get('control_id', 'N/A')}~~ — {f.get('detail', 'N/A')}")
        lines.append("")

    return "\n".join(lines)
