"""
Assessment Orchestrator
Coordinates collectors, evaluators, and report generation.
"""

from __future__ import annotations
import asyncio, json, pathlib, time
from typing import Any
from app.auth import ComplianceCredentials
from app.config import AssessmentConfig
from app.postureiq_evaluators.engine import evaluate_all
from app.postureiq_reports.json_report import generate_json_report
from app.postureiq_reports.html_report import generate_html_report
from app.postureiq_reports.markdown_report import generate_markdown_report
from app.postureiq_reports.postureiq_report_html import generate_postureiq_report_html
from app.postureiq_reports.postureiq_report_md import generate_postureiq_report_md
from app.postureiq_reports.data_exports import export_data_files, save_raw_evidence
from app.postureiq_reports.delta_report import find_previous_results, compute_delta, generate_delta_section
from app.postureiq_reports.drift_report_html import generate_drift_report_html
from app.postureiq_reports.executive_dashboard import generate_executive_dashboard
from app.postureiq_reports.oscal_export import export_oscal
from app.postureiq_reports.excel_export import generate_excel_report
from app.postureiq_reports.master_report import generate_master_report
from app.postureiq_reports.methodology_report import generate_methodology_html
from app.postureiq_reports.remediation import generate_remediation_playbooks
from app.postureiq_reports.sarif_export import export_sarif
from app.postureiq_reports.pdf_export import convert_all_html_to_pdf
from app.postureiq_evaluators.attack_paths import analyze_attack_paths
from app.postureiq_evaluators.priority_ranking import rank_findings, generate_priority_summary
from app.postureiq_evaluators.ai_fix_recommendations import generate_ai_fixes_batch
from app.postureiq_evaluators.suppressions import load_suppressions, apply_suppressions, generate_exception_report
from app.logger import log


def _per_fw_domain_scores(control_results: list[dict]) -> dict[str, dict]:
    """Compute domain scores for a single framework's control results.

    Controls with ``missing_evidence`` status (resource type absent from the
    environment) are tracked separately and excluded from the compliance
    percentage so that non-existent resources don't drag the score down.
    """
    domains: dict[str, dict] = {}
    for cr in control_results:
        d = cr.get("Domain", "other")
        if d not in domains:
            domains[d] = {"Total": 0, "Compliant": 0, "MissingEvidence": 0}
        if cr["Status"] == "missing_evidence":
            domains[d]["MissingEvidence"] += 1
        else:
            domains[d]["Total"] += 1
            if cr["Status"] == "compliant":
                domains[d]["Compliant"] += 1
    return {
        d: {**v, "Score": round(v["Compliant"] / v["Total"] * 100, 1) if v["Total"] else 0}
        for d, v in domains.items()
    }


def _build_collector_stats(completed: list[str], failed: list[str],
                           access_denied: list[dict],
                           timings: list[dict] | None = None) -> list[dict]:
    """Build collector stats list for the methodology report."""
    # If we have real timing data from the collection phase, use it
    if timings:
        ad_set = {a.get("collector", "") for a in access_denied}
        stats = []
        for t in timings:
            status = t["status"]
            if t["name"] in ad_set:
                status = "access_denied"
            stats.append({"name": t["name"], "source": t["source"],
                          "records": t["records"], "duration": t["duration"],
                          "status": status})
        return stats

    # Fallback: no timing data available
    stats: list[dict] = []
    ad_set = {a.get("collector", "") for a in access_denied}
    for name in completed:
        source = "Entra" if "entra" in name.lower() else "Azure"
        status = "access_denied" if name in ad_set else "success"
        stats.append({"name": name, "source": source, "records": 0, "duration": 0, "status": status})
    for name in failed:
        source = "Entra" if "entra" in name.lower() else "Azure"
        stats.append({"name": name, "source": source, "records": 0, "duration": 0, "status": "failed"})
    return stats


# ── Collector Registry ────────────────────────────────────────────────
# Auto-discover all collectors via the plugin registry.
# Importing the modules triggers the @register_collector decorators.
from app.collectors.registry import discover_collectors, get_collector_functions

discover_collectors()

# Build lists from the registry (sorted by priority).
AZURE_COLLECTORS = get_collector_functions(source="azure")
ENTRA_COLLECTORS = get_collector_functions(source="entra")

# Entra collectors that are overhead for PostureIQ's Azure-focused purpose.
# PostureIQ uses Entra for role assignments & identity risk — not general
# user lifecycle stats, MFA coverage percentages, or audit log posture.
# These collectors remain available for Compliance and Data Security assessments.
_POSTUREIQ_SKIP_ENTRA = {
    "collect_entra_users",        # Heavy: paginates all users + groups for aggregate stats
    "collect_entra_user_details", # Heavy: sign-in activity + MFA + OAuth grants for all users
    "collect_entra_audit_logs",   # Medium: 5000 sign-ins + 2000 audit events (general logging)
}
POSTUREIQ_ENTRA_COLLECTORS = [
    fn for fn in ENTRA_COLLECTORS if fn.__name__ not in _POSTUREIQ_SKIP_ENTRA
]


def _checkpoint_path(output_dir: str) -> pathlib.Path:
    return pathlib.Path(output_dir) / ".checkpoint.json"


def _save_checkpoint(output_dir: str, evidence: list[dict], completed: list[str], failed: list[str]):
    path = _checkpoint_path(output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"completed": completed, "failed": failed, "evidence": evidence}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, default=str)
    log.info("Checkpoint saved: %d evidence, %d/%d collectors done/failed",
             len(evidence), len(completed), len(failed))


def _load_checkpoint(output_dir: str) -> tuple[list[dict], set[str]] | None:
    path = _checkpoint_path(output_dir)
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        evidence = data.get("evidence", [])
        completed = set(data.get("completed", []))
        log.info("Checkpoint loaded: %d evidence, %d collectors completed",
                 len(evidence), len(completed))
        return evidence, completed
    except (json.JSONDecodeError, KeyError) as exc:
        log.warning("Corrupt checkpoint file, starting fresh: %s", exc)
        return None


def _clear_checkpoint(output_dir: str):
    path = _checkpoint_path(output_dir)
    if path.is_file():
        path.unlink()


# ── Incremental / Delta Collection ───────────────────────────────────────

def _last_run_path(output_dir: str) -> pathlib.Path:
    return pathlib.Path(output_dir) / ".last_run.json"


def _save_last_run(output_dir: str, evidence: list[dict], ts: str) -> None:
    """Persist last-run metadata so the next --delta run can detect changes."""
    resource_ids = sorted({e.get("ResourceId", "") for e in evidence if e.get("ResourceId")})
    data = {"timestamp": ts, "resource_count": len(resource_ids), "resource_ids": resource_ids}
    path = _last_run_path(output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, default=str)


def _load_last_run(output_dir: str) -> dict | None:
    path = _last_run_path(output_dir)
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, KeyError):
        return None


async def run_postureiq_assessment(
    creds: ComplianceCredentials,
    config: AssessmentConfig | None = None,
    domains: list[str] | None = None,
    generate_reports: bool = True,
    output_dir: str = "output",
    delta: bool = False,
) -> dict[str, Any]:
    """
    Run full PostureIQ assessment.
    Returns dict with summary, findings, control_results, report_paths.

    When *delta* is True, only re-collect resources changed since the last run
    (based on activity-log change detection and .last_run.json metadata).
    """
    if config is None:
        config = AssessmentConfig.from_env()

    effective_output_dir = output_dir or config.output_dir

    start = time.time()
    log.info("=" * 60)
    log.info("PostureIQ Assessment Starting")
    log.info("Frameworks: %s", ", ".join(config.frameworks))
    log.info("=" * 60)

    # Get tenant info
    tenant_info = await creds.get_tenant_info()
    log.info("Tenant: %s (%s)", tenant_info.get("display_name"), tenant_info.get("tenant_id"))

    # Collect subscriptions (honouring subscription_filter from config)
    sub_filter = config.collectors.subscription_filter or config.auth.subscription_filter or None
    subscriptions = await creds.list_subscriptions(subscription_filter=sub_filter)
    log.info("Subscriptions: %d", len(subscriptions))

    # Warm the shared ResourceInventory cache (Phase 6.4)
    from app.collectors.inventory import ResourceInventory
    inventory = ResourceInventory.instance()
    await inventory.ensure_loaded(creds, subscriptions)

    # Delta mode: load last-run metadata for comparison (Phase 6.2)
    last_run = _load_last_run(effective_output_dir) if delta else None
    if delta and last_run:
        log.info("Delta mode: last run at %s (%d resources)",
                 last_run.get("timestamp", "?"), last_run.get("resource_count", 0))
    elif delta:
        log.info("Delta mode requested but no previous run found — running full scan")

    # Phase 1: Run all collectors concurrently
    phase1_start = time.time()
    log.info("Phase 1: Collecting evidence...")
    all_evidence: list[dict] = []
    completed_collectors: list[str] = []
    failed_collectors: list[str] = []
    access_denied_collectors: list[dict] = []  # {collector, source, apis}

    # Check for checkpoint resume
    checkpoint = None
    if config.checkpoint_enabled:
        checkpoint = _load_checkpoint(effective_output_dir)
    if checkpoint:
        all_evidence, done_set = checkpoint
        log.info("Resuming from checkpoint (%d evidence, %d collectors done)",
                 len(all_evidence), len(done_set))
    else:
        done_set = set()

    # ── Helper: run a group of collectors in batches ─────────────────
    collector_timings: list[dict] = []  # per-collector timing data

    async def _run_collector_group(
        fns: list,
        batch_size: int,
        label: str,
        user_limit: int = 0,
    ) -> tuple[list[dict], list[str], list[str]]:
        """Run a list of collector functions in batches and return (evidence, completed, failed)."""
        ev: list[dict] = []
        ok: list[str] = []
        fail: list[str] = []
        for i in range(0, len(fns), batch_size):
            batch = fns[i:i + batch_size]
            coros = []
            for fn in batch:
                if fn.__name__ == "collect_entra_user_details" and user_limit > 0:
                    coro = fn(creds, user_sample_limit=user_limit)
                else:
                    coro = fn(creds, subscriptions) if label == "Azure" else fn(creds)
                if timeout > 0:
                    coro = asyncio.wait_for(coro, timeout=timeout)
                coros.append(coro)
            t0 = time.time()
            batch_results = await asyncio.gather(*coros, return_exceptions=True)
            batch_elapsed = time.time() - t0
            for fn, r in zip(batch, batch_results):
                elapsed_per = round(batch_elapsed, 2)
                if isinstance(r, list):
                    ev.extend(r)
                    ok.append(fn.__name__)
                    collector_timings.append({"name": fn.__name__, "source": label, "records": len(r), "duration": elapsed_per, "status": "success"})
                elif isinstance(r, TimeoutError):
                    # Recover any partial evidence accumulated before the timeout
                    partial = getattr(fn, '_partial_evidence', None)
                    if partial:
                        ev.extend(partial)
                        log.warning("%s collector timed out after %ds: %s — recovered %d partial records",
                                    label, timeout, fn.__name__, len(partial))
                        collector_timings.append({"name": fn.__name__, "source": label, "records": len(partial), "duration": elapsed_per, "status": "timeout_partial"})
                    else:
                        log.warning("%s collector timed out after %ds: %s", label, timeout, fn.__name__)
                        collector_timings.append({"name": fn.__name__, "source": label, "records": 0, "duration": elapsed_per, "status": "timeout"})
                    fail.append(fn.__name__)
                elif isinstance(r, Exception):
                    log.error("%s collector error: %s — %s", label, fn.__name__, r)
                    fail.append(fn.__name__)
                    collector_timings.append({"name": fn.__name__, "source": label, "records": 0, "duration": elapsed_per, "status": "error"})
        return ev, ok, fail

    # Build collector tasks — Azure and Entra run CONCURRENTLY
    az_batch = config.collectors.azure_batch_size or 8
    entra_batch = config.collectors.entra_batch_size or 6
    timeout = config.collectors.collector_timeout or 0
    user_limit = config.collectors.user_sample_limit or 0

    group_coros = []
    group_labels = []

    if config.collectors.azure_enabled:
        azure_fns = [fn for fn in AZURE_COLLECTORS if fn.__name__ not in done_set]
        group_coros.append(_run_collector_group(azure_fns, az_batch, "Azure"))
        group_labels.append("Azure")
    else:
        log.info("Azure collectors disabled by config.")

    if config.collectors.entra_enabled:
        entra_fns = [fn for fn in POSTUREIQ_ENTRA_COLLECTORS if fn.__name__ not in done_set]
        log.info("PostureIQ Entra collectors: %d (skipped %d overhead)",
                 len(entra_fns), len(ENTRA_COLLECTORS) - len(POSTUREIQ_ENTRA_COLLECTORS))
        group_coros.append(_run_collector_group(entra_fns, entra_batch, "Entra", user_limit=user_limit))
        group_labels.append("Entra")
    else:
        log.info("Entra collectors disabled by config.")

    # Run both groups concurrently (biggest perf win — Entra no longer waits for Azure)
    if group_coros:
        group_results = await asyncio.gather(*group_coros)
        for label, (ev, ok, fail) in zip(group_labels, group_results):
            all_evidence.extend(ev)
            completed_collectors.extend(ok)
            failed_collectors.extend(fail)
            log.info("%s collection done: %d records from %d collectors (%d failed)",
                     label, len(ev), len(ok), len(fail))

    if config.checkpoint_enabled:
        _save_checkpoint(effective_output_dir, all_evidence,
                        completed_collectors, failed_collectors)

    log.info("Evidence collected: %d records (%.1fs)", len(all_evidence), time.time() - phase1_start)

    # Log slowest collectors for performance visibility
    if collector_timings:
        by_dur = sorted(collector_timings, key=lambda t: t["duration"], reverse=True)
        log.info("Slowest collectors: %s",
                 ", ".join(f"{t['name']}={t['duration']:.1f}s" for t in by_dur[:5]))

    # Extract access-denied markers from evidence
    for ev in all_evidence:
        if ev.get("EvidenceType") == "access-denied" and ev.get("Data", {}).get("AccessDenied"):
            d = ev.get("Data", {})
            access_denied_collectors.append({
                "collector": d.get("Collector", ev.get("Collector", "Unknown")),
                "source": ev.get("Source", "Unknown"),
                "api": d.get("Api", "Unknown"),
                "status_code": d.get("StatusCode", 403),
            })

    if access_denied_collectors:
        log.warning("Access Denied for %d collectors: %s",
                    len(access_denied_collectors),
                    ", ".join(c["collector"] for c in access_denied_collectors))

    # Clear checkpoint — collection succeeded
    if config.checkpoint_enabled:
        _clear_checkpoint(effective_output_dir)

    # Save last-run metadata for future delta mode (Phase 6.2)
    from datetime import datetime, timezone
    _save_last_run(effective_output_dir, all_evidence,
                   datetime.now(timezone.utc).isoformat())

    # Phase 2: Evaluate
    phase2_start = time.time()
    log.info("Phase 2: Evaluating compliance...")
    results = evaluate_all(all_evidence, frameworks=config.frameworks, domains=domains, thresholds=config.thresholds)
    log.info("Phase 2 complete (%.1fs)", time.time() - phase2_start)

    # ── Phase 2.1: Attack Path Analysis ──────────────────────────────
    phase2_1_start = time.time()
    log.info("Phase 2.1: Attack path analysis...")
    evidence_idx = {}
    for ev in all_evidence:
        etype = ev.get("EvidenceType", "")
        if etype:
            evidence_idx.setdefault(etype, []).append(ev)
    attack_path_result = analyze_attack_paths(evidence_idx)
    results["attack_paths"] = attack_path_result
    results["summary"]["AttackPaths"] = attack_path_result["summary"]
    log.info("Phase 2.1 complete: %d attack paths (%.1fs)",
             attack_path_result["summary"]["TotalPaths"],
             time.time() - phase2_1_start)

    # ── Phase 2.2: Priority Ranking ──────────────────────────────────
    phase2_2_start = time.time()
    log.info("Phase 2.2: Priority ranking...")
    results["findings"] = rank_findings(results["findings"])
    priority_summary = generate_priority_summary(results["findings"])
    results["summary"]["PrioritySummary"] = priority_summary
    log.info("Phase 2.2 complete: %d findings ranked, top priority=%.1f (%.1fs)",
             priority_summary["TotalRanked"],
             priority_summary["Top10"][0]["Priority"] if priority_summary["Top10"] else 0,
             time.time() - phase2_2_start)

    # ── Phase 2.3: Exception / Suppression Tracking ──────────────────
    suppression_path = pathlib.Path(effective_output_dir).parent / "suppressions.json"
    suppressions = load_suppressions(str(suppression_path))
    suppressed_findings: list[dict] = []
    if suppressions:
        results["findings"], suppressed_findings = apply_suppressions(
            results["findings"], suppressions)
    exception_report = generate_exception_report(suppressions, suppressed_findings)
    results["exception_report"] = exception_report
    results["suppressed_findings"] = suppressed_findings
    results["summary"]["Exceptions"] = {
        "TotalRules": exception_report["TotalRules"],
        "Suppressed": exception_report["SuppressedCount"],
        "ExpiredRules": exception_report["ExpiredRules"],
        "ExpiringSoon": exception_report["ExpiringSoon"],
    }

    # ── Phase 2.4: AI-Powered Fix Recommendations ────────────────────
    phase2_4_start = time.time()
    log.info("Phase 2.4: Generating AI fix recommendations...")
    try:
        ai_fixes = await generate_ai_fixes_batch(results["findings"], max_findings=15)
        results["summary"]["AIFixes"] = len(ai_fixes)
        log.info("Phase 2.4 complete: %d AI fixes generated (%.1fs)",
                 len(ai_fixes), time.time() - phase2_4_start)
    except Exception as exc:
        log.warning("AI fix generation skipped: %s", exc)
        results["summary"]["AIFixes"] = 0

    # Phase 2.5: Delta comparison against previous run
    delta_result = None
    prev = find_previous_results(config.output_dir)
    if prev:
        delta_result = compute_delta(results, prev)
        log.info("Delta: %s", delta_result["summary"])

    # Phase 3: Generate reports (honour output_formats from config)
    report_paths = {}
    if generate_reports:
        phase3_start = time.time()
        log.info("Phase 3: Generating reports...")
        formats = config.output_formats or ["json", "html", "md"]
        multi = len(config.frameworks) > 1

        def _generate_reports_for(fw_results, fw_dir, label):
            """Generate per-framework report files (HTML + Excel + PDF) into fw_dir."""
            rp = {}
            rargs = dict(
                results=fw_results,
                evidence=all_evidence,
                tenant_info=tenant_info,
                output_dir=fw_dir,
                access_denied=access_denied_collectors,
            )

            def _safe(key, fn, *a, **kw):
                try:
                    rp[key] = fn(*a, **kw)
                except Exception as exc:
                    log.error("Report '%s' failed for %s: %s", key, label, exc)

            if "html" in formats:
                _safe("compliance_html", generate_postureiq_report_html, **rargs)
            if "oscal" in formats:
                _safe("oscal", export_oscal, fw_results, tenant_info, fw_dir)
            _safe("excel", generate_excel_report, fw_results, fw_dir, framework=label)
            return rp

        if multi:
            # Per-framework reports in subfolders
            for fw_key in config.frameworks:
                fw_controls = [c for c in results["control_results"] if c["Framework"] == fw_key]
                fw_findings = [f for f in results["findings"] if f.get("Framework") == fw_key]
                fw_missing = [m for m in results["missing_evidence"] if m.get("Framework") == fw_key]
                fw_summary_data = results["summary"].get("FrameworkSummaries", {}).get(fw_key, {})
                fw_summary = {
                    **fw_summary_data,
                    "TotalFindings": len(fw_findings),
                    "TotalEvidence": len(all_evidence),
                    "CriticalFindings": sum(1 for f in fw_findings if f.get("Severity") == "critical"),
                    "HighFindings": sum(1 for f in fw_findings if f.get("Severity") == "high"),
                    "MediumFindings": sum(1 for f in fw_findings if f.get("Severity") == "medium"),
                    "Frameworks": [fw_key],
                    "FrameworkSummaries": {fw_key: fw_summary_data},
                    "DomainScores": _per_fw_domain_scores(fw_controls),
                }
                fw_results = {
                    "findings": fw_findings,
                    "control_results": fw_controls,
                    "missing_evidence": fw_missing,
                    "summary": fw_summary,
                }
                fw_dir = str(pathlib.Path(effective_output_dir) / fw_key)
                rp = _generate_reports_for(fw_results, fw_dir, fw_key)
                report_paths[fw_key] = rp
                log.info("  %s reports → %s", fw_key, fw_dir)
        else:
            # Single framework — always use subfolder for consistency
            fw_key = config.frameworks[0]
            fw_dir = str(pathlib.Path(effective_output_dir) / fw_key)
            rp = _generate_reports_for(results, fw_dir, fw_key)
            report_paths[fw_key] = rp
            log.info("  %s reports → %s", fw_key, fw_dir)

        # Shared data exports + raw evidence (always in root)
        if "json" in formats:
            export_paths = export_data_files(results, all_evidence, effective_output_dir,
                                             access_denied=access_denied_collectors)
            report_paths["data_exports"] = export_paths
        report_paths["raw_evidence"] = save_raw_evidence(all_evidence, effective_output_dir)

        # Drift report HTML (always in root, requires delta)
        if "html" in formats and delta_result:
            try:
                report_paths["drift_html"] = generate_drift_report_html(
                    delta=delta_result,
                    results=results,
                    tenant_info=tenant_info,
                    output_dir=effective_output_dir,
                )
            except Exception as exc:
                log.error("Drift report HTML failed: %s", exc)

        # SARIF export (always in root)
        if "sarif" in formats or "json" in formats:
            try:
                report_paths["sarif"] = export_sarif(
                    results=results,
                    tenant_info=tenant_info,
                    output_dir=effective_output_dir,
                )
            except Exception as exc:
                log.error("SARIF export failed: %s", exc)

        # Remediation playbooks (always in root)
        try:
            report_paths["remediation"] = generate_remediation_playbooks(
                findings=results.get("findings", []),
                output_dir=effective_output_dir,
            )
        except Exception as exc:
            log.error("Remediation playbooks failed: %s", exc)

    # Generate PDFs from all HTML reports
    if generate_reports and ("html" in formats):
        pdf_start = time.time()
        try:
            pdf_paths = await convert_all_html_to_pdf(effective_output_dir)
            if pdf_paths:
                report_paths["pdf_reports"] = [str(p) for p in pdf_paths]
                log.info("PDF generation: %d files (%.1fs)", len(pdf_paths), time.time() - pdf_start)
        except Exception as exc:
            log.error("PDF generation failed: %s", exc)

    if generate_reports:
        log.info("Phase 3 complete (%.1fs)", time.time() - phase3_start)

    elapsed = time.time() - start
    log.info("=" * 60)
    log.info("Assessment complete in %.1f seconds", elapsed)
    log.info("Score: %.1f%% (%d/%d compliant)",
             results["summary"]["ComplianceScore"],
             results["summary"]["Compliant"],
             results["summary"]["TotalControls"])
    log.info("=" * 60)

    final = {
        "summary": results["summary"],
        "findings": results["findings"],
        "control_results": results["control_results"],
        "missing_evidence": results["missing_evidence"],
        "access_denied": access_denied_collectors,
        "report_paths": report_paths,
        "tenant_info": tenant_info,
        "elapsed_seconds": round(elapsed, 1),
        "evidence_count": len(all_evidence),
        "delta": delta_result,
    }

    # ── Persist to history for auditing / trend analysis ──
    try:
        from app.evidence_history import save_run
        tid = tenant_info.get("tenant_id", "unknown")
        save_run(tid, final)
    except Exception as exc:
        log.warning("History save skipped: %s", exc)

    return final


async def run_multi_tenant_assessment(
    config: AssessmentConfig | None = None,
    domains: list[str] | None = None,
    generate_reports: bool = True,
    output_dir: str = "output",
) -> dict[str, Any]:
    """
    Run assessments across multiple tenants (primary + additional_tenants).
    Returns aggregated results with per-tenant breakdowns.
    """
    if config is None:
        config = AssessmentConfig.from_env()

    tenant_ids = []
    if config.auth.tenant_id:
        tenant_ids.append(config.auth.tenant_id)
    tenant_ids.extend(config.additional_tenants)
    tenant_ids = list(dict.fromkeys(tenant_ids))  # dedupe

    if len(tenant_ids) <= 1:
        # Single tenant — fall through to normal assessment
        creds = ComplianceCredentials(
            tenant_id=config.auth.tenant_id or None,
            auth_mode=config.auth.auth_mode,
        )
        return await run_postureiq_assessment(
            creds=creds, config=config, domains=domains,
            generate_reports=generate_reports, output_dir=output_dir,
        )

    log.info("=" * 60)
    log.info("Multi-Tenant Assessment: %d tenants", len(tenant_ids))
    log.info("=" * 60)

    all_results: dict[str, dict] = {}
    aggregated_findings: list[dict] = []
    aggregated_controls: list[dict] = []
    aggregated_missing: list[dict] = []
    total_evidence = 0

    for tenant_id in tenant_ids:
        log.info("─" * 40)
        log.info("Tenant: %s", tenant_id)
        log.info("─" * 40)
        tenant_dir = str(pathlib.Path(output_dir) / f"tenant-{tenant_id[:8]}")

        try:
            creds = ComplianceCredentials(
                tenant_id=tenant_id,
                auth_mode=config.auth.auth_mode,
            )
            result = await run_postureiq_assessment(
                creds=creds, config=config, domains=domains,
                generate_reports=generate_reports, output_dir=tenant_dir,
            )
            all_results[tenant_id] = result

            # Tag findings with tenant  
            for f in result.get("findings", []):
                f["TenantId"] = tenant_id
                f["TenantName"] = result.get("tenant_info", {}).get("display_name", tenant_id)
            for c in result.get("control_results", []):
                c["TenantId"] = tenant_id

            aggregated_findings.extend(result.get("findings", []))
            aggregated_controls.extend(result.get("control_results", []))
            aggregated_missing.extend(result.get("missing_evidence", []))
            total_evidence += result.get("evidence_count", 0)

        except Exception as exc:
            log.error("Tenant %s failed: %s", tenant_id, exc)
            all_results[tenant_id] = {"error": str(exc)}

    # Build aggregated summary
    total_controls = len(aggregated_controls)
    compliant = sum(1 for c in aggregated_controls if c.get("Status") == "compliant")
    score = round((compliant / total_controls) * 100, 1) if total_controls else 0

    summary = {
        "MultiTenant": True,
        "TenantCount": len(tenant_ids),
        "TotalControls": total_controls,
        "Compliant": compliant,
        "ComplianceScore": score,
        "TotalFindings": len(aggregated_findings),
        "TotalEvidence": total_evidence,
        "CriticalFindings": sum(1 for f in aggregated_findings if f.get("Severity") == "critical"),
        "HighFindings": sum(1 for f in aggregated_findings if f.get("Severity") == "high"),
        "TenantResults": {
            tid: {
                "Score": r.get("summary", {}).get("ComplianceScore", 0),
                "TenantName": r.get("tenant_info", {}).get("display_name", tid),
                "Findings": r.get("summary", {}).get("TotalFindings", 0),
            }
            for tid, r in all_results.items()
            if "error" not in r
        },
        "FailedTenants": [tid for tid, r in all_results.items() if "error" in r],
    }

    log.info("=" * 60)
    log.info("Multi-Tenant Assessment Complete")
    log.info("Tenants: %d, Score: %.1f%%, Findings: %d",
             len(tenant_ids), score, len(aggregated_findings))
    log.info("=" * 60)

    return {
        "summary": summary,
        "findings": aggregated_findings,
        "control_results": aggregated_controls,
        "missing_evidence": aggregated_missing,
        "tenant_results": all_results,
    }
