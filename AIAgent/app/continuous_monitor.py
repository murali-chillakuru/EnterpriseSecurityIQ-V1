"""
Continuous Monitoring Engine
Scheduled and webhook-driven re-assessments with drift detection.
Supports cron-style scheduling, change-triggered collection,
and trend tracking over time.
"""

from __future__ import annotations
import asyncio
import json
import pathlib
import time
from datetime import datetime, timezone
from typing import Any, Callable
from app.auth import ComplianceCredentials
from app.config import AssessmentConfig
from app.logger import log


class MonitoringSchedule:
    """Defines a monitoring schedule with intervals and scope."""

    def __init__(
        self,
        interval_minutes: int = 60,
        collectors: list[str] | None = None,
        frameworks: list[str] | None = None,
        domains: list[str] | None = None,
        alert_on_regression: bool = True,
        min_score_threshold: float = 70.0,
    ):
        self.interval_minutes = interval_minutes
        self.collectors = collectors  # None = all
        self.frameworks = frameworks
        self.domains = domains
        self.alert_on_regression = alert_on_regression
        self.min_score_threshold = min_score_threshold


class TrendTracker:
    """Tracks compliance scores and finding counts over time."""

    def __init__(self, storage_path: str = "output/.trends.json"):
        self.storage_path = pathlib.Path(storage_path)
        self.data: list[dict] = []
        self._load()

    def _load(self):
        if self.storage_path.is_file():
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.data = []

    def _save(self):
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, default=str)

    def record(self, result: dict) -> dict:
        """Record a snapshot from an assessment result. Returns the trend entry."""
        summary = result.get("summary", {})
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": summary.get("ComplianceScore", 0),
            "total_controls": summary.get("TotalControls", 0),
            "compliant": summary.get("Compliant", 0),
            "findings": summary.get("TotalFindings", 0),
            "critical": summary.get("CriticalFindings", 0),
            "high": summary.get("HighFindings", 0),
            "evidence_count": result.get("evidence_count", 0),
        }
        self.data.append(entry)
        # Keep last 1000 entries
        if len(self.data) > 1000:
            self.data = self.data[-1000:]
        self._save()
        return entry

    def get_trend(self, last_n: int = 30) -> list[dict]:
        """Return the last N trend entries."""
        return self.data[-last_n:]

    def detect_regression(self, current_score: float) -> dict | None:
        """Detect if current score is a regression from the recent average."""
        recent = self.data[-10:] if len(self.data) >= 2 else []
        if not recent:
            return None
        avg = sum(e["score"] for e in recent) / len(recent)
        if current_score < avg - 5.0:  # 5-point drop threshold
            return {
                "regression": True,
                "current_score": current_score,
                "average_score": round(avg, 1),
                "drop": round(avg - current_score, 1),
            }
        return None


class ContinuousMonitor:
    """
    Continuous monitoring loop.
    Runs repeated assessments at a configured interval,
    tracks trends, detects regressions, and fires alert callbacks.
    """

    def __init__(
        self,
        creds: ComplianceCredentials,
        config: AssessmentConfig | None = None,
        schedule: MonitoringSchedule | None = None,
        output_dir: str = "output",
        on_alert: Callable[[dict], Any] | None = None,
    ):
        self.creds = creds
        self.config = config or AssessmentConfig.from_env()
        self.schedule = schedule or MonitoringSchedule()
        self.output_dir = output_dir
        self.on_alert = on_alert
        self.tracker = TrendTracker(
            storage_path=str(pathlib.Path(output_dir) / ".trends.json")
        )
        self._running = False
        self._iteration = 0

    async def run_once(self) -> dict[str, Any]:
        """Run a single monitoring iteration."""
        from app.postureiq_orchestrator import run_postureiq_assessment

        self._iteration += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        run_dir = str(pathlib.Path(self.output_dir) / f"monitor_{ts}")

        log.info("Monitor iteration #%d starting at %s", self._iteration, ts)

        result = await run_postureiq_assessment(
            creds=self.creds,
            config=self.config,
            domains=self.schedule.domains,
            generate_reports=True,
            output_dir=run_dir,
            delta=True,
        )

        # Track trend
        entry = self.tracker.record(result)
        score = entry["score"]

        # Regression detection
        regression = self.tracker.detect_regression(score)
        if regression and self.schedule.alert_on_regression and self.on_alert:
            await self._fire_alert("regression", regression, result)

        # Score below threshold
        if score < self.schedule.min_score_threshold and self.on_alert:
            await self._fire_alert("below_threshold", {
                "score": score,
                "threshold": self.schedule.min_score_threshold,
            }, result)

        # New critical findings
        critical = result.get("summary", {}).get("CriticalFindings", 0)
        if critical > 0 and self.on_alert:
            await self._fire_alert("critical_findings", {
                "count": critical,
            }, result)

        log.info("Monitor iteration #%d complete: score=%.1f%%, findings=%d",
                 self._iteration, score, entry["findings"])

        return {
            "iteration": self._iteration,
            "trend_entry": entry,
            "regression": regression,
            "result": result,
        }

    async def run_loop(self, max_iterations: int = 0):
        """
        Run continuous monitoring loop.
        max_iterations=0 means run indefinitely.
        """
        self._running = True
        log.info("Continuous monitoring started (interval=%d min, max=%d)",
                 self.schedule.interval_minutes, max_iterations)

        iteration = 0
        while self._running:
            iteration += 1
            try:
                await self.run_once()
            except Exception as exc:
                log.error("Monitor iteration #%d failed: %s", iteration, exc)
                if self.on_alert:
                    await self._fire_alert("error", {"error": str(exc)}, {})

            if max_iterations > 0 and iteration >= max_iterations:
                log.info("Max iterations reached (%d), stopping", max_iterations)
                break

            if self._running:
                log.info("Next iteration in %d minutes", self.schedule.interval_minutes)
                await asyncio.sleep(self.schedule.interval_minutes * 60)

        self._running = False
        log.info("Continuous monitoring stopped after %d iterations", iteration)

    def stop(self):
        """Stop the monitoring loop gracefully."""
        self._running = False

    async def _fire_alert(self, alert_type: str, details: dict, result: dict):
        """Fire an alert callback."""
        alert = {
            "type": alert_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iteration": self._iteration,
            "details": details,
        }
        log.warning("ALERT [%s]: %s", alert_type, json.dumps(details, default=str))
        if self.on_alert:
            try:
                r = self.on_alert(alert)
                if asyncio.iscoroutine(r):
                    await r
            except Exception as exc:
                log.error("Alert callback failed: %s", exc)
