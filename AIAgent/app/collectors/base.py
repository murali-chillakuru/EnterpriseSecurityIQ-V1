"""
EnterpriseSecurityIQ — Base Collector
Provides retry logic, pagination helpers, and the standard collector pattern.
Gracefully handles 403/401 (Access Denied) — reports what the user cannot access
instead of silently returning empty data.
"""

from __future__ import annotations
import asyncio
import time
from typing import Any, AsyncIterator, Callable
from app.models import CollectorResult, EvidenceRecord, Source
from app.logger import log


MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds, doubles each retry

# HTTP status codes that indicate the user lacks permissions
ACCESS_DENIED_CODES = {401, 403}


def _v(obj, default=""):
    """Safely extract .value from Azure SDK enums; return str as-is."""
    if obj is None:
        return default
    return obj.value if hasattr(obj, "value") else str(obj)


class AccessDeniedError(Exception):
    """Raised when a collector encounters 403/401 — insufficient permissions."""
    def __init__(self, api: str, status: int = 403, message: str = ""):
        self.api = api
        self.status = status
        super().__init__(message or f"Access Denied ({status}) for {api}")


def _extract_status(exc: Exception) -> int | None:
    """Extract HTTP status code from various Azure/Graph SDK exception types."""
    for attr in ("response_status_code", "status_code", "error_code"):
        val = getattr(exc, attr, None)
        if isinstance(val, int):
            return val
    # azure-mgmt exceptions often wrap an inner response
    response = getattr(exc, "response", None)
    if response and hasattr(response, "status_code"):
        return response.status_code
    # Check the string representation as a fallback
    exc_str = str(exc).lower()
    if "403" in exc_str or "forbidden" in exc_str or "authorization" in exc_str:
        return 403
    if "401" in exc_str or "unauthorized" in exc_str:
        return 401
    return None


async def run_collector(
    name: str,
    source: str,
    collect_fn: Callable[[], Any],
) -> CollectorResult:
    """Execute a collector function with retry and timing.
    Returns access_denied=True when the user's token lacks permissions."""
    start = time.monotonic()
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            data = await collect_fn()
            duration = time.monotonic() - start
            if data is None:
                data = []
            log.info("[%s] Collected %d records (%.1fs)", name, len(data), duration)
            return CollectorResult(
                collector=name,
                source=source,
                success=True,
                data=data,
                duration_seconds=round(duration, 2),
                record_count=len(data),
            )
        except AccessDeniedError as ade:
            duration = time.monotonic() - start
            log.warning("[%s] Access Denied (%d): %s — user lacks required permission",
                        name, ade.status, ade.api)
            # Inject an access-denied evidence marker so the report can display it
            marker = make_evidence(
                source=source,
                collector=name,
                evidence_type="access-denied",
                description=f"Access Denied: insufficient permissions for {ade.api}",
                data={"Collector": name, "Api": ade.api, "StatusCode": ade.status,
                      "AccessDenied": True},
            )
            return CollectorResult(
                collector=name,
                source=source,
                success=True,  # not a failure — just restricted access
                data=[marker],
                duration_seconds=round(duration, 2),
                record_count=0,
                access_denied=True,
                access_denied_apis=[ade.api],
            )
        except Exception as exc:
            duration = time.monotonic() - start
            # Check if this is actually an access denied error
            status = _extract_status(exc)
            if status in ACCESS_DENIED_CODES:
                log.warning("[%s] Access Denied (%s): %s", name, status, exc)
                marker = make_evidence(
                    source=source,
                    collector=name,
                    evidence_type="access-denied",
                    description=f"Access Denied: insufficient permissions for {name}",
                    data={"Collector": name, "Api": name, "StatusCode": status,
                          "AccessDenied": True},
                )
                return CollectorResult(
                    collector=name,
                    source=source,
                    success=True,
                    data=[marker],
                    duration_seconds=round(duration, 2),
                    record_count=0,
                    access_denied=True,
                    access_denied_apis=[name],
                )
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF * (2 ** (attempt - 1))
                log.warning("[%s] Attempt %d failed: %s — retrying in %ds", name, attempt, exc, wait)
                await asyncio.sleep(wait)
            else:
                log.error("[%s] Failed after %d attempts: %s", name, MAX_RETRIES, exc)
                return CollectorResult(
                    collector=name,
                    source=source,
                    success=False,
                    error=str(exc),
                    duration_seconds=round(duration, 2),
                )


def make_evidence(
    source: str,
    collector: str,
    evidence_type: str,
    description: str,
    data: dict,
    resource_id: str = "",
    resource_type: str = "",
) -> dict:
    """Shortcut to create an evidence dict (PascalCase keys)."""
    return EvidenceRecord(
        source=source,
        collector=collector,
        evidence_type=evidence_type,
        description=description,
        data=data,
        resource_id=resource_id,
        resource_type=resource_type,
    ).to_dict()


async def paginate_graph(request_builder, top: int = 999, max_retries: int = 3) -> list[Any]:
    """Page through a Microsoft Graph collection, respecting $top and 429 throttling.
    Raises AccessDeniedError on 403/401 so the collector can report it clearly."""
    items: list[Any] = []

    async def _get_with_retry(builder):
        for attempt in range(1, max_retries + 1):
            try:
                return await builder.get()
            except Exception as exc:
                status = getattr(exc, "response_status_code", None) or getattr(exc, "status_code", None)
                # Access denied — raise immediately, do not retry
                if status in ACCESS_DENIED_CODES:
                    api_name = str(getattr(builder, '_url_template', 'Graph API'))
                    raise AccessDeniedError(api=api_name, status=status, message=str(exc))
                # Detect 429 Too Many Requests
                if status == 429:
                    retry_after = 10  # default
                    headers = getattr(exc, "response_headers", None) or {}
                    if hasattr(headers, "get"):
                        ra = headers.get("Retry-After") or headers.get("retry-after")
                        if ra:
                            try:
                                retry_after = int(ra)
                            except (ValueError, TypeError):
                                pass
                    log.warning("Graph 429 throttled (attempt %d/%d), retrying in %ds",
                                attempt, max_retries, retry_after)
                    await asyncio.sleep(retry_after)
                    continue
                # Check string for access denied patterns
                exc_str = str(exc).lower()
                if "403" in exc_str or "forbidden" in exc_str or "insufficient privileges" in exc_str:
                    raise AccessDeniedError(api="Graph API", status=403, message=str(exc))
                if "401" in exc_str or "unauthorized" in exc_str:
                    raise AccessDeniedError(api="Graph API", status=401, message=str(exc))
                raise
        return None

    try:
        page = await _get_with_retry(request_builder)
        if page and page.value:
            items.extend(page.value)
        while page and page.odata_next_link:
            page = await _get_with_retry(request_builder.with_url(page.odata_next_link))
            if page and page.value:
                items.extend(page.value)
                if len(items) % 10000 < top:
                    log.info("  … paged %d items so far", len(items))
    except AccessDeniedError:
        raise  # Let run_collector handle this
    except Exception as exc:
        log.warning("Graph pagination error: %s", exc)
    return items


async def paginate_arm(pager) -> list[Any]:
    """Iterate an Azure ARM async pager.
    Also handles SDK methods that return a coroutine (awaitable) instead of
    an async iterable — e.g. pricings.list(), virtual_machine_extensions.list().
    Raises AccessDeniedError on 403/401 so the collector can report it clearly."""
    import inspect

    items: list[Any] = []
    try:
        # Some newer Azure SDK methods return a coroutine, not an async pager
        if inspect.iscoroutine(pager):
            result = await pager
            if result is None:
                return []
            # Result with .value list (e.g. PricingList.value)
            if hasattr(result, "value") and isinstance(result.value, list):
                return result.value
            # Result is itself an async iterable
            if hasattr(result, "__aiter__"):
                async for item in result:
                    items.append(item)
                return items
            # Result is a plain iterable (list, tuple, etc.)
            if hasattr(result, "__iter__") and not isinstance(result, (str, bytes)):
                return list(result)
            return [result]

        async for item in pager:
            items.append(item)
    except Exception as exc:
        status = _extract_status(exc)
        if status in ACCESS_DENIED_CODES:
            raise AccessDeniedError(api="ARM API", status=status, message=str(exc))
        log.warning("ARM pagination error: %s", exc)
    return items
