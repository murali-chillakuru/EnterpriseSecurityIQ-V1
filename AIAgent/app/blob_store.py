"""
Persistent report storage using Azure Blob Storage with managed identity.

Reports are written to the local filesystem first, then uploaded to blob
storage for persistence across container restarts / redeployments.  When a
report is requested but missing locally, it is fetched from blob storage on
demand.
"""

from __future__ import annotations

import os
import pathlib
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContainerClient

from app.logger import log

_STORAGE_ACCOUNT = os.getenv("REPORT_STORAGE_ACCOUNT", "esiqnewstorage")
_CONTAINER_NAME = os.getenv("REPORT_STORAGE_CONTAINER", "reports")

_container_client: ContainerClient | None = None


def _get_container() -> ContainerClient:
    """Return (and cache) the blob container client."""
    global _container_client
    if _container_client is None:
        account_url = f"https://{_STORAGE_ACCOUNT}.blob.core.windows.net"
        credential = DefaultAzureCredential()
        svc = BlobServiceClient(account_url=account_url, credential=credential)
        _container_client = svc.get_container_client(_CONTAINER_NAME)
    return _container_client


# ── Upload ──────────────────────────────────────────────────────

def upload_directory(local_dir: pathlib.Path, output_root: pathlib.Path) -> int:
    """Upload every file under *local_dir* to blob storage.

    Blob names mirror the relative path from *output_root*, e.g.
    ``20260413_050025_PM/AI-Agent-Security/report.html``.

    Returns the number of files uploaded.
    """
    container = _get_container()
    count = 0
    for p in local_dir.rglob("*"):
        if not p.is_file():
            continue
        blob_name = p.relative_to(output_root).as_posix()
        try:
            with open(p, "rb") as fh:
                container.upload_blob(name=blob_name, data=fh, overwrite=True)
            count += 1
        except Exception as exc:
            log.warning("Blob upload failed for %s: %s", blob_name, exc)
    if count:
        log.info("Uploaded %d report file(s) to blob storage", count)
    return count


# ── Download ────────────────────────────────────────────────────

def download_to_local(blob_name: str, local_path: pathlib.Path) -> bool:
    """Download a single blob to *local_path*.  Returns True on success."""
    try:
        container = _get_container()
        blob = container.get_blob_client(blob_name)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as fh:
            fh.write(blob.download_blob().readall())
        return True
    except Exception as exc:
        log.debug("Blob download failed for %s: %s", blob_name, exc)
        return False


# ── List ────────────────────────────────────────────────────────

def list_reports(mime_suffixes: set[str]) -> list[dict[str, str]]:
    """Return metadata for all blobs whose suffix is in *mime_suffixes*."""
    try:
        container = _get_container()
        results: list[dict[str, str]] = []
        for blob in container.list_blobs():
            suffix = pathlib.PurePosixPath(blob.name).suffix
            if suffix in mime_suffixes:
                results.append({
                    "name": pathlib.PurePosixPath(blob.name).name,
                    "path": blob.name,
                    "url": f"/reports/{blob.name}",
                    "size": str(blob.size),
                })
        return sorted(results, key=lambda r: r["path"], reverse=True)
    except Exception as exc:
        log.warning("Blob list failed: %s", exc)
        return []
