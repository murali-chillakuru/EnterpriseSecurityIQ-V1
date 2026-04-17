"""
Resource Inventory
Shared singleton that caches the ARM resource list across collectors.
Collectors that need to enumerate resources (e.g. storage accounts, VMs)
reference the inventory instead of re-listing from Azure.
"""

from __future__ import annotations
import asyncio
from typing import Any
from app.logger import log


class ResourceInventory:
    """Thread-safe cache of Azure resource lists.

    Usage::

        inv = ResourceInventory.instance()
        # Populate once (idempotent)
        await inv.ensure_loaded(creds, subscriptions)
        # Then query from any collector:
        storage = inv.by_type("Microsoft.Storage/storageAccounts")
        vms = inv.by_type("Microsoft.Compute/virtualMachines")
        all_res = inv.all()
    """

    _instance: ResourceInventory | None = None
    _lock = asyncio.Lock()

    def __init__(self) -> None:
        self._resources: list[dict] = []
        self._by_type: dict[str, list[dict]] = {}
        self._by_sub: dict[str, list[dict]] = {}
        self._loaded = False

    @classmethod
    def instance(cls) -> ResourceInventory:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        cls._instance = None

    @property
    def loaded(self) -> bool:
        return self._loaded

    async def ensure_loaded(self, creds: Any, subscriptions: list[dict]) -> None:
        """Load the resource list if not already cached.  Idempotent."""
        async with self._lock:
            if self._loaded:
                return
            await self._load(creds, subscriptions)
            self._loaded = True

    async def _load(self, creds: Any, subscriptions: list[dict]) -> None:
        from azure.mgmt.resource import ResourceManagementClient
        from app.collectors.base import paginate_arm

        for sub in subscriptions:
            sub_id = sub.get("subscription_id", sub.get("id", ""))
            sub_name = sub.get("display_name", sub_id)
            try:
                client = ResourceManagementClient(creds.credential, sub_id)
                resources = await paginate_arm(client.resources.list())
                for r in resources:
                    rtype = getattr(r, "type", "") or ""
                    entry = {
                        "ResourceId": getattr(r, "id", ""),
                        "Name": getattr(r, "name", ""),
                        "Type": rtype,
                        "Location": getattr(r, "location", ""),
                        "SubscriptionId": sub_id,
                        "SubscriptionName": sub_name,
                    }
                    self._resources.append(entry)
                    self._by_type.setdefault(rtype, []).append(entry)
                    self._by_sub.setdefault(sub_id, []).append(entry)
            except Exception as exc:
                log.warning("ResourceInventory: failed for sub %s: %s", sub_id, exc)

        log.info("ResourceInventory: cached %d resources across %d subscriptions",
                 len(self._resources), len(self._by_sub))

    def all(self) -> list[dict]:
        return self._resources

    def by_type(self, resource_type: str) -> list[dict]:
        return self._by_type.get(resource_type, [])

    def by_subscription(self, sub_id: str) -> list[dict]:
        return self._by_sub.get(sub_id, [])

    def types(self) -> list[str]:
        return sorted(self._by_type.keys())

    def count(self) -> int:
        return len(self._resources)
