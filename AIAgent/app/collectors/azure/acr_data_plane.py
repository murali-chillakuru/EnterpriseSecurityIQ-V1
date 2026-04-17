"""
Azure Container Registry Data-Plane Collector
Repository enumeration, tag mutability, and image manifest details.
"""

from __future__ import annotations
from azure.containerregistry.aio import ContainerRegistryClient
from azure.mgmt.containerregistry.aio import ContainerRegistryManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="acr_data_plane", plane="data", source="azure", priority=240)
async def collect_azure_acr_data_plane(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                mgmt = ContainerRegistryManagementClient(creds.credential, sub_id)
                registries = await paginate_arm(mgmt.registries.list())

                for reg in registries:
                    login_server = getattr(reg, "login_server", None) or ""
                    if not login_server:
                        continue

                    repo_count = 0
                    total_tags = 0
                    repos_without_tag_immutability = 0
                    stale_repos = 0

                    try:
                        acr = ContainerRegistryClient(
                            endpoint=f"https://{login_server}",
                            credential=creds.credential,
                            audience="https://management.azure.com",
                        )
                        async for repo_name in acr.list_repository_names():
                            repo_count += 1
                            try:
                                repo_props = await acr.get_repository_properties(repo_name)
                                if repo_props:
                                    writable = getattr(repo_props, "can_write", True)
                                    can_delete = getattr(repo_props, "can_delete", True)
                                    if writable and can_delete:
                                        repos_without_tag_immutability += 1
                                    tag_count = getattr(repo_props, "tag_count", 0)
                                    total_tags += tag_count or 0
                                    # A repository with 0 tags may be stale
                                    if not tag_count:
                                        stale_repos += 1
                            except Exception:
                                pass
                        await acr.close()
                    except Exception as exc:
                        log.debug("  [AcrDataPlane] %s data-plane: %s", login_server, exc)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AcrDataPlane",
                        evidence_type="azure-acr-repository",
                        description=f"ACR repos: {reg.name}",
                        data={
                            "RegistryId": reg.id,
                            "RegistryName": reg.name,
                            "LoginServer": login_server,
                            "RepositoryCount": repo_count,
                            "TotalTags": total_tags,
                            "ReposWithoutTagImmutability": repos_without_tag_immutability,
                            "StaleRepositories": stale_repos,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=reg.id or "",
                        resource_type="Microsoft.ContainerRegistry/registries",
                    ))

                await mgmt.close()
                log.info("  [AcrDataPlane] %s: %d registries inspected", sub_name, len(registries))
            except Exception as exc:
                log.warning("  [AcrDataPlane] %s failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("AcrDataPlane", Source.AZURE, _collect)
    return result.data
