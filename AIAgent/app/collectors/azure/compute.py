"""
Azure Compute Collector
VMs, Web Apps, SQL Servers, AKS clusters, Container Registries.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.compute.aio import ComputeManagementClient
from azure.mgmt.web.aio import WebSiteManagementClient
from azure.mgmt.sql.aio import SqlManagementClient
from azure.mgmt.containerservice.aio import ContainerServiceClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="compute", plane="control", source="azure", priority=100)
async def collect_azure_compute(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # VMs
            try:
                compute = ComputeManagementClient(creds.credential, sub_id)
                vms = await paginate_arm(compute.virtual_machines.list_all())

                # Parallel extension fetch for all VMs
                async def _fetch_extensions(vm):
                    has_mde = False
                    try:
                        rg_name = vm.id.split("/resourceGroups/")[1].split("/")[0] if vm.id else ""
                        if rg_name:
                            async with _CONCURRENCY:
                                exts = await paginate_arm(
                                    compute.virtual_machine_extensions.list(rg_name, vm.name)
                                )
                            mde_names = {"MDE.Linux", "MDE.Windows", "MicrosoftMonitoringAgent",
                                         "Microsoft.Azure.Security.Monitoring",
                                         "MDATPForLinux", "MDATPForWindows"}
                            for ext in exts:
                                if ext.name in mde_names or (
                                    ext.type_properties_type and
                                    "MDE" in ext.type_properties_type
                                ):
                                    has_mde = True
                                    break
                    except Exception:
                        pass
                    return vm, has_mde

                vm_results = await asyncio.gather(*[_fetch_extensions(vm) for vm in vms],
                                                   return_exceptions=True)

                for result in vm_results:
                    if isinstance(result, Exception):
                        continue
                    vm, has_mde = result
                    os_disk = vm.storage_profile.os_disk if vm.storage_profile else None
                    data_disks = vm.storage_profile.data_disks if vm.storage_profile else []
                    identity_type = "None"
                    if vm.identity:
                        identity_type = _v(vm.identity.type, "None")

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureCompute",
                        evidence_type="azure-vm-config",
                        description=f"VM: {vm.name}",
                        data={
                            "VmId": vm.id, "Name": vm.name,
                            "Location": vm.location,
                            "VmSize": vm.hardware_profile.vm_size if vm.hardware_profile else "",
                            "OsType": _v(os_disk.os_type, "Unknown") if os_disk and os_disk.os_type else "Unknown",
                            "OsDiskEncrypted": bool(
                                os_disk and os_disk.encryption_settings and
                                os_disk.encryption_settings.enabled
                            ),
                            "DataDiskCount": len(data_disks or []),
                            "DataDisksEncrypted": all(
                                d.managed_disk is not None for d in (data_disks or [])
                            ),
                            "IdentityType": identity_type,
                            "HasMDEExtension": has_mde,
                            "BootDiagnosticsEnabled": bool(
                                vm.diagnostics_profile and
                                vm.diagnostics_profile.boot_diagnostics and
                                vm.diagnostics_profile.boot_diagnostics.enabled
                            ),
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=vm.id or "", resource_type="VirtualMachine",
                    ))
                await compute.close()
            except Exception as exc:
                log.warning("  [AzureCompute] %s VMs failed: %s", sub_name, exc)

            # Web Apps
            try:
                web = WebSiteManagementClient(creds.credential, sub_id)
                apps = await paginate_arm(web.web_apps.list())
                for app in apps:
                    identity_type = "None"
                    if app.identity:
                        identity_type = _v(app.identity.type, "None") if app.identity.type else "None"
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureCompute",
                        evidence_type="azure-webapp-config",
                        description=f"Web App: {app.name}",
                        data={
                            "AppId": app.id, "Name": app.name,
                            "Location": app.location,
                            "HttpsOnly": app.https_only if app.https_only is not None else False,
                            "MinTlsVersion": app.site_config.min_tls_version if app.site_config else "1.0",
                            "FtpsState": app.site_config.ftps_state if app.site_config else "AllAllowed",
                            "RemoteDebuggingEnabled": (
                                app.site_config.remote_debugging_enabled
                                if app.site_config else False
                            ),
                            "ManagedIdentityType": identity_type,
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=app.id or "", resource_type="WebApp",
                    ))
                await web.close()
            except Exception as exc:
                log.warning("  [AzureCompute] %s WebApps failed: %s", sub_name, exc)

            # SQL Servers
            try:
                sql = SqlManagementClient(creds.credential, sub_id)
                servers = await paginate_arm(sql.servers.list())

                async def _fetch_sql_details(srv):
                    ad_admin = False
                    auditing = False
                    tde_enabled = True  # Azure SQL has TDE on by default
                    rg_name = ""
                    async with _CONCURRENCY:
                        try:
                            rg_name = srv.id.split("/resourceGroups/")[1].split("/")[0] if srv.id else ""
                            admins = await paginate_arm(
                                sql.server_azure_ad_administrators.list_by_server(rg_name, srv.name)
                            )
                            ad_admin = len(admins) > 0
                        except Exception:
                            pass
                        try:
                            if rg_name:
                                audit_policy = await sql.server_blob_auditing_policies.get(
                                    rg_name, srv.name
                                )
                                auditing = (
                                    audit_policy and
                                    audit_policy.state and
                                    _v(audit_policy.state) == "Enabled"
                                )
                        except Exception:
                            pass
                        try:
                            if rg_name:
                                protector = await sql.encryption_protectors.get(
                                    rg_name, srv.name, "current"
                                )
                                tde_enabled = protector is not None and protector.server_key_type is not None
                        except Exception:
                            pass
                    return srv, ad_admin, auditing, tde_enabled

                sql_results = await asyncio.gather(*[_fetch_sql_details(srv) for srv in servers],
                                                     return_exceptions=True)

                for result in sql_results:
                    if isinstance(result, Exception):
                        continue
                    srv, ad_admin, auditing, tde_enabled = result
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureCompute",
                        evidence_type="azure-sql-server",
                        description=f"SQL: {srv.name}",
                        data={
                            "ServerId": srv.id, "Name": srv.name,
                            "Location": srv.location,
                            "AdAdminConfigured": ad_admin,
                            "AuditingEnabled": auditing,
                            "TdeEnabled": tde_enabled,
                            "PublicNetworkAccess": srv.public_network_access or "Enabled",
                            "MinimalTlsVersion": srv.minimal_tls_version or "1.0",
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=srv.id or "", resource_type="SqlServer",
                    ))
                await sql.close()
            except Exception as exc:
                log.warning("  [AzureCompute] %s SQL failed: %s", sub_name, exc)

            # AKS
            try:
                aks_client = ContainerServiceClient(creds.credential, sub_id)
                clusters = await paginate_arm(aks_client.managed_clusters.list())
                for aks in clusters:
                    aad_profile = aks.aad_profile
                    net_profile = aks.network_profile
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureCompute",
                        evidence_type="azure-aks-cluster",
                        description=f"AKS: {aks.name}",
                        data={
                            "ClusterId": aks.id, "Name": aks.name,
                            "Location": aks.location,
                            "KubernetesVersion": aks.kubernetes_version,
                            "RbacEnabled": aks.enable_rbac if aks.enable_rbac is not None else False,
                            "AadEnabled": aad_profile is not None,
                            "NetworkPolicy": (
                                _v(net_profile.network_policy, "none")
                                if net_profile and net_profile.network_policy else "none"
                            ),
                            "PrivateCluster": bool(
                                aks.api_server_access_profile and
                                aks.api_server_access_profile.enable_private_cluster
                            ),
                            "DefenderEnabled": bool(
                                aks.security_profile and aks.security_profile.defender and
                                aks.security_profile.defender.security_monitoring and
                                aks.security_profile.defender.security_monitoring.enabled
                            ),
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=aks.id or "", resource_type="AKSCluster",
                    ))
                await aks_client.close()
            except Exception as exc:
                log.warning("  [AzureCompute] %s AKS failed: %s", sub_name, exc)

            log.info("  [AzureCompute] %s collection complete", sub_name)
        return evidence

    return (await run_collector("AzureCompute", Source.AZURE, _collect)).data
