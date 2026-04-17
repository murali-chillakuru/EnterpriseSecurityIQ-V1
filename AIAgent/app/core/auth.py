"""
EnterpriseSecurityIQ — Authentication

Both ARM and Graph operations use DefaultAzureCredential, which picks up
the logged-in az cli session, managed identity, or environment variables.
No interactive browser/device-code prompts are required.

Service principal mode uses a single ClientSecretCredential for both.

User-delegated mode (token passthrough) accepts pre-acquired OAuth tokens
from the SPA and wraps them in a credential that returns the correct token
for the requested scope (Graph vs ARM).
"""

from __future__ import annotations
import os
import time
import httpx
from azure.core.credentials import AccessToken
from azure.core.credentials_async import AsyncTokenCredential
from azure.identity.aio import (
    AzureCliCredential,
    DefaultAzureCredential,
    ClientSecretCredential,
)
from azure.mgmt.resource.subscriptions.aio import SubscriptionClient
from msgraph import GraphServiceClient
from msgraph_beta import GraphServiceClient as BetaGraphServiceClient
from app.core.logger import log


class UserTokenCredential(AsyncTokenCredential):
    """Wraps pre-acquired user OAuth tokens (Graph + ARM) into an
    AsyncTokenCredential that the Azure SDKs and MS Graph SDK can consume.

    The SPA acquires two tokens:
      - graph_token:  for https://graph.microsoft.com scopes
      - arm_token:    for https://management.azure.com scopes

    get_token() inspects the requested scopes and returns the appropriate one.
    """

    def __init__(self, graph_token: str, arm_token: str):
        self._graph_token = graph_token
        self._arm_token = arm_token
        # Tokens from MSAL.js are typically valid 60-90 min; set a generous expiry
        self._expires_on = int(time.time()) + 3600

    async def get_token(self, *scopes: str, **kwargs) -> AccessToken:
        scope_str = " ".join(scopes).lower()
        if "graph.microsoft.com" in scope_str:
            return AccessToken(self._graph_token, self._expires_on)
        if "management.azure.com" in scope_str or "management.core.windows.net" in scope_str:
            return AccessToken(self._arm_token, self._expires_on)
        # Default to ARM token for other scopes (e.g. resource-specific)
        return AccessToken(self._arm_token, self._expires_on)

    async def close(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


# ── Per-request context variable for user-delegated credentials ─
# Set by api.py before executing tool functions; read by agent.py _get_creds().
import contextvars
_request_creds: contextvars.ContextVar["ComplianceCredentials | None"] = contextvars.ContextVar(
    "_request_creds", default=None
)


class ComplianceCredentials:
    """Manages Azure + Graph credentials for assessment.

    ARM calls:  DefaultAzureCredential / AzureCliCredential.
    Graph calls: Same credential with .default scope (uses az login session).
    SP mode:     ClientSecretCredential for both (CI/CD pipelines).
    """

    def __init__(self, tenant_id: str = "", auth_mode: str = "auto",
                 user_credential: AsyncTokenCredential | None = None):
        # When a user_credential is provided with an explicit tenant_id
        # (decoded from the user's JWT), prefer it over the hosting env var.
        if user_credential and tenant_id:
            self.tenant_id = tenant_id
        else:
            self.tenant_id = tenant_id or os.getenv("AZURE_TENANT_ID", "")
        self.auth_mode = auth_mode or os.getenv("ENTERPRISESECURITYIQ_AUTH_MODE", "auto")
        self._credential = None
        self._user_credential = user_credential  # pre-acquired user tokens
        self._http_client: httpx.AsyncClient | None = None
        self._graph_client: GraphServiceClient | None = None
        self._beta_graph_client: BetaGraphServiceClient | None = None

    @property
    def credential(self):
        if self._user_credential is not None:
            return self._user_credential
        if self._credential is None:
            self._credential = self._create_credential()
        return self._credential

    def _create_credential(self):
        mode = self.auth_mode.lower()
        if mode == "serviceprincipal":
            client_id = os.getenv("AZURE_CLIENT_ID", "")
            client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
            if not client_id or not client_secret:
                raise ValueError("ServicePrincipal mode requires AZURE_CLIENT_ID and AZURE_CLIENT_SECRET")
            log.info("Auth mode: ServicePrincipal (tenant=%s, client=%s)", self.tenant_id, client_id)
            return ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        elif mode == "appregistration":
            # Enhancement #1: App Registration fallback for elevated Graph scopes
            # Uses client credentials with pre-consented application permissions
            client_id = os.getenv("ENTERPRISESECURITYIQ_APP_CLIENT_ID", os.getenv("AZURE_CLIENT_ID", ""))
            client_secret = os.getenv("ENTERPRISESECURITYIQ_APP_CLIENT_SECRET", os.getenv("AZURE_CLIENT_SECRET", ""))
            if not client_id or not client_secret:
                raise ValueError(
                    "AppRegistration mode requires ENTERPRISESECURITYIQ_APP_CLIENT_ID and "
                    "ENTERPRISESECURITYIQ_APP_CLIENT_SECRET environment variables"
                )
            log.info(
                "Auth mode: AppRegistration (tenant=%s, client=%s) — "
                "elevated Graph permissions for M365 compliance APIs",
                self.tenant_id, client_id,
            )
            return ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        elif mode == "azurecli":
            log.info("Auth mode: AzureCliCredential (using az login session)")
            return AzureCliCredential(
                tenant_id=self.tenant_id if self.tenant_id else None,
            )
        else:
            # Auto: prefer Azure CLI if user is logged in, fall back to DefaultAzureCredential
            log.info("Auth mode: DefaultAzureCredential (using logged-in user's token)")
            kwargs = {}
            if self.tenant_id:
                kwargs["additionally_allowed_tenants"] = [self.tenant_id]
                # Exclude the shared token cache to avoid stale credential issues
                kwargs["exclude_shared_token_cache_credential"] = True
            else:
                kwargs["additionally_allowed_tenants"] = ["*"]
            return DefaultAzureCredential(**kwargs)

    def _get_http_client(self) -> httpx.AsyncClient:
        """Return a shared httpx.AsyncClient with robust timeout and connection pool settings."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=30.0),
                limits=httpx.Limits(
                    max_connections=20,
                    max_keepalive_connections=10,
                    keepalive_expiry=30,
                ),
            )
        return self._http_client

    def get_graph_client(self) -> GraphServiceClient:
        """Return a GraphServiceClient (v1.0) with a shared httpx connection pool.

        Uses .default scope — the logged-in user's Entra roles determine
        what Graph APIs are accessible. No interactive prompts.
        """
        if self._graph_client is None:
            from kiota_authentication_azure.azure_identity_authentication_provider import (
                AzureIdentityAuthenticationProvider,
            )
            from kiota_http.httpx_request_adapter import HttpxRequestAdapter

            auth_provider = AzureIdentityAuthenticationProvider(
                self.credential,
                scopes=["https://graph.microsoft.com/.default"],
            )
            adapter = HttpxRequestAdapter(auth_provider, http_client=self._get_http_client())
            self._graph_client = GraphServiceClient(request_adapter=adapter)
            log.info("Graph auth: using credential with .default scope (shared httpx pool)")
        return self._graph_client

    def get_graph_beta_client(self) -> BetaGraphServiceClient:
        """Return a beta GraphServiceClient with a shared httpx connection pool.

        Used for PIM governance endpoints, riskyServicePrincipals, etc.
        """
        if self._beta_graph_client is None:
            from kiota_authentication_azure.azure_identity_authentication_provider import (
                AzureIdentityAuthenticationProvider,
            )
            from kiota_http.httpx_request_adapter import HttpxRequestAdapter

            auth_provider = AzureIdentityAuthenticationProvider(
                self.credential,
                scopes=["https://graph.microsoft.com/.default"],
            )
            adapter = HttpxRequestAdapter(auth_provider, http_client=self._get_http_client())
            self._beta_graph_client = BetaGraphServiceClient(request_adapter=adapter)
            log.info("Graph auth (beta): using credential with .default scope (shared httpx pool)")
        return self._beta_graph_client

    def get_subscription_client(self) -> SubscriptionClient:
        return SubscriptionClient(credential=self.credential)

    async def list_subscriptions(self, subscription_filter: list[str] | None = None) -> list[dict]:
        subs = []
        client = self.get_subscription_client()
        try:
            async for sub in client.subscriptions.list():
                info = {
                    "subscription_id": sub.subscription_id,
                    "display_name": sub.display_name,
                    "state": sub.state.value if hasattr(sub.state, "value") else str(sub.state or "Unknown"),
                    "tenant_id": sub.tenant_id,
                }
                if subscription_filter:
                    if sub.subscription_id in subscription_filter or sub.display_name in subscription_filter:
                        subs.append(info)
                else:
                    if info["state"] == "Enabled":
                        subs.append(info)
        finally:
            await client.close()
        log.info("Discovered %d subscriptions", len(subs))
        return subs

    async def get_tenant_info(self) -> dict:
        graph = self.get_graph_client()
        orgs = await graph.organization.get()
        if orgs and orgs.value:
            org = orgs.value[0]
            return {
                "tenant_id": org.id,
                "display_name": org.display_name,
                "on_premises_sync_enabled": org.on_premises_sync_enabled,
                "verified_domains": [d.name for d in (org.verified_domains or [])],
            }
        return {"tenant_id": self.tenant_id, "display_name": "Unknown"}

    async def close(self):
        self._graph_client = None
        self._beta_graph_client = None
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        if self._credential:
            await self._credential.close()

    # ------------------------------------------------------------------
    # Pre-flight permissions check
    # ------------------------------------------------------------------
    # Minimum Entra roles that grant sufficient read access for assessment
    _SUFFICIENT_ROLES = {
        "Global Administrator", "Global Reader", "Security Administrator",
        "Security Reader", "Compliance Administrator",
    }

    async def preflight_check(self) -> dict:
        """Verify the logged-in identity has the minimum permissions to run
        a full assessment.  Returns a dict with:
          ok        – bool, True if assessment can proceed
          user      – str, user principal name or app id
          tenant    – str, tenant display name
          roles     – list[str], active Entra directory roles
          arm_subs  – int, number of accessible subscriptions
          graph_ok  – bool, Graph directory read succeeded
          warnings  – list[str], non-fatal issues
          errors    – list[str], blocking issues
        """
        result: dict = {
            "ok": True, "user": "unknown", "tenant": "unknown",
            "roles": [], "arm_subs": 0, "graph_ok": False,
            "warnings": [], "errors": [],
        }

        # 1. ARM check — can we list subscriptions?
        try:
            subs = await self.list_subscriptions()
            result["arm_subs"] = len(subs)
            if not subs:
                result["warnings"].append("No enabled Azure subscriptions found — ARM collectors will return no data.")
        except Exception as exc:
            result["errors"].append(f"ARM access failed (cannot list subscriptions): {exc}")
            result["ok"] = False

        # 2. Graph check — read /me and tenant org
        graph = self.get_graph_client()
        try:
            me = await graph.me.get()
            result["user"] = getattr(me, "user_principal_name", None) or getattr(me, "display_name", "unknown")
        except Exception:
            # Service principal path — no /me endpoint
            result["user"] = "(service principal)"

        try:
            orgs = await graph.organization.get()
            if orgs and orgs.value:
                result["tenant"] = orgs.value[0].display_name or "unknown"
            result["graph_ok"] = True
        except Exception as exc:
            result["errors"].append(f"Graph access failed (cannot read organization): {exc}")
            result["ok"] = False

        # 3. Entra role check — list the user's active directory role assignments
        try:
            my_roles: list[str] = []

            # Approach 1: /me/memberOf — check both odata_type and additional_data
            try:
                member_of = await graph.me.member_of.get()
                if member_of and member_of.value:
                    log.info("[preflight] /me/memberOf returned %d items", len(member_of.value))
                    for item in member_of.value:
                        odata = getattr(item, "odata_type", "") or ""
                        ad = getattr(item, "additional_data", {}) or {}
                        if not odata:
                            odata = ad.get("@odata.type", "")
                        dname = getattr(item, "display_name", None) or ad.get("displayName")
                        log.info("[preflight]   memberOf item: odata=%s  name=%s", odata, dname)
                        if "directoryRole" in odata:
                            if dname:
                                my_roles.append(dname)
                else:
                    log.warning("[preflight] /me/memberOf returned no items")
            except Exception as exc1:
                log.warning("[preflight] Approach 1 (/me/memberOf) failed: %s", exc1, exc_info=True)

            # Approach 2 (fallback): /directoryRoles then match members
            if not my_roles:
                try:
                    me_obj = await graph.me.get()
                    me_id = getattr(me_obj, "id", None)
                    log.info("[preflight] Approach 2: me_id=%s", me_id)
                    if me_id:
                        roles_resp = await graph.directory_roles.get()
                        if roles_resp and roles_resp.value:
                            log.info("[preflight] %d activated directory roles found", len(roles_resp.value))
                            for role in roles_resp.value:
                                role_id = getattr(role, "id", "")
                                role_name = getattr(role, "display_name", "?")
                                try:
                                    members = await graph.directory_roles.by_directory_role_id(role_id).members.get()
                                    if members and members.value:
                                        for m in members.value:
                                            mid = getattr(m, "id", None)
                                            if not mid:
                                                m_ad = getattr(m, "additional_data", {}) or {}
                                                mid = m_ad.get("id")
                                            if mid == me_id:
                                                log.info("[preflight]   Matched role: %s", role_name)
                                                if role_name:
                                                    my_roles.append(role_name)
                                                break
                                except Exception as exc_m:
                                    log.debug("[preflight]   members(%s) failed: %s", role_name, exc_m)
                                    continue
                except Exception as exc2:
                    log.warning("[preflight] Approach 2 (/directoryRoles) failed: %s", exc2, exc_info=True)

            # Approach 3 (fallback): direct REST call via httpx for /me/memberOf
            if not my_roles:
                try:
                    from azure.core.credentials import AccessToken
                    tok: AccessToken = await self.credential.get_token("https://graph.microsoft.com/.default")
                    headers = {"Authorization": f"Bearer {tok.token}", "ConsistencyLevel": "eventual"}
                    url = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=displayName"
                    http = self._get_http_client()
                    resp = await http.get(url, headers=headers)
                    log.info("[preflight] Approach 3 REST status=%s body=%s", resp.status_code, resp.text[:500])
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data.get("value", []):
                            dn = item.get("displayName")
                            if dn:
                                my_roles.append(dn)
                                log.info("[preflight]   REST role: %s", dn)
                except Exception as exc3:
                    log.warning("[preflight] Approach 3 (REST) failed: %s", exc3)

            result["roles"] = my_roles

            # Check if any sufficient role is present
            if not (set(my_roles) & self._SUFFICIENT_ROLES):
                result["warnings"].append(
                    f"User has roles {my_roles} but none of the recommended "
                    f"roles {sorted(self._SUFFICIENT_ROLES)}. "
                    "Some Entra collectors may get 403 errors."
                )
        except Exception as exc:
            result["warnings"].append(f"Could not enumerate Entra roles: {exc}")

        # 4. Quick Graph permission probes — test a few critical endpoints
        probes = {
            "Users": "User.Read.All",
            "ConditionalAccess": "Policy.Read.All",
            "RoleManagement": "RoleManagement.Read.All",
        }
        for probe_name, scope_hint in probes.items():
            try:
                if probe_name == "Users":
                    await graph.users.get(
                        request_configuration=lambda c: setattr(c.query_parameters, 'top', 1) or c
                    )
                elif probe_name == "ConditionalAccess":
                    await graph.identity.conditional_access.policies.get()
                elif probe_name == "RoleManagement":
                    await graph.directory_roles.get()
            except Exception as exc:
                err_str = str(exc)
                if "403" in err_str or "Forbidden" in err_str or "Authorization" in err_str:
                    result["warnings"].append(
                        f"Graph probe '{probe_name}' returned 403 — may need {scope_hint} permission."
                    )
                elif "401" in err_str or "Unauthorized" in err_str:
                    result["errors"].append(
                        f"Graph probe '{probe_name}' returned 401 — credentials may be invalid."
                    )
                    result["ok"] = False

        return result
