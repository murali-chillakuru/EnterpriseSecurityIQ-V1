# PostureIQ — Authentication Architecture

> Comprehensive reference for all identity objects, permissions, and auth flows
> used by PostureIQ.

---

## Table of Contents

0. [Security Model (v33+)](#0-security-model-v33)
1. [Key Concepts](#1-key-concepts)
2. [Identity Objects](#2-identity-objects)
3. [App Registration (EnterpriseSecurityIQ-SPA)](#3-app-registration-enterprisesecurityiq-spa)
4. [Service Principal (Enterprise Application)](#4-service-principal-enterprise-application)
5. [User-Assigned Managed Identity (ESIQNew-identity)](#5-user-assigned-managed-identity-esiqnew-identity)
6. [Permissions Summary](#6-permissions-summary)
7. [Authentication Flow — End to End](#7-authentication-flow--end-to-end)
8. [Credential Resolution in Code](#8-credential-resolution-in-code)
9. [Dual-Auth Model: User-Delegated vs Managed Identity](#9-dual-auth-model-user-delegated-vs-managed-identity)
10. [MSAL.js Configuration](#10-msaljs-configuration)
11. [Troubleshooting](#11-troubleshooting)
12. [Reference IDs](#12-reference-ids)

---

## 0. Security Model (v33+)

> **Critical design principle**: The `/chat` API endpoint **requires** user-delegated tokens.
> Requests without valid `graph_token` and `arm_token` are rejected with HTTP 401.
> The managed identity (`ESIQNew-identity`) is used **only** for:
> - CLI scripts (`run_risk_analysis.py`, `run_data_security.py`, etc.) run from a terminal
> - Infrastructure tasks (ACR pull, blob storage, Azure AI Foundry access)
>
> This ensures that web app users always operate under their own Entra ID permissions — no
> privilege escalation through a managed identity fallback.

---

## 1. Key Concepts

### Application (App Registration) vs Service Principal (SPN)

| Concept | What it is | Azure Portal location |
|---|---|---|
| **App Registration** | A *template/definition* of your application in Entra ID. Defines the client ID, redirect URIs, and what API permissions the app *declares* it needs. Think of it as the "blueprint." | Entra ID > App registrations |
| **Service Principal (SPN)** | An *instance* of the app registration in a specific tenant. When an app registration is created, a corresponding SPN (Enterprise Application) is automatically created in the same tenant. The SPN is what actually gets permissions *granted/consented* and is what users interact with. Think of it as the "running instance." | Entra ID > Enterprise applications |
| **Managed Identity** | A special type of Service Principal managed by Azure itself (no secrets to rotate). Assigned to Azure resources (VMs, Container Apps, Functions) so they can authenticate to other Azure services. | Entra ID > Enterprise applications (type = Managed Identity) |

**Analogy**: An App Registration is like a class definition. A Service Principal is like an object instance of that class. A Managed Identity is like an auto-managed object that Azure creates and handles the credentials for.

### Delegated vs Application Permissions

| Permission type | Who is acting | When to use |
|---|---|---|
| **Delegated** | A *signed-in user* — the app acts on behalf of the user. Access is limited by both the app's permissions AND the user's own permissions. | SPA/web apps where a human logs in |
| **Application** | The *application itself* — no user context. The app has the full permission regardless of any user. | Background services, daemons, managed identities |

---

## 2. Identity Objects

PostureIQ uses **two distinct identity objects** with different roles:

```
┌──────────────────────────────────────────────────────────┐
│                      Entra ID Tenant                     │
│              4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67        │
│                                                          │
│  ┌─────────────────────────────┐                         │
│  │  App Registration           │                         │
│  │  "EnterpriseSecurityIQ-SPA" │                         │
│  │  appId: ffb6f10d-...        │                         │
│  │  (defines the SPA client)   │                         │
│  └──────────┬──────────────────┘                         │
│             │ creates                                    │
│  ┌──────────▼──────────────────┐                         │
│  │  Service Principal (SPN)    │                         │
│  │  objectId: 1b42cfa1-...     │                         │
│  │  (runtime identity for SPA) │                         │
│  │  Has: delegated permissions │                         │
│  └─────────────────────────────┘                         │
│                                                          │
│  ┌─────────────────────────────┐                         │
│  │  Managed Identity           │                         │
│  │  "ESIQNew-identity"         │                         │
│  │  clientId: d5d10273-...     │                         │
│  │  (backend server identity)  │                         │
│  │  Has: application perms     │                         │
│  └─────────────────────────────┘                         │
└──────────────────────────────────────────────────────────┘
```

---

## 3. App Registration (EnterpriseSecurityIQ-SPA)

### Purpose

The App Registration defines the **SPA (Single Page Application)** that end users interact with in the browser. It tells Entra ID:
- "This application exists and has client ID `ffb6f10d-...`"
- "Users should be redirected back to these URLs after login"
- "This app needs these API permissions on behalf of signed-in users"

### Configuration

| Property | Value |
|---|---|
| Display name | `EnterpriseSecurityIQ-SPA` |
| Application (client) ID | `ffb6f10d-6991-430e-b3d6-23a0101a92b1` |
| Object ID | `fe171c21-b3a1-480d-a5f5-41e7c515d843` |
| Sign-in audience | `AzureADMyOrg` (single tenant) |
| Platform | **SPA** (important: NOT "Web") |
| Supported account types | Accounts in this organizational directory only |

### Redirect URIs (SPA Platform)

These are registered under the **SPA** platform (not "Web"). This is critical because:
- **SPA platform** → Entra ID uses Authorization Code Flow with PKCE (no client secret needed, suitable for browser apps)
- **Web platform** → Entra ID expects a confidential client with a client secret (would fail for a browser SPA)

| Redirect URI | Purpose |
|---|---|
| `http://localhost:8088` | Local development |
| `https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` | Production (Container App) |

### Declared Delegated Permissions

These permissions are declared in the App Registration and define what the SPA *can request* on behalf of a signed-in user:

**Microsoft Graph (8 declared)**:

| Permission | Type | Description | Admin Consent | Status |
|---|---|---|---|---|
| `User.Read` | Delegated | Sign in and read user profile | No | Granted |
| `Directory.Read.All` | Delegated | Read directory data (users, groups, roles) | Yes | Granted |
| `Policy.Read.All` | Delegated | Read all organization policies (Conditional Access, auth methods) | Yes | Granted |
| `RoleManagement.Read.All` | Delegated | Read role management data (PIM, role assignments) | Yes | Granted |
| `AuditLog.Read.All` | Delegated | Read sign-in activity logs (stale account detection) | Yes | Granted (v33) |
| `UserAuthenticationMethod.Read.All` | Delegated | Read MFA registration details | Yes | Granted (v33) |
| `IdentityRiskyUser.Read.All` | Delegated | Read risky user detections | Yes | Granted (v33) |
| `openid` | Delegated | Sign users in (OpenID Connect) | No | Granted |
| `profile` | Delegated | View users' basic profile | No | Granted |
| `offline_access` | Delegated | Maintain access to data (refresh tokens) | No | Granted |

**Azure Service Management (2 declared)**:

| Permission | Type | Description | Admin Consent | Status |
|---|---|---|---|---|
| `user_impersonation` | Delegated | Access Azure Resource Manager as the user | No | Granted |

### How the App Registration is Used

1. The browser SPA loads MSAL.js configured with `clientId: "ffb6f10d-..."` 
2. User clicks "Sign in with Microsoft" → MSAL.js redirects to `login.microsoftonline.com`
3. Entra ID looks up the App Registration by client ID to validate the redirect URI
4. After authentication, Entra ID issues tokens scoped to the declared permissions
5. The SPA receives a Graph API token and an ARM token

---

## 4. Service Principal (Enterprise Application)

### Purpose

The Service Principal is the **runtime representation** of the App Registration in the tenant. It is what:
- Actually holds the **consent grants** (admin consent)
- Appears in "Enterprise applications" in the portal
- Users see when they are asked to consent to permissions
- Can be disabled to block all sign-ins

### Configuration

| Property | Value |
|---|---|
| Display name | `EnterpriseSecurityIQ-SPA` |
| Object ID (SPN) | `1b42cfa1-b40a-4488-8f75-3ce3de2a11e6` |
| Application ID | `ffb6f10d-6991-430e-b3d6-23a0101a92b1` (same as App Registration) |
| Service principal type | `Application` |
| Account enabled | `true` |
| Owner tenant | `4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67` |

### Admin Consent Grants (oauth2PermissionGrants)

Admin consent was granted for all principals (tenant-wide), meaning any user in the tenant can sign in without individual consent prompts:

| Resource | Consent type | Scopes granted |
|---|---|---|
| Microsoft Graph (`8bd0732c-...`) | AllPrincipals (tenant-wide) | `User.Read Directory.Read.All Policy.Read.All RoleManagement.Read.All AuditLog.Read.All UserAuthenticationMethod.Read.All IdentityRiskyUser.Read.All openid profile offline_access` |
| Azure Service Management (`2b6caaea-...`) | AllPrincipals (tenant-wide) | `user_impersonation` |

### How the SPN is Used

The SPN is never directly referenced in code. Entra ID automatically uses it behind the scenes:
1. When a user signs in via the SPA, Entra ID checks the SPN to verify consent exists
2. Token claims include the SPN's `appId` as the `aud` (audience)
3. Admins can revoke access by disabling the SPN in Enterprise Applications

---

## 5. User-Assigned Managed Identity (ESIQNew-identity)

### Purpose

The Managed Identity is the **server-side identity** for the Container App backend. It is used when:
- No user is signed in (fallback mode)
- Backend needs to authenticate to Azure AI Foundry, Key Vault, ACR, etc.
- Application-level Graph API access (reads directory data without a user context)

### Configuration

| Property | Value |
|---|---|
| Name | `ESIQNew-identity` |
| Client ID | `d5d10273-4a8b-4251-9b9d-00fe035df97a` |
| Principal ID (Object ID) | `d742617c-6f14-4215-be65-e1f7b68866de` |
| Tenant ID | `4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67` |
| Type | User-assigned managed identity |
| Assigned to | Container App `esiqnew-agent` |

### Application Permissions (App Role Assignments)

Unlike the App Registration which has *delegated* permissions (on behalf of a user), the Managed Identity has *application* permissions (acts as itself):

| Permission | App Role ID | Resource | Description |
|---|---|---|---|
| `Directory.Read.All` | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` | Microsoft Graph | Read all directory data |
| `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | Microsoft Graph | Read all organization policies |
| `RoleManagement.Read.All` | `c7fbd983-d9aa-4fa7-84b8-17382c103bc4` | Microsoft Graph | Read all role management data |
| `AuditLog.Read.All` | `b0afded3-3588-46d8-8b3d-9842eff778da` | Microsoft Graph | Read sign-in activity logs (v33) |
| `UserAuthenticationMethod.Read.All` | `38d9df27-64da-44fd-b7c5-a6fbac20248f` | Microsoft Graph | Read MFA registration details (v33) |
| `IdentityRiskyUser.Read.All` | `dc5007c0-2d7d-4c42-879c-2dab87571379` | Microsoft Graph | Read risky user detections (v33) |

### How the Managed Identity is Used

1. **CLI scripts** (e.g. `run_risk_analysis.py`, `run_data_security.py`): `DefaultAzureCredential` picks up the managed identity when run inside the container, or `az login` session when run locally
2. When requesting a Graph API token with scope `https://graph.microsoft.com/.default`, the token includes the application permissions above
3. No secrets to manage — Azure handles credential rotation
4. **NOT used by the web API**: The `/chat` endpoint requires user-delegated tokens (v33+). The managed identity is no longer a fallback for unauthenticated web requests

---

## 6. Permissions Summary

```
┌───────────────────────────────────────────────────────────────┐
│                     Permission Model                          │
├───────────────────────┬───────────────────────────────────────┤
│  USER-DELEGATED       │  APPLICATION (Managed Identity)       │
│  (SPA → user login)   │  (CLI scripts only — no web fallback) │
├───────────────────────┼───────────────────────────────────────┤
│  User.Read            │  Directory.Read.All                   │
│  Directory.Read.All   │  Policy.Read.All                      │
│  Policy.Read.All      │  RoleManagement.Read.All              │
│  RoleManagement.Read  │  AuditLog.Read.All                    │
│  .All                 │  UserAuthenticationMethod.Read.All    │
│  AuditLog.Read.All    │  IdentityRiskyUser.Read.All           │
│  UserAuthentication   │                                       │
│  Method.Read.All      │  (no ARM — MI uses Azure RBAC         │
│  IdentityRiskyUser   │   role assignments instead)            │
│  .Read.All            │                                       │
│  user_impersonation   │                                       │
│  (ARM access)         │                                       │
│  openid, profile,     │                                       │
│  offline_access       │                                       │
├───────────────────────┼───────────────────────────────────────┤
│  Scoped to user's own │  Full tenant-wide read access         │
│  Entra role + consent │  (application-level, CLI only)        │
└───────────────────────┴───────────────────────────────────────┘
```

---

## 7. Authentication Flow — End to End

### Sequence Diagram

```
User Browser (SPA)          Entra ID               Container App (API)      Azure/Graph APIs
       │                        │                         │                       │
       │  1. Click "Sign In"    │                         │                       │
       │───────────────────────>│                         │                       │
       │  loginRedirect()       │                         │                       │
       │  (PKCE code challenge) │                         │                       │
       │                        │                         │                       │
       │  2. User enters creds  │                         │                       │
       │<───────────────────────│                         │                       │
       │  302 redirect + code   │                         │                       │
       │                        │                         │                       │
       │  3. handleRedirect()   │                         │                       │
       │───────────────────────>│                         │                       │
       │  Exchange code for     │                         │                       │
       │  tokens (PKCE verifier)│                         │                       │
       │<───────────────────────│                         │                       │
       │  id_token + access     │                         │                       │
       │  tokens (cached)       │                         │                       │
       │                        │                         │                       │
       │  4. acquireTokenSilent │                         │                       │
       │  (Graph scopes)        │                         │                       │
       │───────────────────────>│                         │                       │
       │<───────────────────────│                         │                       │
       │  graph_token           │                         │                       │
       │                        │                         │                       │
       │  5. acquireTokenSilent │                         │                       │
       │  (ARM scopes)          │                         │                       │
       │───────────────────────>│                         │                       │
       │<───────────────────────│                         │                       │
       │  arm_token             │                         │                       │
       │                        │                         │                       │
       │  6. POST /chat         │                         │                       │
       │  { message, graph_token, arm_token }             │                       │
       │────────────────────────────────────────────────>│                       │
       │                        │                         │                       │
       │                        │  7. UserTokenCredential │                       │
       │                        │  wraps both tokens      │                       │
       │                        │                         │                       │
       │                        │  8. Tool calls Graph API│                       │
       │                        │  (user's graph_token)   │                       │
       │                        │─────────────────────────────────────────────────>│
       │                        │                         │<──────────────────────│
       │                        │                         │                       │
       │                        │  9. Tool calls ARM API  │                       │
       │                        │  (user's arm_token)     │                       │
       │                        │─────────────────────────────────────────────────>│
       │                        │                         │<──────────────────────│
       │                        │                         │                       │
       │  10. Response           │                         │                       │
       │<────────────────────────────────────────────────│                       │
```

### Step-by-Step

| Step | Component | Action |
|------|-----------|--------|
| 1 | SPA (MSAL.js) | User clicks "Sign in with Microsoft". MSAL.js calls `loginRedirect()` with PKCE code challenge. Browser redirects to `login.microsoftonline.com`. |
| 2 | Entra ID | User authenticates (password, MFA, etc.). Entra ID validates the App Registration's redirect URI. |
| 3 | SPA (MSAL.js) | Browser returns to the SPA with an authorization code. `handleRedirectPromise()` exchanges the code for tokens using PKCE verifier. |
| 4 | SPA (MSAL.js) | `acquireTokenSilent()` gets a Graph API access token for scopes: `User.Read`, `Directory.Read.All`, `Policy.Read.All`, `RoleManagement.Read.All`. |
| 5 | SPA (MSAL.js) | `acquireTokenSilent()` gets an ARM access token for scope: `https://management.azure.com/user_impersonation`. |
| 6 | SPA → API | SPA sends `POST /chat` with the message AND both tokens in the request body. |
| 7 | API (`api.py`) | `UserTokenCredential` wraps both tokens. `ComplianceCredentials` is created with this credential. Stored in `_request_creds` context variable. |
| 8-9 | Agent tools (`agent.py`) | Each tool function calls `_get_creds()` to retrieve the per-request credentials. Graph SDK and ARM SDK use the user's tokens. API calls run as the signed-in user (delegated access). |
| 10 | API → SPA | Response returned to the browser. |

---

## 8. Credential Resolution in Code

### File: `app/auth.py`

```python
# UserTokenCredential — wraps SPA-acquired tokens
class UserTokenCredential(AsyncTokenCredential):
    def __init__(self, graph_token: str, arm_token: str):
        # Inspects requested scopes to return the correct token
        # "graph.microsoft.com" → returns graph_token
        # "management.azure.com" → returns arm_token

# ComplianceCredentials — main credential manager
class ComplianceCredentials:
    def __init__(self, user_credential=None):
        # If user_credential is provided → use it (delegated mode)
        # Otherwise → creates DefaultAzureCredential (managed identity)

    @property
    def credential(self):
        # Priority: user_credential > _credential (auto-created)

# Context variable for per-request credential passing
_request_creds: ContextVar[ComplianceCredentials | None]
```

### File: `app/api.py` — Token Enforcement (v33+)

```python
@app.post("/chat")
async def chat(req: ChatRequest):
    # SECURITY: Reject requests without user tokens — no managed identity fallback
    if not req.graph_token or not req.arm_token:
        raise HTTPException(status_code=401, detail="Authentication required")

    user_cred = UserTokenCredential(graph_token=..., arm_token=...)
    creds = ComplianceCredentials(user_credential=user_cred)
    _request_creds.set(creds)       # Always user-delegated for web API
```

> **v33 security change**: Prior to v33, missing tokens silently fell back to the
> managed identity, allowing unauthenticated callers to access tenant data with
> application-level permissions. This fallback was removed.

### File: `app/agent.py` — Tool Functions

```python
def _get_creds() -> ComplianceCredentials:
    """Return per-request user credentials if available, else managed identity."""
    creds = _request_creds.get(None)
    if creds is not None:
        return creds               # User-delegated tokens from SPA
    return ComplianceCredentials()  # Managed identity (DefaultAzureCredential)
```

All 14 tool functions (`run_postureiq_assessment`, `query_results`, `search_tenant`, `analyze_risk`, `assess_data_security`, `generate_rbac_report`, `generate_report`, `assess_copilot_readiness`, `assess_ai_agent_security`, `check_permissions`, `compare_runs`, `search_exposure`, `generate_custom_report`, `query_assessment_history`) call `_get_creds()` at the start.

---

## 9. Dual-Auth Model: User-Delegated vs Managed Identity

```
                    ┌─────────────────────┐
                    │  User signs in via   │
                    │  SPA + MSAL.js?      │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Tokens sent in    │
                    │   POST /chat body?  │
                    └──────┬────────┬─────┘
                     YES   │        │  NO
                    ┌──────▼─────┐  │
                    │ Delegated  │  │
                    │ Mode       │  │
                    │            │  │
                    │ Graph →    │  │  ┌──────────────┐
                    │ user token │  └─>│ MI Mode      │
                    │ ARM →      │     │              │
                    │ user token │     │ Graph → MI   │
                    │            │     │ ARM → MI     │
                    │ Scoped to  │     │              │
                    │ user perms │     │ Full app     │
                    └────────────┘     │ permissions  │
                                       └──────────────┘
```

| Aspect | User-Delegated Mode | Managed Identity Mode |
|---|---|---|
| When active | User logged in via SPA, tokens sent | CLI scripts (`run_risk_analysis.py`, etc.) |
| Graph identity | Signed-in user | `ESIQNew-identity` managed identity |
| ARM identity | Signed-in user | `ESIQNew-identity` managed identity |
| Permission scope | Intersection of app's delegated permissions AND user's Entra roles | Full application permissions granted to MI |
| Audit trail | Actions logged as the signed-in user's UPN | Actions logged as the managed identity |
| Use case | Interactive web usage (enforced — 401 without tokens) | CLI-only — automated/scheduled assessments |
| `/chat` API | **Required** — requests without tokens are rejected (401) | N/A — CLI scripts don't use the `/chat` endpoint |

---

## 10. MSAL.js Configuration

### Library

- **Version**: MSAL.js v5.6.3 (`@azure/msal-browser`)
- **Hosting**: Self-hosted at `/msal-browser.min.js` (served by FastAPI)
- **Why self-hosted**: The Microsoft CDN URL for v2.38.3 returned 404 (version removed). Self-hosting eliminates CDN dependency.

### Auth Flow

- **Protocol**: OAuth 2.0 Authorization Code Flow with PKCE
- **Method**: `loginRedirect()` / `handleRedirectPromise()` (not popup — Edge InPrivate blocks popups)
- **Token cache**: `sessionStorage` (scoped to browser tab)

### Configuration Object

```javascript
const MSAL_CONFIG = {
  auth: {
    clientId: "ffb6f10d-6991-430e-b3d6-23a0101a92b1",  // App Registration
    authority: "https://login.microsoftonline.com/4a3eb5f4-...",  // Tenant
    redirectUri: window.location.origin,  // Must match SPA redirect URIs
  },
  cache: { cacheLocation: "sessionStorage" }
};
```

### Token Acquisition

```javascript
// Graph token (delegated)
const GRAPH_SCOPES = [
  "User.Read", "Directory.Read.All",
  "Policy.Read.All", "RoleManagement.Read.All",
  "AuditLog.Read.All",                    // v33: sign-in activity
  "UserAuthenticationMethod.Read.All",     // v33: MFA details
  "IdentityRiskyUser.Read.All",            // v33: risky users
];

// ARM token (delegated)
const ARM_SCOPES = ["https://management.azure.com/user_impersonation"];

// Silent first → redirect fallback
const resp = await msalInstance.acquireTokenSilent({
  scopes: GRAPH_SCOPES, account: currentAccount
});
```

---

## 11. Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| "MSAL library failed to load" (red text) | CDN 404 or ad-blocker | Self-hosted at `/msal-browser.min.js` (current setup) |
| Login button does nothing (no redirect) | Redirect URIs under "Web" platform instead of "SPA" | Move to SPA platform: Portal > App Registration > Authentication |
| Popup blocked in InPrivate | `loginPopup()` blocked by browser | Switch to `loginRedirect()` (current setup) |
| "Chat: using managed identity" in logs | SPA didn't send tokens | Check MSAL init, user login state, token acquisition |
| "AADSTS50011: Reply URL mismatch" | Missing redirect URI in App Registration | Add the exact URL to SPA redirect URIs |
| "AADSTS65001: Consent required" | Admin consent not granted | Click "Grant admin consent" in API permissions |
| Permissions work in SPA but not MI | MI has application perms, not delegated | Grant app role assignments to MI via `az rest` |

---

## 12. Reference IDs

### Tenant
| Property | Value |
|---|---|
| Tenant ID | `4a3eb5f4-1ec6-4a73-bb03-1ca63cb52d67` |
| Tenant domain | `MngEnvMCAP250477.onmicrosoft.com` |

### App Registration
| Property | Value |
|---|---|
| Display name | `EnterpriseSecurityIQ-SPA` |
| Application (client) ID | `ffb6f10d-6991-430e-b3d6-23a0101a92b1` |
| Object ID | `fe171c21-b3a1-480d-a5f5-41e7c515d843` |

### Service Principal (SPN)
| Property | Value |
|---|---|
| Display name | `EnterpriseSecurityIQ-SPA` |
| Object ID | `1b42cfa1-b40a-4488-8f75-3ce3de2a11e6` |
| Application ID | `ffb6f10d-6991-430e-b3d6-23a0101a92b1` |

### Managed Identity
| Property | Value |
|---|---|
| Name | `ESIQNew-identity` |
| Client ID | `d5d10273-4a8b-4251-9b9d-00fe035df97a` |
| Principal ID | `d742617c-6f14-4215-be65-e1f7b68866de` |

### Infrastructure
| Property | Value |
|---|---|
| Container App | `esiqnew-agent` |
| FQDN | `esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io` |
| ACR | `esiqnewacr.azurecr.io` |
| Image | `esiqnew-agent:v33` |
| Foundry Agent | `asst_N4hpInCl30eZHaim3vtJTZiT` |
| Resource Group | `ESIQNew-RG` |
| Region | `northeurope` |

### Microsoft Graph SPN (Permission Target)
| Property | Value |
|---|---|
| Object ID | `8bd0732c-62ce-469b-a109-a0e8cb2985ca` |
| App Role: Directory.Read.All | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` |
| App Role: Policy.Read.All | `246dd0d5-5bd0-4def-940b-0421030a5b68` |
| App Role: RoleManagement.Read.All | `c7fbd983-d9aa-4fa7-84b8-17382c103bc4` |
| App Role: AuditLog.Read.All | `b0afded3-3588-46d8-8b3d-9842eff778da` |
| App Role: UserAuthenticationMethod.Read.All | `38d9df27-64da-44fd-b7c5-a6fbac20248f` |
| App Role: IdentityRiskyUser.Read.All | `dc5007c0-2d7d-4c42-879c-2dab87571379` |

---

## Code Files Reference

| File | Role |
|---|---|
| `webapp/index.html` | SPA — MSAL.js config, login flow, token acquisition, chat UI |
| `webapp/msal-browser.min.js` | Self-hosted MSAL.js v5.6.3 library |
| `AIAgent/app/auth.py` | `UserTokenCredential`, `ComplianceCredentials`, `_request_creds` context var |
| `AIAgent/app/api.py` | `/chat` endpoint — token passthrough, credential setup |
| `AIAgent/app/agent.py` | 14 tool functions, `_get_creds()` helper, system prompt |
