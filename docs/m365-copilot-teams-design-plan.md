# PostureIQ — M365 Copilot & Teams Integration Design Plan

**Author:** Copilot Agent  
**Date:** April 14, 2026  
**Status:** Design Proposal — Ready for Review

---

## 1. Executive Summary

This document describes the architecture, implementation steps, and prerequisites for
publishing PostureIQ as a **Microsoft 365 Copilot agent** (declarative agent)
and a **Teams app** (bot + tab). The goal is to let users invoke security assessments,
query compliance results, and receive reports directly from Microsoft 365 Copilot chat
and Microsoft Teams — without visiting the standalone web dashboard.

### Delivery Options

| Option | Effort | Capability | Recommended |
|--------|--------|-----------|-------------|
| **A. Declarative Copilot Agent** (API Plugin) | Medium | Natural language → tool calls in M365 Copilot | ✅ Yes (primary) |
| **B. Teams Bot + Tab** | Medium-High | Bot commands + embedded dashboard tab | ✅ Yes (secondary) |
| **C. Both A + B in one Teams App** | High | Full M365 integration | ✅ Ideal end state |

**Recommendation:** Start with **Option A** (Declarative Agent with API Plugin) — it
gets PostureIQ into M365 Copilot with minimal code changes, then extend to
Teams bot + tab as a Phase 2.

---

## 2. Architecture — Current State

```
┌──────────────────────────────────────────────────────────┐
│  User (Browser)                                          │
│  ↓ MSAL.js → Entra ID → Graph + ARM tokens              │
│  ↓ POST /chat (SSE)                                     │
│  ↓                                                       │
│  ┌────────────────────────────────────┐                  │
│  │ Container App (esiqnew-agent)       │                  │
│  │  FastAPI + OpenAI function-calling  │                  │
│  │  13 tools (agent.py)                │                  │
│  │  SSE streaming response             │                  │
│  └────────────────────────────────────┘                  │
│       ↓ MI (RBAC)          ↓ User tokens (OBO)           │
│  Azure OpenAI          Azure ARM / Graph API              │
└──────────────────────────────────────────────────────────┘
```

**Key constraint:** The agent currently requires user-delegated ARM + Graph tokens
passed in each `/chat` request body. M365 Copilot and Teams Bot Framework cannot send
arbitrary tokens — they provide the user's SSO token for your app, but **not** pre-acquired
ARM/Graph tokens.

---

## 3. Architecture — Target State (Option A: Declarative Agent)

```
┌─────────────────────────────────────────────────────────────────┐
│  M365 Copilot (Teams / copilot.microsoft.com)                   │
│  ↓                                                               │
│  Declarative Agent Manifest (agent.json)                         │
│  → References API Plugin (openapi.json)                          │
│       ↓ OAuth 2.0 (on-behalf-of)                                 │
│       ↓                                                          │
│  ┌──────────────────────────────────────────────────┐            │
│  │ Container App (esiqnew-agent)                     │            │
│  │                                                    │            │
│  │  NEW: /api/v1/assessment   (REST, JSON response)  │            │
│  │  NEW: /api/v1/risk         (REST, JSON response)  │            │
│  │  NEW: /api/v1/copilot      (REST, JSON response)  │            │
│  │  NEW: /api/v1/query        (REST, JSON response)  │            │
│  │  NEW: /api/v1/permissions  (REST, JSON response)  │            │
│  │  NEW: /api/v1/rbac         (REST, JSON response)  │            │
│  │                                                    │            │
│  │  Auth: Validate JWT → extract OBO token →          │            │
│  │        exchange for ARM + Graph tokens              │            │
│  └──────────────────────────────────────────────────┘            │
│       ↓ OBO flow          ↓ MI (infra)                           │
│  ARM / Graph API      Azure OpenAI / Storage / ACR               │
└─────────────────────────────────────────────────────────────────┘
```

### What Changes

| Component | Current | Target |
|-----------|---------|--------|
| **API surface** | Single `/chat` SSE endpoint | REST endpoints per tool (JSON request/response) |
| **Auth flow** | SPA sends pre-acquired ARM+Graph tokens | Server-side OBO: receives SSO JWT, exchanges for ARM+Graph |
| **Response format** | SSE stream with tool events | Standard JSON responses (Copilot handles display) |
| **App Registration** | SPA-only (public client) | Add Web redirect + client secret for OBO |
| **Manifest files** | None | `declarativeAgent.json` + `openapi.yaml` + Teams app manifest |

---

## 4. Phase 1 — Declarative Copilot Agent (API Plugin)

### 4.1 Prerequisites

1. **Teams Admin Center** access to upload custom apps
2. **Copilot for Microsoft 365** license assigned to target users
3. **App Registration update**: Add `Web` platform with redirect URI, generate client secret, add API scope (`api://<app-id>/access_as_user`)
4. **Graph API permissions**: Ensure existing delegated permissions cover OBO scope

### 4.2 App Registration Changes

```
Current:
  Platform: SPA (single-page application)
  Redirect: https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io

Add:
  Platform: Web
  Redirect: https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io/auth/callback
  Client Secret: (generate new)
  Expose API:
    Scope: api://<client-id>/access_as_user
    Authorized client apps:
      - ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b  (Teams desktop)
      - 1fec8e78-bce4-4aaf-ab1b-5451cc387264  (Teams web)
      - 5e3ce6c0-2b1f-4285-8d4b-75ee78787346  (Teams mobile)
      - 4765445b-32c6-49b0-83e6-1d93765276ca  (M365 desktop)
      - 4345a7b9-9a63-4910-a426-35363201d503  (M365 web)
      - 0ec893e0-5785-4de6-99da-4ed124e5296c  (M365 mobile)
```

### 4.3 New API Endpoints (REST, JSON)

Each endpoint maps to one agent tool, accepts JSON body, returns JSON response:

```python
# api_v1.py — new router

from fastapi import APIRouter, Depends, Request
from app.auth_obo import validate_and_exchange_token

router = APIRouter(prefix="/api/v1")

@router.post("/assessment")
async def run_assessment_api(request: Request, body: AssessmentRequest):
    """Run compliance assessment — used by Copilot API plugin."""
    creds = await validate_and_exchange_token(request)
    result = await run_assessment(scope=body.scope, frameworks=body.frameworks, subscriptions=body.subscriptions)
    return {"status": "complete", "result": result}

@router.post("/risk")
async def analyze_risk_api(request: Request, body: RiskRequest):
    creds = await validate_and_exchange_token(request)
    result = await analyze_risk(scope=body.scope, subscriptions=body.subscriptions)
    return {"status": "complete", "result": result}

# ... similar for /copilot, /query, /rbac, /data-security, /permissions
```

### 4.4 OBO Token Exchange

```python
# auth_obo.py — On-Behalf-Of token exchange

from msal import ConfidentialClientApplication

async def validate_and_exchange_token(request: Request):
    """
    1. Extract Bearer token from Authorization header
    2. Validate JWT signature + audience
    3. Exchange via OBO for ARM token (https://management.azure.com/.default)
    4. Exchange via OBO for Graph token (https://graph.microsoft.com/.default)
    5. Return ComplianceCredentials with both tokens
    """
    sso_token = request.headers.get("Authorization", "").replace("Bearer ", "")

    app = ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    )

    arm_result = app.acquire_token_on_behalf_of(
        user_assertion=sso_token,
        scopes=["https://management.azure.com/.default"],
    )

    graph_result = app.acquire_token_on_behalf_of(
        user_assertion=sso_token,
        scopes=["https://graph.microsoft.com/.default"],
    )

    return ComplianceCredentials(
        arm_token=arm_result["access_token"],
        graph_token=graph_result["access_token"],
    )
```

### 4.5 OpenAPI Spec (API Plugin Definition)

```yaml
# openapi.yaml
openapi: 3.0.3
info:
  title: EnterpriseSecurityIQ
  description: AI-powered compliance and security assessment for Azure & Entra ID
  version: 1.0.0
servers:
  - url: https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io
paths:
  /api/v1/assessment:
    post:
      operationId: runAssessment
      summary: Run a compliance assessment against Azure environment
      description: >
        Evaluates Azure resources against selected compliance frameworks.
        Returns compliance score, findings, and domain-level breakdowns.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                scope:
                  type: string
                  description: "'full' or comma-separated domains"
                  default: full
                frameworks:
                  type: string
                  description: "'all' or comma-separated framework names"
                  default: all
                subscriptions:
                  type: string
                  description: "Optional comma-separated subscription IDs"
      responses:
        '200':
          description: Assessment results
          content:
            application/json:
              schema:
                type: object
                properties:
                  status: { type: string }
                  result: { type: string }

  /api/v1/risk:
    post:
      operationId: analyzeRisk
      summary: Run a Security Risk Gap Analysis
      # ... similar schema

  /api/v1/copilot-readiness:
    post:
      operationId: assessCopilotReadiness
      summary: Evaluate M365 Copilot readiness

  /api/v1/query:
    post:
      operationId: queryResults
      summary: Query assessment results with natural language

  /api/v1/rbac:
    post:
      operationId: generateRbacReport
      summary: Generate RBAC hierarchy report

  /api/v1/permissions:
    post:
      operationId: checkPermissions
      summary: Check caller's Azure and Graph permissions

security:
  - oauth2: [access_as_user]

components:
  securitySchemes:
    oauth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
          tokenUrl: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
          scopes:
            access_as_user: Access EnterpriseSecurityIQ as the signed-in user
```

### 4.6 Declarative Agent Manifest

```json
{
  "$schema": "https://developer.microsoft.com/json-schemas/copilot/declarative-agent/v1.4/schema.json",
  "version": "v1.4",
  "name": "EnterpriseSecurityIQ",
  "description": "AI-powered compliance and security intelligence for Azure, Entra ID, M365 Copilot, and AI agents. Run assessments, analyze risks, query findings, and generate reports.",
  "instructions": "You are EnterpriseSecurityIQ, an enterprise security compliance agent. When users ask about their security posture, compliance status, or risk analysis, use the available tools to run assessments against their Azure environment. Always check permissions first if users report errors. Present results clearly with scores, findings by severity, and actionable remediation steps.",
  "capabilities": [
    {
      "name": "actions",
      "plugins": [
        {
          "id": "enterprisesecurityiq-plugin",
          "file": "openapi.yaml"
        }
      ]
    }
  ],
  "conversation_starters": [
    { "text": "Run a compliance assessment against all frameworks" },
    { "text": "What's my security risk score?" },
    { "text": "Check my M365 Copilot readiness" },
    { "text": "Show my RBAC role assignments" },
    { "text": "Analyze data security posture" },
    { "text": "What are my critical compliance gaps?" }
  ]
}
```

### 4.7 Teams App Manifest (appPackage for Upload)

```json
{
  "$schema": "https://developer.microsoft.com/json-schemas/teams/vDevPreview/MicrosoftTeams.schema.json",
  "manifestVersion": "devPreview",
  "version": "1.0.0",
  "id": "<app-id>",
  "developer": {
    "name": "EnterpriseSecurityIQ",
    "websiteUrl": "https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io",
    "privacyUrl": "https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io/privacy",
    "termsOfUseUrl": "https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io/terms"
  },
  "name": { "short": "SecurityIQ", "full": "EnterpriseSecurityIQ" },
  "description": {
    "short": "AI-powered Azure compliance and security intelligence",
    "full": "Run compliance assessments, risk analysis, RBAC reports, Copilot readiness checks, and AI agent security evaluations against your Azure tenant."
  },
  "icons": { "color": "color.png", "outline": "outline.png" },
  "accentColor": "#1F6FEB",
  "copilotAgents": {
    "declarativeAgents": [
      {
        "id": "esiq-agent",
        "file": "declarativeAgent.json"
      }
    ]
  },
  "validDomains": [
    "esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io"
  ],
  "webApplicationInfo": {
    "id": "<client-id>",
    "resource": "api://<client-id>"
  }
}
```

---

## 5. Phase 2 — Teams Bot + Tab (Optional Enhancement)

### 5.1 Teams Bot

Add a Bot Framework adapter to the Container App for richer Teams integration:

- **Proactive notifications:** Send compliance alerts when scores drop
- **Adaptive Cards:** Rich formatted assessment summaries with action buttons
- **Task modules:** Launch the full dashboard as an embedded iframe

### 5.2 Teams Tab

Embed the existing SPA dashboard as a Teams tab:

```json
"staticTabs": [
  {
    "entityId": "dashboard",
    "name": "Dashboard",
    "contentUrl": "https://esiqnew-agent.delightfulbush-cc9cf399.northeurope.azurecontainerapps.io?inTeams=true",
    "scopes": ["personal"]
  }
]
```

The SPA already handles MSAL authentication. For Teams, you'd add `@microsoft/teams-js`
SDK to detect the Teams context and use `authentication.getAuthToken()` for SSO.

---

## 6. Implementation Checklist

### Phase 1 — Declarative Agent (Estimated: 3-5 days of dev)

| # | Task | Files | Status |
|---|------|-------|--------|
| 1 | Update App Registration: add Web platform, client secret, expose API scope, authorize Teams client IDs | Azure Portal | ⬜ |
| 2 | Create `auth_obo.py` — validate SSO JWT + OBO exchange for ARM & Graph tokens | `AIAgent/app/auth_obo.py` | ⬜ |
| 3 | Create `api_v1.py` — REST endpoints per tool (JSON in/out, no SSE) | `AIAgent/app/api_v1.py` | ⬜ |
| 4 | Register `api_v1` router in `api.py` (`app.include_router(...)`) | `AIAgent/app/api.py` | ⬜ |
| 5 | Add env vars: `ESIQ_CLIENT_SECRET`, `ESIQ_OBO_SCOPES` | Container App | ⬜ |
| 6 | Write `openapi.yaml` — full OpenAPI 3.0 spec for all endpoints | `AIAgent/openapi.yaml` | ⬜ |
| 7 | Write `declarativeAgent.json` | `appPackage/declarativeAgent.json` | ⬜ |
| 8 | Write Teams app manifest `manifest.json` | `appPackage/manifest.json` | ⬜ |
| 9 | Create app icons (color.png 192×192, outline.png 32×32) | `appPackage/` | ⬜ |
| 10 | Package as .zip, upload to Teams Admin Center | Manual | ⬜ |
| 11 | Test in M365 Copilot: `@EnterpriseSecurityIQ run assessment` | Manual | ⬜ |
| 12 | Build + deploy updated container image | ACR + Container App | ⬜ |

### Phase 2 — Teams Bot + Tab (Estimated: 3-4 additional days)

| # | Task | Status |
|---|------|--------|
| 1 | Add Bot Framework SDK adapter | ⬜ |
| 2 | Design Adaptive Cards for assessment results | ⬜ |
| 3 | Add static tab pointing to SPA dashboard | ⬜ |
| 4 | Integrate `@microsoft/teams-js` in SPA for Teams SSO | ⬜ |
| 5 | Add proactive notification for score changes | ⬜ |

---

## 7. Security Considerations

| Concern | Mitigation |
|---------|------------|
| Client secret for OBO | Store in Key Vault, reference via env var secret ref |
| Token scope | OBO exchanges request only the minimum scopes needed (ARM Reader, Graph ReadAll) |
| User impersonation | OBO tokens carry the user's identity — same permission model as the SPA |
| Admin consent | Some Graph permissions may need admin consent; document in deployment guide |
| Rate limiting | API plugin calls are rate-limited by M365 Copilot orchestrator; add server-side throttling for safety |
| Data in Copilot context | Assessment results returned to Copilot stay in the user's context; comply with Microsoft data handling |
| Timeout | M365 Copilot has a ~30s plugin timeout; long-running assessments need async pattern (return task ID → poll) |

### Timeout Strategy for Long-Running Assessments

Full compliance assessments can take 2-5 minutes. The Copilot API plugin timeout is ~30s.

**Solution:** Async pattern with polling:

1. `POST /api/v1/assessment` → starts assessment, returns `{ "taskId": "abc123", "status": "running" }`
2. Copilot sees `status: running` and calls `GET /api/v1/assessment/abc123` periodically
3. When complete, returns full results

This requires defining the polling pattern in the OpenAPI spec using the
`x-openai-isConsequential` and response schema patterns.

---

## 8. User Experience in M365 Copilot

**Example interaction:**

> **User:** @PostureIQ What's my compliance score?
>
> **Copilot:** I'll run a compliance assessment for you.  
> *[Calls runAssessment API]*
>
> **PostureIQ:**  
> ## Assessment Complete
> **Compliance Score: 73%**  
> - Controls Assessed: 247
> - Non-Compliant: 42
> - Critical Findings: 3
> - High Findings: 12
>
> **Top Issues:**
> - [CRITICAL] MFA not enforced for privileged accounts
> - [HIGH] 23 storage accounts allow public blob access
> - [HIGH] No DLP policies for sensitive content
>
> Would you like me to generate a detailed report or analyze specific domains?

---

## 9. Alternatives Considered

| Alternative | Why Not |
|-------------|---------|
| **Message Extension (search)** | Read-only search, can't run assessments |
| **Power Platform connector** | Adds complexity; direct API plugin is simpler |
| **Copilot Studio agent** | Requires separate platform; we already have the engine |
| **Graph connector** | For indexing content into M365 search, not for running tools |

---

## 10. Dependencies & Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Copilot license requirement | Users without Copilot license can't use the agent | Teams bot fallback (Phase 2) |
| OBO token exchange failures | Users in certain Entra ID configurations may fail OBO | Clear error messages, fallback to SPA |
| Plugin approval delay | Teams Admin Center may require IT approval for custom apps | Pre-engage IT admin, document security posture |
| Assessment timeout | Copilot ~30s timeout too short for full assessment | Async polling pattern |
| Foundry agent registration conflict | Current Foundry registration may conflict with Copilot agent | Use separate agent IDs |
