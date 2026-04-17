"""
EnterpriseSecurityIQ — REST API + Agent Chat

Serves:
  GET  /                    — Web dashboard (SPA)
  POST /chat                — Agent chat with function-calling
  POST /assessments         — Start assessment in background
  GET  /assessments/{id}    — Poll assessment status
  GET  /health              — Health check

On startup, registers the agent in the Foundry project (Assistants API)
so it appears in the ai.azure.com portal with tracing/evals/guardrails.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv

# Load .env BEFORE reading any env vars — ensures vars are available
# regardless of entry point (main.py, uvicorn --reload, Docker, etc.)
# Resolve path relative to this file: api.py → app/ → AIAgent/.env
load_dotenv(pathlib.Path(__file__).resolve().parent.parent / ".env", override=False)

import httpx
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from openai import APIError, AsyncAzureOpenAI, BadRequestError, RateLimitError
from pydantic import BaseModel, Field

from app.agent import SYSTEM_PROMPT, TOOLS, get_session_context_summary, get_completed_assessment_tools, clear_session, _request_conversation_id
from app.auth import ComplianceCredentials, UserTokenCredential, _request_creds
from app.config import AssessmentConfig
from app.logger import log
from app.postureiq_orchestrator import run_postureiq_assessment as _bg_run_assessment

# ── Environment ─────────────────────────────────────────────────
OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1")
OPENAI_FALLBACK = os.getenv("AZURE_OPENAI_FALLBACK_DEPLOYMENT", "gpt-4.1")
PROJECT_ENDPOINT = os.getenv("FOUNDRY_PROJECT_ENDPOINT", "")
API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2025-01-01-preview")

# ── Tool map — agent.py functions keyed by name ─────────────────
TOOL_MAP: dict[str, Any] = {f.__name__: f for f in TOOLS}

# ── Tool schemas (OpenAI function-calling format) ───────────────
TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "query_results", "description": "Query any assessment results in session — data security, risk analysis, copilot readiness, AI agent security, RBAC, PostureIQ (risk scoring, attack paths, priority ranking, quick wins, AI fixes).", "parameters": {"type": "object", "properties": {"question": {"type": "string", "description": "Natural language question about assessment results"}}, "required": ["question"]}}},
    {"type": "function", "function": {"name": "search_tenant", "description": "Cloud Explorer — explore Microsoft cloud resources, identities, and configurations using natural language. Covers Azure Resource Graph (VMs, storage, networking, SQL, Key Vaults, AKS, AI services, policies, Defender) and Entra ID (users, groups, apps, roles, conditional access, PIM, risky users, consent grants).", "parameters": {"type": "object", "properties": {"question": {"type": "string", "description": "Natural language question about Azure resources, Entra ID objects, or cloud configuration"}}, "required": ["question"]}}},
    {"type": "function", "function": {"name": "analyze_risk", "description": "Run a Security Risk Gap Analysis with composite scoring and remediation runbooks.", "parameters": {"type": "object", "properties": {"scope": {"type": "string", "description": "Scope: 'full' or comma-separated categories (identity, network, defender, config, insider_risk)"}, "subscriptions": {"type": "string", "description": "Optional comma-separated subscription IDs"}}}}},
    {"type": "function", "function": {"name": "assess_data_security", "description": "Evaluate data-layer security posture: storage, database, Key Vault, encryption, classification.", "parameters": {"type": "object", "properties": {"scope": {"type": "string", "description": "Scope: 'full' or comma-separated categories (storage, database, keyvault, encryption, classification, data_lifecycle, dlp_alerts)"}, "subscriptions": {"type": "string", "description": "Optional comma-separated subscription IDs"}}}}},
    {"type": "function", "function": {"name": "generate_rbac_report", "description": "Generate an interactive RBAC hierarchy tree report showing role assignments.", "parameters": {"type": "object", "properties": {"subscriptions": {"type": "string", "description": "Comma-separated subscription IDs or 'all'"}}}}},
    {"type": "function", "function": {"name": "generate_report", "description": "Generate compliance reports from the most recent assessment results.", "parameters": {"type": "object", "properties": {"format": {"type": "string", "description": "Report format: 'html', 'json', or 'both'", "enum": ["html", "json", "both"]}}}}},
    {"type": "function", "function": {"name": "assess_copilot_readiness", "description": "Evaluate M365 Copilot Premium readiness: oversharing, labels, DLP, access governance.", "parameters": {"type": "object", "properties": {"scope": {"type": "string", "description": "Scope: 'full' or comma-separated categories"}, "subscriptions": {"type": "string", "description": "Optional comma-separated subscription IDs to limit the assessment to"}}}}},
    {"type": "function", "function": {"name": "assess_ai_agent_security", "description": "Evaluate AI agent security across Copilot Studio, Foundry, and custom agents.", "parameters": {"type": "object", "properties": {"scope": {"type": "string", "description": "Scope: 'full' or comma-separated platforms (copilot_studio, foundry, custom)"}, "subscriptions": {"type": "string", "description": "Optional comma-separated subscription IDs to limit the assessment to"}}}}},
    {"type": "function", "function": {"name": "check_permissions", "description": "Probe the caller's Azure and Graph API permissions before running assessments.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "compare_runs", "description": "Compare current assessment results against a previous run.", "parameters": {"type": "object", "properties": {"run_dir": {"type": "string", "description": "Optional path to previous run directory"}}}}},
    {"type": "function", "function": {"name": "search_exposure", "description": "Search for sensitive data exposure: public storage, open NSGs, unencrypted VMs, etc.", "parameters": {"type": "object", "properties": {"category": {"type": "string", "description": "Category: 'all' or one of: public_storage, open_nsg, unencrypted_vms, unattached_disks, public_ips"}}}}},
    {"type": "function", "function": {"name": "run_postureiq_assessment", "description": "Run a PostureIQ security posture assessment with risk-weighted scoring, attack path analysis, priority ranking, AI-powered fix recommendations, and compliance framework mapping.", "parameters": {"type": "object", "properties": {"scope": {"type": "string", "description": "Assessment scope: 'full' for all domains, or comma-separated domain names (access, identity, data_protection, logging, network, governance)"}, "frameworks": {"type": "string", "description": "Compliance frameworks: 'all' or comma-separated names (FedRAMP, CIS, ISO-27001, NIST-800-53, PCI-DSS, MCSB, HIPAA, SOC2, GDPR, NIST-CSF, CSA-CCM)"}, "subscriptions": {"type": "string", "description": "Optional comma-separated subscription IDs to limit the assessment to"}}}}},
    {"type": "function", "function": {"name": "query_assessment_history", "description": "Query PostureIQ assessment history for auditing, trend analysis, and change tracking.", "parameters": {"type": "object", "properties": {"action": {"type": "string", "description": "Action: 'list', 'trend', 'detail', or 'compare'", "enum": ["list", "trend", "detail", "compare"]}, "timestamp": {"type": "string", "description": "Run timestamp for detail/compare actions"}, "limit": {"type": "integer", "description": "Number of runs to return (default 10)"}}}}},
]

# ── Page-level tool isolation ───────────────────────────────────
# Each page only gets its own assessment tool(s) + common utilities.
# Tools not listed here (query_results, search_tenant, check_permissions,
# compare_runs, generate_report, query_assessment_history) are always available.
PAGE_ALLOWED_TOOLS: dict[str, set[str]] = {
    "PostureIQ":        {"run_postureiq_assessment", "generate_rbac_report", "analyze_risk", "search_exposure"},
    "DataSecurity":     {"assess_data_security", "search_exposure"},
    "RiskAnalysis":     {"analyze_risk", "search_exposure"},
    "CopilotReadiness": {"assess_copilot_readiness"},
    "AIAgentSecurity":  {"assess_ai_agent_security"},
    "RBACReport":       {"generate_rbac_report"},
}
ALL_ASSESSMENT_TOOLS = {
    "run_postureiq_assessment", "generate_rbac_report", "analyze_risk",
    "search_exposure", "assess_data_security", "assess_copilot_readiness",
    "assess_ai_agent_security",
}

# ── Globals ─────────────────────────────────────────────────────
_chat_client: AsyncAzureOpenAI | None = None
_foundry_agent_id: str | None = None
_WEBAPP_DIR = pathlib.Path(__file__).resolve().parent.parent / "webapp"
_OUTPUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "output"


# ── Lifespan ────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create Azure OpenAI client and register Foundry agent."""
    global _chat_client, _foundry_agent_id

    if OPENAI_ENDPOINT:
        credential = DefaultAzureCredential()
        token_provider = get_bearer_token_provider(
            credential, "https://cognitiveservices.azure.com/.default"
        )
        _chat_client = AsyncAzureOpenAI(
            azure_endpoint=OPENAI_ENDPOINT,
            api_version=API_VERSION,
            azure_ad_token_provider=token_provider,
            timeout=httpx.Timeout(900, connect=30),
        )
        log.info("Azure OpenAI client initialised (endpoint=%s)", OPENAI_ENDPOINT)

        # Register / find agent in Foundry Agent Service
        if PROJECT_ENDPOINT:
            try:
                # The Agent Service at services.ai.azure.com requires
                # the https://cognitiveservices.azure.com scope; use OPENAI_ENDPOINT
                # (cognitiveservices.azure.com) which supports the Assistants API.
                foundry_client = AsyncAzureOpenAI(
                    azure_endpoint=OPENAI_ENDPOINT,
                    api_version=API_VERSION,
                    azure_ad_token_provider=token_provider,
                )
                existing = await foundry_client.beta.assistants.list(limit=100)
                for a in existing.data:
                    if a.name == "EnterpriseSecurityIQ":
                        _foundry_agent_id = a.id
                        log.info("Found existing Foundry agent: %s", _foundry_agent_id)
                        break
                if not _foundry_agent_id:
                    agent = await foundry_client.beta.assistants.create(
                        model=OPENAI_DEPLOYMENT,
                        name="EnterpriseSecurityIQ",
                        instructions=SYSTEM_PROMPT,
                        tools=TOOL_SCHEMAS,
                    )
                    _foundry_agent_id = agent.id
                    log.info("Registered Foundry agent: %s", _foundry_agent_id)
                await foundry_client.close()
            except Exception as exc:
                log.warning("Foundry agent registration skipped: %s", exc)
    else:
        log.warning("AZURE_OPENAI_ENDPOINT not set — chat endpoint disabled")

    yield  # ── app is running ──

    if _chat_client:
        await _chat_client.close()


app = FastAPI(
    title="EnterpriseSecurityIQ API", version="2.0.0", lifespan=lifespan
)

# ── CORS (allows SPA on a separate origin, e.g. Azure Static Web Apps) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ──────────────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = Field(default_factory=list)
    graph_token: str | None = Field(default=None, description="User's Graph API access token from MSAL.js")
    arm_token: str | None = Field(default=None, description="User's ARM access token from MSAL.js")
    frameworks: list[str] | None = Field(default=None, description="Explicit framework list from sidebar picker — overrides LLM interpretation")
    conversation_id: str | None = Field(default=None, description="Unique conversation ID for per-session state isolation")
    mode: str | None = Field(default=None, description="Session mode: 'tenant_search' forces direct API queries instead of LLM routing")
    page: str | None = Field(default=None, description="Source page — restricts which assessment tools the LLM can invoke")


class ChatResponse(BaseModel):
    response: str
    tools_used: list[str] = Field(default_factory=list)


class AssessmentRequest(BaseModel):
    frameworks: list[str] = Field(default=["FedRAMP"])
    domains: list[str] | None = None
    output_formats: list[str] = Field(default=["json"])
    webhook_url: str | None = None


class AssessmentResponse(BaseModel):
    status: str
    message: str
    task_id: str | None = None


# ── In-memory task state (swap for Redis/DB in production) ──────
_tasks: dict[str, dict[str, Any]] = {}
_task_counter = 0


async def _run_and_notify(task_id: str, req: AssessmentRequest) -> None:
    """Run assessment in background and optionally POST results to webhook."""
    _tasks[task_id]["status"] = "running"
    try:
        config = AssessmentConfig.from_env()
        config.frameworks = req.frameworks
        config.output_formats = req.output_formats
        creds = ComplianceCredentials()
        result = await _bg_run_assessment(creds=creds, config=config, domains=req.domains)
        await creds.close()
        _tasks[task_id] = {"status": "completed", "result": result}

        if req.webhook_url:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    await client.post(req.webhook_url, json={
                        "task_id": task_id,
                        "status": "completed",
                        "summary": result.get("summary"),
                    })
            except Exception as exc:
                log.warning("Webhook delivery failed: %s", exc)
    except Exception as exc:
        _tasks[task_id] = {"status": "failed", "error": str(exc)}
        log.error("Background assessment failed: %s", exc)


# ── Chat (function-calling loop) ────────────────────────────────
async def _execute_tool(name: str, arguments: dict) -> str:
    """Execute an agent tool by name and return the result string."""
    func = TOOL_MAP.get(name)
    if not func:
        return f"Unknown tool: {name}"
    try:
        return await func(**arguments)
    except Exception as exc:
        log.error("Tool %s failed: %s", name, exc, exc_info=True)
        return f"Tool execution error: {exc}"


@app.post("/chat")
async def chat(req: ChatRequest):
    """Chat with the EnterpriseSecurityIQ agent (SSE stream with keepalive).

    Returns a text/event-stream.  Each line is either:
      : keepalive          — empty SSE comment to prevent proxy timeout
      data: {"type":"tool","name":"...","status":"running"|"done"}
      data: {"response":"...","tools_used":[...]}   — final result
      data: {"error":"..."}                          — on failure
    """
    if not _chat_client:
        raise HTTPException(
            status_code=503,
            detail="Chat not available — AZURE_OPENAI_ENDPOINT not configured",
        )

    # Require user-delegated tokens from MSAL.js — reject requests without them
    # to prevent unauthenticated callers from falling back to the managed identity
    # (which has broad application-level permissions).
    if not req.graph_token or not req.arm_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required — sign in via the web app to access this API.",
        )

    user_cred = UserTokenCredential(
        graph_token=req.graph_token, arm_token=req.arm_token
    )

    # Decode the user's tenant ID from the ARM JWT so downstream code
    # (reports, management-group queries) targets the correct tenant
    # instead of falling back to the hosting tenant's AZURE_TENANT_ID.
    user_tenant_id = ""
    try:
        import base64 as _b64
        _payload = req.arm_token.split(".")[1]
        _payload += "=" * (-len(_payload) % 4)  # pad for base64
        _claims = json.loads(_b64.urlsafe_b64decode(_payload))
        user_tenant_id = _claims.get("tid", "")
    except Exception:
        log.warning("Could not decode tenant ID from ARM token — falling back to env var")

    creds = ComplianceCredentials(user_credential=user_cred, tenant_id=user_tenant_id)
    _request_creds.set(creds)
    if req.conversation_id:
        _request_conversation_id.set(req.conversation_id)
    log.info("Chat: using user-delegated tokens (conversation=%s)", req.conversation_id or "global")

    async def _sse_generator():
        messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]

        # Inject session context so the LLM knows what data is already available
        session_ctx = await get_session_context_summary()
        if session_ctx:
            messages.append({"role": "system", "content": session_ctx})

        # Strip assessment tools that already ran from the schema so the LLM
        # literally cannot re-invoke them on follow-up questions.
        _completed = await get_completed_assessment_tools()
        active_schemas = (
            [t for t in TOOL_SCHEMAS if t["function"]["name"] not in _completed]
            if _completed else list(TOOL_SCHEMAS)
        )

        # Page-level isolation: keep only the assessment tools that belong
        # to the requesting page (common/utility tools always pass through).
        if req.page and req.page in PAGE_ALLOWED_TOOLS:
            allowed = PAGE_ALLOWED_TOOLS[req.page]
            active_schemas = [
                t for t in active_schemas
                if t["function"]["name"] not in ALL_ASSESSMENT_TOOLS
                or t["function"]["name"] in allowed
            ]

        # ── Permissions Check mode: strip ALL assessment tools so the LLM
        # physically cannot trigger any assessment regardless of user input ──
        if req.mode == "permissions_check":
            active_schemas = [
                t for t in active_schemas
                if t["function"]["name"] not in ALL_ASSESSMENT_TOOLS
            ]
            messages.append({"role": "system", "content": (
                "PERMISSIONS CHECK MODE — You are helping the user check and understand their "
                "Azure and Microsoft 365 permissions, roles, and access levels. "
                "RULES: "
                "1. ONLY check, list, and explain the user's permissions, roles, and access levels. "
                "2. NEVER run any assessment, security scan, compliance evaluation, or posture check. "
                "3. If the user asks to run an assessment, respond: "
                "'This is the Check Permissions tool. I can only check your permissions here. "
                "To run an assessment, please use the Run Assessment option from the navigation bar.' "
                "4. Use the check_permissions tool to probe Azure and Graph API permissions. "
                "5. Use search_tenant to look up role assignments, group memberships, and directory roles. "
                "6. Be thorough — list every role, permission, and access level you find."
            )})

        for h in req.history[-20:]:
            messages.append({"role": h.role, "content": h.content})
        messages.append({"role": "user", "content": req.message})

        tools_used: list[str] = []
        max_rounds = 10
        total_prompt_tokens = 0
        total_completion_tokens = 0

        # Pricing per 1M tokens (USD) — gpt-4.1 defaults
        INPUT_COST_PER_M = float(os.getenv("TOKEN_COST_INPUT_PER_M", "2.00"))
        OUTPUT_COST_PER_M = float(os.getenv("TOKEN_COST_OUTPUT_PER_M", "8.00"))

        _active_model = OPENAI_DEPLOYMENT

        # ── Tenant Search mode: force direct API execution first ──
        if req.mode == "tenant_search":
            yield f"data: {json.dumps({'type': 'tool', 'name': 'search_tenant', 'status': 'running'})}\n\n"
            try:
                tool_result = await _execute_tool("search_tenant", {"question": req.message})
                tools_used.append("search_tenant")
            except Exception as exc:
                tool_result = f"Tenant search error: {exc}"
            yield f"data: {json.dumps({'type': 'tool', 'name': 'search_tenant', 'status': 'done'})}\n\n"

            # Feed real results to LLM for formatting — instruct it to present data only
            messages.append({"role": "system", "content": (
                "CLOUD EXPLORER MODE — The search_tenant tool was executed and returned REAL data "
                "from the user's connected Microsoft cloud tenant. The results are below. "
                "RULES: "
                "1. Present ONLY the real data returned by the tool. "
                "2. Do NOT fabricate, hallucinate, invent, or add example/demo data under any circumstances. "
                "3. If the data is empty, say: 'No results found for this query.' "
                "4. If there's an error, explain the error honestly. "
                "5. Format results using markdown tables for tabular data, or structured lists for other data. "
                "6. NEVER say 'I don't have access' or 'I can't query your tenant' — the tool already did. "
                "7. Do NOT offer generic security advice. Only discuss what the data shows. "
                "8. Include counts (e.g., 'Found 42 virtual machines across 3 subscriptions')."
            )})
            messages.append({"role": "assistant", "content": None, "tool_calls": [{"id": "ts_forced", "type": "function", "function": {"name": "search_tenant", "arguments": json.dumps({"question": req.message})}}]})
            messages.append({"role": "tool", "tool_call_id": "ts_forced", "content": tool_result})

            # One LLM pass to format the results — NO tools available.
            # Cloud Explorer is 100% independent: search_tenant already ran,
            # now the LLM only formats the results. No assessment tools,
            # no RBAC reports, no other tools can be invoked.
            try:
                response = await _chat_client.chat.completions.create(
                    model=_active_model,
                    messages=messages,
                )
            except (BadRequestError, RateLimitError, APIError) as model_err:
                err_body = str(model_err).lower()
                if "context_length" in err_body or "max.*token" in err_body:
                    log.warning("Context length exceeded on %s — trimming messages and retrying on %s", _active_model, OPENAI_FALLBACK)
                    _active_model = OPENAI_FALLBACK
                    # Keep system + last 2 messages to stay within context
                    sys_msgs = [m for m in messages if m.get("role") == "system"]
                    other_msgs = [m for m in messages if m.get("role") != "system"]
                    messages = sys_msgs + other_msgs[-2:]
                elif _active_model != OPENAI_FALLBACK:
                    log.warning("Model %s failed (%s), falling back to %s", _active_model, model_err, OPENAI_FALLBACK)
                    _active_model = OPENAI_FALLBACK
                else:
                    raise
                response = await _chat_client.chat.completions.create(
                    model=_active_model,
                    messages=messages,
                )
            choice = response.choices[0]
            if response.usage:
                total_prompt_tokens += response.usage.prompt_tokens or 0
                total_completion_tokens += response.usage.completion_tokens or 0

            total_tokens = total_prompt_tokens + total_completion_tokens
            est_cost = (total_prompt_tokens / 1_000_000 * INPUT_COST_PER_M) + (total_completion_tokens / 1_000_000 * OUTPUT_COST_PER_M)
            yield f"data: {json.dumps({'type': 'token_usage', 'prompt_tokens': total_prompt_tokens, 'completion_tokens': total_completion_tokens, 'total_tokens': total_tokens, 'estimated_cost_usd': round(est_cost, 6), 'model': _active_model})}\n\n"
            yield f"data: {json.dumps({'response': choice.message.content or '', 'tools_used': tools_used})}\n\n"
            return

        try:
            for _ in range(max_rounds):
                try:
                    response = await _chat_client.chat.completions.create(
                        model=_active_model,
                        messages=messages,
                        tools=active_schemas,
                        tool_choice="auto",
                    )
                except (BadRequestError, RateLimitError, APIError) as model_err:
                    err_body = str(model_err).lower()
                    if "context_length" in err_body or "max.*token" in err_body:
                        log.warning("Context length exceeded on %s — trimming messages and retrying on %s", _active_model, OPENAI_FALLBACK)
                        _active_model = OPENAI_FALLBACK
                        # Keep system + last 2 messages to stay within context
                        sys_msgs = [m for m in messages if m.get("role") == "system"]
                        other_msgs = [m for m in messages if m.get("role") != "system"]
                        messages = sys_msgs + other_msgs[-2:]
                    elif _active_model != OPENAI_FALLBACK:
                        log.warning("Model %s failed (%s), falling back to %s", _active_model, model_err, OPENAI_FALLBACK)
                        _active_model = OPENAI_FALLBACK
                    else:
                        raise
                    response = await _chat_client.chat.completions.create(
                        model=_active_model,
                        messages=messages,
                        tools=active_schemas,
                        tool_choice="auto",
                    )
                choice = response.choices[0]

                # Accumulate token usage
                if response.usage:
                    total_prompt_tokens += response.usage.prompt_tokens or 0
                    total_completion_tokens += response.usage.completion_tokens or 0

                if choice.finish_reason == "stop" or not choice.message.tool_calls:
                    # Emit token usage before final response
                    total_tokens = total_prompt_tokens + total_completion_tokens
                    est_cost = (total_prompt_tokens / 1_000_000 * INPUT_COST_PER_M) + (total_completion_tokens / 1_000_000 * OUTPUT_COST_PER_M)
                    yield f"data: {json.dumps({'type': 'token_usage', 'prompt_tokens': total_prompt_tokens, 'completion_tokens': total_completion_tokens, 'total_tokens': total_tokens, 'estimated_cost_usd': round(est_cost, 6), 'model': _active_model})}\n\n"
                    yield f"data: {json.dumps({'response': choice.message.content or '', 'tools_used': tools_used})}\n\n"
                    return

                # Append assistant message (with tool_calls) to context
                messages.append(choice.message.model_dump(exclude_none=True))

                for tc in choice.message.tool_calls:
                    tools_used.append(tc.function.name)
                    yield f"data: {json.dumps({'type': 'tool', 'name': tc.function.name, 'status': 'running'})}\n\n"

                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}

                    # Override frameworks for PostureIQ when SPA sent explicit list
                    if tc.function.name == "run_postureiq_assessment" and req.frameworks:
                        args["frameworks"] = ",".join(req.frameworks)
                        log.info("Overriding LLM frameworks with explicit list: %s", req.frameworks)

                    # Execute tool in a task; send keepalives every 15s to
                    # prevent the Envoy proxy from returning a 504.
                    tool_task = asyncio.ensure_future(_execute_tool(tc.function.name, args))
                    while not tool_task.done():
                        try:
                            await asyncio.wait_for(asyncio.shield(tool_task), timeout=15)
                        except asyncio.TimeoutError:
                            yield ": keepalive\n\n"
                        except Exception:
                            break  # task raised — handled below

                    if tool_task.done() and tool_task.exception():
                        result = f"Tool execution error: {tool_task.exception()}"
                    else:
                        result = tool_task.result()
                    yield f"data: {json.dumps({'type': 'tool', 'name': tc.function.name, 'status': 'done'})}\n\n"

                    # Extract report URLs from tool result and emit them
                    # as dedicated SSE events so the frontend can render
                    # download buttons regardless of LLM rewriting.
                    for m in re.finditer(r'\[([^\]]+)\]\((/reports/[^)]+)\)', result):
                        yield f"data: {json.dumps({'type': 'report', 'name': m.group(1), 'url': m.group(2)})}\n\n"

                    # Extract structured report table JSON if present
                    rt_match = re.search(r'<!--REPORT_TABLE:(.*?)-->', result)
                    if rt_match:
                        try:
                            rt_data = json.loads(rt_match.group(1))
                            yield f"data: {json.dumps({'type': 'report_table', **rt_data})}\n\n"
                        except json.JSONDecodeError:
                            pass

                    # Truncate tool result for LLM context: strip the
                    # REPORT_TABLE JSON blob (already emitted via SSE) and cap
                    # total length to prevent token-limit failures on the next
                    # LLM call.  Full data remains in session state for query_results.
                    llm_result = re.sub(r'<!--REPORT_TABLE:.*?-->', '', result).strip()
                    _MAX_TOOL_RESULT_CHARS = 4000
                    if len(llm_result) > _MAX_TOOL_RESULT_CHARS:
                        llm_result = llm_result[:_MAX_TOOL_RESULT_CHARS] + "\n\n…(truncated — full data cached in session for follow-up questions)"

                    messages.append(
                        {"role": "tool", "tool_call_id": tc.id, "content": llm_result}
                    )

            # Emit token usage even on max iterations
            total_tokens = total_prompt_tokens + total_completion_tokens
            est_cost = (total_prompt_tokens / 1_000_000 * INPUT_COST_PER_M) + (total_completion_tokens / 1_000_000 * OUTPUT_COST_PER_M)
            yield f"data: {json.dumps({'type': 'token_usage', 'prompt_tokens': total_prompt_tokens, 'completion_tokens': total_completion_tokens, 'total_tokens': total_tokens, 'estimated_cost_usd': round(est_cost, 6), 'model': _active_model})}\n\n"
            yield f"data: {json.dumps({'response': 'Maximum tool iterations reached.', 'tools_used': tools_used})}\n\n"
        except Exception as exc:
            log.error("Chat SSE error: %s", exc, exc_info=True)
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        finally:
            # Close the per-request credentials once all tools are done
            await creds.close()

    return StreamingResponse(
        _sse_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Endpoints ───────────────────────────────────────────────────
@app.post("/assessments", response_model=AssessmentResponse)
async def start_assessment(req: AssessmentRequest, bg: BackgroundTasks) -> AssessmentResponse:
    """Start an assessment asynchronously. Returns a task_id for polling."""
    global _task_counter
    _task_counter += 1
    task_id = f"task-{_task_counter}"
    _tasks[task_id] = {"status": "queued"}
    bg.add_task(_run_and_notify, task_id, req)
    return AssessmentResponse(status="accepted", message="Assessment queued", task_id=task_id)


@app.get("/assessments/{task_id}")
async def get_assessment(task_id: str) -> dict[str, Any]:
    """Poll for the result of an assessment."""
    task = _tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task_id, **task}


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "agent_registered": bool(_foundry_agent_id),
        "agent_id": _foundry_agent_id or "none",
    }


class ResetRequest(BaseModel):
    conversation_id: str = Field(..., description="Conversation ID to clear")


@app.post("/reset")
async def reset_session(req: ResetRequest):
    """Clear server-side session state for a conversation."""
    await clear_session(req.conversation_id)
    log.info("Session reset for conversation: %s", req.conversation_id)
    return {"status": "ok", "conversation_id": req.conversation_id}


# ── Report file serving ─────────────────────────────────────────
_MIME_MAP = {".html": "text/html", ".json": "application/json", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".pdf": "application/pdf", ".csv": "text/csv", ".zip": "application/zip"}


@app.get("/reports")
async def list_reports() -> list[dict[str, str]]:
    """List all generated report files available for download.

    Returns the union of local files and blob storage entries so that
    reports persisted before a container restart still appear.
    """
    from app.blob_store import list_reports as _blob_list

    # Local files
    seen: set[str] = set()
    reports: list[dict[str, str]] = []
    if _OUTPUT_DIR.exists():
        for p in sorted(_OUTPUT_DIR.rglob("*"), reverse=True):
            if p.is_file() and p.suffix in _MIME_MAP:
                rel = p.relative_to(_OUTPUT_DIR).as_posix()
                seen.add(rel)
                reports.append({"name": p.name, "path": rel, "url": f"/reports/{rel}", "size": str(p.stat().st_size)})

    # Blob storage (adds reports not present locally)
    for entry in _blob_list(set(_MIME_MAP.keys())):
        if entry["path"] not in seen:
            reports.append(entry)

    reports.sort(key=lambda r: r["path"], reverse=True)
    return reports


@app.get("/reports/{file_path:path}")
async def serve_report(file_path: str):
    """Serve a generated report file from the output directory.

    Falls back to Azure Blob Storage when the file is missing locally
    (e.g. after a container restart or redeployment).
    """
    from app.blob_store import download_to_local as _blob_download

    # Resolve and ensure the path is within _OUTPUT_DIR (prevent path traversal)
    target = (_OUTPUT_DIR / file_path).resolve()
    if not str(target).startswith(str(_OUTPUT_DIR.resolve())):
        raise HTTPException(status_code=403, detail="Access denied")

    # Try local first; if missing, fetch from blob storage
    if not target.is_file():
        if not _blob_download(file_path, target):
            raise HTTPException(status_code=404, detail="Report not found")

    media = _MIME_MAP.get(target.suffix, "application/octet-stream")
    return FileResponse(target, media_type=media, filename=target.name)


# ── SPA Dashboard ──────────────────────────────────────────────
@app.get("/msal-browser.min.js")
async def serve_msal_js():
    """Serve self-hosted MSAL.js library."""
    js = _WEBAPP_DIR / "msal-browser.min.js"
    if js.exists():
        return FileResponse(js, media_type="application/javascript")
    return Response(status_code=404, content="MSAL JS not found")


@app.get("/{name}.html")
async def serve_spa_page(name: str):
    """Serve any SPA page from the webapp directory."""
    import re
    if not re.match(r'^[A-Za-z0-9_-]+$', name):
        raise HTTPException(status_code=400, detail="Invalid page name")
    page = _WEBAPP_DIR / f"{name}.html"
    if page.exists():
        return FileResponse(page, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")


@app.get("/")
async def serve_dashboard():
    """Serve the web portal (same-origin, no CORS needed)."""
    index = _WEBAPP_DIR / "index.html"
    if index.exists():
        return FileResponse(index, media_type="text/html")
    return {"message": "Dashboard not available — webapp/ not found in container"}
