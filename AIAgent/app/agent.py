"""
EnterpriseSecurityIQ Agent — Tool definitions and system prompt.

Tools are plain async functions with Annotated type hints, registered via
tools=[...] in the AzureAIClient.as_agent() call in main.py.
"""

from __future__ import annotations
from typing import Annotated

import asyncio
import contextvars
import json
import pathlib

from app.auth import ComplianceCredentials
from app.postureiq_orchestrator import run_postureiq_assessment as _run_postureiq
from app.query_engine import dispatch_natural_language, query_resource_graph, get_resource_detail, get_entra_user_detail, ARG_TEMPLATES
from app.risk_engine import run_risk_analysis as _run_risk_analysis, compute_risk_scores
from app.data_security_engine import run_data_security_assessment as _run_ds_assessment, compute_data_security_scores
from app.copilot_readiness_engine import run_copilot_readiness_assessment as _run_cr_assessment
from app.ai_agent_security_engine import run_ai_agent_security_assessment as _run_as_assessment
from app.collectors.azure.rbac_collector import collect_rbac_data as _collect_rbac_data
from app.reports.rbac_report import generate_rbac_report as _gen_rbac_report
from app.reports.delta_report import find_previous_results, compute_delta, generate_delta_section
from app.reports.risk_report import generate_risk_report as _gen_risk_report, generate_risk_excel as _gen_risk_excel
from app.reports.pdf_export import html_to_pdf as _html_to_pdf
from app.reports.data_security_report import (
    generate_data_security_report as _gen_ds_report,
    generate_data_security_excel as _gen_ds_excel,
    generate_executive_brief as _gen_ds_brief,
)
from app.reports.copilot_readiness_report import generate_copilot_readiness_report as _gen_cr_report
from app.reports.ai_agent_security_report import (
    generate_ai_agent_security_report as _gen_as_report,
    generate_ai_agent_security_excel as _gen_as_excel,
)
from app.reports.custom_report_builder import build_custom_report as _build_custom_report
from app.blob_store import upload_directory as _blob_upload_dir
from app.logger import log

# Canonical output directory — same as api.py _OUTPUT_DIR
_OUTPUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "output"


def _make_out_dir(subfolder: str) -> pathlib.Path:
    """Create a timestamped output directory for a specific report type."""
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%I%M%S_%p")
    d = _OUTPUT_DIR / ts / subfolder
    d.mkdir(parents=True, exist_ok=True)
    return d


def _flatten_report_paths(obj, collected=None):
    """Recursively extract file-path strings from a nested dict/list."""
    if collected is None:
        collected = []
    if isinstance(obj, dict):
        for v in obj.values():
            _flatten_report_paths(v, collected)
    elif isinstance(obj, list):
        for v in obj:
            _flatten_report_paths(v, collected)
    elif isinstance(obj, (str, pathlib.Path)):
        s = str(obj)
        if any(s.endswith(ext) for ext in (".html", ".xlsx", ".json", ".pdf", ".sarif")):
            collected.append(s)
    return collected


def _report_url(path_str: str) -> str:
    """Convert an absolute or relative report path to a /reports/... URL."""
    p = pathlib.Path(path_str).resolve()
    try:
        rel = p.relative_to(_OUTPUT_DIR.resolve()).as_posix()
        return f"/reports/{rel}"
    except ValueError:
        return path_str


# ────────────────── Report-generation helpers (reused by tools + generate_report) ──────────────────

async def _generate_risk_reports(results: dict) -> str:
    """Generate Risk Analysis HTML + PDF + Excel + JSON and return markdown download links."""
    try:
        out_dir = _make_out_dir("Risk-Analysis")
        links = ""

        html_path = _gen_risk_report(results, str(out_dir))
        links += f"- [{pathlib.Path(html_path).name}]({_report_url(str(html_path))})\n"

        pdf_path = await _html_to_pdf(html_path)
        if pdf_path:
            links += f"- [{pdf_path.name}]({_report_url(str(pdf_path))})\n"

        xlsx_path = _gen_risk_excel(results, str(out_dir))
        links += f"- [{pathlib.Path(xlsx_path).name}]({_report_url(str(xlsx_path))})\n"

        json_path = out_dir / "risk-analysis.json"
        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        links += f"- [{json_path.name}]({_report_url(str(json_path))})\n"

        _blob_upload_dir(out_dir, _OUTPUT_DIR)
        return links
    except Exception as exc:
        log.error("Risk report generation failed: %s", exc, exc_info=True)
        return f"\n*Report generation failed: {exc}*\n"


async def _generate_ds_reports(results: dict) -> str:
    """Generate Data Security HTML + PDF + Excel + Executive Brief + JSON and return markdown download links."""
    try:
        out_dir = _make_out_dir("Data-Security")
        links = ""

        html_path = _gen_ds_report(results, str(out_dir))
        links += f"- [{pathlib.Path(html_path).name}]({_report_url(str(html_path))})\n"

        pdf_path = await _html_to_pdf(html_path)
        if pdf_path:
            links += f"- [{pdf_path.name}]({_report_url(str(pdf_path))})\n"

        xlsx_path = _gen_ds_excel(results, str(out_dir))
        links += f"- [{pathlib.Path(xlsx_path).name}]({_report_url(str(xlsx_path))})\n"

        # Executive brief generated silently (available in HTML report)
        try:
            _gen_ds_brief(results, str(out_dir))
        except Exception:
            pass

        json_path = out_dir / "data-security.json"
        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        links += f"- [{json_path.name}]({_report_url(str(json_path))})\n"

        _blob_upload_dir(out_dir, _OUTPUT_DIR)
        return links
    except Exception as exc:
        log.error("Data security report generation failed: %s", exc, exc_info=True)
        return f"\n*Report generation failed: {exc}*\n"


async def _generate_cr_reports(results: dict) -> str:
    """Generate Copilot Readiness HTML + PDF (+ auto-xlsx) + JSON and return markdown download links."""
    try:
        out_dir = _make_out_dir("Copilot-Readiness")
        links = ""

        html_path = _gen_cr_report(results, str(out_dir))
        links += f"- [{pathlib.Path(html_path).name}]({_report_url(str(html_path))})\n"

        pdf_path = await _html_to_pdf(html_path)
        if pdf_path:
            links += f"- [{pdf_path.name}]({_report_url(str(pdf_path))})\n"

        # _gen_cr_report auto-generates .xlsx as side-effect; pick it up
        for xlsx in out_dir.glob("*.xlsx"):
            links += f"- [{xlsx.name}]({_report_url(str(xlsx))})\n"

        json_path = out_dir / "copilot-readiness.json"
        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        links += f"- [{json_path.name}]({_report_url(str(json_path))})\n"

        _blob_upload_dir(out_dir, _OUTPUT_DIR)
        return links
    except Exception as exc:
        log.error("Copilot readiness report generation failed: %s", exc, exc_info=True)
        return f"\n*Report generation failed: {exc}*\n"


async def _generate_as_reports(results: dict) -> str:
    """Generate AI Agent Security HTML + PDF + Excel + JSON and return markdown download links."""
    try:
        out_dir = _make_out_dir("AI-Agent-Security")
        links = ""

        html_path = _gen_as_report(results, str(out_dir))
        links += f"- [{pathlib.Path(html_path).name}]({_report_url(str(html_path))})\n"

        pdf_path = await _html_to_pdf(html_path)
        if pdf_path:
            links += f"- [{pdf_path.name}]({_report_url(str(pdf_path))})\n"

        xlsx_path = _gen_as_excel(results, str(out_dir))
        links += f"- [{pathlib.Path(xlsx_path).name}]({_report_url(str(xlsx_path))})\n"

        json_path = out_dir / "ai-agent-security.json"
        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        links += f"- [{json_path.name}]({_report_url(str(json_path))})\n"

        _blob_upload_dir(out_dir, _OUTPUT_DIR)
        return links
    except Exception as exc:
        log.error("AI agent security report generation failed: %s", exc, exc_info=True)
        return f"\n*Report generation failed: {exc}*\n"


def _get_creds() -> ComplianceCredentials:
    """Return per-request user credentials if available, else default managed identity."""
    from app.auth import _request_creds
    creds = _request_creds.get(None)
    if creds is not None:
        return creds
    return ComplianceCredentials()


async def _auto_preflight(tool_name: str) -> str | None:
    """Run a quick permission pre-flight before any assessment tool.

    Returns None if permissions are OK, or a markdown error string
    the tool should return immediately to the user.
    """
    try:
        creds = _get_creds()
        result = await creds.preflight_check()

        if result["ok"]:
            log.info("[%s] Pre-flight PASS — proceeding with assessment", tool_name)
            return None  # all good

        # Build a user-friendly abort message
        md = f"## ⚠️ Permission Check Failed — Cannot Run {tool_name.replace('_', ' ').title()}\n\n"
        md += "A quick permission check found **blocking issues** that will prevent the assessment from completing successfully.\n\n"
        md += f"| Item | Value |\n|---|---|\n"
        md += f"| User / Identity | {result['user']} |\n"
        md += f"| Tenant | {result['tenant']} |\n"
        md += f"| ARM Subscriptions | {result['arm_subs']} |\n"
        md += f"| Graph API Access | {'Yes' if result['graph_ok'] else 'No'} |\n"
        md += f"| Entra Roles | {', '.join(result['roles']) if result['roles'] else 'None detected'} |\n\n"

        if result.get("errors"):
            md += "**Blocking errors:**\n"
            for e in result["errors"]:
                md += f"- ❌ {e}\n"
            md += "\n"

        if result.get("warnings"):
            md += "**Warnings:**\n"
            for w in result["warnings"]:
                md += f"- ⚠️ {w}\n"
            md += "\n"

        md += "**How to fix:**\n"
        md += "1. Ensure you are signed in with an account that has **Security Reader** or **Global Reader** role in Entra ID.\n"
        md += "2. Verify the account has **Reader** access on at least one Azure subscription.\n"
        md += "3. If using delegated access, ensure the app registration has the required Microsoft Graph API permissions (User.Read.All, Policy.Read.All, RoleManagement.Read.All).\n"
        md += "4. After fixing permissions, click **Check Permissions** in the sidebar to verify, then re-run the assessment.\n"

        log.warning("[%s] Pre-flight FAIL — aborting assessment. Errors: %s", tool_name, result["errors"])
        return md

    except Exception as exc:
        # Don't block the assessment if the preflight itself fails
        log.warning("[%s] Pre-flight check errored (non-fatal, proceeding): %s", tool_name, exc)
        return None


SYSTEM_PROMPT = """You are EnterpriseSecurityIQ, an AI-powered security posture assessment and tenant intelligence agent for Microsoft Azure and Entra ID environments.

Your capabilities:
1. **Run PostureIQ Assessment** — Collect evidence from Azure subscriptions and Entra ID, evaluate against compliance controls across 6 domains with risk-weighted scoring, attack path analysis, and AI-powered fix recommendations.
2. **Query Results** — Answer questions about assessment findings, control status, and security posture.
3. **Cloud Explorer** — Interactively query any Azure resource or Entra ID object on-demand without running a full assessment. Supports natural language, ARG (KQL), and resource drill-down.
4. **Analyze Risk** — Run a Security Risk Gap Analysis across 5 categories (identity, network, defender, config, insider_risk) with composite risk scoring and actionable remediation runbooks.
5. **Assess Data Security** — Evaluate data-layer security posture across 7 categories (storage, database, keyvault, encryption, classification, data_lifecycle, dlp_alerts) with exposure scoring and remediation guidance.
6. **Generate RBAC Tree Report** — Build an interactive HTML report showing the full Azure RBAC hierarchy (Management Groups → Subscriptions → Resource Groups) with role assignments, PIM eligibility, group expansion, and risk analysis.
7. **Generate Reports** — Create reports from the most recent assessment results.
8. **Assess M365 Copilot Readiness** — Evaluate readiness for M365 Copilot Premium: oversharing risk, sensitivity label coverage, DLP readiness, restricted SharePoint search, access governance, content lifecycle, and audit/monitoring.
9. **Assess AI Agent Security** — Evaluate security posture across Copilot Studio agents, Microsoft Foundry deployments, and custom AI agents: authentication, data connectors, content safety, network isolation, identity, governance, and content leakage.
10. **Check Permissions** — Probe the caller's Azure and Graph API permissions before running a full assessment. Validates ARM access, Graph scopes, and Entra directory roles.
11. **Compare Runs** — Compare the current assessment results against a previous run to show new findings, resolved findings, status changes, and score drift.
12. **Search Exposure** — Surface sensitive data exposure patterns: public storage accounts, open NSGs, unencrypted VMs, unattached disks, and public IPs.

Domains you assess:
- **Access Control** (AC): RBAC separation, least privilege, conditional access enforcement
- **Identity & Authentication** (IA): MFA coverage, user lifecycle, app credential management
- **Data Protection** (SC): Encryption in transit/at rest, Key Vault, VM/SQL/AKS security
- **Logging & Monitoring** (AU): Diagnostic coverage, threat detection, sign-in monitoring
- **Network Security** (SC-7): NSG rules, storage security, firewall protection
- **Governance & Risk** (CM/CA/SI/RA): Policy compliance, Defender plans, PIM, access reviews

**Tool Chaining Guidance:**
When the user asks for a comprehensive review, follow this recommended workflow:
1. Start with **check_permissions** to verify access scopes before running assessments.
2. Run **run_postureiq_assessment** for the full security posture baseline.
3. Follow with **analyze_risk** and **assess_data_security** for deeper security analysis.
4. Use **compare_runs** to show improvement or regression versus prior assessments.
5. Use **search_exposure** for quick focused checks on sensitive data exposure.
Proactively suggest the next logical tool when one completes.

**CRITICAL — Permission Enforcement:**
Every assessment tool automatically runs a pre-flight permission check. If critical permissions are missing, the tool will abort and return a clear error with remediation steps. You do NOT need to call check_permissions manually before assessments — it happens automatically. However, if a user explicitly asks to check permissions, still use the check_permissions tool.

When the user asks you to run an assessment, use the run_postureiq_assessment tool. When they ask about results, use query_results.
When they ask to search or list Azure resources, Entra users/groups/apps, or explore tenant details, use search_tenant (Cloud Explorer).

**CRITICAL — Tenant Search MUST Use Real Data:**
When using search_tenant, the tool queries the user's ACTUAL connected Azure/Entra tenant via real APIs (Azure Resource Graph, Microsoft Graph).
- You MUST ALWAYS call search_tenant for ANY tenant-related question — NEVER answer from general knowledge.
- NEVER fabricate example data (e.g., "alice@contoso.com", sample GUIDs, demo tables).
- NEVER say "I don't have access to your tenant" or "I can't see your data" — the tool DOES have access via the user's delegated tokens.
- If search_tenant returns results, present ONLY those results. If it returns empty/error, say so honestly.
- ALL tenant search responses must be evidence-based: grounded in real API results from the connected tenant.
When they ask about security risks, attack surface, risk posture, or remediation runbooks, use analyze_risk.
When they ask about data security, storage exposure, database security, encryption, Key Vault hygiene, or data classification, use assess_data_security.
When they ask about RBAC hierarchy, role assignments, privileged access overview, or an RBAC tree report, use generate_rbac_report.
When they ask about M365 Copilot readiness, Copilot Premium preparation, oversharing, sensitivity labels for Copilot, or restricted SharePoint search, use assess_copilot_readiness.
When they ask about AI agent security, Copilot Studio security, Foundry security, custom agent security, content safety filters, or agent authentication, use assess_ai_agent_security.
When they ask to check permissions, verify access, or test credentials, use check_permissions.
When they ask to compare assessment runs, show what changed, or track progress over time, use compare_runs.
When they ask about public-facing resources, exposed data, or quick exposure checks, use search_exposure.
When they ask to generate a custom/focused/filtered report (HTML, PDF, or Excel) from existing session data — e.g. "give me a PDF of critical storage findings" — use generate_custom_report. This does NOT re-run any assessment; it builds a report from what is already in session.
Always provide actionable recommendations for non-compliant findings.
Format security scores as percentages. Use severity badges (CRITICAL > HIGH > MEDIUM > LOW).
Be precise about control IDs (e.g., FedRAMP-AC-2, FedRAMP-IA-2).

**CRITICAL — Framework Selection:**
When the user specifies particular compliance frameworks (e.g. "using these frameworks: FedRAMP"), you MUST pass EXACTLY those framework names to the run_postureiq_assessment tool's `frameworks` parameter as a comma-separated string.
NEVER default to "all" unless the user explicitly asks for "all frameworks" or does not mention specific frameworks.
Example: if the user says "Run an assessment using FedRAMP", call run_postureiq_assessment(frameworks="FedRAMP"), NOT run_postureiq_assessment(frameworks="all").

**CRITICAL — Assessment Output Rules (applies to ALL sidebar assessment tools):**
When ANY assessment tool (run_postureiq_assessment, analyze_risk, assess_data_security, generate_rbac_report, assess_copilot_readiness, assess_ai_agent_security) returns results, your ENTIRE response MUST follow this exact template — no exceptions:

1. **Executive Summary** (MANDATORY, max 300 words): Write a single paragraph summarizing the overall score/status, the most critical 2-3 risks found, and one key recommended action. Use severity emoji badges: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW.

2. **Download Links**: Download buttons are rendered AUTOMATICALLY by the app below your response. Do NOT output any download links, download tables, file names, URLs, or "Download Links Table" headings in your text. The app handles this.

3. **Follow-Up Prompt** (MANDATORY): End with exactly: "Want to explore specific categories, findings, or remediation steps? Just ask."

4. **STOP** — output ABSOLUTELY NOTHING else. No severity distribution tables. No category breakdowns. No top findings lists. No remediation steps. No priority sections. No domain scores. No bullet-point lists of findings. No "Here's what I found" expansions. No download links or tables. The detailed reports contain all of that — the user will download them or ask follow-up questions.

**CRITICAL — Follow-Up & Conversational Formatting:**
These rules apply ONLY when the user asks follow-up questions or uses Check Permissions / Tenant Search:

1. **Answer from existing results FIRST.** Use the `query_results` tool to look up specifics — do NOT re-run assessments. Only re-run if user explicitly says "run again", "re-run", "refresh", or "re-assess".
2. **CRITICAL — Present query_results data directly.** When query_results returns data (findings, resources, scores), you MUST present that data to the user in a clear structured format (tables, lists, headings). NEVER say "I don't have details" or suggest re-running when query_results returned actual data. The data from query_results IS real tenant data — present it.
3. **Rich detail is welcome in follow-ups.** When the user asks to drill down (e.g., "tell me about encryption findings", "what are the critical issues", "show me storage risks"), provide detailed markdown tables, severity badges, remediation steps, and structured analysis. Use clear headings and tables — never dump raw data.
4. **Never fabricate or hallucinate findings.** Every answer must be grounded in actual tool data. If unavailable, tell the user which assessment to run.
5. **Do NOT repeat download links** in follow-up responses. Reports were already presented.
6. **Check Permissions and Tenant Search** are NOT assessments — format their output naturally with tables and clear structure. The "assessment output rules" above do NOT apply to these tools.

**CRITICAL — Out-of-Scope Query Handling (applies to ALL tools):**
When a user asks a question that falls outside the scope of the tool that just ran or the current assessment context, you MUST:
1. **Acknowledge the question clearly** — e.g., "That's a great question about RBAC role assignments."
2. **Explain that this tool cannot answer it** and be specific about what the CURRENT tool covers:
   - Data Security covers: storage, databases, Key Vault, encryption, classification, data lifecycle, DLP alerts.
   - PostureIQ covers: access control, identity/auth, data protection, logging/monitoring, network security, governance/risk.
   - Risk Analysis covers: identity risk, network risk, Defender gaps, configuration drift, insider risk.
   - Copilot Readiness covers: oversharing, sensitivity labels, DLP, restricted SharePoint search, access governance, content lifecycle, audit/monitoring.
   - AI Agent Security covers: Copilot Studio agents, Foundry deployments, custom AI agents, content safety, agent authentication.
   - RBAC Report covers: role assignments, PIM eligibility, group expansion, management group hierarchy.
   - Cloud Explorer covers: real-time Azure resource and Entra ID object queries.
3. **Suggest Cloud Explorer** — if the question relates to querying tenant resources or data that could be explored interactively, suggest: "You can try asking this in **Cloud Explorer**, which can interactively query any Azure resource or Entra ID object in your tenant."
4. **NEVER give a vague response** like "I don't have that data" or "I can't see tool output" without explaining what the current tool CAN do.
5. **NEVER suggest the user run PowerShell/CLI commands** for data that an available EnterpriseSecurityIQ tool can provide.

You authenticate using the caller's Azure credentials via DefaultAzureCredential.
"""

# ── Collector → Required Permission mapping ─────────────────────
_COLLECTOR_PERMISSIONS: dict[str, str] = {
    # Entra / Graph collectors
    "EntraConditionalAccess": "Policy.Read.All",
    "EntraIdentityProtection": "IdentityRiskEvent.Read.All / IdentityRiskyUser.Read.All",
    "EntraRoles": "RoleManagement.Read.All",
    "EntraUsers": "User.Read.All",
    "EntraUserDetails": "UserAuthenticationMethod.Read.All",
    "EntraApplications": "Application.Read.All",
    "EntraWorkloadIdentity": "Application.Read.All",
    "EntraGovernance": "AccessReview.Read.All / EntitlementManagement.Read.All",
    "EntraAuditLogs": "AuditLog.Read.All",
    "EntraSecurityPolicies": "Policy.Read.All",
    "EntraRiskPolicies": "Policy.Read.All",
    "EntraTenant": "Directory.Read.All",
    "EntraAIIdentity": "Application.Read.All",
    "M365SensitivityLabels": "InformationProtection.Read",
    "M365LabelAnalytics": "InformationProtection.Read",
    "M365DLPAlerts": "Policy.Read.All",
    "M365Retention": "Policy.Read.All",
    "M365InsiderRisk": "Policy.Read.All",
    "M365eDiscovery": "Policy.Read.All",
    "SharePointOneDrive": "Sites.Read.All",
    "CopilotStudio": "Directory.Read.All",
    "FoundryConfig": "Contributor on AI Foundry resource",
    # Azure / ARM collectors
    "AzureDefenderPlans": "Security Reader on subscription",
    "AzureDefenderAdvanced": "Security Reader on subscription",
    "AzureSecurity": "Security Reader on subscription",
    "AzureSentinel": "Microsoft Sentinel Reader on workspace",
    "AzurePolicy": "Reader on subscription",
    "AzurePolicyCompliance": "Reader on subscription",
    "AzureNetwork": "Reader on subscription",
    "AzureNetworkExpanded": "Reader on subscription",
    "AzureStorage": "Reader on subscription",
    "StorageDataPlane": "Storage Blob Data Reader on storage account",
    "AzureDatabases": "Reader on subscription",
    "SqlDetailed": "Reader on SQL Server",
    "RdbmsDetailed": "Reader on database server",
    "AzureCosmosDBDataPlane": "Cosmos DB Account Reader on account",
    "AzureCompute": "Reader on subscription",
    "AzureContainers": "Reader on subscription",
    "AzureAKSInCluster": "Azure Kubernetes Service Cluster User on cluster",
    "AzureFunctions": "Reader on subscription",
    "AzureMonitoring": "Monitoring Reader on subscription",
    "AzureDiagnostics": "Reader on subscription",
    "AzureActivityLogs": "Reader on subscription",
    "AzureRBAC": "Reader on subscription",
    "AzurePurviewDLP": "Reader on Purview account",
    "AzureBackupDR": "Reader on subscription",
    "AzureApiManagement": "Reader on subscription",
    "AzureAPIMDataPlane": "Reader on API Management",
    "AcrDataPlane": "AcrPull on container registry",
    "AzureMLCognitive": "Reader on subscription",
    "AzureAIServices": "Cognitive Services User on resource",
    "AzureAIContentSafety": "Reader on AI Services resource",
    "AzureRedisIoTLogic": "Reader on subscription",
    "AzureMessaging": "Reader on subscription",
    "AzureDNS": "Reader on subscription",
    "AzureFrontDoorCDN": "Reader on subscription",
    "AzureArcHybrid": "Reader on subscription",
    "AzureBatchACI": "Reader on subscription",
    "AzureCostBilling": "Cost Management Reader on subscription",
    "AzureDataAnalytics": "Reader on subscription",
    "AzureManagedDisks": "Reader on subscription",
    "AzureAdditionalServices": "Reader on subscription",
    "AzureAppGateway": "Reader on subscription",
    "AzureResources": "Reader on subscription",
    "WebAppDetailed": "Reader on App Service",
}


def _permissions_impact_warning(access_denied: list[dict]) -> str:
    """Build a markdown warning block from a list of access-denied collector entries."""
    if not access_denied:
        return ""
    lines = [
        f"\n> ⚠️ **{len(access_denied)} data source(s) unavailable** due to insufficient permissions. "
        "Scores may be lower than actual.\n",
        "| Collector | Source | Required Permission |",
        "|---|---|---|",
    ]
    seen = set()
    for ad in access_denied:
        collector = ad.get("collector", "Unknown")
        if collector in seen:
            continue
        seen.add(collector)
        source = ad.get("source", "Unknown")
        perm = _COLLECTOR_PERMISSIONS.get(collector, "Check docs for required role")
        lines.append(f"| {collector} | {source} | {perm} |")
    lines.append("")
    return "\n".join(lines)


# ── Per-conversation session state ──────────────────────────────
_session_states: dict[str, dict] = {}      # keyed by conversation_id
_session_lock = asyncio.Lock()
_request_conversation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_request_conversation_id", default="__global__"
)

def _convo_id() -> str:
    return _request_conversation_id.get()

async def _get_session_state() -> dict:
    async with _session_lock:
        return dict(_session_states.get(_convo_id(), {}))

async def _set_session_state(state: dict) -> None:
    async with _session_lock:
        _session_states[_convo_id()] = state

async def _update_session_state(key: str, value) -> None:
    async with _session_lock:
        _session_states.setdefault(_convo_id(), {})[key] = value

async def clear_session(conversation_id: str | None = None) -> None:
    """Clear session state for a specific conversation (or current)."""
    cid = conversation_id or _convo_id()
    async with _session_lock:
        _session_states.pop(cid, None)


async def get_session_context_summary() -> str | None:
    """Return a brief summary of what assessment data is currently in session.
    Used by api.py to inject context so the LLM knows what's available
    and can answer follow-up questions without re-running tools."""
    state = await _get_session_state()
    if not state:
        return None

    parts = ["SESSION CONTEXT — The following assessment data is available from prior tool runs in this session. "
             "Use `query_results` to look up details. Do NOT re-run these assessments for follow-up questions."]

    # Data Security
    ds = state.get("data_security_results")
    if ds:
        ds_scores = ds.get("DataSecurityScores", {})
        # Count unique resources by type
        _res_types: dict[str, int] = {}
        for f in ds.get("Findings", []):
            for r in f.get("AffectedResources") or []:
                rt = r.get("Type", "resource")
                _res_types[rt] = _res_types.get(rt, 0) + 1
        res_summary = ", ".join(f"{c} {t}s" for t, c in sorted(_res_types.items(), key=lambda x: -x[1])[:5])
        parts.append(f"• Data Security: {ds_scores.get('OverallScore', 0)}/100 "
                      f"({ds_scores.get('OverallLevel', '').upper()}), "
                      f"{ds.get('FindingCount', 0)} findings across "
                      f"{', '.join(ds_scores.get('CategoryScores', {}).keys())}. "
                      f"Affected resources include: {res_summary}. "
                      f"Use query_results to list individual resources by type.")

    # Risk Analysis
    risk = state.get("risk_results")
    if risk:
        r_scores = risk.get("RiskScores", {})
        parts.append(f"• Risk Analysis: {r_scores.get('OverallScore', 0)}/100 "
                      f"({r_scores.get('OverallLevel', '').upper()}), "
                      f"{risk.get('FindingCount', 0)} findings")

    # Copilot Readiness
    cr = state.get("copilot_readiness_results")
    if cr:
        cr_scores = cr.get("ReadinessScores", cr.get("CopilotReadinessScores", {}))
        parts.append(f"• Copilot Readiness: {cr_scores.get('OverallScore', 0)}/100, "
                      f"{len(cr.get('Findings', []))} findings")

    # AI Agent Security
    ais = state.get("ai_agent_security_results")
    if ais:
        ai_scores = ais.get("AgentSecurityScores", ais.get("SecurityScores", ais.get("AIAgentSecurityScores", {})))
        parts.append(f"• AI Agent Security: {ai_scores.get('OverallScore', 0)}/100, "
                      f"{len(ais.get('Findings', []))} findings")

    # RBAC
    rbac = state.get("rbac_results")
    if rbac:
        rbac_stats = rbac.get("stats", {})
        rbac_risks = rbac.get("risks", [])
        parts.append(f"• RBAC Report: {rbac_stats.get('subscription_count', 0)} subscriptions, "
                      f"{rbac_stats.get('total_assignments', 0)} assignments, "
                      f"{rbac_stats.get('eligible_assignments', 0)} PIM eligible, "
                      f"{len(rbac_risks)} risks, "
                      f"score {rbac_stats.get('rbac_score', 0)}/100. "
                      f"Use query_results to list subscriptions, role assignments, risks, or principals.")

    # PostureIQ
    piq = state.get("postureiq_results")
    if piq:
        piq_summary = piq.get("summary", {})
        risk_s = piq_summary.get("RiskSummary", {})
        attack_s = piq_summary.get("AttackPaths", {})
        prio_s = piq_summary.get("PrioritySummary", {})
        parts.append(
            f"• PostureIQ: score {piq_summary.get('ComplianceScore', 0):.0f}%, "
            f"{piq_summary.get('TotalFindings', 0)} findings, "
            f"risk tiers: {risk_s.get('CriticalRisk', 0)} critical / {risk_s.get('HighRisk', 0)} high / {risk_s.get('MediumRisk', 0)} medium, "
            f"{attack_s.get('TotalPaths', 0)} attack paths "
            f"(escalation={attack_s.get('PrivilegeEscalation', 0)}, lateral={attack_s.get('LateralMovement', 0)}, "
            f"credential-chain={attack_s.get('CredentialChain', 0)}, CA-bypass={attack_s.get('CABypass', 0)}, "
            f"network-pivot={attack_s.get('NetworkPivot', 0)}), "
            f"{prio_s.get('ByLabel', {}).get('Fix Immediately', 0)} fix-immediately, "
            f"{len(prio_s.get('QuickWins', []))} quick wins. "
            f"Use query_results to list findings, attack paths, priorities, or quick wins."
        )

    # Tenant Search cached results
    ts_cache = state.get("tenant_search_results", [])
    if ts_cache:
        total_items = sum(e.get("count", 0) for e in ts_cache)
        queries = [e.get("question", "")[:50] for e in ts_cache[-3:]]
        parts.append(f"• Tenant Search: {len(ts_cache)} cached searches, {total_items} total items. "
                      f"Recent queries: {'; '.join(queries)}. "
                      f"Use query_results to filter cached search results by keyword.")

    if len(parts) == 1:
        return None  # Only header, no actual data
    return "\n".join(parts)


# ── Session-duplicate guard ─────────────────────────────────────
# Maps each assessment tool to its session-state key and a human label.
_TOOL_SESSION_KEYS: dict[str, tuple[str, str]] = {
    "analyze_risk":             ("risk_results",                "Risk Analysis"),
    "assess_data_security":     ("data_security_results",       "Data Security"),
    "generate_rbac_report":     ("rbac_results",                "RBAC Report"),
    "assess_copilot_readiness": ("copilot_readiness_results",   "Copilot Readiness"),
    "assess_ai_agent_security": ("ai_agent_security_results",   "AI Agent Security"),
    "run_postureiq_assessment": ("postureiq_results",           "PostureIQ"),
}

async def _session_duplicate_guard(tool_name: str) -> str | None:
    """If results already exist in this session, return a redirect message
    telling the LLM to use query_results instead of re-running.
    Returns None when no prior results exist (allow the tool to proceed)."""
    entry = _TOOL_SESSION_KEYS.get(tool_name)
    if not entry:
        return None
    session_key, label = entry
    state = await _get_session_state()
    existing = state.get(session_key) if state else None
    if not existing:
        return None

    # Build a concise summary of what's already cached
    hint = f"{label} results are already available in this session."
    if session_key == "postureiq_results":
        s = existing.get("summary", {})
        hint += f" Score: {s.get('ComplianceScore', 0):.0f}%, {s.get('TotalFindings', 0)} findings."
    elif session_key in ("data_security_results", "risk_results"):
        sc = existing.get("DataSecurityScores", existing.get("RiskScores", {}))
        hint += f" Score: {sc.get('OverallScore', 0)}/100, {existing.get('FindingCount', 0)} findings."
    elif session_key == "rbac_results":
        st = existing.get("stats", {})
        hint += f" {st.get('total_assignments', 0)} assignments, {len(existing.get('risks', []))} risks."
    elif session_key == "copilot_readiness_results":
        sc = existing.get("CopilotReadinessScores", existing.get("ReadinessScores", {}))
        hint += f" Score: {sc.get('OverallScore', 0)}/100, {len(existing.get('Findings', []))} findings."
    elif session_key == "ai_agent_security_results":
        sc = existing.get("AgentSecurityScores", existing.get("SecurityScores", {}))
        hint += f" Score: {sc.get('OverallScore', 0)}/100, {len(existing.get('Findings', []))} findings."

    return (
        f"{hint}\n\n"
        "Use the `query_results` tool to answer follow-up questions from this data. "
        "Do NOT re-run the assessment. To run a fresh assessment, the user must start a New Chat."
    )


async def get_completed_assessment_tools() -> set[str]:
    """Return the set of assessment tool names that already have cached results
    in the current session.  Called from api.py to strip those tools from the
    LLM's tool schema so it literally cannot re-invoke them."""
    state = await _get_session_state()
    if not state:
        return set()
    return {tool for tool, (key, _) in _TOOL_SESSION_KEYS.items() if state.get(key)}


async def query_results(
    question: Annotated[
        str,
        "Natural language question about any assessment results stored in the session — "
        "compliance controls, data security findings, risk analysis, copilot readiness, "
        "AI agent security, RBAC, PostureIQ (risk scoring, attack paths, priority ranking, "
        "quick wins, AI fixes), or general summary. Searches across ALL assessment types.",
    ],
) -> str:
    """Query stored assessment results. Searches compliance, data security, risk analysis, copilot readiness, AI agent security, RBAC, and PostureIQ data. Use this for follow-up questions instead of re-running assessments."""
    state = await _get_session_state()

    if not state:
        return "No assessment results available. Please run an assessment first."

    def _fmt_resources(f: dict, limit: int = 8) -> str:
        """Format AffectedResources names from a finding into a compact line."""
        res = f.get("AffectedResources") or []
        names = [r.get("Name") or r.get("ResourceName") or r.get("ResourceId", "").rsplit("/", 1)[-1] for r in res]
        names = [n for n in names if n and n != "Unknown"]
        if not names:
            cnt = f.get("AffectedCount", 0)
            return f" ({cnt} resources)" if cnt else ""
        total = len(names)
        shown = names[:limit]
        suffix = f", … +{total - limit} more" if total > limit else ""
        return f" ({total} resources)\n  Resources: {', '.join(shown)}{suffix}\n"

    def _resource_centric_view(findings: list[dict], type_patterns: list[str]) -> str | None:
        """Scan ALL findings, extract resources matching type patterns, group by resource name."""
        by_resource: dict[str, list[dict]] = {}
        for f in findings:
            for r in f.get("AffectedResources") or []:
                rtype = (r.get("Type") or "").lower()
                rname = r.get("Name") or r.get("ResourceName") or r.get("ResourceId", "").rsplit("/", 1)[-1]
                if not rname or rname == "Unknown":
                    continue
                if type_patterns and not any(p in rtype for p in type_patterns):
                    continue
                by_resource.setdefault(rname, []).append({
                    "title": f.get("Title", ""),
                    "severity": f.get("Severity", ""),
                    "remediation": (f.get("Remediation") or {}).get("Description", ""),
                    "category": f.get("Category", ""),
                })
        if not by_resource:
            return None
        # Sort resources by issue count (most issues first)
        result = f"REAL TENANT DATA — {len(by_resource)} resource(s) found:\n\n"
        for name, issues in sorted(by_resource.items(), key=lambda x: -len(x[1])):
            result += f"### {name} ({len(issues)} issue{'s' if len(issues) != 1 else ''})\n"
            for iss in sorted(issues, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"].lower(), 4)):
                result += f"- **[{iss['severity'].upper()}]** {iss['title']}\n"
                if iss["remediation"]:
                    result += f"  → {iss['remediation']}\n"
        return result

    q = question.lower()

    # ── Data Security results ──
    ds = state.get("data_security_results")
    if ds and any(kw in q for kw in ["data security", "storage", "database", "keyvault", "key vault",
                                       "encryption", "classification", "data lifecycle", "dlp",
                                       "data exposure", "blob", "sql", "cosmos", "account",
                                       "disk", "tls", "public access", "private endpoint",
                                       "need attention", "at risk", "vulnerable", "issue",
                                       "finding", "problem", "insecure", "misconfigured"]):
        scores = ds.get("DataSecurityScores", {})
        findings = ds.get("Findings", [])
        cats = scores.get("CategoryScores", {})

        # ── Resource-type search (must come BEFORE category matching) ──
        _DS_RESOURCE_TYPES = {
            "storage account": ["storage", "blob", "storageaccount"],
            "storage": ["storage", "blob", "storageaccount"],
            "blob": ["storage", "blob"],
            "database": ["database", "sql", "cosmos", "mysql", "postgres", "mariadb"],
            "sql": ["sql", "database"],
            "cosmos": ["cosmos"],
            "key vault": ["keyvault", "key_vault", "vault"],
            "keyvault": ["keyvault", "key_vault", "vault"],
            "disk": ["disk", "manageddisk"],
        }
        for phrase, patterns in _DS_RESOURCE_TYPES.items():
            if phrase in q:
                view = _resource_centric_view(findings, patterns)
                if view:
                    return f"## Data Security — {phrase.title()} Resources\n\n{view}"
                break  # matched phrase but no resources — fall through

        # Search by category
        for cat_key, cat_data in cats.items():
            if cat_key.lower() in q:
                cat_findings = [f for f in findings if f.get("Category", "").lower() == cat_key.lower()]
                result = f"## Data Security — {cat_key.title()}\n"
                result += f"Score: {cat_data.get('Score', 0):.0f}/100 ({cat_data.get('Level', '').upper()})\n"
                result += f"Findings: {cat_data.get('FindingCount', 0)}\n\n"
                for f in sorted(cat_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:15]:
                    result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', '')}{_fmt_resources(f)}\n"
                    if f.get("Remediation", {}).get("Description"):
                        result += f"  → {f['Remediation']['Description']}\n"
                return result

        # Search by severity
        if any(kw in q for kw in ["critical", "high", "severe"]):
            severe = [f for f in findings if f.get("Severity", "").lower() in ("critical", "high")]
            severe.sort(key=lambda x: {"critical": 0, "high": 1}.get(x.get("Severity", "").lower(), 2))
            result = f"## Data Security — Critical/High Findings ({len(severe)})\n\n"
            for f in severe[:20]:
                result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', '')}{_fmt_resources(f)}\n"
                if f.get("Remediation", {}).get("Description"):
                    result += f"  → {f['Remediation']['Description']}\n"
            return result

        # General data security summary
        result = f"## Data Security Summary\n\n"
        result += f"Overall Score: {scores.get('OverallScore', 0)}/100 ({scores.get('OverallLevel', '').upper()})\n"
        result += f"Total Findings: {ds.get('FindingCount', 0)}\n\n"
        dist = scores.get("SeverityDistribution", {})
        result += f"| Severity | Count |\n|---|---|\n"
        for sev in ("critical", "high", "medium", "low"):
            result += f"| {sev.title()} | {dist.get(sev, 0)} |\n"
        result += f"\n**Categories:**\n"
        for cat, cs in cats.items():
            result += f"- {cat.title()}: {cs.get('Score', 0):.0f}/100 — {cs.get('FindingCount', 0)} findings\n"
        result += f"\n**All Findings:**\n"
        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:25]:
            result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', '')}{_fmt_resources(f)}\n"
        return result

    # ── Risk Analysis results ──
    risk = state.get("risk_results")
    if risk and any(kw in q for kw in ["risk", "threat", "attack", "vulnerability", "remediation",
                                        "identity risk", "network risk", "defender", "insider",
                                        "config", "posture", "gap", "vm", "virtual machine",
                                        "service principal", "app registration", "user",
                                        "stale", "dormant", "nsg", "firewall"]):
        scores = risk.get("RiskScores", {})
        findings = risk.get("Findings", [])
        cats = risk.get("CategoryCounts", {})

        # Resource-type search for risk
        _RISK_RESOURCE_TYPES = {
            "vm": ["vm", "virtualmachine"],
            "virtual machine": ["vm", "virtualmachine"],
            "service principal": ["serviceprincipal", "application"],
            "app registration": ["application", "serviceprincipal"],
            "nsg": ["nsg", "networksecuritygroup"],
            "firewall": ["firewall"],
        }
        for phrase, patterns in _RISK_RESOURCE_TYPES.items():
            if phrase in q:
                view = _resource_centric_view(findings, patterns)
                if view:
                    return f"## Risk Analysis — {phrase.title()} Resources\n\n{view}"
                break

        # Search by category
        for cat in ["identity", "network", "defender", "config", "insider_risk"]:
            if cat.replace("_", " ") in q or cat in q:
                cat_findings = [f for f in findings if f.get("Category", "").lower() == cat.lower()]
                result = f"## Risk Analysis — {cat.replace('_', ' ').title()}\n"
                result += f"Findings: {len(cat_findings)}\n\n"
                for f in sorted(cat_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:15]:
                    result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', '')}{_fmt_resources(f)}\n"
                    if f.get("Remediation", {}).get("Description"):
                        result += f"  → {f['Remediation']['Description']}\n"
                return result

        # Search by severity
        if any(kw in q for kw in ["critical", "high", "severe"]):
            severe = [f for f in findings if f.get("Severity", "").lower() in ("critical", "high")]
            severe.sort(key=lambda x: {"critical": 0, "high": 1}.get(x.get("Severity", "").lower(), 2))
            result = f"## Risk Analysis — Critical/High Findings ({len(severe)})\n\n"
            for f in severe[:20]:
                result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', '')}{_fmt_resources(f)}\n"
                if f.get("Remediation", {}).get("Description"):
                    result += f"  → {f['Remediation']['Description']}\n"
            return result

        # General risk summary
        result = f"## Risk Analysis Summary\n\n"
        result += f"Overall Risk Score: {scores.get('OverallScore', 0)}/100 ({scores.get('OverallLevel', '').upper()})\n\n"
        for cat, count in cats.items():
            result += f"- {cat.replace('_', ' ').title()}: {count} findings\n"
        top = scores.get("TopFindings", [])
        if top:
            result += f"\n**Top Risks:**\n"
            for t in top[:5]:
                result += f"- **[{t.get('Severity', '').upper()}]** {t.get('Title', '')}{_fmt_resources(t)}\n"
        result += f"\n**All Findings:**\n"
        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:25]:
            result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', '')}{_fmt_resources(f)}\n"
        return result

    # ── Copilot Readiness results ──
    cr = state.get("copilot_readiness_results")
    if cr and any(kw in q for kw in ["copilot", "m365", "oversharing", "sensitivity label",
                                       "dlp", "sharepoint search", "readiness",
                                       "sharepoint", "site", "label", "sharing",
                                       "need attention", "at risk", "issue", "finding",
                                       "problem", "gap", "license"]):
        scores = cr.get("ReadinessScores", cr.get("CopilotReadinessScores", {}))
        findings = cr.get("Findings", [])

        # Resource-type search for copilot readiness
        for phrase in ["sharepoint", "site", "tenant"]:
            if phrase in q:
                view = _resource_centric_view(findings, [])
                if view:
                    return f"## Copilot Readiness — Resources\n\n{view}"
                break

        # Search by category
        cr_cats = cr.get("Categories", {})
        for cat_key in cr_cats:
            if cat_key.lower().replace("_", " ") in q or cat_key.lower() in q:
                cat_findings = [f for f in findings if f.get("Category", "").lower() == cat_key.lower()]
                result = f"## Copilot Readiness — {cat_key.replace('_', ' ').title()}\n"
                result += f"Findings: {len(cat_findings)}\n\n"
                for f in sorted(cat_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:15]:
                    result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', f.get('Description', ''))}{_fmt_resources(f)}\n"
                    if (f.get("Remediation") or {}).get("Description"):
                        result += f"  → {f['Remediation']['Description']}\n"
                return result

        # Search by severity
        if any(kw in q for kw in ["critical", "high", "severe"]):
            severe = [f for f in findings if f.get("Severity", "").lower() in ("critical", "high")]
            severe.sort(key=lambda x: {"critical": 0, "high": 1}.get(x.get("Severity", "").lower(), 2))
            result = f"## Copilot Readiness — Critical/High Findings ({len(severe)})\n\n"
            for f in severe[:20]:
                result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', f.get('Description', ''))}{_fmt_resources(f)}\n"
                if (f.get("Remediation") or {}).get("Description"):
                    result += f"  → {f['Remediation']['Description']}\n"
            return result

        # General summary
        result = f"## Copilot Readiness Summary\n\n"
        result += f"Overall Score: {scores.get('OverallScore', 0)}/100 ({scores.get('OverallLevel', '').upper()})\n"
        result += f"Total Findings: {len(findings)}\n\n"
        if cr_cats:
            result += "**Categories:**\n"
            for cat_key, cat_list in cr_cats.items():
                result += f"- {cat_key.replace('_', ' ').title()}: {len(cat_list) if isinstance(cat_list, list) else 0} findings\n"
            result += "\n"
        result += "**All Findings:**\n"
        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:20]:
            result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', f.get('Description', ''))}{_fmt_resources(f)}\n"
        return result

    # ── AI Agent Security results ──
    ais = state.get("ai_agent_security_results")
    if ais and any(kw in q for kw in ["ai agent", "copilot studio", "foundry", "agent security",
                                        "content safety", "agent auth",
                                        "bot", "agent", "environment",
                                        "need attention", "at risk", "issue", "finding",
                                        "problem"]):
        scores = ais.get("AgentSecurityScores", ais.get("SecurityScores", ais.get("AIAgentSecurityScores", {})))
        findings = ais.get("Findings", [])

        # Resource-type search for AI agent security
        _AI_RESOURCE_TYPES = {
            "bot": ["copilotstudiobot", "bot"],
            "copilot studio": ["copilotstudiobot", "bot"],
            "agent": ["bot", "agent", "foundry"],
            "environment": ["environment", "powerplatform"],
        }
        for phrase, patterns in _AI_RESOURCE_TYPES.items():
            if phrase in q:
                view = _resource_centric_view(findings, patterns)
                if view:
                    return f"## AI Agent Security — {phrase.title()} Resources\n\n{view}"
                break

        # Search by category
        ais_cats = ais.get("Categories", {})
        for cat_key in ais_cats:
            if cat_key.lower().replace("_", " ") in q or cat_key.lower() in q:
                cat_findings = [f for f in findings if f.get("Category", "").lower() == cat_key.lower()]
                result = f"## AI Agent Security — {cat_key.replace('_', ' ').title()}\n"
                result += f"Findings: {len(cat_findings)}\n\n"
                for f in sorted(cat_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:15]:
                    result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', f.get('Description', ''))}{_fmt_resources(f)}\n"
                    if (f.get("Remediation") or {}).get("Description"):
                        result += f"  → {f['Remediation']['Description']}\n"
                return result

        # Search by severity
        if any(kw in q for kw in ["critical", "high", "severe"]):
            severe = [f for f in findings if f.get("Severity", "").lower() in ("critical", "high")]
            severe.sort(key=lambda x: {"critical": 0, "high": 1}.get(x.get("Severity", "").lower(), 2))
            result = f"## AI Agent Security — Critical/High Findings ({len(severe)})\n\n"
            for f in severe[:20]:
                result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', f.get('Description', ''))}{_fmt_resources(f)}\n"
                if (f.get("Remediation") or {}).get("Description"):
                    result += f"  → {f['Remediation']['Description']}\n"
            return result

        # General summary
        result = f"## AI Agent Security Summary\n\n"
        result += f"Overall Score: {scores.get('OverallScore', 0)}/100 ({scores.get('OverallLevel', '').upper()})\n"
        result += f"Total Findings: {len(findings)}\n\n"
        if ais_cats:
            result += "**Categories:**\n"
            for cat_key, cat_list in ais_cats.items():
                result += f"- {cat_key.replace('_', ' ').title()}: {len(cat_list) if isinstance(cat_list, list) else 0} findings\n"
            result += "\n"
        result += "**All Findings:**\n"
        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("Severity", "").lower(), 4))[:20]:
            result += f"- **[{f.get('Severity', '').upper()}]** {f.get('Title', f.get('Description', ''))}{_fmt_resources(f)}\n"
        return result

    # ── RBAC Report results ──
    rbac = state.get("rbac_results")
    if rbac and any(kw in q for kw in ["rbac", "role", "assignment", "subscription", "management group",
                                         "pim", "eligible", "privileged", "owner", "contributor",
                                         "reader", "principal", "user", "group", "service principal",
                                         "resource group", "hierarchy", "tree", "permission",
                                         "direct assignment", "direct role"]):
        rbac_stats = rbac.get("stats", {})
        rbac_risks = rbac.get("risks", [])
        rbac_tree = rbac.get("tree", {})
        principals = rbac.get("principals", {})

        def _flatten_subs(node: dict) -> list[dict]:
            """Recursively extract subscription nodes from the RBAC tree."""
            subs = []
            if node.get("type") == "Subscription":
                subs.append(node)
            for child in node.get("children") or []:
                subs.extend(_flatten_subs(child))
            return subs

        def _flatten_all_assignments(node: dict) -> list[dict]:
            """Recursively collect ALL assignments from the tree."""
            assignments = []
            for a in node.get("assignments") or []:
                a["_scope_name"] = node.get("display_name") or node.get("name", "")
                a["_scope_type"] = node.get("type", "")
                assignments.append(a)
            for a in node.get("eligible") or []:
                a["_scope_name"] = node.get("display_name") or node.get("name", "")
                a["_scope_type"] = node.get("type", "")
                a["status"] = "Eligible"
                assignments.append(a)
            for child in node.get("children") or []:
                assignments.extend(_flatten_all_assignments(child))
            for rg in node.get("resource_groups") or []:
                for a in rg.get("assignments") or []:
                    a["_scope_name"] = rg.get("name", "")
                    a["_scope_type"] = "ResourceGroup"
                    assignments.append(a)
            return assignments

        # Subscription-focused queries
        if any(kw in q for kw in ["subscription"]):
            subs = _flatten_subs(rbac_tree)
            if not subs:
                return "## RBAC — Subscriptions\n\nNo subscriptions found in the RBAC tree."
            # Check if asking about direct assignments
            if any(kw in q for kw in ["direct", "assignment", "role"]):
                result = f"## RBAC — Subscriptions with Direct Role Assignments\n\n"
                result += f"REAL TENANT DATA — {len(subs)} subscription(s):\n\n"
                for sub in subs:
                    assigns = sub.get("assignments") or []
                    eligible = sub.get("eligible") or []
                    if assigns or eligible or "all" in q or "list" in q:
                        result += f"### {sub.get('display_name', sub.get('name', 'Unknown'))}\n"
                        result += f"ID: `{sub.get('id', '')}`\n"
                        result += f"Active assignments: {len(assigns)} | PIM eligible: {len(eligible)}\n\n"
                        if assigns:
                            for a in assigns[:15]:
                                p = principals.get(a.get("principal_id", ""), {})
                                pname = p.get("display_name", a.get("principal_id", "Unknown"))
                                result += f"- **{a.get('role_name', '')}** → {pname} ({a.get('principal_type', '')})"
                                if a.get("is_privileged"):
                                    result += " 🔴 PRIVILEGED"
                                result += "\n"
                        if eligible:
                            result += f"  _PIM eligible:_\n"
                            for a in eligible[:10]:
                                p = principals.get(a.get("principal_id", ""), {})
                                pname = p.get("display_name", a.get("principal_id", "Unknown"))
                                result += f"  - **{a.get('role_name', '')}** → {pname} ({a.get('principal_type', '')})\n"
                        result += "\n"
                return result
            else:
                result = f"## RBAC — Subscriptions ({len(subs)})\n\n"
                for sub in subs:
                    assigns = sub.get("assignments") or []
                    eligible = sub.get("eligible") or []
                    result += f"- **{sub.get('display_name', sub.get('name', 'Unknown'))}** — "
                    result += f"{len(assigns)} active assignments, {len(eligible)} PIM eligible\n"
                return result

        # Risk-focused queries
        if any(kw in q for kw in ["risk", "privileged", "owner", "standing", "dangerous", "concern"]):
            if not rbac_risks:
                return "## RBAC — Risks\n\nNo RBAC risks found. Your role assignment hygiene looks good."
            result = f"## RBAC — Risks ({len(rbac_risks)})\n\n"
            for r in sorted(rbac_risks, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "").lower(), 4))[:25]:
                p = principals.get(r.get("principal_id", ""), {})
                pname = p.get("display_name", r.get("principal_id", "Unknown"))
                result += f"- **[{r.get('severity', '').upper()}]** {r.get('title', '')}\n"
                result += f"  Principal: {pname} | Role: {r.get('role_name', '')} | Scope: {r.get('scope', '')}\n"
                if r.get("remediation"):
                    result += f"  → {r['remediation']}\n"
            return result

        # PIM / eligible queries
        if any(kw in q for kw in ["pim", "eligible"]):
            all_assigns = _flatten_all_assignments(rbac_tree)
            eligible = [a for a in all_assigns if a.get("status", "").lower() == "eligible"]
            if not eligible:
                return "## RBAC — PIM Eligible\n\nNo PIM-eligible role assignments found."
            result = f"## RBAC — PIM Eligible Assignments ({len(eligible)})\n\n"
            for a in eligible[:25]:
                p = principals.get(a.get("principal_id", ""), {})
                pname = p.get("display_name", a.get("principal_id", "Unknown"))
                result += f"- **{a.get('role_name', '')}** → {pname} ({a.get('principal_type', '')})"
                result += f" @ {a.get('_scope_name', '')} ({a.get('_scope_type', '')})\n"
            return result

        # Role-name search (owner, contributor, reader, etc.)
        for role_kw in ["owner", "contributor", "reader"]:
            if role_kw in q:
                all_assigns = _flatten_all_assignments(rbac_tree)
                matched = [a for a in all_assigns if role_kw in (a.get("role_name") or "").lower()]
                if not matched:
                    return f"## RBAC — {role_kw.title()} Assignments\n\nNo {role_kw} role assignments found."
                result = f"## RBAC — {role_kw.title()} Role Assignments ({len(matched)})\n\n"
                for a in matched[:25]:
                    p = principals.get(a.get("principal_id", ""), {})
                    pname = p.get("display_name", a.get("principal_id", "Unknown"))
                    result += f"- **{a.get('role_name', '')}** → {pname} ({a.get('principal_type', '')})"
                    result += f" @ {a.get('_scope_name', '')} ({a.get('_scope_type', '')})"
                    if a.get("is_privileged"):
                        result += " 🔴"
                    result += "\n"
                return result

        # General RBAC summary
        result = f"## RBAC Report Summary\n\n"
        result += f"RBAC Score: {rbac_stats.get('rbac_score', 0)}/100\n"
        result += f"Subscriptions: {rbac_stats.get('subscription_count', 0)} | "
        result += f"Management Groups: {rbac_stats.get('management_groups', 0)}\n"
        result += f"Total Assignments: {rbac_stats.get('total_assignments', 0)} | "
        result += f"Active: {rbac_stats.get('active_assignments', 0)} | "
        result += f"PIM Eligible: {rbac_stats.get('eligible_assignments', 0)}\n"
        result += f"Privileged Active: {rbac_stats.get('privileged_active', 0)} | "
        result += f"Privileged Eligible: {rbac_stats.get('privileged_eligible', 0)}\n"
        result += f"Unique Principals: {rbac_stats.get('unique_principals', 0)} | "
        result += f"Custom Roles: {rbac_stats.get('custom_roles', 0)}\n"
        result += f"Risks: {len(rbac_risks)}\n\n"
        if rbac_risks:
            result += "**Top Risks:**\n"
            for r in sorted(rbac_risks, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "").lower(), 4))[:10]:
                result += f"- **[{r.get('severity', '').upper()}]** {r.get('title', '')}\n"
        return result

    # ── PostureIQ results ──
    piq = state.get("postureiq_results")
    if piq and any(kw in q for kw in ["postureiq", "posture", "risk score", "risk tier",
                                        "attack path", "lateral movement", "privilege escalation",
                                        "credential chain", "keyvault chain", "key vault chain",
                                        "ca bypass", "conditional access bypass", "network pivot",
                                        "app mi chain", "managed identity chain",
                                        "priority", "quick win", "fix immediately", "fix soon",
                                        "plan fix", "effort", "ai fix", "remediation script",
                                        "top 5", "top 10", "top five", "top ten",
                                        "10 top", "5 top", "top risk", "top issue",
                                        "action immediately", "required action", "actions immediately",
                                        "address immediately", "address now", "act on",
                                        "finding", "non-compliant", "fail", "critical", "high",
                                        "framework", "compliance", "score", "summary",
                                        "exception", "suppression", "audit trail",
                                        "private endpoint", "network", "domain",
                                        "risk", "across all", "among all", "all framework",
                                        "worst", "most important", "biggest", "urgent"]):
        piq_summary = piq.get("summary", {})
        piq_findings = piq.get("findings", [])
        piq_controls = piq.get("control_results", [])

        # ── Fix Immediately / top priority queries ──
        if any(kw in q for kw in ["fix immediately", "action immediately", "actions immediately",
                                    "address immediately", "address now", "act on", "urgent",
                                    "required action", "top 5", "top 10", "top five", "top ten",
                                    "10 top", "5 top", "top risk", "top issue",
                                    "worst", "most important", "biggest",
                                    "priority", "quick win",
                                    "across all", "among all", "all framework"]):
            # Gather priority-enriched findings
            fix_imm = [f for f in piq_findings
                       if f.get("PriorityLabel") == "Fix Immediately"
                       or f.get("RiskTier") in ("Critical", "High")]
            fix_imm.sort(key=lambda x: (
                -x.get("RiskScore", 0),
                x.get("PriorityRank", 9999),
            ))

            # Deduplicate by ControlId across frameworks
            seen_controls: dict[str, dict] = {}
            for f in fix_imm:
                cid = f.get("ControlId", "")
                title = f.get("Title") or f.get("Description", "")
                key = f"{cid}::{title}"
                if key not in seen_controls:
                    seen_controls[key] = f
                else:
                    # Merge framework info
                    existing_fw = seen_controls[key].get("Framework", "")
                    new_fw = f.get("Framework", "")
                    if new_fw and new_fw not in existing_fw:
                        seen_controls[key]["Framework"] = f"{existing_fw}, {new_fw}"

            consolidated = list(seen_controls.values())
            consolidated.sort(key=lambda x: (
                -x.get("RiskScore", 0),
                x.get("PriorityRank", 9999),
            ))

            # Determine limit
            limit = 5
            if any(kw in q for kw in ["top 10", "top ten"]):
                limit = 10
            elif any(kw in q for kw in ["all", "every", "full list"]):
                limit = len(consolidated)

            # Quick wins sub-filter
            if "quick win" in q:
                consolidated = [f for f in consolidated if f.get("EffortHours", 99) <= 2]
                result = f"## PostureIQ — Quick Wins ({len(consolidated)} findings, ≤2h effort each)\n\n"
            else:
                result = f"## PostureIQ — Top {min(limit, len(consolidated))} Priority Findings (consolidated across frameworks)\n\n"

            result += "| Rank | Finding / Risk | Severity | Risk Score | Frameworks | Remediation | Effort |\n"
            result += "|------|---------------|----------|------------|------------|-------------|--------|\n"
            for i, f in enumerate(consolidated[:limit], 1):
                title = f.get("Title") or f.get("Description", "")
                sev = f.get("Severity", "").upper()
                rscore = f.get("RiskScore", 0)
                fw = f.get("Framework", "")
                rem = (f.get("Remediation") or {}).get("Description", "") if isinstance(f.get("Remediation"), dict) else str(f.get("Remediation", ""))
                effort = f.get("EffortHours", "—")
                result += f"| {i} | {title} | {sev} | {rscore:.0f} | {fw} | {rem[:100]} | {effort}h |\n"

            prio_summary = piq_summary.get("PrioritySummary", {})
            if prio_summary:
                labels = prio_summary.get("ByLabel", {})
                result += (
                    f"\n**Overall:** {labels.get('Fix Immediately', 0)} fix immediately, "
                    f"{labels.get('Fix Soon', 0)} fix soon, "
                    f"{labels.get('Plan Fix', 0)} plan fix | "
                    f"Total effort: {prio_summary.get('TotalEffortHours', 0)}h | "
                    f"Quick wins: {len(prio_summary.get('QuickWins', []))}\n"
                )
            return result

        # ── Attack path queries ──
        if any(kw in q for kw in ["attack path", "lateral movement", "privilege escalation",
                                    "exposed", "high-value", "credential chain", "keyvault chain",
                                    "key vault chain", "ca bypass", "conditional access bypass",
                                    "network pivot", "app mi chain", "managed identity chain"]):
            ap = piq_summary.get("AttackPaths", {})
            ap_details = piq.get("attack_paths", [])
            result = f"## PostureIQ — Attack Path Analysis (Multi-Hop Deep)\n\n"
            result += (
                f"**Total Paths:** {ap.get('TotalPaths', 0)} | "
                f"**Critical:** {ap.get('CriticalPaths', 0)} | "
                f"**High:** {ap.get('HighPaths', 0)} | "
                f"**Medium:** {ap.get('MediumPaths', 0)}\n\n"
            )
            result += (
                f"| Category | Count |\n|---|---|\n"
                f"| Privilege Escalation | {ap.get('PrivilegeEscalation', 0)} |\n"
                f"| Lateral Movement | {ap.get('LateralMovement', 0)} |\n"
                f"| Exposed High-Value | {ap.get('ExposedHighValue', 0)} |\n"
                f"| Credential Chain | {ap.get('CredentialChain', 0)} |\n"
                f"| CA Bypass (No MFA) | {ap.get('CABypass', 0)} |\n"
                f"| Network Pivot | {ap.get('NetworkPivot', 0)} |\n"
                f"| App → MI Chain | {ap.get('AppMIChain', 0)} |\n\n"
            )

            # Allow filtering by subtype
            all_paths = (ap_details.get("paths", []) if isinstance(ap_details, dict)
                         else ap_details if isinstance(ap_details, list) else [])
            filter_type = None
            if "credential chain" in q or "keyvault" in q or "key vault" in q:
                filter_type = "credential_chain"
            elif "ca bypass" in q or "conditional access" in q:
                filter_type = "ca_bypass"
            elif "network pivot" in q:
                filter_type = "network_pivot"
            elif "app mi" in q or "managed identity chain" in q:
                filter_type = "app_mi_to_resource"

            if filter_type and all_paths:
                filtered = [p for p in all_paths
                            if p.get("Type") == filter_type or p.get("Subtype") == filter_type]
                if filtered:
                    result += f"### Filtered: {filter_type.replace('_', ' ').title()} ({len(filtered)})\n\n"
                    for p in sorted(filtered, key=lambda x: x.get("RiskScore", 0), reverse=True)[:15]:
                        result += (f"- **[{p.get('Severity', '').upper()} / Score {p.get('RiskScore', 0)}]** "
                                   f"{p.get('Chain', p.get('description', ''))}\n")
                else:
                    result += f"_No paths of type '{filter_type}' found._\n"
            elif all_paths:
                result += "### Top Paths (by Risk Score)\n\n"
                for p in sorted(all_paths, key=lambda x: x.get("RiskScore", 0), reverse=True)[:15]:
                    ptype = p.get("Type", "")
                    subtype = p.get("Subtype", "")
                    label = f"{ptype}" + (f"/{subtype}" if subtype else "")
                    result += (f"- **[{p.get('Severity', '').upper()} / Score {p.get('RiskScore', 0)}]** "
                               f"`{label}`: {p.get('Chain', p.get('description', ''))}\n")
            elif ap.get("TotalPaths", 0) > 0:
                result += "_Attack path details are in the PostureIQ report files._\n"
            else:
                result += "No attack paths identified.\n"
            return result

        # ── AI fix script queries ──
        if any(kw in q for kw in ["ai fix", "remediation script", "cli", "powershell"]):
            ai_fixes = piq.get("ai_fixes", [])
            result = f"## PostureIQ — AI Fix Recommendations ({len(ai_fixes)} scripts)\n\n"
            if ai_fixes:
                for fix in ai_fixes[:15]:
                    result += f"### {fix.get('control_id', '')} — {fix.get('resource_id', '').rsplit('/', 1)[-1]}\n"
                    result += f"**Impact:** {fix.get('impact', '')}\n"
                    result += f"**Downtime:** {fix.get('downtime', 'Unknown')}\n"
                    result += f"**Prerequisites:** {fix.get('prerequisites', '')}\n"
                    if fix.get("cli"):
                        result += f"```bash\n{fix['cli']}\n```\n"
                    if fix.get("powershell"):
                        result += f"```powershell\n{fix['powershell']}\n```\n"
            else:
                result += "_AI fix scripts were not generated in this run._\n"
            return result

        # ── Risk tier / risk score queries ──
        if any(kw in q for kw in ["risk score", "risk tier", "critical risk", "high risk"]):
            rs = piq_summary.get("RiskSummary", {})
            result = f"## PostureIQ — Risk Intelligence\n\n"
            result += f"| Risk Tier | Count |\n|---|---|\n"
            result += f"| Critical (≥80) | {rs.get('CriticalRisk', 0)} |\n"
            result += f"| High (60-79) | {rs.get('HighRisk', 0)} |\n"
            result += f"| Medium (40-59) | {rs.get('MediumRisk', 0)} |\n"
            result += f"| Low (<40) | {rs.get('LowRisk', 0)} |\n\n"
            # Show top findings by risk score
            by_risk = sorted(piq_findings, key=lambda x: -x.get("RiskScore", 0))
            if by_risk:
                result += "**Top findings by RiskScore:**\n"
                for f in by_risk[:15]:
                    result += (f"- **{f.get('RiskScore', 0):.0f}** [{f.get('RiskTier', '')}] "
                              f"{f.get('Title') or f.get('Description', '')} "
                              f"({f.get('Framework', '')})\n")
            return result

        # ── Domain queries ──
        for domain in ["access", "identity", "data_protection", "logging", "network",
                        "governance", "incident_response", "change_management",
                        "business_continuity", "asset_management"]:
            if domain.replace("_", " ") in q or domain in q:
                domain_findings = [f for f in piq_findings if f.get("Domain") == domain]
                domain_findings.sort(key=lambda x: -x.get("RiskScore", 0))
                result = f"## PostureIQ — {domain.replace('_', ' ').title()} Domain ({len(domain_findings)} findings)\n\n"
                for f in domain_findings[:20]:
                    result += (f"- **[{f.get('Severity', '').upper()}]** {f.get('Title') or f.get('Description', '')} "
                              f"(RiskScore: {f.get('RiskScore', 0):.0f}){_fmt_resources(f)}\n")
                    if (f.get("Remediation") or {}).get("Description") if isinstance(f.get("Remediation"), dict) else None:
                        result += f"  → {f['Remediation']['Description']}\n"
                return result

        # ── Framework queries ──
        for fw in ["fedramp", "cis", "iso", "nist", "pci", "mcsb", "hipaa", "soc2", "gdpr", "csa"]:
            if fw in q:
                fw_findings = [f for f in piq_findings if fw in (f.get("Framework", "")).lower()]
                fw_findings.sort(key=lambda x: -x.get("RiskScore", 0))
                nc = [f for f in fw_findings if f.get("Status") == "non_compliant"]
                result = f"## PostureIQ — {fw.upper()} Findings ({len(fw_findings)} total, {len(nc)} non-compliant)\n\n"
                for f in nc[:20]:
                    result += (f"- **[{f.get('Severity', '').upper()}]** {f.get('ControlId', '')}: "
                              f"{f.get('Title') or f.get('Description', '')} "
                              f"(RiskScore: {f.get('RiskScore', 0):.0f}){_fmt_resources(f)}\n")
                return result

        # ── Severity filter ──
        if any(kw in q for kw in ["critical", "high", "severe"]):
            severe = [f for f in piq_findings if f.get("Severity", "").lower() in ("critical", "high")]
            severe.sort(key=lambda x: -x.get("RiskScore", 0))
            result = f"## PostureIQ — Critical/High Findings ({len(severe)})\n\n"
            for f in severe[:25]:
                result += (f"- **[{f.get('Severity', '').upper()}]** {f.get('Title') or f.get('Description', '')} "
                          f"(RiskScore: {f.get('RiskScore', 0):.0f}, {f.get('Framework', '')}){_fmt_resources(f)}\n")
            return result

        # ── Control ID search ──
        for ctrl in piq_controls:
            cid = ctrl.get("ControlId", "")
            if cid.lower() in q or cid.lower().replace("fedramp-", "") in q:
                related = [f for f in piq_findings if f.get("ControlId") == cid]
                result = f"## PostureIQ — {cid}: {ctrl.get('ControlTitle', '')}\n"
                result += f"- Status: {ctrl['Status']}\n- Severity: {ctrl['Severity']}\n"
                result += f"- Findings: {len(related)}\n\n"
                for rf in related:
                    result += (f"- [{rf['Status'].upper()}] {rf.get('Title') or rf.get('Description', '')} "
                              f"(RiskScore: {rf.get('RiskScore', 0):.0f}){_fmt_resources(rf)}\n")
                return result

        # ── General PostureIQ summary ──
        result = f"## PostureIQ Assessment Summary\n\n"
        result += (f"**Posture Score:** {piq_summary.get('ComplianceScore', 0):.0f}% | "
                   f"**Controls:** {piq_summary.get('TotalControls', 0)} | "
                   f"**Findings:** {piq_summary.get('TotalFindings', 0)}\n\n")

        rs = piq_summary.get("RiskSummary", {})
        if rs:
            result += f"**Risk Tiers:** Critical: {rs.get('CriticalRisk', 0)} | High: {rs.get('HighRisk', 0)} | Medium: {rs.get('MediumRisk', 0)} | Low: {rs.get('LowRisk', 0)}\n"

        ap = piq_summary.get("AttackPaths", {})
        if ap and ap.get("TotalPaths", 0) > 0:
            result += (f"**Attack Paths:** {ap['TotalPaths']} total ({ap.get('CriticalPaths', 0)} critical, "
                      f"{ap.get('PrivilegeEscalation', 0)} privilege escalation, "
                      f"{ap.get('LateralMovement', 0)} lateral movement)\n")

        prio = piq_summary.get("PrioritySummary", {})
        if prio:
            labels = prio.get("ByLabel", {})
            result += (f"**Priority:** {labels.get('Fix Immediately', 0)} fix immediately | "
                      f"{labels.get('Fix Soon', 0)} fix soon | "
                      f"Quick wins: {len(prio.get('QuickWins', []))} | "
                      f"Total effort: {prio.get('TotalEffortHours', 0)}h\n")

        ai_fixes = piq_summary.get("AIFixes", 0)
        if ai_fixes:
            result += f"**AI Fix Scripts:** {ai_fixes} generated\n"

        result += "\n**Severity Breakdown:**\n"
        sev_dist: dict[str, int] = {}
        for f in piq_findings:
            sev = f.get("Severity", "unknown").lower()
            sev_dist[sev] = sev_dist.get(sev, 0) + 1
        for sev in ("critical", "high", "medium", "low"):
            if sev_dist.get(sev):
                result += f"- {sev.title()}: {sev_dist[sev]}\n"

        result += (f"\nUse follow-up queries like: "
                   f"'top 5 fix immediately', 'attack paths', 'quick wins', "
                   f"'AI fix scripts', 'critical findings', 'identity domain'\n")
        return result

    # ── Tenant Search cached results ──
    ts_cache = state.get("tenant_search_results", [])
    if ts_cache:
        # Search across all cached tenant search results
        all_ts_rows: list[dict] = []
        for entry in ts_cache:
            all_ts_rows.extend(entry.get("results", []))
        if all_ts_rows:
            # Filter by keyword from the question
            q_tokens = [t for t in q.split() if len(t) > 2]
            matched = []
            for r in all_ts_rows:
                r_str = " ".join(str(v).lower() for v in r.values() if v)
                if any(tok in r_str for tok in q_tokens):
                    matched.append(r)
            if matched:
                result = f"## Tenant Search Results ({len(matched)} matching)\n\n"
                for item in matched[:30]:
                    name = item.get("name", item.get("displayName", item.get("id", "N/A")))
                    rtype = item.get("type", "")
                    loc = item.get("location", "")
                    extra_parts = []
                    if "userPrincipalName" in item:
                        extra_parts.append(item["userPrincipalName"])
                    if rtype:
                        extra_parts.append(rtype)
                    if loc:
                        extra_parts.append(loc)
                    if "riskLevel" in item and item["riskLevel"]:
                        extra_parts.append(f"Risk: {item['riskLevel']}")
                    extra = f" ({', '.join(extra_parts)})" if extra_parts else ""
                    result += f"- **{name}**{extra}\n"
                if len(matched) > 30:
                    result += f"\n*... and {len(matched) - 30} more*\n"
                return result

    # ── Catch-all: try resource extraction from ANY available assessment ──
    all_findings: list[dict] = []
    for src_key in ("data_security_results", "risk_results", "copilot_readiness_results", "ai_agent_security_results", "postureiq_results"):
        src = state.get(src_key)
        if src and isinstance(src, dict):
            all_findings.extend(src.get("Findings") or [])
    if all_findings:
        view = _resource_centric_view(all_findings, [])  # no type filter — match all
        if view:
            return f"## Resources From All Assessments\n\n{view}"

    # Summary — show cross-assessment overview
    if not findings and not controls:
        # Build a multi-assessment summary from whatever is in session
        parts = []
        if ds:
            ds_scores = ds.get("DataSecurityScores", {})
            parts.append(f"- **Data Security**: {ds_scores.get('OverallScore', 0)}/100 ({ds_scores.get('OverallLevel', '').upper()}) — {ds.get('FindingCount', 0)} findings")
        if risk:
            r_scores = risk.get("RiskScores", {})
            parts.append(f"- **Risk Analysis**: {r_scores.get('OverallScore', 0)}/100 ({r_scores.get('OverallLevel', '').upper()}) — {risk.get('FindingCount', 0)} findings")
        if cr:
            cr_scores = cr.get("ReadinessScores", cr.get("CopilotReadinessScores", {}))
            parts.append(f"- **Copilot Readiness**: {cr_scores.get('OverallScore', 0)}/100 — {len(cr.get('Findings', []))} findings")
        if ais:
            ai_scores = ais.get("AgentSecurityScores", ais.get("SecurityScores", ais.get("AIAgentSecurityScores", {})))
            parts.append(f"- **AI Agent Security**: {ai_scores.get('OverallScore', 0)}/100 — {len(ais.get('Findings', []))} findings")
        rbac_s = state.get("rbac_results")
        if rbac_s:
            rs = rbac_s.get("stats", {})
            parts.append(f"- **RBAC Report**: score {rs.get('rbac_score', 0)}/100, "
                          f"{rs.get('total_assignments', 0)} assignments, {len(rbac_s.get('risks', []))} risks")
        piq_s = state.get("postureiq_results")
        if piq_s:
            piq_sum = piq_s.get("summary", {})
            parts.append(f"- **PostureIQ**: score {piq_sum.get('ComplianceScore', 0):.0f}%, "
                          f"{piq_sum.get('TotalFindings', 0)} findings")
        if parts:
            return "## Session Assessment Summary\n\n" + "\n".join(parts) + "\n\nAsk about a specific assessment type or finding for details."
        return "No detailed results found for that query. Try asking about a specific domain, category, or severity level."

    return "No detailed results found for that query. Try asking about a specific assessment type, domain, or severity level."


async def generate_report(
    format: Annotated[
        str,
        "Report format: 'html', 'json', or 'both'",
    ] = "both",
) -> str:
    """Generate a report from the most recent assessment results."""
    state = await _get_session_state()

    if not state:
        return "No assessment results available. Please run an assessment first."

    # ── Detect assessment type stored in session and dispatch accordingly ──
    if "risk_results" in state:
        return await _generate_risk_reports(state["risk_results"])
    if "data_security_results" in state:
        return await _generate_ds_reports(state["data_security_results"])
    if "copilot_readiness_results" in state:
        return await _generate_cr_reports(state["copilot_readiness_results"])
    if "ai_agent_security_results" in state:
        return await _generate_as_reports(state["ai_agent_security_results"])
    if "rbac_results" in state:
        data = state["rbac_results"]
        out_dir = _OUTPUT_DIR / "RBAC-Report"
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = _gen_rbac_report(data, out_dir)
        paths = [f"- [{report_path.name}]({_report_url(str(report_path))})"]
        pdf_path = await _html_to_pdf(report_path)
        if pdf_path:
            paths.append(f"- [{pdf_path.name}]({_report_url(str(pdf_path))})")
        xlsx_path = out_dir / "rbac-report.xlsx"
        if xlsx_path.exists():
            paths.append(f"- [{xlsx_path.name}]({_report_url(str(xlsx_path))})")
        _blob_upload_dir(out_dir, _OUTPUT_DIR)
        return "**RBAC Report:**\n" + "\n".join(paths)

    return "No supported assessment results found in session. Please run an assessment first."


async def search_tenant(
    question: Annotated[
        str,
        "Natural language query about Azure resources or Entra ID objects. "
        "Examples: 'list all VMs without disk encryption', 'show guest users', "
        "'which storage accounts allow public access', 'list Global Admins', "
        "'show conditional access policies', 'find unattached disks'. "
        "Can also use /arg prefix for raw KQL: '/arg Resources | where type =~ ...'",
    ],
) -> str:
    """Search Azure resources or Entra ID objects interactively using natural language or KQL."""
    try:
        log.info("[search_tenant] Searching tenant: %s", question[:80])
        creds = _get_creds()

        # Check for raw KQL prefix
        if question.strip().lower().startswith("/arg "):
            kql = question.strip()[5:]
            rows = await query_resource_graph(creds, kql)
            if not rows:
                return "No resources found matching the KQL query."
            result_md = f"## ARG Query Results ({len(rows)} resources)\n\n"
            for row in rows[:30]:
                result_md += f"- **{row.get('name', 'N/A')}** ({row.get('type', '')}) "
                result_md += f"[{row.get('location', '')}] {row.get('resourceGroup', '')}\n"
            if len(rows) > 30:
                result_md += f"\n*... and {len(rows) - 30} more*\n"
            return result_md

        # Check for resource detail request
        if question.strip().startswith("/resource "):
            res_id = question.strip()[10:]
            detail = await get_resource_detail(creds, res_id)
            if "error" in detail:
                return f"Error: {detail['error']}"
            import json
            return f"## Resource Detail\n\n```json\n{json.dumps(detail, indent=2, default=str)}\n```"

        # Check for user detail request
        if question.strip().startswith("/user "):
            user_id = question.strip()[6:]
            detail = await get_entra_user_detail(creds, user_id)
            if "error" in detail:
                return f"Error: {detail['error']}"
            import json
            return f"## User Detail\n\n```json\n{json.dumps(detail, indent=2, default=str)}\n```"

        # Natural language dispatch
        state = await _get_session_state()
        findings = state.get("findings", []) if state else []

        result = await dispatch_natural_language(creds, question, findings=findings or None)

        source = result.get("source", "none")
        count = result.get("count", 0)
        rows = result.get("results", [])

        if source == "none":
            return result.get("message", "No results found.")

        if not rows:
            return f"Query executed ({result.get('query_used', '')}) but returned no results."

        # ── Cache results in session for follow-ups (keep last 10) ──
        cached_entry = {
            "question": question,
            "source": source,
            "query_used": result.get("query_used", ""),
            "count": count,
            "results": rows,
        }
        state = state or {}
        ts_cache = state.get("tenant_search_results", [])
        ts_cache.append(cached_entry)
        if len(ts_cache) > 10:
            ts_cache = ts_cache[-10:]
        await _update_session_state("tenant_search_results", ts_cache)

        # Format results as markdown
        result_md = f"## Search Results ({count} items, source: {source})\n"
        result_md += f"*Query: {result.get('query_used', '')}*\n\n"

        if source == "findings":
            for f in rows[:20]:
                sev = f.get("Severity", "").upper()
                status = f.get("Status", "")
                result_md += f"- **[{sev}]** {f.get('ControlId', '')} — {f.get('Description', '')}\n"
                if status == "non_compliant" and f.get("Recommendation"):
                    result_md += f"  → {f['Recommendation']}\n"
        elif source == "entra":
            query_used = result.get("query_used", "")

            # ── Admin-users flat view: render as a structured table ──
            if query_used == "admin_users" and rows and "roleName" in rows[0]:
                result_md += "| UserPrincipalName | DisplayName | Role | Assignment | Via Group |\n"
                result_md += "|---|---|---|---|---|\n"
                for item in rows[:100]:
                    upn = item.get("userPrincipalName", "N/A")
                    dn = item.get("displayName", "")
                    role = item.get("roleName", "")
                    atype = item.get("assignmentType", "Direct")
                    via = item.get("viaGroup", "") or ""
                    result_md += f"| {upn} | {dn} | {role} | {atype} | {via} |\n"

            # ── Directory roles with member expansion ──
            elif query_used == "directory_roles" and rows and "members" in rows[0]:
                for role_item in rows:
                    rname = role_item.get("displayName", "Unknown")
                    members = role_item.get("members", [])
                    result_md += f"\n### {rname} ({len(members)} members)\n\n"
                    if members:
                        result_md += "| UserPrincipalName | DisplayName | Assignment | Via Group |\n"
                        result_md += "|---|---|---|---|\n"
                        for m in members[:50]:
                            upn = m.get("userPrincipalName", "N/A")
                            dn = m.get("displayName", "")
                            atype = m.get("assignmentType", "Direct")
                            via = m.get("viaGroup", "") or ""
                            result_md += f"| {upn} | {dn} | {atype} | {via} |\n"
                    else:
                        result_md += "*No members assigned*\n"

            # ── Generic Entra result formatting ──
            else:
                for item in rows[:30]:
                    name = item.get("displayName", item.get("name", item.get("id", "N/A")))
                    extra_parts = []
                    if "userPrincipalName" in item:
                        extra_parts.append(item["userPrincipalName"])
                    if "accountEnabled" in item:
                        extra_parts.append("Enabled" if item["accountEnabled"] else "DISABLED")
                    if "riskLevel" in item and item["riskLevel"]:
                        extra_parts.append(f"Risk: {item['riskLevel']}")
                    if "riskState" in item and item["riskState"]:
                        extra_parts.append(item["riskState"])
                    if "memberCount" in item:
                        extra_parts.append(f"{item['memberCount']} members")
                    if "state" in item:
                        extra_parts.append(item["state"])
                    if "isEnabled" in item:
                        extra_parts.append("Enabled" if item["isEnabled"] else "Disabled")
                    if "consentType" in item:
                        extra_parts.append(f"consent: {item['consentType']}")
                    if "scope" in item and isinstance(item["scope"], str):
                        extra_parts.append(f"scope: {item['scope'][:60]}")
                    if "webUrl" in item:
                        extra_parts.append(item["webUrl"])
                    if "servicePrincipalType" in item:
                        extra_parts.append(item["servicePrincipalType"])
                    if "lastSignInDateTime" in item and item["lastSignInDateTime"]:
                        extra_parts.append(f"lastSignIn: {item['lastSignInDateTime'][:10]}")
                    extra = f" ({', '.join(extra_parts)})" if extra_parts else ""
                    result_md += f"- **{name}**{extra}\n"
        else:  # ARG / multi
            for row in rows[:30]:
                name = row.get("name", "N/A")
                rtype = row.get("type", "")
                loc = row.get("location", "")
                rg = row.get("resourceGroup", "")
                line = f"- **{name}** ({rtype}) [{loc}] {rg}"
                # Surface security-relevant properties when present
                sec_parts = []
                props = row.get("properties", row)
                if isinstance(props, dict):
                    if "publicNetworkAccess" in props:
                        sec_parts.append(f"publicAccess={props['publicNetworkAccess']}")
                    if "httpsOnly" in props:
                        sec_parts.append(f"httpsOnly={props['httpsOnly']}")
                    if "minimumTlsVersion" in props:
                        sec_parts.append(f"TLS={props['minimumTlsVersion']}")
                    if "encryption" in props and isinstance(props["encryption"], dict):
                        sec_parts.append("encrypted")
                    if "privateEndpointConnections" in props:
                        pec = props["privateEndpointConnections"]
                        sec_parts.append(f"privateEndpoints={len(pec) if isinstance(pec, list) else '?'}")
                    if "allowBlobPublicAccess" in props:
                        sec_parts.append(f"blobPublicAccess={props['allowBlobPublicAccess']}")
                if sec_parts:
                    line += f" | {', '.join(sec_parts)}"
                result_md += line + "\n"

        if count > 30:
            result_md += f"\n*... and {count - 30} more results*\n"

        return result_md

    except Exception as exc:
        log.error("Tenant search failed: %s", exc, exc_info=True)
        return f"Search failed: {exc}"


async def analyze_risk(
    scope: Annotated[
        str,
        "Scope of risk analysis: 'full' runs all categories, or comma-separated "
        "category names (identity, network, defender, config, insider_risk)",
    ] = "full",
    subscriptions: Annotated[
        str,
        "Optional comma-separated subscription IDs to limit the analysis to. "
        "Leave empty to include all accessible subscriptions.",
    ] = "",
) -> str:
    """Run a Security Risk Gap Analysis with composite scoring and remediation runbooks."""
    try:
        # ── Session-duplicate guard (instant — must run before slow preflight) ──
        dup = await _session_duplicate_guard("analyze_risk")
        if dup:
            return dup

        # ── Auto pre-flight permission check ──
        preflight_abort = await _auto_preflight("analyze_risk")
        if preflight_abort:
            return preflight_abort

        log.info("[analyze_risk] Starting risk analysis (scope=%s, subs=%s) …", scope, subscriptions or "all")
        creds = _get_creds()

        if subscriptions:
            sub_filter = [s.strip() for s in subscriptions.split(",")]
            subs = await creds.list_subscriptions(subscription_filter=sub_filter)
            log.info("[analyze_risk] Scoped to %d subscription(s)", len(subs))

        # Reuse evidence from a prior assessment if available
        state = await _get_session_state()
        evidence = state.get("evidence") if state else None

        results = await _run_risk_analysis(
            creds=creds,
            evidence=evidence,
        )

        # Cache for subsequent queries
        await _update_session_state("risk_results", results)

        # Check for permission issues from session (prior assessment run)
        state = await _get_session_state()
        perm_warning = _permissions_impact_warning(state.get("access_denied", []))

        scores = results.get("RiskScores", {})

        md = perm_warning
        md += f"## Security Risk Gap Analysis Complete\n\n"
        md += f"**Overall Risk Score: {scores.get('OverallRiskScore', 0)}/100 "
        md += f"({scores.get('OverallRiskLevel', 'unknown').upper()})** | "
        md += f"Subscriptions: {results.get('SubscriptionCount', 0)} | "
        md += f"Findings: {len(results.get('Findings', []))}\n\n"

        # ── Generate downloadable reports ──
        md += await _generate_risk_reports(results)

        md += "\n_Full data cached — ask follow-up questions to explore categories, findings, or remediations._\n"

        return md

    except Exception as exc:
        log.error("Risk analysis failed: %s", exc, exc_info=True)
        return f"Risk analysis failed: {exc}"


async def assess_data_security(
    scope: Annotated[
        str,
        "Scope of data security assessment: 'full' runs all categories, or comma-separated "
        "category names (storage, database, keyvault, encryption, classification, data_lifecycle, dlp_alerts)",
    ] = "full",
    subscriptions: Annotated[
        str,
        "Optional comma-separated subscription IDs to limit the assessment to. "
        "Leave empty to include all accessible subscriptions.",
    ] = "",
) -> str:
    """Evaluate data-layer security posture: storage exposure, database security, Key Vault hygiene, encryption, and data classification."""
    try:
        # ── Session-duplicate guard (instant — must run before slow preflight) ──
        dup = await _session_duplicate_guard("assess_data_security")
        if dup:
            return dup

        # ── Auto pre-flight permission check ──
        preflight_abort = await _auto_preflight("assess_data_security")
        if preflight_abort:
            return preflight_abort

        log.info("[assess_data_security] Starting data security assessment (scope=%s, subs=%s) …", scope, subscriptions or "all")
        creds = _get_creds()

        if subscriptions:
            sub_filter = [s.strip() for s in subscriptions.split(",")]
            subs = await creds.list_subscriptions(subscription_filter=sub_filter)
            log.info("[assess_data_security] Scoped to %d subscription(s)", len(subs))

        # Reuse evidence from a prior assessment if available
        state = await _get_session_state()
        evidence = state.get("evidence") if state else None

        results = await _run_ds_assessment(creds=creds, evidence=evidence)

        # Cache for subsequent queries
        await _update_session_state("data_security_results", results)

        # Check for permission issues
        perm_warning = _permissions_impact_warning(
            state.get("access_denied", []) if state else []
        )
        # Also surface collection errors from the engine itself
        coll_errors = results.get("CollectionErrors", [])
        if coll_errors and not perm_warning:
            perm_warning = (
                f"\n> ⚠️ **{len(coll_errors)} data source(s) had collection errors.** "
                "Some findings may be incomplete.\n\n"
            )

        scores = results.get("DataSecurityScores", {})

        md = perm_warning
        md += f"## Data Security Assessment Complete\n\n"
        md += f"**Overall Score: {scores.get('OverallScore', 0)}/100 "
        md += f"({scores.get('OverallLevel', 'unknown').upper()})** | "
        md += f"Subscriptions: {results.get('SubscriptionCount', 0)} | "
        md += f"Findings: {results.get('FindingCount', 0)}\n\n"

        # ── Generate downloadable reports ──
        md += await _generate_ds_reports(results)

        md += "\n_Full data cached — ask follow-up questions to explore categories, findings, or remediations._\n"

        return md

    except Exception as exc:
        log.error("Data security assessment failed: %s", exc, exc_info=True)
        return f"Data security assessment failed: {exc}"


async def generate_rbac_report(
    subscriptions: Annotated[
        str,
        "Optional comma-separated subscription IDs to scope. Leave empty or 'all' for every subscription.",
    ] = "all",
) -> str:
    """Generate an interactive RBAC hierarchy tree report showing role assignments across Management Groups, Subscriptions, and Resource Groups."""
    try:
        # ── Session-duplicate guard (instant — must run before slow preflight) ──
        dup = await _session_duplicate_guard("generate_rbac_report")
        if dup:
            return dup

        # ── Auto pre-flight permission check ──
        preflight_abort = await _auto_preflight("generate_rbac_report")
        if preflight_abort:
            return preflight_abort

        log.info("[generate_rbac_report] Building RBAC hierarchy report …")
        from datetime import datetime, timezone

        creds = _get_creds()
        subs = await creds.list_subscriptions()

        if subscriptions and subscriptions.lower() != "all":
            filter_ids = {s.strip() for s in subscriptions.split(",")}
            subs = [s for s in subs if s["subscription_id"] in filter_ids]

        if not subs:
            return "No subscriptions found. Check your Azure login and permissions."

        data = await _collect_rbac_data(creds, subs)

        # Save to output/<timestamp>/RBAC-Report/
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%I%M%S_%p")
        out_dir = _OUTPUT_DIR / ts / "RBAC-Report"
        out_dir.mkdir(parents=True, exist_ok=True)

        raw_path = out_dir / "rbac-data.json"
        raw_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

        report_path = _gen_rbac_report(data, out_dir)

        # Generate PDF from the HTML report
        pdf_path = await _html_to_pdf(report_path)

        # Build text summary for the LLM
        stats = data.get("stats", {})
        risks = data.get("risks", [])

        md = ""
        # Check for permission issues from session
        state = await _get_session_state()
        perm_warning = _permissions_impact_warning(
            state.get("access_denied", []) if state else []
        )
        md += perm_warning

        md += "## RBAC Tree Report Generated\n\n"
        md += f"**Subscriptions: {stats.get('subscription_count', 0)} | "
        md += f"Assignments: {stats.get('total_assignments', 0)} | "
        md += f"PIM Eligible: {stats.get('eligible_assignments', 0)} | "
        md += f"Risks: {len(risks)}**\n\n"

        report_url = _report_url(str(report_path))
        md += f"- [{report_path.name}]({report_url})\n"
        if pdf_path:
            md += f"- [{pdf_path.name}]({_report_url(str(pdf_path))})\n"
        xlsx_path = out_dir / "rbac-report.xlsx"
        if xlsx_path.exists():
            xlsx_url = _report_url(str(xlsx_path))
            md += f"- [{xlsx_path.name}]({xlsx_url})\n"
        md += "\n"

        md += "_Full data cached — ask follow-up questions to explore assignments, risks, or PIM details._\n"

        # ── Cache RBAC data in session state for follow-up queries ──
        await _update_session_state("rbac_results", data)

        _blob_upload_dir(out_dir, _OUTPUT_DIR)
        return md

    except Exception as exc:
        log.error("RBAC tree report failed: %s", exc, exc_info=True)
        return f"RBAC tree report failed: {exc}"


async def assess_copilot_readiness(
    scope: Annotated[
        str,
        "Scope of readiness assessment: 'full' runs all categories, or comma-separated "
        "category names (oversharing_risk, label_coverage, dlp_readiness, restricted_search, "
        "access_governance, content_lifecycle, audit_monitoring)",
    ] = "full",
    subscriptions: Annotated[
        str,
        "Optional comma-separated subscription IDs to limit the assessment to. "
        "Leave empty to include all accessible subscriptions.",
    ] = "",
) -> str:
    """Evaluate M365 Copilot Premium readiness: oversharing, sensitivity labels, DLP, restricted search, access governance, and audit monitoring."""
    try:
        # ── Session-duplicate guard (instant — must run before slow preflight) ──
        dup = await _session_duplicate_guard("assess_copilot_readiness")
        if dup:
            return dup

        # ── Auto pre-flight permission check ──
        preflight_abort = await _auto_preflight("assess_copilot_readiness")
        if preflight_abort:
            return preflight_abort

        log.info("[assess_copilot_readiness] Starting Copilot readiness assessment (scope=%s) …", scope)
        creds = _get_creds()

        subs = None
        if subscriptions:
            sub_filter = [s.strip() for s in subscriptions.split(",")]
            subs = await creds.list_subscriptions(subscription_filter=sub_filter)
            log.info("[assess_copilot_readiness] Scoped to %d subscription(s)", len(subs))

        state = await _get_session_state()
        evidence = state.get("evidence") if state else None

        results = await _run_cr_assessment(creds=creds, evidence=evidence, subscriptions=subs)

        await _update_session_state("copilot_readiness_results", results)

        # Check for permission issues
        perm_warning = _permissions_impact_warning(
            state.get("access_denied", []) if state else []
        )

        scores = results.get("CopilotReadinessScores", {})

        md = perm_warning
        md += f"## M365 Copilot Readiness Assessment Complete\n\n"
        md += f"**Readiness: {scores.get('ReadinessStatus', 'UNKNOWN')} — "
        md += f"{scores.get('OverallScore', 0)}/100** | "
        md += f"Findings: {results.get('FindingCount', 0)}\n\n"

        # ── Generate downloadable reports ──
        md += await _generate_cr_reports(results)

        md += "\n_Full data cached — ask follow-up questions to explore categories, findings, or remediations._\n"

        return md

    except Exception as exc:
        log.error("Copilot readiness assessment failed: %s", exc, exc_info=True)
        return f"Copilot readiness assessment failed: {exc}"


async def assess_ai_agent_security(
    scope: Annotated[
        str,
        "Scope of AI agent security assessment: 'full' runs all platforms, or comma-separated "
        "platform names (copilot_studio, foundry, custom)",
    ] = "full",
    subscriptions: Annotated[
        str,
        "Optional comma-separated subscription IDs to limit the assessment to. "
        "Leave empty to include all accessible subscriptions.",
    ] = "",
) -> str:
    """Evaluate AI agent security posture across Copilot Studio, Microsoft Foundry, and custom agents."""
    try:
        # ── Session-duplicate guard (instant — must run before slow preflight) ──
        dup = await _session_duplicate_guard("assess_ai_agent_security")
        if dup:
            return dup

        # ── Auto pre-flight permission check ──
        preflight_abort = await _auto_preflight("assess_ai_agent_security")
        if preflight_abort:
            return preflight_abort

        log.info("[assess_ai_agent_security] Starting AI agent security assessment (scope=%s) …", scope)
        creds = _get_creds()

        subs = None
        if subscriptions:
            sub_filter = [s.strip() for s in subscriptions.split(",")]
            subs = await creds.list_subscriptions(subscription_filter=sub_filter)
            log.info("[assess_ai_agent_security] Scoped to %d subscription(s)", len(subs))

        state = await _get_session_state()
        evidence = state.get("evidence") if state else None

        results = await _run_as_assessment(creds=creds, evidence=evidence, subscriptions=subs)

        await _update_session_state("ai_agent_security_results", results)

        # Check for permission issues
        perm_warning = _permissions_impact_warning(
            state.get("access_denied", []) if state else []
        )

        scores = results.get("AgentSecurityScores", {})

        md = perm_warning
        md += f"## AI Agent Security Assessment Complete\n\n"
        md += f"**Overall Score: {scores.get('OverallScore', 0)}/100 "
        md += f"({scores.get('OverallLevel', 'unknown').upper()})** | "
        md += f"Findings: {results.get('FindingCount', 0)}\n\n"

        # ── Generate downloadable reports ──
        md += await _generate_as_reports(results)

        md += "\n_Full data cached — ask follow-up questions to explore platforms, findings, or remediations._\n"

        return md

    except Exception as exc:
        log.error("AI agent security assessment failed: %s", exc, exc_info=True)
        return f"AI agent security assessment failed: {exc}"


async def check_permissions() -> str:
    """Probe the caller's Azure and Graph API permissions before running a full assessment. Reports ARM access, Graph scopes, Entra roles, and any gaps."""
    try:
        log.info("[check_permissions] Probing Azure and Graph API permissions …")
        creds = _get_creds()
        result = await creds.preflight_check()

        md = "## Permission Pre-flight Check\n\n"
        status = "PASS" if result["ok"] else "FAIL"
        md += f"**Status: {status}**\n\n"
        md += f"| Item | Value |\n|---|---|\n"
        md += f"| User / Identity | {result['user']} |\n"
        md += f"| Tenant | {result['tenant']} |\n"
        md += f"| ARM Subscriptions | {result['arm_subs']} |\n"
        md += f"| Graph API Access | {'Yes' if result['graph_ok'] else 'No'} |\n"
        md += f"| Entra Roles | {', '.join(result['roles']) if result['roles'] else 'None detected'} |\n"

        if result.get("warnings"):
            md += "\n**Warnings:**\n"
            for w in result["warnings"]:
                md += f"- ⚠ {w}\n"

        if result.get("errors"):
            md += "\n**Errors (blocking):**\n"
            for e in result["errors"]:
                md += f"- ❌ {e}\n"

        if result["ok"]:
            md += "\n✅ Permissions look good — you can proceed with assessments.\n"
        else:
            md += "\n❌ Some required permissions are missing. Fix the errors above before running assessments.\n"

        return md

    except Exception as exc:
        log.error("Permission check failed: %s", exc, exc_info=True)
        return f"Permission check failed: {exc}"


async def compare_runs(
    run_dir: Annotated[
        str,
        "Optional path to a specific previous run directory to compare against. "
        "Leave empty to auto-detect the most recent previous run from the output folder.",
    ] = "",
) -> str:
    """Compare the current assessment results against a previous run to show new findings, resolved findings, status changes, and score drift."""
    state = await _get_session_state()

    if not state:
        return "No current assessment results in session. Please run an assessment first."

    try:
        log.info("[compare_runs] Looking for previous assessment results …")
        output_dir = str(_OUTPUT_DIR)

        if run_dir:
            # Load specific previous run
            prev_path = pathlib.Path(run_dir)
            if not prev_path.exists():
                prev_path = pathlib.Path(output_dir) / run_dir
            candidates = list(prev_path.glob("**/assessment-results*.json"))
            if not candidates:
                return f"No assessment-results JSON found in {prev_path}"
            prev_data = json.loads(candidates[0].read_text(encoding="utf-8"))
        else:
            prev_data = find_previous_results(output_dir)

        if not prev_data:
            return "No previous assessment run found in the output directory. Run at least two assessments to compare."

        delta = compute_delta(state, prev_data)
        md = generate_delta_section(delta)

        log.info(
            "[compare_runs] Delta computed: %d new, %d resolved, %d status changes",
            len(delta.get("new_findings", [])),
            len(delta.get("resolved_findings", [])),
            len(delta.get("status_changes", [])),
        )

        return md

    except Exception as exc:
        log.error("Run comparison failed: %s", exc, exc_info=True)
        return f"Run comparison failed: {exc}"


async def query_assessment_history(
    action: Annotated[
        str,
        "Action: 'list' to see recent runs, 'trend' for score trend, "
        "'compare' to compare two runs, 'detail' to load full results for a timestamp.",
    ] = "list",
    timestamp: Annotated[
        str,
        "Specific run timestamp (e.g. '20260415T130000Z') for 'detail' or 'compare'. "
        "For 'compare', this is the older run to compare against current session.",
    ] = "",
    limit: Annotated[
        int,
        "Number of runs to return for 'list' or 'trend'. Default 10.",
    ] = 10,
) -> str:
    """Query PostureIQ assessment history for auditing, trend analysis, and change tracking."""
    try:
        from app.evidence_history import list_runs, load_run, get_score_trend

        creds = _get_creds()
        tenant_info = await creds.get_tenant_info()
        tid = tenant_info.get("tenant_id", "unknown")

        if action == "list":
            runs = list_runs(tid, limit=limit)
            if not runs:
                return "No assessment history found. Run a PostureIQ assessment first."
            result = f"## Assessment History ({len(runs)} runs)\n\n"
            result += "| Run | Score | Findings | Critical | Frameworks |\n"
            result += "|-----|-------|----------|----------|------------|\n"
            for r in runs:
                result += (f"| {r['timestamp']} | {r.get('score', 0):.0f}% | "
                           f"{r.get('total_findings', 0)} | {r.get('critical_findings', 0)} | "
                           f"{', '.join(r.get('frameworks', []))} |\n")
            return result

        elif action == "trend":
            trend = get_score_trend(tid, last_n=limit)
            if not trend:
                return "No trend data available. Run multiple PostureIQ assessments first."
            result = "## Score Trend\n\n"
            result += "| Date | Score | Findings |\n"
            result += "|------|-------|----------|\n"
            for t in trend:
                result += f"| {t['timestamp']} | {t['score']:.0f}% | {t['findings']} |\n"
            # Direction
            if len(trend) >= 2:
                delta = trend[-1]["score"] - trend[0]["score"]
                direction = "improving" if delta > 0 else "declining" if delta < 0 else "stable"
                result += f"\n**Trend:** {direction} ({delta:+.0f}% over {len(trend)} runs)\n"
            return result

        elif action == "detail" and timestamp:
            data = load_run(tid, timestamp)
            if not data:
                return f"No results found for timestamp {timestamp}."
            summary = data.get("summary", {})
            result = (f"## Run Detail: {timestamp}\n\n"
                      f"**Score:** {summary.get('ComplianceScore', 0):.0f}%\n"
                      f"**Controls:** {summary.get('TotalControls', 0)}\n"
                      f"**Findings:** {summary.get('TotalFindings', 0)} "
                      f"({summary.get('CriticalFindings', 0)} critical)\n"
                      f"**Frameworks:** {', '.join(summary.get('Frameworks', []))}\n")
            return result

        elif action == "compare" and timestamp:
            state = await _get_session_state()
            current = state.get("postureiq_results") if state else None
            if not current:
                return "No current PostureIQ results in session. Run an assessment first."
            prev = load_run(tid, timestamp)
            if not prev:
                return f"No historical results found for {timestamp}."
            delta = compute_delta(current, prev)
            md = generate_delta_section(delta)
            return f"## Comparison: Current vs {timestamp}\n\n{md}"

        return "Invalid action. Use 'list', 'trend', 'detail', or 'compare'."

    except Exception as exc:
        log.error("History query failed: %s", exc, exc_info=True)
        return f"History query failed: {exc}"


async def search_exposure(
    category: Annotated[
        str,
        "Exposure category to search: 'all' for everything, or one of: "
        "public_storage, open_nsg, unencrypted_vms, unattached_disks, public_ips",
    ] = "all",
) -> str:
    """Search for sensitive data exposure patterns: public storage, open NSGs, unencrypted VMs, unattached disks, and public IPs."""
    EXPOSURE_QUERIES = {
        "public_storage": ("Public Storage Accounts", "storage_public_access"),
        "open_nsg": ("Open NSG Rules (Internet-Inbound)", "nsg_open_rules"),
        "unencrypted_vms": ("VMs Without Disk Encryption", "vms_without_disk_encryption"),
        "unattached_disks": ("Unattached Managed Disks", "unattached_disks"),
        "public_ips": ("Public IP Addresses", "public_ips"),
    }

    try:
        log.info("[search_exposure] Scanning for exposure patterns (category=%s) …", category)
        creds = _get_creds()

        if category != "all" and category not in EXPOSURE_QUERIES:
            return f"Unknown category '{category}'. Choose from: all, {', '.join(EXPOSURE_QUERIES)}"

        cats = EXPOSURE_QUERIES if category == "all" else {category: EXPOSURE_QUERIES[category]}

        md = "## Sensitive Data Exposure Scan\n\n"
        total_exposed = 0

        for _, (title, template_key) in cats.items():
            kql = ARG_TEMPLATES.get(template_key, "")
            if not kql:
                md += f"### {title}\n*Template not found*\n\n"
                continue

            rows = await query_resource_graph(creds, kql)
            count = len(rows)
            total_exposed += count

            md += f"### {title} ({count} found)\n"
            if count == 0:
                md += "✅ No exposed resources found.\n\n"
            else:
                for row in rows[:15]:
                    name = row.get("name", "N/A")
                    rg = row.get("resourceGroup", "")
                    loc = row.get("location", "")
                    md += f"- **{name}** [{loc}] {rg}\n"
                if count > 15:
                    md += f"*... and {count - 15} more*\n"
                md += "\n"


        md += f"---\n**Total Exposed Resources: {total_exposed}**\n"
        if total_exposed == 0:
            md += "✅ No exposure patterns detected.\n"
        else:
            md += "⚠ Review the resources above and apply recommended mitigations.\n"

        # Cache exposure results in session for follow-ups
        from datetime import datetime, timezone as _tz
        await _update_session_state("exposure_results", {
            "category": category,
            "total_exposed": total_exposed,
            "scan_time": str(datetime.now(_tz.utc)),
        })

        log.info("[search_exposure] Scan complete: %d exposed resources found", total_exposed)
        return md

    except Exception as exc:
        log.error("Exposure search failed: %s", exc, exc_info=True)
        return f"Exposure search failed: {exc}"


async def generate_custom_report(
    topic: Annotated[
        str,
        "Natural-language description of what the report should cover. "
        "Examples: 'critical storage findings', 'all high-severity issues across every assessment', "
        "'AI agent security posture', 'copilot readiness gaps'.",
    ],
    format: Annotated[
        str,
        "Output format: 'html', 'pdf', 'excel', or 'all' (generates all three)",
    ] = "all",
    severity: Annotated[
        str,
        "Optional comma-separated severity filter: 'critical', 'high', 'medium', 'low'. "
        "Leave empty to include all severities.",
    ] = "",
    category: Annotated[
        str,
        "Optional comma-separated category filter (e.g. 'storage,database'). "
        "Leave empty to include all categories.",
    ] = "",
) -> str:
    """Generate a focused HTML / PDF / Excel report from existing session assessment data based on the requested topic. Does NOT re-run any assessment."""
    state = await _get_session_state()

    if not state:
        return "No assessment results available in session. Please run an assessment first."

    try:
        out_dir = _make_out_dir("Custom-Report")
        paths = await _build_custom_report(
            state=state,
            topic=topic,
            fmt=format.lower().strip(),
            output_dir=out_dir,
            severity_filter=severity if severity else None,
            category_filter=category if category else None,
        )

        md = "## Custom Report Generated\n\n"
        md += f"**Topic:** {topic}\n"
        if severity:
            md += f"**Severity Filter:** {severity}\n"
        if category:
            md += f"**Category Filter:** {category}\n"
        md += "\n**Reports:**\n"

        for fmt_key, path in paths.items():
            url = _report_url(str(path))
            md += f"- [{path.name}]({url})\n"

        _blob_upload_dir(out_dir, _OUTPUT_DIR)
        return md

    except ValueError as ve:
        return str(ve)
    except Exception as exc:
        log.error("Custom report generation failed: %s", exc, exc_info=True)
        return f"Custom report generation failed: {exc}"


async def run_postureiq_assessment(
    scope: Annotated[
        str,
        "Assessment scope: 'full' for all domains, or comma-separated domain names "
        "(access, identity, data_protection, logging, network, governance)",
    ] = "full",
    frameworks: Annotated[
        str,
        "Compliance frameworks to evaluate: 'all' for every framework, or comma-separated "
        "framework names (FedRAMP, CIS, ISO-27001, NIST-800-53, PCI-DSS, MCSB, HIPAA, "
        "SOC2, GDPR, NIST-CSF, CSA-CCM). Defaults to all frameworks.",
    ] = "all",
    subscriptions: Annotated[
        str,
        "Optional comma-separated subscription IDs to limit the assessment to. "
        "Leave empty to include all accessible subscriptions.",
    ] = "",
) -> str:
    """Run a PostureIQ security posture assessment against the caller's Azure environment using one or more compliance frameworks."""

    # ── Session-duplicate guard (instant — must run before slow preflight) ──
    dup = await _session_duplicate_guard("run_postureiq_assessment")
    if dup:
        return dup

    preflight_abort = await _auto_preflight("run_postureiq_assessment")
    if preflight_abort:
        return preflight_abort

    ALL_FRAMEWORKS = [
        "FedRAMP", "CIS", "ISO-27001", "NIST-800-53", "PCI-DSS",
        "MCSB", "HIPAA", "SOC2", "GDPR", "NIST-CSF", "CSA-CCM",
    ]

    try:
        fw_list = ALL_FRAMEWORKS if frameworks.lower() == "all" else [
            f.strip() for f in frameworks.split(",")
        ]
        log.info("[run_postureiq_assessment] Starting PostureIQ assessment (scope=%s, frameworks=%s) …", scope, fw_list)
        creds = _get_creds()

        domains = None
        if scope != "full":
            domains = [d.strip() for d in scope.split(",")]

        from app.config import AssessmentConfig
        config = AssessmentConfig.from_env()
        config.frameworks = fw_list

        if subscriptions:
            sub_filter = [s.strip() for s in subscriptions.split(",")]
            config.collectors.subscription_filter = sub_filter
            log.info("[run_postureiq_assessment] Scoped to subscriptions: %s", sub_filter)

        results = await _run_postureiq(
            creds=creds,
            config=config,
            domains=domains,
            generate_reports=True,
            output_dir=str(_OUTPUT_DIR),
        )

        await _update_session_state("postureiq_results", results)

        summary = results["summary"]
        perm_warning = _permissions_impact_warning(results.get("access_denied", []))

        result_text = perm_warning + (
            f"## PostureIQ Assessment Complete\n\n"
            f"**Frameworks:** {', '.join(fw_list)}\n\n"
            f"**Posture Score: {summary['ComplianceScore']:.0f}%** | "
            f"Controls: {summary['TotalControls']} | "
            f"Compliant: {summary['Compliant']} | "
            f"Non-Compliant: {summary['NonCompliant']} | "
            f"Findings: {summary['TotalFindings']}\n\n"
        )

        # Risk & Attack Path summary
        risk_summary = summary.get("RiskSummary", {})
        attack_paths = summary.get("AttackPaths", {})
        priority = summary.get("PrioritySummary", {})
        ai_fixes = summary.get("AIFixes", 0)

        if risk_summary:
            result_text += (
                f"### Risk Intelligence\n"
                f"- **Critical Risk:** {risk_summary.get('CriticalRisk', 0)} | "
                f"**High Risk:** {risk_summary.get('HighRisk', 0)} | "
                f"**Medium Risk:** {risk_summary.get('MediumRisk', 0)}\n"
            )

        if attack_paths and attack_paths.get("TotalPaths", 0) > 0:
            result_text += (
                f"- **Attack Paths:** {attack_paths['TotalPaths']} identified "
                f"({attack_paths.get('CriticalPaths', 0)} critical, "
                f"{attack_paths.get('PrivilegeEscalation', 0)} privilege escalation, "
                f"{attack_paths.get('LateralMovement', 0)} lateral movement, "
                f"{attack_paths.get('CredentialChain', 0)} credential chain, "
                f"{attack_paths.get('CABypass', 0)} CA bypass, "
                f"{attack_paths.get('NetworkPivot', 0)} network pivot)\n"
            )

        if priority and priority.get("TotalRanked", 0) > 0:
            labels = priority.get("ByLabel", {})
            result_text += (
                f"- **Priority Ranking:** {labels.get('Fix Immediately', 0)} fix immediately, "
                f"{labels.get('Fix Soon', 0)} fix soon, "
                f"{labels.get('Plan Fix', 0)} plan fix\n"
                f"- **Estimated Effort:** {priority.get('TotalEffortHours', 0)}h total | "
                f"**Quick Wins:** {len(priority.get('QuickWins', []))}\n"
            )

        if ai_fixes:
            result_text += f"- **AI Fix Scripts:** {ai_fixes} tenant-specific remediation scripts generated\n"

        result_text += "\n"

        raw_paths = results.get("report_paths", {})
        flat_paths = _flatten_report_paths(raw_paths) if raw_paths else []
        if not flat_paths:
            if _OUTPUT_DIR.exists():
                for f in sorted(_OUTPUT_DIR.rglob("*"), key=lambda x: x.stat().st_mtime, reverse=True)[:20]:
                    if f.suffix in (".html", ".xlsx", ".json") and f.is_file():
                        flat_paths.append(str(f))

        report_table_rows = []
        shared_files = []
        pdf_by_dir: dict[str, list[tuple[str, str]]] = {}
        for pdf_fp in _flatten_report_paths(raw_paths.get("pdf_reports", [])):
            p = pathlib.Path(pdf_fp)
            pdf_by_dir.setdefault(str(p.parent), []).append((str(p), p.name))

        for fw_key in fw_list:
            fw_data = raw_paths.get(fw_key, {})
            if not fw_data:
                continue
            row = {"framework": fw_key}
            fw_flat = _flatten_report_paths(fw_data)
            fw_dir = None
            for fp in fw_flat:
                p = pathlib.Path(fp)
                ext = p.suffix.lower()
                url = _report_url(fp)
                if ext == ".html":
                    row["html"] = url; row["html_name"] = p.name; fw_dir = str(p.parent)
                elif ext == ".pdf":
                    row["pdf"] = url; row["pdf_name"] = p.name
                elif ext == ".xlsx":
                    row["xlsx"] = url; row["xlsx_name"] = p.name
                elif ext == ".json":
                    row["json"] = url; row["json_name"] = p.name
            if "pdf" not in row and fw_dir and fw_dir in pdf_by_dir:
                for pdf_path, pdf_name in pdf_by_dir[fw_dir]:
                    row["pdf"] = _report_url(pdf_path); row["pdf_name"] = pdf_name; break
            report_table_rows.append(row)

        for key in ("data_exports", "raw_evidence", "sarif", "drift_html", "remediation"):
            items = raw_paths.get(key)
            if not items:
                continue
            for fp in _flatten_report_paths(items):
                p = pathlib.Path(fp)
                shared_files.append({"name": p.name, "url": _report_url(fp)})

        zip_url = None
        if flat_paths:
            try:
                import zipfile
                resolved = [pathlib.Path(rp).resolve() for rp in flat_paths]
                zip_root = resolved[0].parent
                for rp in resolved[1:]:
                    while zip_root != _OUTPUT_DIR.resolve() and not rp.is_relative_to(zip_root):
                        zip_root = zip_root.parent
                if not str(zip_root).startswith(str(_OUTPUT_DIR.resolve())):
                    zip_root = _OUTPUT_DIR.resolve()
                zip_path = zip_root / "all-postureiq-reports.zip"
                included = 0
                allowed_dirs = {rp.parent for rp in resolved}
                allowed_suffixes = (".html", ".xlsx", ".json", ".pdf", ".csv", ".sarif")
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for d in sorted(allowed_dirs):
                        for f in sorted(d.iterdir()):
                            if f.is_file() and f.suffix in allowed_suffixes and f != zip_path:
                                zf.write(f, f.relative_to(zip_root)); included += 1
                zip_url = _report_url(str(zip_path))
                result_text += f"\n- [all-postureiq-reports.zip]({zip_url})\n"
                log.info("ZIP bundle created: %s (%d files)", zip_path, included)
            except Exception as exc:
                log.warning("ZIP bundle failed: %s", exc)

        report_table = {"rows": report_table_rows, "shared": shared_files, "zip": zip_url}
        result_text += f"\n<!--REPORT_TABLE:{json.dumps(report_table)}-->\n"
        result_text += f"\nTime: {results.get('elapsed_seconds', 0)}s\n"
        result_text += "\n_Full data cached — ask follow-up questions to explore controls, domains, or findings._\n"

        if _OUTPUT_DIR.exists():
            for d in _OUTPUT_DIR.iterdir():
                if d.is_dir():
                    _blob_upload_dir(d, _OUTPUT_DIR)

        return result_text

    except Exception as exc:
        log.error("PostureIQ assessment failed: %s", exc, exc_info=True)
        return f"PostureIQ assessment failed: {exc}"


# Exported tool list for main.py registration
TOOLS = [query_results, search_tenant, analyze_risk, assess_data_security, generate_rbac_report, generate_report, assess_copilot_readiness, assess_ai_agent_security, check_permissions, compare_runs, search_exposure, generate_custom_report, run_postureiq_assessment, query_assessment_history]
