"""
AI-Powered Fix Recommendations
Uses the Azure OpenAI backend to generate tenant-specific, runnable
remediation scripts (Azure CLI + PowerShell) for non-compliant findings.
"""

from __future__ import annotations
import json, os
from typing import Any
from app.logger import log


# System prompt for the remediation script generator
_SYSTEM_PROMPT = """\
You are an Azure security remediation expert. Given a non-compliant finding
from a security posture assessment, generate a precise, runnable remediation
script. Provide BOTH Azure CLI and PowerShell versions.

Rules:
- Use the EXACT resource name and resource group from the finding.
- Include prerequisite checks (e.g. az account set).
- Add comments explaining each step.
- If the fix requires downtime or has side effects, add a WARNING comment.
- Never include secrets, tokens, or passwords in scripts.
- If the fix cannot be fully automated, describe the manual steps.
- Keep scripts concise (under 20 lines each).

Return JSON with this exact structure:
{
  "title": "Brief fix title",
  "cli": "# Azure CLI script\\naz ...",
  "powershell": "# PowerShell script\\n...",
  "impact": "none|low|medium|high",
  "downtime": false,
  "prerequisites": ["list of prerequisites"],
  "warning": "optional warning message or null",
  "manual_steps": "optional manual steps or null"
}
"""


async def generate_ai_fix(
    finding: dict[str, Any],
    client: Any | None = None,
) -> dict[str, Any] | None:
    """Generate an AI-powered remediation script for a single finding.

    Args:
        finding: The non-compliant finding dict.
        client: An AsyncAzureOpenAI client instance. If None, creates one.

    Returns:
        Remediation dict with cli, powershell, impact fields, or None on failure.
    """
    if finding.get("Status") != "non_compliant":
        return None

    description = finding.get("Description", "")
    recommendation = finding.get("Recommendation", "")
    resource_id = finding.get("ResourceId", "")
    resource_type = finding.get("ResourceType", "")
    domain = finding.get("Domain", "")
    control_id = finding.get("ControlId", "")
    severity = finding.get("Severity", "")

    # Extract resource group and name from resource ID
    rg = ""
    resource_name = ""
    if resource_id:
        parts = resource_id.split("/")
        for i, p in enumerate(parts):
            if p.lower() == "resourcegroups" and i + 1 < len(parts):
                rg = parts[i + 1]
            if i == len(parts) - 1:
                resource_name = p

    user_message = (
        f"Finding: {description}\n"
        f"Control: {control_id} ({severity})\n"
        f"Domain: {domain}\n"
        f"Resource: {resource_name} (type: {resource_type})\n"
        f"Resource Group: {rg}\n"
        f"Resource ID: {resource_id}\n"
        f"Current Recommendation: {recommendation}\n\n"
        f"Generate a remediation script to fix this finding."
    )

    try:
        if client is None:
            from openai import AsyncAzureOpenAI
            client = AsyncAzureOpenAI(
                azure_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT", ""),
                api_key=os.environ.get("AZURE_OPENAI_API_KEY", ""),
                api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
            )

        deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4.1")

        response = await client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            max_tokens=1000,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        fix = json.loads(content)

        # Validate required fields
        if "cli" not in fix or "powershell" not in fix:
            log.warning("AI fix response missing required fields for %s", control_id)
            return None

        fix["ai_generated"] = True
        fix["control_id"] = control_id
        fix["resource_id"] = resource_id
        return fix

    except Exception as exc:
        log.warning("AI fix generation failed for %s: %s", control_id, exc)
        return None


async def generate_ai_fixes_batch(
    findings: list[dict[str, Any]],
    client: Any | None = None,
    max_findings: int = 20,
) -> list[dict[str, Any]]:
    """Generate AI-powered fixes for the top-priority non-compliant findings.

    Processes up to max_findings to control cost and latency.
    Attaches results directly to finding dicts as 'ai_remediation' key.

    Returns list of findings that received AI-generated fixes.
    """
    # Only process ranked, non-compliant findings
    candidates = [
        f for f in findings
        if f.get("Status") == "non_compliant" and f.get("PriorityRank")
    ]
    candidates.sort(key=lambda f: f.get("PriorityRank", 9999))
    candidates = candidates[:max_findings]

    if not candidates:
        log.info("No candidates for AI fix generation")
        return []

    log.info("Generating AI fixes for top %d findings...", len(candidates))

    if client is None:
        try:
            from openai import AsyncAzureOpenAI
            client = AsyncAzureOpenAI(
                azure_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT", ""),
                api_key=os.environ.get("AZURE_OPENAI_API_KEY", ""),
                api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
            )
        except Exception as exc:
            log.warning("Cannot create OpenAI client for AI fixes: %s", exc)
            return []

    fixed = []
    for f in candidates:
        fix = await generate_ai_fix(f, client=client)
        if fix:
            f["ai_remediation"] = fix
            fixed.append(f)

    log.info("AI fixes generated: %d/%d findings", len(fixed), len(candidates))
    return fixed
