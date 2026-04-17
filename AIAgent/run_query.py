"""
EnterpriseSecurityIQ — Interactive Query Runner (CLI)

Provides a conversational interface to query Azure and Entra resources
on-demand without running a full compliance assessment.

Usage:
    python run_query.py --tenant <tenant-id>
    python run_query.py --tenant <tenant-id> --query "list all VMs without disk encryption"
    python run_query.py --tenant <tenant-id> --arg-kql "Resources | where type =~ 'microsoft.compute/virtualmachines'"
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime

from app.auth import ComplianceCredentials
from app.query_engine import (
    dispatch_natural_language,
    query_resource_graph,
    query_entra_users,
    get_resource_detail,
    get_entra_user_detail,
    cross_reference_findings,
    ARG_TEMPLATES,
)


def _format_results(result: dict, verbose: bool = False) -> str:
    """Format query results for terminal output."""
    lines = []
    source = result.get("source", "none")
    count = result.get("count", 0)
    query_used = result.get("query_used", "")
    error = result.get("error")

    if error:
        lines.append(f"  ERROR: {error}")
        return "\n".join(lines)

    if source == "none":
        lines.append(f"  {result.get('message', 'No results.')}")
        return "\n".join(lines)

    lines.append(f"  Source: {source.upper()} | Query: {query_used} | Results: {count}")
    lines.append("")

    rows = result.get("results", [])
    if not rows:
        lines.append("  (no matching resources found)")
        return "\n".join(lines)

    # Auto-detect table columns from first row
    if isinstance(rows[0], dict):
        keys = list(rows[0].keys())
        # Truncate wide values
        max_col = 40 if not verbose else 80

        # Header
        header = " | ".join(k[:20].ljust(20) for k in keys[:8])
        lines.append(f"  {header}")
        lines.append(f"  {'-' * len(header)}")

        for row in rows[:50]:
            vals = []
            for k in keys[:8]:
                v = str(row.get(k, ""))
                if len(v) > max_col:
                    v = v[:max_col - 3] + "..."
                vals.append(v[:20].ljust(20))
            lines.append(f"  {' | '.join(vals)}")

        if len(rows) > 50:
            lines.append(f"  ... and {len(rows) - 50} more")

    return "\n".join(lines)


def _print_help():
    """Print interactive mode commands."""
    print("""
  Commands:
    <natural language>     Search resources (e.g., "show all VMs", "list guest users")
    /arg <KQL>             Execute raw ARG query
    /user <id|upn>         Get detailed Entra user info
    /resource <id>         Get detailed Azure resource info
    /templates             List available ARG query templates
    /template <name>       Run a named ARG template
    /findings <keyword>    Search compliance findings (requires prior assessment)
    /export <file.json>    Export last query results to JSON
    /help                  Show this help
    /quit                  Exit
""")


async def _interactive_loop(creds: ComplianceCredentials, findings: list[dict] | None = None):
    """Run the interactive query REPL."""
    print("\n=== EnterpriseSecurityIQ Interactive Query ===")
    print("Type a question or /help for commands. /quit to exit.\n")

    last_results: dict = {}

    while True:
        try:
            user_input = input("query> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue

        if user_input.lower() in ("/quit", "/exit", "/q"):
            print("Exiting.")
            break

        if user_input.lower() == "/help":
            _print_help()
            continue

        if user_input.lower() == "/templates":
            print("\n  Available ARG templates:")
            for name in ARG_TEMPLATES:
                print(f"    - {name}")
            print()
            continue

        if user_input.lower().startswith("/template "):
            name = user_input[10:].strip()
            if name not in ARG_TEMPLATES:
                print(f"  Unknown template: {name}. Use /templates to list.")
                continue
            print(f"  Running template: {name}...")
            try:
                rows = await query_resource_graph(creds, ARG_TEMPLATES[name])
                last_results = {"source": "arg", "query_used": name, "results": rows, "count": len(rows)}
                print(_format_results(last_results))
            except Exception as exc:
                print(f"  ERROR: {exc}")
            continue

        if user_input.lower().startswith("/arg "):
            kql = user_input[5:].strip()
            print(f"  Running ARG query...")
            try:
                rows = await query_resource_graph(creds, kql)
                last_results = {"source": "arg", "query_used": "custom_kql", "results": rows, "count": len(rows)}
                print(_format_results(last_results))
            except Exception as exc:
                print(f"  ERROR: {exc}")
            continue

        if user_input.lower().startswith("/user "):
            user_id = user_input[6:].strip()
            print(f"  Looking up user: {user_id}...")
            try:
                detail = await get_entra_user_detail(creds, user_id)
                last_results = {"source": "entra", "query_used": f"user_detail({user_id})",
                                "results": [detail], "count": 1}
                print(json.dumps(detail, indent=2, default=str))
            except Exception as exc:
                print(f"  ERROR: {exc}")
            continue

        if user_input.lower().startswith("/resource "):
            res_id = user_input[10:].strip()
            print(f"  Looking up resource...")
            try:
                detail = await get_resource_detail(creds, res_id)
                last_results = {"source": "arg", "query_used": f"resource_detail",
                                "results": [detail], "count": 1}
                print(json.dumps(detail, indent=2, default=str))
            except Exception as exc:
                print(f"  ERROR: {exc}")
            continue

        if user_input.lower().startswith("/findings "):
            keyword = user_input[10:].strip()
            if not findings:
                print("  No assessment findings loaded. Run an assessment first.")
                continue
            matched = cross_reference_findings(findings, keyword)
            last_results = {"source": "findings", "query_used": f"findings({keyword})",
                            "results": matched, "count": len(matched)}
            print(_format_results(last_results))
            continue

        if user_input.lower().startswith("/export "):
            filename = user_input[8:].strip()
            if not last_results.get("results"):
                print("  No results to export. Run a query first.")
                continue
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(last_results["results"], f, indent=2, default=str)
                print(f"  Exported {last_results['count']} results to {filename}")
            except Exception as exc:
                print(f"  ERROR: {exc}")
            continue

        # Natural language query
        print("  Searching...")
        try:
            result = await dispatch_natural_language(creds, user_input, findings=findings)
            last_results = result
            print(_format_results(result))
        except Exception as exc:
            print(f"  ERROR: {exc}")
        print()


async def _single_query(creds: ComplianceCredentials, query: str, kql: str | None = None):
    """Execute a single query and print results."""
    if kql:
        rows = await query_resource_graph(creds, kql)
        result = {"source": "arg", "query_used": "custom_kql", "results": rows, "count": len(rows)}
    else:
        result = await dispatch_natural_language(creds, query)

    print(_format_results(result))


async def main():
    parser = argparse.ArgumentParser(description="EnterpriseSecurityIQ Interactive Query")
    parser.add_argument("--tenant", "-t", required=True, help="Azure tenant ID")
    parser.add_argument("--query", "-q", default=None, help="Single query (non-interactive)")
    parser.add_argument("--arg-kql", default=None, help="Raw ARG KQL query (non-interactive)")
    parser.add_argument("--findings", "-f", default=None,
                        help="Path to findings JSON for compliance cross-reference")
    args = parser.parse_args()

    creds = ComplianceCredentials(tenant_id=args.tenant)

    # Pre-flight
    print("Connecting to tenant...")
    try:
        pf = await creds.preflight_check()
        print(f"  User   : {pf['user']}")
        print(f"  Tenant : {pf['tenant']}")
        print(f"  Subs   : {pf['arm_subs']}")
        if not pf["ok"]:
            for e in pf["errors"]:
                print(f"  ERROR: {e}")
            print("Connection failed. Check your credentials.")
            await creds.close()
            return
    except Exception as exc:
        print(f"  Connection error: {exc}")
        await creds.close()
        return

    # Load findings if provided
    findings = None
    if args.findings:
        try:
            with open(args.findings, "r", encoding="utf-8") as f:
                findings = json.load(f)
            print(f"  Loaded {len(findings)} findings for cross-reference.")
        except Exception as exc:
            print(f"  WARNING: Could not load findings: {exc}")

    try:
        if args.query or args.arg_kql:
            await _single_query(creds, args.query or "", kql=args.arg_kql)
        else:
            await _interactive_loop(creds, findings=findings)
    finally:
        await creds.close()


if __name__ == "__main__":
    asyncio.run(main())
