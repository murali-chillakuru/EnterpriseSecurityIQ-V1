"""
Entra User Details Collector
Per-user details: last sign-in, MFA registration, stale checks, lifecycle.
Optimized: aggregates stats in memory, only emits evidence for problematic users
(stale, never-signed-in, guests) to avoid creating tens of thousands of records.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from app.models import Source
from app.collectors.base import run_collector, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

STALE_DAYS = 90
# Cap per-user evidence records to keep output manageable
MAX_STALE_EVIDENCE = 200
MAX_MFA_EVIDENCE = 200


@register_collector(name="user_details", plane="control", source="entra", priority=30)
async def collect_entra_user_details(creds: ComplianceCredentials, user_sample_limit: int = 0) -> list[dict]:
    async def _collect():
        evidence = []
        graph = creds.get_graph_client()
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=STALE_DAYS)
        limit = user_sample_limit  # 0 = no limit

        # Page through users with sign-in activity
        config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
            query_parameters=UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=[
                    "id", "displayName", "userPrincipalName", "userType",
                    "accountEnabled", "createdDateTime", "signInActivity",
                    "onPremisesSyncEnabled",
                ],
                top=999,
            ),
        )
        config.headers.add("ConsistencyLevel", "eventual")

        # Streaming pagination — aggregate stats, only store problematic users
        total = 0
        stale_count = 0
        stale_enabled_count = 0
        never_signed_in = 0
        guest_count = 0
        guest_stale = 0
        guest_never_signed = 0
        detail_records_emitted = 0
        page = await graph.users.get(request_configuration=config)

        while page:
            for user in (page.value or []):
                total += 1
                upn = getattr(user, "user_principal_name", "") or ""
                user_type = getattr(user, "user_type", "Member") or "Member"
                enabled = getattr(user, "account_enabled", True)
                created = getattr(user, "created_date_time", None)
                is_guest = user_type == "Guest"

                last_signin = None
                has_never_signed_in = True
                sign_in_activity = getattr(user, "sign_in_activity", None)
                if sign_in_activity:
                    last_signin = getattr(sign_in_activity, "last_sign_in_date_time", None)
                    if last_signin:
                        has_never_signed_in = False

                is_stale = False
                if last_signin and last_signin < stale_threshold:
                    is_stale = True
                elif has_never_signed_in and created and created < stale_threshold:
                    is_stale = True

                if is_stale:
                    stale_count += 1
                    if enabled:
                        stale_enabled_count += 1
                if has_never_signed_in:
                    never_signed_in += 1
                if is_guest:
                    guest_count += 1
                    if is_stale:
                        guest_stale += 1
                    if has_never_signed_in:
                        guest_never_signed += 1

                # Only emit per-user evidence for compliance-relevant users:
                # stale, never signed in, or guest accounts
                is_problematic = is_stale or has_never_signed_in or is_guest
                if is_problematic and detail_records_emitted < MAX_STALE_EVIDENCE:
                    detail_records_emitted += 1
                    evidence.append(make_evidence(
                        source=Source.ENTRA, collector="EntraUserDetails",
                        evidence_type="entra-user-detail",
                        description=f"User: {upn}",
                        data={
                            "UserId": getattr(user, "id", ""),
                            "UserPrincipalName": upn,
                            "DisplayName": getattr(user, "display_name", ""),
                            "UserType": user_type,
                            "AccountEnabled": enabled,
                            "IsStale": is_stale,
                            "HasNeverSignedIn": has_never_signed_in,
                            "LastSignIn": last_signin.isoformat() if last_signin else None,
                            "CreatedDateTime": created.isoformat() if created else None,
                            "OnPremisesSyncEnabled": getattr(user, "on_premises_sync_enabled", False) or False,
                        },
                        resource_id=getattr(user, "id", ""), resource_type="User",
                    ))

                if total % 10000 == 0:
                    log.info("  [EntraUserDetails] Processed %d users...", total)

            # Check user sample limit
            if limit > 0 and total >= limit:
                log.info("  [EntraUserDetails] User sample limit reached (%d), stopping pagination.", limit)
                break

            # Next page
            if page.odata_next_link:
                page = await graph.users.with_url(page.odata_next_link).get()
            else:
                break

        # Lifecycle summary (enriched with counts for evaluators)
        evidence.append(make_evidence(
            source=Source.ENTRA, collector="EntraUserDetails",
            evidence_type="entra-user-lifecycle-summary",
            description="User lifecycle summary",
            data={
                "TotalUsers": total,
                "StaleUsers": stale_count,
                "StaleEnabledUsers": stale_enabled_count,
                "NeverSignedIn": never_signed_in,
                "GuestUsers": guest_count,
                "StaleGuests": guest_stale,
                "GuestNeverSignedIn": guest_never_signed,
                "StalePercentage": round((stale_count / total) * 100, 1) if total > 0 else 0,
                "EvidenceSampled": detail_records_emitted,
            },
        ))

        # MFA Registration Details — aggregate stats, emit only problematic users
        try:
            mfa_page = await graph.reports.authentication_methods.user_registration_details.get()
            mfa_total = 0
            mfa_registered = 0
            mfa_admin_no_mfa = 0
            mfa_not_registered = 0
            mfa_no_default = 0
            passwordless = 0
            sspr = 0
            mfa_records_emitted = 0
            while mfa_page:
                for detail in (mfa_page.value or []):
                    mfa_total += 1
                    is_mfa = getattr(detail, "is_mfa_registered", False)
                    is_admin = getattr(detail, "is_admin", False)
                    default_method = str(getattr(detail, "default_mfa_method", "none"))

                    if is_mfa:
                        mfa_registered += 1
                    else:
                        mfa_not_registered += 1
                    if getattr(detail, "is_passwordless_capable", False):
                        passwordless += 1
                    if getattr(detail, "is_sspr_registered", False):
                        sspr += 1
                    if default_method == "none":
                        mfa_no_default += 1
                    if is_admin and not is_mfa:
                        mfa_admin_no_mfa += 1

                    # Only emit per-user MFA evidence for admins or non-registered users
                    emit_record = (is_admin or not is_mfa) and mfa_records_emitted < MAX_MFA_EVIDENCE
                    if emit_record:
                        mfa_records_emitted += 1
                        evidence.append(make_evidence(
                            source=Source.ENTRA, collector="EntraUserDetails",
                            evidence_type="entra-mfa-registration",
                            description=f"MFA: {getattr(detail, 'user_principal_name', '')}",
                            data={
                                "UserId": getattr(detail, "id", ""),
                                "UserPrincipalName": getattr(detail, "user_principal_name", ""),
                                "IsMfaRegistered": is_mfa,
                                "IsPasswordlessCapable": getattr(detail, "is_passwordless_capable", False),
                                "IsSsprRegistered": getattr(detail, "is_sspr_registered", False),
                                "IsAdmin": is_admin,
                                "DefaultMfaMethod": default_method,
                            },
                            resource_id=getattr(detail, "id", ""), resource_type="MfaRegistration",
                        ))

                if mfa_page.odata_next_link:
                    mfa_page = await graph.reports.authentication_methods.user_registration_details.with_url(
                        mfa_page.odata_next_link
                    ).get()
                else:
                    break

            evidence.append(make_evidence(
                source=Source.ENTRA, collector="EntraUserDetails",
                evidence_type="entra-mfa-summary",
                description="MFA registration summary",
                data={
                    "TotalUsers": mfa_total,
                    "MfaRegistered": mfa_registered,
                    "MfaRegistrationPercent": round((mfa_registered / mfa_total) * 100, 1) if mfa_total > 0 else 0,
                    "NotRegistered": mfa_not_registered,
                    "NoDefaultMfaMethod": mfa_no_default,
                    "NoDefaultMfaMethodPercent": round((mfa_no_default / mfa_total) * 100, 1) if mfa_total > 0 else 0,
                    "PasswordlessCapable": passwordless,
                    "SsprRegistered": sspr,
                    "AdminsWithoutMfa": mfa_admin_no_mfa,
                    "EvidenceSampled": mfa_records_emitted,
                },
            ))
        except Exception as exc:
            log.warning("  [EntraUserDetails] MFA registration failed: %s", exc)

        # OAuth2 Permission Grants
        try:
            grants = await paginate_graph_raw(graph.oauth2_permission_grants)
            for grant in grants:
                evidence.append(make_evidence(
                    source=Source.ENTRA, collector="EntraUserDetails",
                    evidence_type="entra-oauth2-grant",
                    description=f"OAuth2 grant: {getattr(grant, 'client_id', '')}",
                    data={
                        "Id": getattr(grant, "id", ""),
                        "ClientId": getattr(grant, "client_id", ""),
                        "ConsentType": getattr(grant, "consent_type", ""),
                        "Scope": getattr(grant, "scope", ""),
                        "PrincipalId": getattr(grant, "principal_id", ""),
                    },
                    resource_type="OAuth2Grant",
                ))
        except Exception as exc:
            log.warning("  [EntraUserDetails] OAuth2 grants failed: %s", exc)

        log.info("  [EntraUserDetails] %d users, %d stale, %d never signed in",
                 total, stale_count, never_signed_in)
        return evidence

    return (await run_collector("EntraUserDetails", Source.ENTRA, _collect)).data


async def paginate_graph_raw(request_builder) -> list:
    items = []
    try:
        page = await request_builder.get()
        if page and page.value:
            items.extend(page.value)
        while page and page.odata_next_link:
            page = await request_builder.with_url(page.odata_next_link).get()
            if page and page.value:
                items.extend(page.value)
    except Exception as exc:
        log.warning("Graph pagination: %s", exc)
    return items
