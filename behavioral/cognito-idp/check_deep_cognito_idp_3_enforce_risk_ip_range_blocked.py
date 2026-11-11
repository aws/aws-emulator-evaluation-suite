"""deep-cognito-idp-3-enforce-risk-ip-range-blocked."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-risk-ip-range-blocked"
GROUP = "authorization"
SERVICES = ["cognito-idp"]

# RFC 5737 documentation ranges: no real caller can originate from them, so the only way an
# address in them reaches the risk engine is the ContextData we send.
_BLOCKED_RANGE, _BLOCKED_IP = "203.0.113.0/24", "203.0.113.77"
_SKIPPED_RANGE, _SKIPPED_IP = "198.51.100.0/24", "198.51.100.20"
_UNLISTED_IP = "192.0.2.55"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """In an ENFORCED pool, AdminInitiateAuth from a BlockedIPRangeList address is refused with
    NotAuthorizedException and the exact message and logged with RiskDecision Block, while skipped
    and unlisted addresses sign in, as does the blocked one in an AUDIT twin."""
    idp = ctx.client("cognito-idp")
    exceptions = {"BlockedIPRangeList": [_BLOCKED_RANGE], "SkippedIPRangeList": [_SKIPPED_RANGE]}

    enforced_pool, enforced_client = _risk_pool(ctx, idp, "ENFORCED", exceptions)
    audit_pool, audit_client = _risk_pool(ctx, idp, "AUDIT", exceptions)

    password = _strong_password()
    enforced_user = _confirmed_user(ctx, idp, enforced_pool, password)
    audit_user = _confirmed_user(ctx, idp, audit_pool, password)

    blocked = _auth(idp, enforced_pool, enforced_client, enforced_user, password, _BLOCKED_IP)
    assert blocked == ("NotAuthorizedException", "Request not allowed due to security reasons."), (
        f"ENFORCED pool: correct password from blocked-range IP {_BLOCKED_IP} returned {blocked!r}, "
        f"expected NotAuthorizedException"
    )

    event = _wait_for_event(idp, enforced_pool, enforced_user, _BLOCKED_IP)
    assert event.get("EventResponse") == "Fail", (
        f"auth event from {_BLOCKED_IP} should record EventResponse=Fail, got {event.get('EventResponse')!r}"
    )
    decision = (event.get("EventRisk") or {}).get("RiskDecision")
    assert decision == "Block", (
        f"auth event from {_BLOCKED_IP} should record RiskDecision=Block, got {decision!r}"
    )

    skipped = _auth(idp, enforced_pool, enforced_client, enforced_user, password, _SKIPPED_IP)
    assert skipped == "OK", (
        f"ENFORCED pool: skipped-range IP {_SKIPPED_IP} must be allowed to sign in, got {skipped!r}"
    )
    unlisted = _auth(idp, enforced_pool, enforced_client, enforced_user, password, _UNLISTED_IP)
    assert unlisted == "OK", (
        f"ENFORCED pool: unlisted IP {_UNLISTED_IP} must be allowed to sign in, got {unlisted!r}"
    )

    audit_blocked = _auth(idp, audit_pool, audit_client, audit_user, password, _BLOCKED_IP)
    assert audit_blocked == "OK", (
        f"AUDIT twin: the same blocked-range IP must NOT be refused in AUDIT mode, got {audit_blocked!r}"
    )


def _strong_password() -> str:
    # Random per run so the compromised-credential list never matches and confounds the decision.
    return "Aa1!" + secrets.token_urlsafe(18)


def _risk_pool(ctx, idp, mode: str, exceptions: dict):
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name(f"sim2real-behav-riskip-{mode.lower()}-"),
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": mode},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    stored = idp.set_risk_configuration(
        UserPoolId=pool_id, RiskExceptionConfiguration=exceptions,
    )["RiskConfiguration"]["RiskExceptionConfiguration"]
    assert stored.get("BlockedIPRangeList") == exceptions["BlockedIPRangeList"], (
        f"{mode} pool should store the blocked range, got {stored!r}"
    )
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-riskip-c-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _confirmed_user(ctx, idp, pool_id: str, password: str) -> str:
    username = ctx.unique_name("sim2real-behav-riskip-u-")
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        TemporaryPassword=_strong_password(),
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username


def _auth(idp, pool_id: str, client_id: str, username: str, password: str, ip: str):
    """The string OK on a token-issuing sign-in, else the refusal's (code, message) or a challenge marker."""
    try:
        resp = idp.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
            ContextData={
                "IpAddress": ip,
                "ServerName": "sim2real.example.com",
                "ServerPath": "/login",
                "HttpHeaders": [{"headerName": "User-Agent", "headerValue": "sim2real-behav"}],
            },
        )
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return "OK" if "AccessToken" in (resp.get("AuthenticationResult") or {}) else (
        f"NO-TOKENS:{resp.get('ChallengeName')!r}"
    )


def _wait_for_event(idp, pool_id: str, username: str, ip: str, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    seen = []
    while True:
        seen = []
        kwargs = {"UserPoolId": pool_id, "Username": username, "MaxResults": 60}
        while True:
            page = idp.admin_list_user_auth_events(**kwargs)
            seen.extend(page.get("AuthEvents", []))
            if not page.get("NextToken"):
                break
            kwargs["NextToken"] = page["NextToken"]
        for ev in seen:
            if (ev.get("EventContextData") or {}).get("IpAddress") == ip:
                return ev
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no auth event from {ip} appeared within {timeout_s}s; saw "
                f"{[(e.get('EventContextData') or {}).get('IpAddress') for e in seen]!r}"
            )
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
