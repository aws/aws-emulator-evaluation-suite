"""deep-cognito-idp-3-enforce-risk-user-context-ip-blocked."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-risk-user-context-ip-blocked"
GROUP = "authorization"
SERVICES = ["cognito-idp"]

_BLOCKED_RANGE, _BLOCKED_IP = "203.0.113.0/24", "203.0.113.77"
_SKIPPED_RANGE, _SKIPPED_IP = "198.51.100.0/24", "198.51.100.20"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Through a client that propagates user context, InitiateAuth with UserContextData.IpAddress in
    the blocked range is refused with NotAuthorizedException and the skipped range signs in; a
    non-propagating twin refuses the field with InvalidParameterException and signs in without it."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-riskctx-"),
        UserPoolTier="PLUS",
        UserPoolAddOns={"AdvancedSecurityMode": "ENFORCED"},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    idp.set_risk_configuration(
        UserPoolId=pool_id,
        RiskExceptionConfiguration={
            "BlockedIPRangeList": [_BLOCKED_RANGE], "SkippedIPRangeList": [_SKIPPED_RANGE],
        },
    )

    prop_id, prop_secret = _client(ctx, idp, pool_id, propagate=True)
    twin_id, twin_secret = _client(ctx, idp, pool_id, propagate=False)
    prop_desc = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=prop_id)["UserPoolClient"]
    twin_desc = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=twin_id)["UserPoolClient"]
    assert prop_desc.get("EnablePropagateAdditionalUserContextData") is True, (
        f"propagating client should persist the flag as True, got "
        f"{prop_desc.get('EnablePropagateAdditionalUserContextData')!r}"
    )
    assert twin_desc.get("EnablePropagateAdditionalUserContextData") is False, (
        f"twin client should persist the flag as False, got "
        f"{twin_desc.get('EnablePropagateAdditionalUserContextData')!r}"
    )

    username = ctx.unique_name("sim2real-behav-riskctx-u-")
    password = _strong_password()
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        TemporaryPassword=_strong_password(),
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    blocked = _auth(idp, prop_id, prop_secret, username, password, _BLOCKED_IP)
    assert blocked == ("NotAuthorizedException", "Request not allowed due to security reasons."), (
        f"propagating client: blocked-range UserContextData IP {_BLOCKED_IP} returned {blocked!r}, "
        f"expected NotAuthorizedException"
    )
    skipped = _auth(idp, prop_id, prop_secret, username, password, _SKIPPED_IP)
    assert skipped == "OK", (
        f"propagating client: skipped-range IP {_SKIPPED_IP} must sign in, got {skipped!r}"
    )

    twin_spoof = _auth(idp, twin_id, twin_secret, username, password, _BLOCKED_IP)
    assert twin_spoof == ("InvalidParameterException", "Cannot use IP Address passed into UserContextData"), (
        f"non-propagating twin: a caller-supplied UserContextData.IpAddress returned {twin_spoof!r}, "
        f"expected InvalidParameterException"
    )
    twin_plain = _auth(idp, twin_id, twin_secret, username, password, None)
    assert twin_plain == "OK", (
        f"non-propagating twin: the same sign-in without UserContextData must issue tokens, got {twin_plain!r}"
    )


def _strong_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(18)


def _client(ctx, idp, pool_id: str, propagate: bool):
    resp = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-riskctx-c-"),
        GenerateSecret=True,
        EnablePropagateAdditionalUserContextData=propagate,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    return resp["ClientId"], resp["ClientSecret"]


def _secret_hash(client_id: str, client_secret: str, username: str) -> str:
    digest = hmac.new(client_secret.encode(), (username + client_id).encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def _auth(idp, client_id: str, client_secret: str, username: str, password: str, ip):
    """The string OK on a token-issuing sign-in, else the refusal's (code, message) or a challenge marker."""
    kwargs = {
        "ClientId": client_id,
        "AuthFlow": "USER_PASSWORD_AUTH",
        "AuthParameters": {
            "USERNAME": username,
            "PASSWORD": password,
            "SECRET_HASH": _secret_hash(client_id, client_secret, username),
        },
    }
    if ip is not None:
        kwargs["UserContextData"] = {"IpAddress": ip, "EncodedData": ""}
    try:
        resp = idp.initiate_auth(**kwargs)
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return "OK" if "AccessToken" in (resp.get("AuthenticationResult") or {}) else (
        f"NO-TOKENS:{resp.get('ChallengeName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
