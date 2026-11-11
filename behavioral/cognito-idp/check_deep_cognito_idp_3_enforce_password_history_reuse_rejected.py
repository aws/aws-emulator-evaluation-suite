"""deep-cognito-idp-3-enforce-password-history-reuse-rejected."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-3-enforce-password-history-reuse-rejected"
GROUP = "policy-enforcement"
SERVICES = ["cognito-idp"]


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With PasswordHistorySize=2, ChangePassword and AdminSetUserPassword to the previous password
    are refused with PasswordHistoryPolicyViolationException and the exact message, a password
    outside the window is accepted, and a twin pool accepts the reuse."""
    idp = ctx.client("cognito-idp")
    policy = {
        "MinimumLength": 8,
        "RequireUppercase": True,
        "RequireLowercase": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
    }

    hist_pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pwhist-"),
        Policies={"PasswordPolicy": {**policy, "PasswordHistorySize": 2}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    hist_pool_id = hist_pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=hist_pool_id))
    twin_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pwtwin-"),
        Policies={"PasswordPolicy": policy},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=twin_pool_id))

    got = hist_pool["Policies"]["PasswordPolicy"].get("PasswordHistorySize")
    assert got == 2, f"history pool should persist PasswordHistorySize=2, got {got!r}"

    p1, p2, p3 = _strong_password(), _strong_password(), _strong_password()
    hist_client, hist_user = _user_with_rotation(ctx, idp, hist_pool_id, p1, p2, p3)
    twin_client, twin_user = _user_with_rotation(ctx, idp, twin_pool_id, p1, p2, p3)

    tok = _sign_in(idp, hist_client, hist_user, p3)
    code, message = _error(lambda: idp.change_password(AccessToken=tok, PreviousPassword=p3, ProposedPassword=p2))
    assert code == "PasswordHistoryPolicyViolationException", (
        f"ChangePassword to P2 (inside history window of 2) returned {code!r}, "
        f"expected PasswordHistoryPolicyViolationException"
    )
    expected_message = "Password has previously been used"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    code, message = _error(lambda: idp.admin_set_user_password(
        UserPoolId=hist_pool_id, Username=hist_user, Password=p2, Permanent=True,
    ))
    assert code == "PasswordHistoryPolicyViolationException", (
        f"AdminSetUserPassword to P2 returned {code!r}, expected PasswordHistoryPolicyViolationException"
    )
    expected_message = "Password has previously been used"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert _auth_code(idp, hist_client, hist_user, p3) == "OK", (
        "after the refused reuse the current password P3 must still sign in"
    )
    p2_after = _auth_code(idp, hist_client, hist_user, p2)
    assert p2_after == "NotAuthorizedException: Incorrect username or password.", (
        f"refused P2 must not have been installed; signing in with P2 returned {p2_after!r}"
    )

    tok = _sign_in(idp, hist_client, hist_user, p3)
    idp.change_password(AccessToken=tok, PreviousPassword=p3, ProposedPassword=p1)
    p1_after = _auth_code(idp, hist_client, hist_user, p1)
    assert p1_after == "OK", (
        f"P1 (outside the window of 2) was accepted and must now sign in; InitiateAuth gave {p1_after!r}"
    )
    p3_after = _auth_code(idp, hist_client, hist_user, p3)
    assert p3_after == "NotAuthorizedException: Incorrect username or password.", (
        f"after rotating to P1 the old P3 must no longer sign in; got {p3_after!r}"
    )

    twin_tok = _sign_in(idp, twin_client, twin_user, p3)
    idp.change_password(AccessToken=twin_tok, PreviousPassword=p3, ProposedPassword=p2)
    twin_after = _auth_code(idp, twin_client, twin_user, p2)
    assert twin_after == "OK", (
        f"twin pool without PasswordHistorySize must accept reusing P2; sign-in with P2 gave {twin_after!r}"
    )


def _strong_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(18)


def _user_with_rotation(ctx, idp, pool_id: str, p1: str, p2: str, p3: str):
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-pwhist-c-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-pwhist-u-")
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
        TemporaryPassword=_strong_password(),
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=p1, Permanent=True)
    for old, new in ((p1, p2), (p2, p3)):
        tok = _sign_in(idp, client_id, username, old)
        idp.change_password(AccessToken=tok, PreviousPassword=old, ProposedPassword=new)
    return client_id, username


def _sign_in(idp, client_id: str, username: str, password: str) -> str:
    resp = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected tokens from USER_PASSWORD_AUTH, got {resp!r}"
    return resp["AuthenticationResult"]["AccessToken"]


def _auth_code(idp, client_id: str, username: str, password: str) -> str:
    try:
        resp = idp.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    except ClientError as e:
        return f"{e.response['Error']['Code']}: {e.response['Error'].get('Message')}"
    return "OK" if "AuthenticationResult" in resp else f"NO-TOKENS:{resp.get('ChallengeName')!r}"


class _UnexpectedSuccess(AssertionError):
    pass


def _error(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise _UnexpectedSuccess(f"call expected to be refused SUCCEEDED: {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
