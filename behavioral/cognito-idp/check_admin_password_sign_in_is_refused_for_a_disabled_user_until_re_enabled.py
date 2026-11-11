"""admin-password-sign-in-is-refused-for-a-disabled-user-until-re-enabled."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-password-sign-in-is-refused-for-a-disabled-user-until-re-enabled"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "Adm1n-Flow-Passw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn):
    """Return (Error.Code, HTTP status, Error.Message) of the ClientError fn raises; fail on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (
            err.get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.get("Message") or "",
        )
    raise AssertionError("the call succeeded; expected a refusal")


def _refusal(got, what):
    """(code, message) of an ``_error`` result, after grading its HTTP 4xx status."""
    code, status, message = got
    assert isinstance(status, int) and 400 <= status < 500, (
        f"{what}: answered HTTP {status!r}, expected 4xx"
    )
    return code, message


def _delete_pool_if_present(idp, pool_id):
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _admin_sign_in(idp, pool_id, client_id, username):
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    assert "ChallengeName" not in resp, (
        f"a confirmed user was challenged: {resp.get('ChallengeName')!r}"
    )
    return resp["AuthenticationResult"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """ADMIN_USER_PASSWORD_AUTH signs a confirmed user in with tokens GetUser resolves; after
    AdminDisableUser the same sign-in and the earlier refresh token are refused as disabled, and
    after AdminEnableUser the identical sign-in succeeds and resolves the user again."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-admin-"), UserPoolTags={"sim2real": CHECK}
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(idp, pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-cip-admin-user-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    first = _admin_sign_in(idp, pool_id, client_id, username)
    assert first.get("TokenType") == "Bearer", (
        f"TokenType {first.get('TokenType')!r}, expected Bearer"
    )
    assert idp.get_user(AccessToken=first["AccessToken"])["Username"] == username, (
        "GetUser resolved another user"
    )
    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert (status["Enabled"], status["UserStatus"]) == (True, "CONFIRMED"), (
        f"AdminGetUser (Enabled, UserStatus) {(status['Enabled'], status['UserStatus'])!r}, expected (True, 'CONFIRMED')"
    )

    idp.admin_disable_user(UserPoolId=pool_id, Username=username)
    assert idp.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"] is False, (
        "AdminGetUser still Enabled"
    )
    disabled = ("NotAuthorizedException", "User is disabled.")
    got = _refusal(
        _error(lambda: _admin_sign_in(idp, pool_id, client_id, username)),
        "sign-in of a disabled user",
    )
    assert got == disabled, (
        f"ADMIN_USER_PASSWORD_AUTH for a disabled user: expected {disabled}, got {got!r}"
    )
    got = _refusal(
        _error(
            lambda: idp.admin_initiate_auth(
                UserPoolId=pool_id,
                ClientId=client_id,
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={"REFRESH_TOKEN": first["RefreshToken"]},
            )
        ),
        "refresh for a disabled user",
    )
    assert got == disabled, (
        f"REFRESH_TOKEN_AUTH for a disabled user: expected {disabled}, got {got!r}"
    )

    idp.admin_enable_user(UserPoolId=pool_id, Username=username)
    assert idp.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"] is True, (
        "AdminGetUser not Enabled"
    )
    again = _admin_sign_in(idp, pool_id, client_id, username)
    assert again["AccessToken"] != first["AccessToken"], (
        "the re-enabled sign-in reissued the first access token"
    )
    assert idp.get_user(AccessToken=again["AccessToken"])["Username"] == username, (
        "the new token resolves another user"
    )

    idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    gone = ("UserNotFoundException", "User does not exist.")
    got = _refusal(
        _error(lambda: idp.admin_get_user(UserPoolId=pool_id, Username=username)),
        "AdminGetUser after delete",
    )
    assert got == gone, f"AdminGetUser after AdminDeleteUser: expected {gone}, got {got!r}"
    got = _refusal(
        _error(lambda: _admin_sign_in(idp, pool_id, client_id, username)),
        "sign-in of a deleted user",
    )
    assert got == gone, f"ADMIN_USER_PASSWORD_AUTH for a deleted user: expected {gone}, got {got!r}"
    idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    idp.delete_user_pool(UserPoolId=pool_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
