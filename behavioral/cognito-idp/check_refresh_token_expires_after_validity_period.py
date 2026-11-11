"""refresh-token-expires-after-validity-period."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "refresh-token-expires-after-validity-period"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An app client reports RefreshTokenValidity 60 minutes and its fresh refresh token signs in, and an
    UpdateUserPoolClient below the 60-minute floor fails with InvalidParameterException and its exact
    message, leaving the validity unchanged."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        RefreshTokenValidity=60,
        TokenValidityUnits={"RefreshToken": "minutes"},
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))

    described = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert described["RefreshTokenValidity"] == 60
    assert described["TokenValidityUnits"]["RefreshToken"] == "minutes"

    username, password = _create_confirmed_user(ctx, pool_id)
    auth = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    refresh_token = auth["AuthenticationResult"]["RefreshToken"]

    fresh = idp.get_tokens_from_refresh_token(RefreshToken=refresh_token, ClientId=client_id)
    assert "AccessToken" in fresh["AuthenticationResult"], (
        "a refresh token minted under the configured 60-minute validity must work "
        "immediately, i.e. it is not already expired"
    )

    code, message = _rejection(lambda: idp.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        RefreshTokenValidity=59,
        TokenValidityUnits={"RefreshToken": "minutes"},
    ))
    assert code == "InvalidParameterException", (
        f"a RefreshTokenValidity below the 60-minute floor must be rejected with "
        f"InvalidParameterException, got {code!r} -- the floor is either not enforced "
        f"or enforced with the wrong error"
    )
    expected_message = "Invalid range for token validity."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert unchanged["RefreshTokenValidity"] == 60, (
        f"a rejected UpdateUserPoolClient must leave RefreshTokenValidity unchanged at 60, "
        f"got {unchanged['RefreshTokenValidity']} -- the rejected call must have had no effect"
    )
    assert unchanged["TokenValidityUnits"]["RefreshToken"] == "minutes", (
        f"a rejected UpdateUserPoolClient must leave TokenValidityUnits.RefreshToken "
        f"unchanged at 'minutes', got {unchanged['TokenValidityUnits']['RefreshToken']}"
    )


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _create_confirmed_user(ctx, pool_id):
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username,
        TemporaryPassword="Temp0rary!Passw0rd", MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
