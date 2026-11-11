"""get-user-with-bogus-token-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-user-with-bogus-token-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_PASSWORD = "Sim2Real!23Aa"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUser with a garbage access token fails, while a valid token for a real user in the
    same pool keeps working, so the rejection targets the bogus token itself."""
    idp = ctx.client("cognito-idp")
    pool_id, client_id, username = _setup_confirmed_user(ctx)
    access_token = _get_access_token(idp, pool_id, client_id, username)

    who = idp.get_user(AccessToken=access_token)
    assert who["Username"] == username, f"expected {username}, got {who['Username']}"

    code, message = _error(lambda: idp.get_user(AccessToken="not-a-real-access-token"))
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for an invalid access token, got {code}"
    )
    expected = "Invalid Access Token"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _setup_confirmed_user(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=_PASSWORD,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)
    return pool_id, client_id, username


def _get_access_token(idp, pool_id, client_id, username):
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
