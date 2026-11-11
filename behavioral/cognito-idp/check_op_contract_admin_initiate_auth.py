"""op-contract-adminInitiateAuth."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminInitiateAuth"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminInitiateAuth with ADMIN_USER_PASSWORD_AUTH and correct credentials returns
    a full AuthenticationResult token set, and rejects a wrong password with
    NotAuthorizedException."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(
        ctx, pool_id, explicit_auth_flows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    )
    username = _create_user(ctx, pool_id, _unique(ctx, "user"), _PASSWORD)

    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    assert "ChallengeName" not in resp, f"unexpected challenge: {resp.get('ChallengeName')}"
    result = resp["AuthenticationResult"]
    for key in ("AccessToken", "IdToken", "RefreshToken", "TokenType"):
        assert key in result and result[key], f"missing {key} in AuthenticationResult"
    assert result["TokenType"] == "Bearer", f"expected TokenType Bearer, got {result['TokenType']}"

    # Independent terminal read at the destination: the issued AccessToken must actually
    # be usable, not merely shaped like a token.
    me = idp.get_user(AccessToken=result["AccessToken"])
    assert me["Username"] == username, f"expected GetUser to resolve {username}, got {me['Username']}"

    # Error boundary: wrong password -> NotAuthorizedException (not silently accepted).
    code = _client_error(
        lambda: idp.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": "WrongPassw0rd!99"},
        )
    )
    assert code.get("Code") == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    assert code.get("Message") == "Incorrect username or password.", code.get("Message")


def _unique(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-behav-{kind}-")


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})
    pool_id = idp.create_user_pool(PoolName=_unique(ctx, "pool"), **kwargs)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, explicit_auth_flows=None):
    idp = ctx.client("cognito-idp")
    kwargs = {"UserPoolId": pool_id, "ClientName": _unique(ctx, "client"), "GenerateSecret": False}
    if explicit_auth_flows:
        kwargs["ExplicitAuthFlows"] = explicit_auth_flows
    client_id = idp.create_user_pool_client(**kwargs)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _create_user(ctx, pool_id, username, password=None, permanent=True, attrs=None):
    idp = ctx.client("cognito-idp")
    kwargs = {
        "UserPoolId": pool_id,
        "Username": username,
        "MessageAction": "SUPPRESS",
        "UserAttributes": attrs
        or [
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    }
    if password:
        kwargs["TemporaryPassword"] = password
    idp.admin_create_user(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))
    if password and permanent:
        idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username


def _safe_delete_user(ctx, pool_id, username) -> None:
    idp = ctx.client("cognito-idp")
    try:
        idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
