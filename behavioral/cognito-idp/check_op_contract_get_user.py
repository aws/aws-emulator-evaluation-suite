"""op-contract-get-user."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-user"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUser returns the authenticated user's own attributes; an invalid AccessToken is rejected."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = _password()
    _create_confirmed_user(ctx, pool_id, username, password)

    auth = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    resp = idp.get_user(AccessToken=access_token)
    assert resp["Username"] == username, f"expected Username={username!r}, got {resp['Username']!r}"
    attr_names = {a["Name"] for a in resp["UserAttributes"]}
    assert "sub" in attr_names, f"expected 'sub' in UserAttributes, got {sorted(attr_names)}"

    err = _client_error(lambda: idp.get_user(AccessToken="not-a-real-access-token"))
    assert err.get("Code") == "NotAuthorizedException", f"expected NotAuthorizedException, got {err!r}"
    want = "Invalid Access Token"
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _password() -> str:
    return "Sim2Real!23Aa"


def _create_user_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "UserPoolId": pool_id,
        "ClientName": ctx.unique_name("sim2real-behav-client-"),
        "ExplicitAuthFlows": [
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ],
    }
    params.update(overrides)
    resp = idp.create_user_pool_client(**params)
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, password):
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
