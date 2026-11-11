"""admin-disable-user-blocks-login."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-disable-user-blocks-login"
GROUP = 'user-lifecycle'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
PASSWORD = "Str0ngPassw0rd!"
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _admin_login(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After AdminDisableUser (HTTP 200), AdminInitiateAuth and InitiateAuth are refused with
    NotAuthorizedException "User is disabled." and Enabled is False; AdminEnableUser restores login
    with the unchanged password."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    username, password = _new_confirmed_user(ctx, c, pool_id)

    pre = _admin_login(c, pool_id, client_id, username, password)
    assert pre["AccessToken"]

    status = c.admin_disable_user(UserPoolId=pool_id, Username=username)["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from AdminDisableUser, got {status}"
    assert c.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"] is False

    code, message = _error(lambda: _admin_login(c, pool_id, client_id, username, password))
    assert (code, message) == ("NotAuthorizedException", "User is disabled."), (
        f"expected NotAuthorizedException logging in as a disabled user, got {(code, message)!r}"
    )
    code_self, message_self = _error(
        lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert (code_self, message_self) == ("NotAuthorizedException", "User is disabled."), (
        f"expected NotAuthorizedException on self-service InitiateAuth for a disabled user, "
        f"got {(code_self, message_self)!r}"
    )

    c.admin_enable_user(UserPoolId=pool_id, Username=username)
    assert c.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"] is True

    post = _admin_login(c, pool_id, client_id, username, password)
    assert post["AccessToken"], "expected the original password to work again once re-enabled"


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
