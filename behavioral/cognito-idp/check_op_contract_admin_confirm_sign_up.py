"""op-contract-adminConfirmSignUp."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminConfirmSignUp"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminConfirmSignUp moves a self-signed-up UNCONFIRMED user to CONFIRMED, and
    rejects a username that doesn't exist in the pool."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = _unique(ctx, "user")

    idp.sign_up(
        ClientId=client_id,
        Username=username,
        Password=_PASSWORD,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, pool_id, username))

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "UNCONFIRMED", before["UserStatus"]

    idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)

    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED", f"expected CONFIRMED, got {after['UserStatus']}"

    # Error boundary: nonexistent username -> UserNotFoundException.
    code, message = _error(
        lambda: idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=_unique(ctx, "ghost"))
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert message == "User does not exist.", message


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


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected AdminConfirmSignUp to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
