"""op-contract-admin-enable-user."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-admin-enable-user"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminEnableUser flips a disabled user's Enabled flag back to True (observable via
    AdminGetUser) and rejects enabling a nonexistent user with UserNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword="TestPassw0rd!",
    )
    idp.admin_disable_user(UserPoolId=pool_id, Username=username)
    disabled = idp.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"]
    assert disabled is False, f"expected Enabled=False after disable, got {disabled}"

    resp = idp.admin_enable_user(UserPoolId=pool_id, Username=username)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from AdminEnableUser, got {status}"

    enabled = idp.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"]
    assert enabled is True, f"expected Enabled=True after enable, got {enabled}"

    missing_username = ctx.unique_name("sim2real-missing-")
    code, message = _error(lambda: idp.admin_enable_user(UserPoolId=pool_id, Username=missing_username))
    assert (code, message) == ("UserNotFoundException", "User does not exist."), f"expected UserNotFoundException, got {(code, message)!r}"


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-user-"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
