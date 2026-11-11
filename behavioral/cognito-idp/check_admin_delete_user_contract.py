"""op-contract-admin-delete-user."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-admin-delete-user"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminDeleteUser removes the user (verified via AdminGetUser -> UserNotFoundException)
    and rejects deleting an already-deleted / nonexistent user with UserNotFoundException."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword="TestPassw0rd!",
    )
    idp.admin_get_user(UserPoolId=pool_id, Username=username)  # exists pre-delete
    pre_delete_names = {u["Username"] for u in idp.list_users(UserPoolId=pool_id)["Users"]}
    assert username in pre_delete_names, f"expected {username} in ListUsers pre-delete, got {pre_delete_names}"

    resp = idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    body = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    assert body == {}, f"expected an empty AdminDeleteUser response body, got {body}"

    code, message = _error(lambda: idp.admin_get_user(UserPoolId=pool_id, Username=username))
    assert (code, message) == ("UserNotFoundException", "User does not exist."), f"expected UserNotFoundException post-delete, got {(code, message)!r}"

    post_delete_names = {u["Username"] for u in idp.list_users(UserPoolId=pool_id)["Users"]}
    assert username not in post_delete_names, f"expected {username} absent from ListUsers post-delete, got {post_delete_names}"

    code2, message2 = _error(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    assert (code2, message2) == ("UserNotFoundException", "User does not exist."), f"expected UserNotFoundException on repeat delete, got {(code2, message2)!r}"


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
