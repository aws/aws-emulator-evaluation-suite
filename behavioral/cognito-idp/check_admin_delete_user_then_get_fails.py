"""admin-delete-user-then-get-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-delete-user-then-get-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: AdminGetUser for a deleted user MUST fail."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    # The check deletes the user itself; deleting the pool removes it if the check stops early.

    c.admin_delete_user(UserPoolId=pool_id, Username=username)

    code, message = _error(
        lambda: c.admin_get_user(UserPoolId=pool_id, Username=username)
    )
    assert (code, message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException after delete, got {(code, message)!r}"
    )

    mutate_code, mutate_message = _error(
        lambda: c.admin_disable_user(UserPoolId=pool_id, Username=username)
    )
    assert (mutate_code, mutate_message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException on AdminDisableUser against a deleted user, got {(mutate_code, mutate_message)!r}"
    )


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
