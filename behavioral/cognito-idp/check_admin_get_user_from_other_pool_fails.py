"""admin-get-user-from-other-pool-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-get-user-from-other-pool-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: a username MUST NOT resolve under a different pool."""
    c = ctx.client("cognito-idp")
    pool_a = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_a: c.delete_user_pool(UserPoolId=_id))
    pool_b = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_b: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_a, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_a, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    # positive control: the same lookup scoped to the pool that actually owns the user
    # succeeds, so a cross-pool rejection below can't be confused with admin_get_user
    # failing unconditionally or the user never having been created.
    owning_pool = c.admin_get_user(UserPoolId=pool_a, Username=username)
    assert owning_pool["Username"] == username, (
        f"positive control failed: expected admin_get_user(pool_a, {username!r}) to "
        f"succeed, got {owning_pool!r}"
    )

    code, message = _error(
        lambda: c.admin_get_user(UserPoolId=pool_b, Username=username)
    )
    assert (code, message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException for a cross-pool user lookup, got {(code, message)!r}"
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
