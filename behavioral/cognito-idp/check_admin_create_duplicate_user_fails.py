"""admin-create-duplicate-user-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-create-duplicate-user-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: AdminCreateUser with a username that already exists MUST fail,
    the pool's user count must not change, and the identical username becomes creatable again
    once the original user is gone."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    # positive control: the first create is visible on an independent read.
    users = c.list_users(UserPoolId=pool_id)["Users"]
    assert len(users) == 1, f"expected 1 user after first create, got {len(users)}"
    assert users[0]["Username"] == username, (
        f"expected the created username {username!r}, got {users[0]['Username']!r}"
    )

    code, message = _error(
        lambda: c.admin_create_user(
            UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS"
        )
    )
    assert (code, message) == ("UsernameExistsException", "User account already exists"), (
        f"expected UsernameExistsException for duplicate user, got {(code, message)!r}"
    )

    # effect absent: the pool still has exactly the one original user.
    users_after = c.list_users(UserPoolId=pool_id)["Users"]
    assert len(users_after) == 1, (
        f"expected still 1 user after rejected duplicate, got {len(users_after)}"
    )

    # restore: once the blocking user is gone, the identical username is creatable again.
    c.admin_delete_user(UserPoolId=pool_id, Username=username)
    gone_code, gone_message = _error(
        lambda: c.admin_get_user(UserPoolId=pool_id, Username=username)
    )
    assert (gone_code, gone_message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException after admin_delete_user, got {(gone_code, gone_message)!r}"
    )

    resp = c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    assert resp["User"]["Username"] == username, (
        f"expected recreated user {username!r} once the original was deleted, "
        f"got {resp['User']['Username']!r}"
    )
    users_final = c.list_users(UserPoolId=pool_id)["Users"]
    assert len(users_final) == 1, (
        f"expected exactly 1 user after recreate, got {len(users_final)}"
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
