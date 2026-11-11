"""admin-delete-user-twice-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-delete-user-twice-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After AdminDeleteUser, AdminGetUser and a second AdminDeleteUser both answer
    UserNotFoundException "User does not exist." and ListUsers no longer lists the user."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    # The check deletes the user itself; deleting the pool removes it if the check stops early.

    # positive control: the user is visible via an independent read before deletion
    c.admin_get_user(UserPoolId=pool_id, Username=username)

    c.admin_delete_user(UserPoolId=pool_id, Username=username)

    # independent read (different operation than the mutation) confirms the user is gone
    get_code, get_message = _error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=username))
    assert (get_code, get_message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException from AdminGetUser after delete, got {(get_code, get_message)!r}"
    )

    delete_code, delete_message = _error(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    assert (delete_code, delete_message) == ("UserNotFoundException", "User does not exist."), (
        f"expected UserNotFoundException on a second AdminDeleteUser, got {(delete_code, delete_message)!r}"
    )

    # terminal independent read: the second delete must not have resurrected the user
    names = {u["Username"] for u in c.list_users(UserPoolId=pool_id)["Users"]}
    assert username not in names, (
        f"a double-deleted user must not reappear in ListUsers, got {sorted(names)}"
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
