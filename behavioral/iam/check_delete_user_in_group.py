"""delete-user-in-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-user-in-group"
GROUP = 'errors'
SERVICES = ['iam']

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteUser on a user in a group fails with DeleteConflict and the exact message and the
    user stays; after removing the membership the same call deletes it (GetUser: exact
    NoSuchEntity), as it does at once for a user in no group."""
    iam = ctx.client("iam")

    # Positive control: deleting a user with no dependents succeeds outright.
    control = ctx.unique_name("sim2real-behav-user-control-")
    iam.create_user(UserName=control, Path="/")
    iam.delete_user(UserName=control)
    control_code, control_code_msg = _client_error(lambda: iam.get_user(UserName=control))
    assert control_code == ERR_NO_SUCH_ENTITY, f"control user should be gone, got {control_code!r}"
    assert control_code_msg == f"The user with name {control} cannot be found.", f"unexpected error message {control_code_msg!r}"

    # Break exactly one thing: add the user to a group.
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda n=user: _ignore_missing(lambda: iam.delete_user(UserName=n)))
    group = ctx.unique_name("sim2real-behav-grp-")
    iam.create_group(GroupName=group, Path="/")
    ctx.on_cleanup(lambda n=group: _ignore_missing(lambda: iam.delete_group(GroupName=n)))
    iam.add_user_to_group(UserName=user, GroupName=group)

    code, code_msg = _client_error(lambda: iam.delete_user(UserName=user))
    assert code == ERR_DELETE_CONFLICT, f"Expected {ERR_DELETE_CONFLICT}, got {code!r}"
    assert code_msg == "Cannot delete entity, must remove users from group first.", f"unexpected error message {code_msg!r}"

    # Effect absent: an independent read shows the user is still there.
    still_there = iam.get_user(UserName=user)["User"]["UserName"]
    assert still_there == user, f"user should still exist after DeleteConflict, got {still_there!r}"

    # Restore: remove the membership, then the identical call succeeds.
    iam.remove_user_from_group(UserName=user, GroupName=group)
    iam.delete_user(UserName=user)
    gone_code, gone_code_msg = _client_error(lambda: iam.get_user(UserName=user))
    assert gone_code == ERR_NO_SUCH_ENTITY, f"user should be gone once ungrouped, got {gone_code!r}"
    assert gone_code_msg == f"The user with name {user} cannot be found.", f"unexpected error message {gone_code_msg!r}"


def _ignore_missing(fn):
    """Teardown: run fn(), tolerating only NoSuchEntity for a resource the check already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
