"""delete-group-with-members."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-group-with-members"
GROUP = 'errors'
SERVICES = ['iam']

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


def _unless_gone(fn):
    """Teardown: the body deletes this resource itself, so NoSuchEntity is fine; anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGroup on an empty group succeeds outright. The identical call on a group that still
    has a member fails DeleteConflict and the group survives; once the member is removed, the SAME
    delete call succeeds and the group is gone and unusable."""
    iam = ctx.client("iam")

    # Positive control: an empty group deletes cleanly.
    control_group = ctx.unique_name("sim2real-behav-grp-control-")
    iam.create_group(GroupName=control_group)
    iam.delete_group(GroupName=control_group)
    control_code, control_message = _error_code(lambda: iam.get_group(GroupName=control_group))
    assert control_code == ERR_NO_SUCH_ENTITY, f"control group should be gone, got {control_code!r}"
    assert control_message == f"The group with name {control_group} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {control_message!r}"
    )

    # Break exactly one thing: give the group under test a member.
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    group = ctx.unique_name("sim2real-behav-grp-")
    iam.create_group(GroupName=group, Path="/")
    ctx.on_cleanup(lambda n=group: _unless_gone(lambda: iam.delete_group(GroupName=n)))
    iam.add_user_to_group(UserName=user, GroupName=group)
    ctx.on_cleanup(lambda u=user, g=group: _unless_gone(lambda: iam.remove_user_from_group(UserName=u, GroupName=g)))

    conflict_code, conflict_message = _error_code(lambda: iam.delete_group(GroupName=group))
    assert conflict_code == ERR_DELETE_CONFLICT, f"Expected {ERR_DELETE_CONFLICT}, got {conflict_code!r}"
    assert conflict_message == "Cannot delete entity, must remove users from group first.", (
        f"expected the exact DeleteConflict message AWS returns, got {conflict_message!r}"
    )

    # Effect absent: the rejected delete left the group in place.
    survived = iam.get_group(GroupName=group)
    assert survived["Group"]["GroupName"] == group, "group should still exist after DeleteConflict"

    # Restore, then the identical call succeeds.
    iam.remove_user_from_group(UserName=user, GroupName=group)
    iam.delete_group(GroupName=group)

    # Gone and unusable: an independent read 404s, and a mutation on the dead id also fails.
    gone_code, gone_message = _error_code(lambda: iam.get_group(GroupName=group))
    assert gone_code == ERR_NO_SUCH_ENTITY, f"group should be gone, got {gone_code!r}"
    assert gone_message == f"The group with name {group} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {gone_message!r}"
    )
    mutate_code, mutate_message = _error_code(lambda: iam.add_user_to_group(UserName=user, GroupName=group))
    assert mutate_code == ERR_NO_SUCH_ENTITY, f"add-to-dead-group should 404, got {mutate_code!r}"
    assert mutate_message == f"The group with name {group} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {mutate_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
