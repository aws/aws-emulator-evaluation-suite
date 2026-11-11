"""delete-group-with-member-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-group-with-member-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGroup must be rejected with DeleteConflict while a user is still a member of the
    group (distinct trigger from the inline-policy conflict covered elsewhere: here the
    conflict comes from group membership, not from any policy)."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-behav-membergroup-")
    user_name = ctx.unique_name("sim2real-behav-memberuser-")

    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_group(GroupName=group_name)))

    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.add_user_to_group(GroupName=group_name, UserName=user_name)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.remove_user_from_group(GroupName=group_name, UserName=user_name)
        )
    )

    code, message = _error(lambda: iam.delete_group(GroupName=group_name))
    assert code == "DeleteConflict", f"expected DeleteConflict deleting a group with a member, got {code!r}"
    expected = "Cannot delete entity, must remove users from group first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the group must still exist, still holding the member, after the rejected delete
    got = iam.get_group(GroupName=group_name)
    assert got["Group"]["GroupName"] == group_name, (
        f"expected group {group_name!r} to survive the rejected delete, got {got['Group']['GroupName']!r}"
    )
    members = {u["UserName"] for u in got["Users"]}
    assert user_name in members, f"expected {user_name!r} still a member of {group_name!r}, got {members!r}"

    # once the conflict is resolved, deletion succeeds normally
    iam.remove_user_from_group(GroupName=group_name, UserName=user_name)
    iam.delete_group(GroupName=group_name)
    expected_gone = f"The group with name {group_name} cannot be found."
    code_after, message_after = _error(lambda: iam.get_group(GroupName=group_name))
    assert code_after == "NoSuchEntity", f"expected NoSuchEntity reading a deleted group, got {code_after!r}"
    assert message_after == expected_gone, f"expected message {expected_gone!r}, got {message_after!r}"

    # the dead group id is also unusable for a mutation, not just a read
    code_mutation, message_mutation = _error(
        lambda: iam.add_user_to_group(GroupName=group_name, UserName=user_name)
    )
    assert code_mutation == "NoSuchEntity", (
        f"expected NoSuchEntity mutating a deleted group, got {code_mutation!r}"
    )
    assert message_mutation == expected_gone, (
        f"expected message {expected_gone!r}, got {message_mutation!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
