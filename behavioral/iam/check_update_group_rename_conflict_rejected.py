"""update-group-rename-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-group-rename-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup rejects a rename to a NewGroupName that already exists with
    EntityAlreadyExists and leaves the source group untouched under its original name; the same
    call succeeds (positive control) when the target name is free."""
    iam = ctx.client("iam")
    group_a = ctx.unique_name("sim2real-behav-grename-a-")
    group_b = ctx.unique_name("sim2real-behav-grename-b-")

    created_a = iam.create_group(GroupName=group_a)["Group"]
    created_b = iam.create_group(GroupName=group_b)["Group"]

    current_a = {"value": group_a}
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_group(GroupName=current_a["value"])))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_group(GroupName=group_b)))

    code, message = _error(lambda: iam.update_group(GroupName=group_a, NewGroupName=group_b))
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code!r}"
    expected = f"Group with name {group_b} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: group_a is unchanged, group_b is unchanged (not overwritten/merged).
    unchanged_a = iam.get_group(GroupName=group_a)["Group"]
    assert unchanged_a["GroupId"] == created_a["GroupId"], (
        f"expected group_a GroupId {created_a['GroupId']!r} unchanged, got {unchanged_a['GroupId']!r}"
    )
    unchanged_b = iam.get_group(GroupName=group_b)["Group"]
    assert unchanged_b["GroupId"] == created_b["GroupId"], (
        f"expected group_b GroupId {created_b['GroupId']!r} unchanged, got {unchanged_b['GroupId']!r}"
    )

    # Positive control: renaming to a free name succeeds.
    free_name = ctx.unique_name("sim2real-behav-grename-c-")
    iam.update_group(GroupName=group_a, NewGroupName=free_name)
    current_a["value"] = free_name
    renamed = iam.get_group(GroupName=free_name)["Group"]
    assert renamed["GroupId"] == created_a["GroupId"], (
        f"expected renamed group GroupId {created_a['GroupId']!r}, got {renamed['GroupId']!r}"
    )
    code_old, message_old = _error(lambda: iam.get_group(GroupName=group_a))
    assert code_old == "NoSuchEntity", f"expected NoSuchEntity for stale name, got {code_old!r}"
    expected_old = f"The group with name {group_a} cannot be found."
    assert message_old == expected_old, f"expected message {expected_old!r}, got {message_old!r}"


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
