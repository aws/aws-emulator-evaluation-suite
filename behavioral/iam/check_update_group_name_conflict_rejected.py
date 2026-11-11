"""update-group-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-group-name-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _safe_delete_group(iam, name):
    try:
        iam.delete_group(GroupName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup to a name already taken by another group is rejected and neither group is mutated."""
    iam = ctx.client("iam")

    group_a = ctx.unique_name("sim2real-behav-groupa-")
    group_b = ctx.unique_name("sim2real-behav-groupb-")
    fresh_name = ctx.unique_name("sim2real-behav-groupa2-")

    group_a_id = iam.create_group(GroupName=group_a)["Group"]["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(iam, group_a))
    ctx.on_cleanup(lambda: _safe_delete_group(iam, fresh_name))
    group_b_id = iam.create_group(GroupName=group_b)["Group"]["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(iam, group_b))

    code, message = _error(lambda: iam.update_group(GroupName=group_a, NewGroupName=group_b))
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code}"
    expected = f"Group with name {group_b} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Neither group's identity was disturbed by the rejected rename.
    a_after = iam.get_group(GroupName=group_a)["Group"]
    b_after = iam.get_group(GroupName=group_b)["Group"]
    assert a_after["GroupId"] == group_a_id
    assert b_after["GroupId"] == group_b_id

    # Positive control: renaming group A to a genuinely free name succeeds.
    iam.update_group(GroupName=group_a, NewGroupName=fresh_name)

    renamed = iam.get_group(GroupName=fresh_name)["Group"]
    assert renamed["GroupId"] == group_a_id
    stale_code, stale_message = _error(lambda: iam.get_group(GroupName=group_a))
    assert stale_code == "NoSuchEntity", f"expected NoSuchEntity for the stale name, got {stale_code}"
    expected_stale = f"The group with name {group_a} cannot be found."
    assert stale_message == expected_stale, (
        f"expected message {expected_stale!r}, got {stale_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
