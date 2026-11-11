"""op-contract-add-user-to-group."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-add-user-to-group"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddUserToGroup: success-path membership is observable via ListGroupsForUser; error
    boundary is NoSuchEntityException for a GroupName that doesn't exist."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": "op-contract-add-user-to-group"}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    group_name = ctx.unique_name("sim2real-group-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    iam.add_user_to_group(GroupName=group_name, UserName=user_name)
    ctx.on_cleanup(lambda: iam.remove_user_from_group(GroupName=group_name, UserName=user_name))

    groups = _poll_until(
        lambda: iam.list_groups_for_user(UserName=user_name)["Groups"],
        lambda gs: any(g["GroupName"] == group_name for g in gs),
    )
    assert any(g["GroupName"] == group_name for g in groups)

    missing_group = ctx.unique_name("sim2real-nonexistent-group-")
    code, message = _error(lambda: iam.add_user_to_group(GroupName=missing_group, UserName=user_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The group with name {missing_group} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_until(probe, predicate, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
