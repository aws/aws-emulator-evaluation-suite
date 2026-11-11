"""concurrent-modify-user-group-membership-race."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-modify-user-group-membership-race"
GROUP = "concurrency"
SERVICES = ["elasticache"]

# These tags make a leftover discoverable through the Resource Groups Tagging API and
# attributable to this scenario.
_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent ModifyUserGroup calls adding the same user to one user group converge: the
    user is present exactly once, one call wins and the other is rejected as an invalid-state
    conflict."""
    ec = ctx.client("elasticache")

    # ElastiCache user/group IDs are normalized to lowercase server-side, so use
    # lowercase prefixes to keep the Python-side identifiers matching what
    # DescribeUserGroups echoes back.
    user_a_id = ctx.unique_name("sim2real-uga-")
    user_b_id = ctx.unique_name("sim2real-ugb-")
    group_id = ctx.unique_name("sim2real-ug-")

    ec.create_user(
        UserId=user_a_id,
        UserName=user_a_id,
        Engine="redis",
        AccessString="on ~* +@all",
        NoPasswordRequired=True,
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_user(ec, user_a_id))

    ec.create_user(
        UserId=user_b_id,
        UserName=user_b_id,
        Engine="redis",
        AccessString="on ~* +@all",
        NoPasswordRequired=True,
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_user(ec, user_b_id))

    ec.create_user_group(
        UserGroupId=group_id, Engine="redis", UserIds=["default", user_a_id], Tags=_RESOURCE_TAGS
    )
    ctx.on_cleanup(lambda: _delete_user_group(ec, group_id))
    _wait_for_group_status(ec, group_id, {"active"}, ctx=ctx, timeout_s=_budget_s(ctx, 180.0))

    # Both submits leave the barrier together, so the second lands inside the first's modifying
    # window regardless of how late the pool schedules its thread.
    start = threading.Barrier(2)

    def _add_user_b():
        start.wait(timeout=30)
        return ec.modify_user_group(UserGroupId=group_id, UserIdsToAdd=[user_b_id])

    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_add_user_b) for _ in range(2)]
        for fut in futures:
            try:
                resp = fut.result()
                outcomes.append(("ok", resp["Status"]))
            except ClientError as exc:
                outcomes.append(("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert len(successes) == 1, f"expected exactly one winner, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one loser, got {outcomes}"
    assert failures[0][1] == "InvalidUserGroupState", f"expected InvalidUserGroupState, got {outcomes}"
    expected = f"User group {group_id} has status modifying. Only active user groups can be modified."
    assert failures[0][2] == expected, f"expected {expected!r}, got {failures[0][2]!r}"

    final = _wait_for_group_status(ec, group_id, {"active"}, ctx=ctx, timeout_s=_budget_s(ctx, 180.0))
    user_ids = final["UserIds"]
    assert user_ids.count(user_b_id) == 1, f"expected user_b exactly once, got {user_ids}"
    assert "default" in user_ids
    assert user_a_id in user_ids


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _delete_user(ec, user_id):
    try:
        ec.delete_user(UserId=user_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ServiceLinkedRoleNotFoundFault", "UserNotFound"):
            raise


def _delete_user_group(ec, group_id):
    try:
        ec.delete_user_group(UserGroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ServiceLinkedRoleNotFoundFault",
            "UserGroupNotFound",
        ):
            raise


def _wait_for_group_status(ec, group_id, wanted_statuses, timeout_s=180.0, interval_s=1.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ec.describe_user_groups(UserGroupId=group_id)
        groups = resp.get("UserGroups", [])
        if groups:
            last = groups[0]
            if last["Status"] in wanted_statuses:
                return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"group {group_id} reaching {wanted_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"group {group_id} never reached {wanted_statuses}; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
