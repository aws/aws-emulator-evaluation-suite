"""remove-default-user-from-group-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-default-user-from-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyUserGroup must reject an attempt to remove the mandatory 'default' user from
    a user group (DefaultUserRequired), leaving membership unchanged, while a legitimate
    removal of a non-default member in the same group still succeeds."""
    ec = ctx.client("elasticache")

    user_a_id = ctx.unique_name("sim2real-defu-")
    group_id = ctx.unique_name("sim2real-defg-")

    ec.create_user(
        UserId=user_a_id,
        UserName=user_a_id,
        Engine="redis",
        AccessString="on ~* +@all",
        NoPasswordRequired=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user(ec, user_a_id))

    ec.create_user_group(
        UserGroupId=group_id,
        Engine="redis",
        UserIds=["default", user_a_id],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_group(ec, group_id))
    _wait_for_group_status(ec, group_id, {"active"}, timeout_s=180)

    code, message = _error(lambda: ec.modify_user_group(UserGroupId=group_id, UserIdsToRemove=["default"]))
    assert code == "DefaultUserRequired", f"expected DefaultUserRequired, got {code}"
    expected_message = "Redis user group needs to contain a user with the user name default."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect must be absent: 'default' is still a member and the group settled back to active.
    after_reject = _wait_for_group_status(ec, group_id, {"active"}, timeout_s=60)
    assert "default" in after_reject["UserIds"], f"'default' missing after rejected removal: {after_reject['UserIds']}"
    assert user_a_id in after_reject["UserIds"], f"{user_a_id} missing after rejected removal: {after_reject['UserIds']}"

    # Positive control: removing the non-default member in the same group succeeds.
    ec.modify_user_group(UserGroupId=group_id, UserIdsToRemove=[user_a_id])
    after_control = _wait_for_group_status(ec, group_id, {"active"}, timeout_s=180)
    assert user_a_id not in after_control["UserIds"], f"{user_a_id} still present after accepted removal: {after_control['UserIds']}"
    assert "default" in after_control["UserIds"], f"'default' missing after unrelated removal: {after_control['UserIds']}"


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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


def _wait_for_group_status(ec, group_id, wanted_statuses, timeout_s=180.0, interval_s=3.0):
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
    raise AssertionError(f"group {group_id} never reached {wanted_statuses}; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
