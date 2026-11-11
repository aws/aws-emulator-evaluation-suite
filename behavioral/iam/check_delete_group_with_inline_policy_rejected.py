"""delete-group-with-inline-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-group-with-inline-policy-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_POLICY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGroup is rejected with DeleteConflict while the group still owns an inline policy."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-conflictgroup-")
    policy_name = ctx.unique_name("sim2real-conflictpolicy-")

    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: _safe_delete_group(iam, group_name))

    iam.put_group_policy(GroupName=group_name, PolicyName=policy_name, PolicyDocument=_POLICY_DOC)
    ctx.on_cleanup(lambda: _safe_delete_group_policy(iam, group_name, policy_name))

    code, message = _error(lambda: iam.delete_group(GroupName=group_name))
    assert code == "DeleteConflict", f"expected DeleteConflict deleting a group with an inline policy, got {code}"
    expected = "Cannot delete entity, must delete policies first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the group must still exist, untouched, after the rejected delete
    still_there = iam.get_group(GroupName=group_name)["Group"]
    assert still_there["GroupName"] == group_name, (
        f"expected {group_name} to still exist after the rejected delete, got {still_there!r}"
    )
    remaining_policies = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
    assert policy_name in remaining_policies, (
        f"expected inline policy {policy_name} to survive the rejected delete, "
        f"got {remaining_policies!r}"
    )

    # once the inline policy is removed, DeleteGroup must now succeed
    iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
    iam.delete_group(GroupName=group_name)
    code_after, message_after = _error(lambda: iam.get_group(GroupName=group_name))
    assert code_after == "NoSuchEntity", f"expected NoSuchEntity after successful delete, got {code_after}"
    expected_gone = f"The group with name {group_name} cannot be found."
    assert message_after == expected_gone, f"expected message {expected_gone!r}, got {message_after!r}"


def _safe_delete_group(iam, group_name):
    try:
        iam.delete_group(GroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_group_policy(iam, group_name, policy_name):
    try:
        iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
