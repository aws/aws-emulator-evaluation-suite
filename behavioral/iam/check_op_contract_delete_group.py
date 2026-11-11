"""op-contract-deleteGroup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteGroup"
GROUP = "error-semantics"
SERVICES = ["iam"]

_DENY_ALL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGroup removes an empty group; DeleteConflict when it still has an attached policy."""
    iam = ctx.client("iam")

    # success path
    group_name = ctx.unique_name("sim2real-behav-grp-")
    iam.create_group(GroupName=group_name)
    assert group_name in [g["GroupName"] for g in _listed(iam, "list_groups", "Groups")]
    resp = iam.delete_group(GroupName=group_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    # substantive state check: the group is actually gone from the account's group list,
    # not merely that the call returned 200
    remaining_names = [g["GroupName"] for g in _listed(iam, "list_groups", "Groups")]
    assert group_name not in remaining_names, "deleted group still present in ListGroups"
    code, message = _error(lambda: iam.get_group(GroupName=group_name))
    assert code == "NoSuchEntity", f"expected group gone, got {code}"
    expected = f"The group with name {group_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # error boundary: group with an attached managed policy cannot be deleted
    conflict_group = ctx.unique_name("sim2real-behav-grp-conflict-")
    iam.create_group(GroupName=conflict_group)
    iam.attach_group_policy(GroupName=conflict_group, PolicyArn=_DENY_ALL_POLICY_ARN)

    def _cleanup():
        try:
            iam.detach_group_policy(GroupName=conflict_group, PolicyArn=_DENY_ALL_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_group(GroupName=conflict_group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    conflict_code, conflict_message = _error(lambda: iam.delete_group(GroupName=conflict_group))
    assert conflict_code == "DeleteConflict", f"expected DeleteConflict, got {conflict_code}"
    expected_conflict = "Cannot delete entity, must detach all policies first."
    assert conflict_message == expected_conflict, (
        f"expected message {expected_conflict!r}, got {conflict_message!r}"
    )

    # the group must still exist, still holding the attached policy, after the rejected delete
    still_there = iam.get_group(GroupName=conflict_group)["Group"]
    assert still_there["GroupName"] == conflict_group, "conflict group vanished after a rejected delete"
    attached = [p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=conflict_group)["AttachedPolicies"]]
    assert _DENY_ALL_POLICY_ARN in attached, "attached policy missing after a rejected delete"

    # once the conflict is resolved, the identical DeleteGroup call must now succeed
    iam.detach_group_policy(GroupName=conflict_group, PolicyArn=_DENY_ALL_POLICY_ARN)
    iam.delete_group(GroupName=conflict_group)
    resolved_names = [g["GroupName"] for g in _listed(iam, "list_groups", "Groups")]
    assert conflict_group not in resolved_names, "resolved-and-deleted group still present in ListGroups"
    resolved_code, resolved_message = _error(lambda: iam.get_group(GroupName=conflict_group))
    assert resolved_code == "NoSuchEntity", f"expected group gone after resolved delete, got {resolved_code}"
    expected_resolved = f"The group with name {conflict_group} cannot be found."
    assert resolved_message == expected_resolved, (
        f"expected message {expected_resolved!r}, got {resolved_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _listed(iam, operation, key):
    """Every item an IAM listing returns, across all pages."""
    return [item for page in iam.get_paginator(operation).paginate() for item in page[key]]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
