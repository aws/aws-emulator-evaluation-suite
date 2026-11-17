"""get-lifecycle-policies-filter-by-tags-to-add-exact-set."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-lifecycle-policies-filter-by-tags-to-add-exact-set"
GROUP = "filtering"
SERVICES = ["dlm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLifecyclePolicies TagsToAdd filter, scoped by the test's own TargetTags, returns exactly
    the one policy whose Schedule.TagsToAdd carries the queried key/value and nothing else, and
    a value no policy's TagsToAdd carries returns an empty list rather than every scoped policy."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    tag_key = ctx.unique_name("sim2real-dlm-tta2-")
    target_key = ctx.unique_name("sim2real-dlm-scope-")
    target_value = "scope-me"
    target_tags_filter = [f"{target_key}={target_value}"]

    policy_a = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details(target_key, target_value, tag_key, "a"),
        tags={"sim2real": CHECK},
    )
    policy_b = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details(target_key, target_value, tag_key, "b"),
        tags={"sim2real": CHECK},
    )

    matched_a = dlm.get_lifecycle_policies(
        ResourceTypes=["VOLUME"],
        TargetTags=target_tags_filter,
        TagsToAdd=[f"{tag_key}=a"],
    )["Policies"]
    matched_a_ids = {p["PolicyId"] for p in matched_a}
    assert matched_a_ids == {policy_a}, (
        f"TagsToAdd=['{tag_key}=a'] scoped by TargetTags returned {matched_a_ids!r}, "
        f"expected exactly {{{policy_a!r}}}"
    )

    matched_b = dlm.get_lifecycle_policies(
        ResourceTypes=["VOLUME"],
        TargetTags=target_tags_filter,
        TagsToAdd=[f"{tag_key}=b"],
    )["Policies"]
    matched_b_ids = {p["PolicyId"] for p in matched_b}
    assert matched_b_ids == {policy_b}, (
        f"TagsToAdd=['{tag_key}=b'] scoped by TargetTags returned {matched_b_ids!r}, "
        f"expected exactly {{{policy_b!r}}}"
    )

    matched_c = dlm.get_lifecycle_policies(
        ResourceTypes=["VOLUME"],
        TargetTags=target_tags_filter,
        TagsToAdd=[f"{tag_key}=c"],
    )["Policies"]
    matched_c_ids = {p["PolicyId"] for p in matched_c}
    assert matched_c_ids == set(), (
        f"TagsToAdd=['{tag_key}=c'], a value no policy's Schedule.TagsToAdd carries, "
        f"returned {matched_c_ids!r}, expected an empty set"
    )

    # Positive control: the same TargetTags scope with no TagsToAdd filter still finds both
    # policies, proving the empty result above is a real value miss and not an over-narrow scope.
    scoped_only = dlm.get_lifecycle_policies(
        ResourceTypes=["VOLUME"],
        TargetTags=target_tags_filter,
    )["Policies"]
    scoped_only_ids = {p["PolicyId"] for p in scoped_only}
    assert scoped_only_ids == {policy_a, policy_b}, (
        f"TargetTags={target_tags_filter!r} alone returned {scoped_only_ids!r}, "
        f"expected exactly {{{policy_a!r}, {policy_b!r}}}"
    )


# ===== helpers =====


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dlm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "dlm.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _snapshot_policy_details(
    target_key, target_value, tags_to_add_key, tags_to_add_value, schedule_name="sim2real-sched"
):
    return {
        "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
        "ResourceTypes": ["VOLUME"],
        "TargetTags": [{"Key": target_key, "Value": target_value}],
        "Schedules": [
            {
                "Name": schedule_name,
                "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
                "RetainRule": {"Count": 1},
                "TagsToAdd": [{"Key": tags_to_add_key, "Value": tags_to_add_value}],
            }
        ],
    }


def _create_lifecycle_policy(ctx, dlm, *, role_arn, description, state, policy_details, tags=None):
    kwargs = {
        "ExecutionRoleArn": role_arn,
        "Description": description,
        "State": state,
        "PolicyDetails": policy_details,
    }
    if tags:
        kwargs["Tags"] = tags
    deadline = time.monotonic() + 45.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            policy_id = dlm.create_lifecycle_policy(**kwargs)["PolicyId"]
            ctx.on_cleanup(lambda pid=policy_id: dlm.delete_lifecycle_policy(PolicyId=pid))
            return policy_id
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            if code == "InvalidRequestException" and "role" in message:
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
