"""update-policy-type-immutable-mutation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-policy-type-immutable-mutation-rejected"
GROUP = "overly-permissive"
SERVICES = ["dlm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateLifecyclePolicy rejects changing PolicyDetails.PolicyType (immutable after creation)
    with InvalidRequestException, leaves the original PolicyType/Description untouched, and a
    benign Description-only update on the same policy still succeeds."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    original_description = ctx.unique_name("sim2real-dlm-desc-")
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=original_description,
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "immutable-check"),
        tags={"sim2real-check": CHECK},
    )

    mutated_details = {
        "PolicyType": "IMAGE_MANAGEMENT",
        "ResourceTypes": ["INSTANCE"],
        "TargetTags": [{"Key": "sim2real-dlm-target", "Value": "immutable-check"}],
        "Schedules": [
            {
                "Name": "sim2real-sched",
                "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
                "RetainRule": {"Count": 1},
            }
        ],
    }
    err = _client_error(
        lambda: dlm.update_lifecycle_policy(PolicyId=policy_id, PolicyDetails=mutated_details)
    )
    assert err["Code"] == "InvalidRequestException", (
        f"expected UpdateLifecyclePolicy(PolicyDetails.PolicyType=<changed>) to fail with "
        f"InvalidRequestException, got {err['Code']!r}"
    )
    expected_message = "The following parameter(s) cannot be updated: PolicyType"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    unchanged = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]
    assert unchanged["PolicyDetails"]["PolicyType"] == "EBS_SNAPSHOT_MANAGEMENT", (
        "expected the rejected PolicyType mutation to leave PolicyType untouched at "
        f"EBS_SNAPSHOT_MANAGEMENT, got {unchanged['PolicyDetails']['PolicyType']!r}"
    )
    assert unchanged["Description"] == original_description, (
        f"expected the rejected mutation to leave Description at {original_description!r}, "
        f"got {unchanged['Description']!r}"
    )

    # Positive control: an unrelated Description-only update on the same policy succeeds,
    # proving the rejection above is specific to PolicyType and not a general update failure.
    new_description = ctx.unique_name("sim2real-dlm-updated-desc-")
    dlm.update_lifecycle_policy(PolicyId=policy_id, Description=new_description)
    updated = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]
    assert updated["Description"] == new_description, (
        f"expected Description-only update to take effect as {new_description!r}, "
        f"got {updated['Description']!r}"
    )


def _client_error(fn):
    """Call fn() and return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _snapshot_policy_details(target_key, target_value, schedule_name="sim2real-sched"):
    return {
        "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
        "ResourceTypes": ["VOLUME"],
        "TargetTags": [{"Key": target_key, "Value": target_value}],
        "Schedules": [
            {
                "Name": schedule_name,
                "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
                "RetainRule": {"Count": 1},
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
