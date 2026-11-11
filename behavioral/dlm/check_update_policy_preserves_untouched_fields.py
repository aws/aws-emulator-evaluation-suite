"""update-policy-preserves-untouched-fields."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-policy-preserves-untouched-fields"
GROUP = "state"
SERVICES = ["dlm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateLifecyclePolicy is a partial update: fields not passed in the request are unchanged."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    original_description = ctx.unique_name("sim2real-dlm-original-desc-")
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=original_description,
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "partial-update-check"),
        tags={"sim2real-check": CHECK},
    )
    # Only State is passed; Description and PolicyDetails must be untouched.
    dlm.update_lifecycle_policy(PolicyId=policy_id, State="DISABLED")
    policy = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]
    assert policy["State"] == "DISABLED", (
        f"expected State DISABLED after UpdateLifecyclePolicy(State=DISABLED), got {policy['State']!r}"
    )
    assert policy["Description"] == original_description, (
        f"expected untouched Description {original_description!r}, got {policy['Description']!r}"
    )
    assert policy["PolicyDetails"]["PolicyType"] == "EBS_SNAPSHOT_MANAGEMENT", (
        "expected untouched PolicyDetails.PolicyType EBS_SNAPSHOT_MANAGEMENT, got "
        f"{policy['PolicyDetails']['PolicyType']!r}"
    )
    assert policy["PolicyDetails"]["TargetTags"] == [
        {"Key": "sim2real-dlm-target", "Value": "partial-update-check"}
    ], f"expected untouched TargetTags, got {policy['PolicyDetails']['TargetTags']!r}"
    assert policy["PolicyDetails"]["Schedules"][0]["Name"] == "sim2real-sched", (
        "expected untouched Schedules[0].Name sim2real-sched, got "
        f"{policy['PolicyDetails']['Schedules'][0]!r}"
    )


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
