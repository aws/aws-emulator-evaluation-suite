"""tag-resource-reserved-aws-prefix-key-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["dlm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with an "aws:" key fails with BadRequestException and its exact message and attaches nothing,
    while a normal tag on the same policy is attached."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "reserved-tag-check"),
    )
    policy_arn = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]["PolicyArn"]

    err = _client_error(
        lambda: dlm.tag_resource(ResourceArn=policy_arn, Tags={"aws:reserved": "nope"})
    )
    assert err["Code"] == "BadRequestException", f"code={err['Code']!r}"
    expected_message = (
        "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)"
    )
    assert err.get("Message") == expected_message, f"message={err.get('Message')!r}"

    tags_after_failure = dlm.list_tags_for_resource(ResourceArn=policy_arn)["Tags"]
    assert "aws:reserved" not in tags_after_failure, (
        f"rejected tag key was attached anyway: tags={tags_after_failure!r}"
    )

    # Positive control: a normal tag key on the same policy succeeds.
    dlm.tag_resource(ResourceArn=policy_arn, Tags={"sim2real-normal-tag": "yes"})
    tags_after_success = dlm.list_tags_for_resource(ResourceArn=policy_arn)["Tags"]
    assert tags_after_success.get("sim2real-normal-tag") == "yes", (
        f"expected normal tag to be attached, got tags={tags_after_success!r}"
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
