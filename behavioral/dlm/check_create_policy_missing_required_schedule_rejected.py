"""create-policy-missing-required-schedule-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-missing-required-schedule-rejected"
GROUP = "overly-permissive"
SERVICES = ["dlm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLifecyclePolicy for a custom EBS_SNAPSHOT_MANAGEMENT policy without Schedules fails with
    InvalidRequestException and its exact message and creates no policy, while one with a schedule succeeds."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)

    incomplete_details = {
        "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
        "ResourceTypes": ["VOLUME"],
        "TargetTags": [{"Key": "sim2real-dlm-target", "Value": "missing-schedule"}],
        # Schedules intentionally omitted.
    }
    rejected_description = ctx.unique_name("sim2real-dlm-desc-")

    def _attempt():
        resp = dlm.create_lifecycle_policy(
            ExecutionRoleArn=role_arn,
            Description=rejected_description,
            State="ENABLED",
            PolicyDetails=incomplete_details,
        )
        # Register cleanup immediately: if an over-permissive target creates the
        # policy anyway, the assert below must not leak it.
        policy_id = resp["PolicyId"]
        ctx.on_cleanup(lambda pid=policy_id: dlm.delete_lifecycle_policy(PolicyId=pid))

    err = _client_error(_attempt)
    assert err["Code"] == "InvalidRequestException", (
        f"expected InvalidRequestException when Schedules is omitted from an "
        f"EBS_SNAPSHOT_MANAGEMENT policy, got {err['Code']!r}"
    )
    expected_message = "The following required parameter(s) are missing: {Schedules}"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Independent read: the rejected policy must not exist at the destination.
    surviving = [
        p["PolicyId"]
        for p in dlm.get_lifecycle_policies(
            ResourceTypes=["VOLUME"],
            TargetTags=["sim2real-dlm-target=missing-schedule"],
        )["Policies"]
        if p.get("Description") == rejected_description
    ]
    assert not surviving, (
        f"expected no policy with description {rejected_description!r} to exist "
        f"after the rejected create, found {surviving}"
    )

    # Positive control: the same policy with a valid schedule succeeds.
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "has-schedule"),
        tags={"sim2real-dlm-check": CHECK},
    )
    fetched_id = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]["PolicyId"]
    assert fetched_id == policy_id, (
        f"expected get_lifecycle_policy to return PolicyId {policy_id!r}, got {fetched_id!r}"
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
