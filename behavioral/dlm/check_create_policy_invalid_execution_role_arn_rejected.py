"""create-policy-invalid-execution-role-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-invalid-execution-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["dlm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLifecyclePolicy with an ExecutionRoleArn naming a user in another account fails with
    AccessDeniedException "Cross-account pass role is not allowed." and creates no policy, while a valid
    role creates one."""
    dlm = ctx.client("dlm")
    bad_role_arn = "arn:aws:iam::111122223333:user/not-a-role"
    rejected_description = ctx.unique_name("sim2real-dlm-desc-")
    policy_details = _snapshot_policy_details("sim2real-dlm-target", "bad-role-arn")

    def _attempt():
        resp = dlm.create_lifecycle_policy(
            ExecutionRoleArn=bad_role_arn,
            Description=rejected_description,
            State="ENABLED",
            PolicyDetails=policy_details,
        )
        # Register cleanup immediately: if an over-permissive target creates the
        # policy anyway, the assert below must not leak it.
        policy_id = resp["PolicyId"]
        ctx.on_cleanup(lambda pid=policy_id: dlm.delete_lifecycle_policy(PolicyId=pid))
        return resp

    code, message = _error(_attempt)
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException when ExecutionRoleArn is not a role ARN "
        f"the caller may pass, got {code!r}"
    )
    assert message == "Cross-account pass role is not allowed.", f"unexpected message: {message!r}"

    # Independent read: the rejected policy must not exist at the destination.
    surviving = [
        p["PolicyId"]
        for p in dlm.get_lifecycle_policies(
            ResourceTypes=["VOLUME"],
            TargetTags=["sim2real-dlm-target=bad-role-arn"],
        )["Policies"]
        if p.get("Description") == rejected_description
    ]
    assert not surviving, (
        f"expected no policy with description {rejected_description!r} to exist "
        f"after the rejected create, found {surviving}"
    )

    # Positive control: a real, correctly-formed IAM role succeeds.
    role_arn = _create_execution_role(ctx)
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "good-role-arn"),
        tags={"sim2real-dlm-check": CHECK},
    )
    fetched_id = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]["PolicyId"]
    assert fetched_id == policy_id, (
        f"expected get_lifecycle_policy to return PolicyId {policy_id!r}, got {fetched_id!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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
