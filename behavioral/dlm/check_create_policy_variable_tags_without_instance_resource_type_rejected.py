"""create-policy-variable-tags-without-instance-resource-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-variable-tags-without-instance-resource-type-rejected"
GROUP = "error-semantics"
SERVICES = ["dlm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLifecyclePolicy refuses a Schedule.VariableTags entry when ResourceTypes is VOLUME
    rather than INSTANCE, and the identical VariableTags entry is accepted and read back once
    ResourceTypes is INSTANCE."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    target_key = ctx.unique_name("sim2real-dlm-vtr-target-")

    rejected_kwargs = dict(
        ExecutionRoleArn=role_arn,
        Description=ctx.unique_name("sim2real-dlm-desc-"),
        State="ENABLED",
        PolicyDetails=_policy_details(["VOLUME"], target_key),
        Tags={"sim2real": CHECK},
    )
    err = _client_error(lambda: dlm.create_lifecycle_policy(**rejected_kwargs))
    assert err["Code"] == "InvalidRequestException", f"code={err['Code']!r}"
    assert err.get("Message") == (
        "The following parameter(s) are invalid for Resource Type {VOLUME}: VariableTags"
    ), f"message={err.get('Message')!r}"

    # Positive control: the identical VariableTags entry is accepted for ResourceTypes=INSTANCE.
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_policy_details(["INSTANCE"], target_key),
        tags={"sim2real": CHECK},
    )
    policy = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]
    schedule = policy["PolicyDetails"]["Schedules"][0]
    assert schedule["VariableTags"] == [{"Key": "sim2real-dlm-vt", "Value": "$(instance-id)"}], (
        f"variable_tags={schedule.get('VariableTags')!r}"
    )


# ===== helpers =====


def _policy_details(resource_types, target_key, schedule_name="sim2real-sched"):
    return {
        "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
        "ResourceTypes": resource_types,
        "TargetTags": [{"Key": target_key, "Value": "variable-tags-check"}],
        "Schedules": [
            {
                "Name": schedule_name,
                "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
                "RetainRule": {"Count": 1},
                "VariableTags": [{"Key": "sim2real-dlm-vt", "Value": "$(instance-id)"}],
            }
        ],
    }


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
