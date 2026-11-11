"""get-lifecycle-policy-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-lifecycle-policy-not-found"
GROUP = "error-semantics"
SERVICES = ["dlm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Get, Update and DeleteLifecyclePolicy on a deleted policy's id fail with ResourceNotFoundException
    "The resource {<id>} was not found.", while a live policy still reads back."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)

    # Obtain a validly-formatted PolicyId that is guaranteed not to exist.
    gone_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "not-found-gone"),
        tags={"sim2real": CHECK},
        register_cleanup=False,
    )
    dlm.delete_lifecycle_policy(PolicyId=gone_id)

    not_found_message = f"The resource {{{gone_id}}} was not found."
    err = _client_error(lambda: dlm.get_lifecycle_policy(PolicyId=gone_id))
    assert err["Code"] == "ResourceNotFoundException", f"code={err['Code']!r}"
    assert err.get("Message") == not_found_message, f"message={err.get('Message')!r}"

    # Update and a repeat Delete answer the same PolicyId-not-found error.
    update_err = _client_error(
        lambda: dlm.update_lifecycle_policy(PolicyId=gone_id, State="DISABLED")
    )
    assert update_err["Code"] == "ResourceNotFoundException", f"update_code={update_err['Code']!r}"
    assert update_err.get("Message") == not_found_message, (
        f"update_message={update_err.get('Message')!r}"
    )

    delete_err = _client_error(lambda: dlm.delete_lifecycle_policy(PolicyId=gone_id))
    assert delete_err["Code"] == "ResourceNotFoundException", f"delete_code={delete_err['Code']!r}"
    assert delete_err.get("Message") == not_found_message, (
        f"delete_message={delete_err.get('Message')!r}"
    )

    # Positive control: a real, live policy is retrievable without error.
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "not-found-control"),
        tags={"sim2real": CHECK},
    )
    policy = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]
    assert policy["PolicyId"] == policy_id, f"policy_id={policy['PolicyId']!r}"


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


def _create_lifecycle_policy(
    ctx, dlm, *, role_arn, description, state, policy_details, tags=None, register_cleanup=True
):
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
            if register_cleanup:
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
