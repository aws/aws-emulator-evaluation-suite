"""delete-lifecycle-policy-removes-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-lifecycle-policy-removes-policy"
GROUP = "state"
SERVICES = ["dlm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLifecyclePolicy removes the policy so it is no longer retrievable by
    GetLifecyclePolicy, and a subsequent mutation on the same (now-dead) PolicyId is
    also rejected rather than silently accepted."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "delete-check"),
        tags={"sim2real-check": CHECK},
        register_cleanup=False,
    )
    # Confirm it exists before deleting.
    fetched_id = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]["PolicyId"]
    assert fetched_id == policy_id, f"expected pre-delete GetLifecyclePolicy to echo {policy_id!r}, got {fetched_id!r}"

    dlm.delete_lifecycle_policy(PolicyId=policy_id)

    not_found_message = f"The resource {{{policy_id}}} was not found."
    update_err = _client_error(lambda: dlm.update_lifecycle_policy(PolicyId=policy_id, State="DISABLED"))
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected UpdateLifecyclePolicy on the deleted policy to raise ResourceNotFoundException, got {update_err['Code']!r}"
    )
    assert update_err.get("Message") == not_found_message, (
        f"expected UpdateLifecyclePolicy message {not_found_message!r}, got {update_err.get('Message')!r}"
    )

    # Terminal assertion: an independent read (not the delete or update call above) confirms gone.
    get_err = _client_error(lambda: dlm.get_lifecycle_policy(PolicyId=policy_id))
    assert get_err["Code"] == "ResourceNotFoundException", (
        f"expected GetLifecyclePolicy on the deleted policy to raise ResourceNotFoundException, got {get_err['Code']!r}"
    )
    assert get_err.get("Message") == not_found_message, (
        f"expected GetLifecyclePolicy message {not_found_message!r}, got {get_err.get('Message')!r}"
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
