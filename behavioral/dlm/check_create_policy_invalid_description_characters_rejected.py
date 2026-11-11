"""create-policy-invalid-description-characters-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-invalid-description-characters-rejected"
GROUP = "overly-permissive"
SERVICES = ["dlm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLifecyclePolicy rejects a Description containing characters outside
    [0-9A-Za-z _-] with InvalidRequestException, and no policy is created; a Description using
    only allowed characters in the same file succeeds as the positive control."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    target_key, target_value = "sim2real-dlm-target", "bad-description"
    policy_details = _snapshot_policy_details(target_key, target_value)

    def _attempt():
        resp = dlm.create_lifecycle_policy(
            ExecutionRoleArn=role_arn,
            Description="invalid!description#chars",
            State="ENABLED",
            PolicyDetails=policy_details,
        )
        policy_id = resp["PolicyId"]
        ctx.on_cleanup(lambda: dlm.delete_lifecycle_policy(PolicyId=policy_id))

    err = _client_error(_attempt)
    assert err["Code"] == "InvalidRequestException", (
        f"expected CreateLifecyclePolicy to reject a Description with disallowed characters "
        f"with InvalidRequestException, got {err['Code']!r}"
    )
    expected_message = (
        "The following parameter(s) are invalid: Description {invalid!description#chars}"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Independent read: no policy carrying this run's target tag exists, i.e. the rejected
    # create had no effect. This is a real GetLifecyclePolicies call, not local state.
    # GetLifecyclePolicies.TargetTags is "key=value" strings, unlike CreateLifecyclePolicy's
    # Tags/TargetTags dict shape.
    tag_filter = f"{target_key}={target_value}"
    survivors = dlm.get_lifecycle_policies(TargetTags=[tag_filter])["Policies"]
    assert not survivors, (
        f"expected GetLifecyclePolicies(TargetTags=[{tag_filter!r}]) to return no policies "
        f"after the rejected create, found {survivors!r}"
    )

    # Positive control: an allowed-character description succeeds.
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-valid-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "good-description"),
    )
    fetched_id = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]["PolicyId"]
    assert fetched_id == policy_id, (
        f"expected GetLifecyclePolicy({policy_id!r}) to return the same PolicyId, got {fetched_id!r}"
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
