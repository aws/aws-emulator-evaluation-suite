"""get-lifecycle-policies-filter-by-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-lifecycle-policies-filter-by-state"
GROUP = "filtering"
SERVICES = ["dlm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLifecyclePolicies with a State filter returns a named policy only when its State matches, even when
    it is named in PolicyIds (one id per call, as AWS honors only the last of several)."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    enabled_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "state-filter-enabled"),
        tags={"sim2real:managed": "true"},
    )
    disabled_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="DISABLED",
        policy_details=_snapshot_policy_details("sim2real-dlm-target", "state-filter-disabled"),
        tags={"sim2real:managed": "true"},
    )

    # The enabled policy matches an ENABLED-state filter naming it directly.
    matched = dlm.get_lifecycle_policies(PolicyIds=[enabled_id], State="ENABLED")["Policies"]
    matched_ids = {p["PolicyId"] for p in matched}
    assert matched_ids == {enabled_id}, f"n_matched={len(matched_ids)}"

    # The disabled policy does NOT match an ENABLED-state filter, even though it is named
    # directly by PolicyIds -- the State filter excludes it.
    excluded = dlm.get_lifecycle_policies(PolicyIds=[disabled_id], State="ENABLED")["Policies"]
    excluded_ids = {p["PolicyId"] for p in excluded}
    assert disabled_id not in excluded_ids, f"n_excluded={len(excluded_ids)}"

    # And the disabled policy DOES match a DISABLED-state filter on the same id.
    confirmed = dlm.get_lifecycle_policies(PolicyIds=[disabled_id], State="DISABLED")["Policies"]
    confirmed_ids = {p["PolicyId"] for p in confirmed}
    assert confirmed_ids == {disabled_id}, f"n_confirmed={len(confirmed_ids)}"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
