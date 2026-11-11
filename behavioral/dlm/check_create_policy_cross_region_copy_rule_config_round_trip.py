"""create-policy-cross-region-copy-rule-config-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-cross-region-copy-rule-config-round-trip"
GROUP = "state"
SERVICES = ["dlm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CrossRegionCopyRule nested inside a schedule is persisted faithfully: the target region,
    encryption flag, and retention settings all round-trip exactly through GetLifecyclePolicy."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    # A cross-region copy needs an actual second region distinct from ctx.region; there is no way
    # to derive "some other region" from the account, so the literal is the destination itself.
    target_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    policy_details = {
        "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
        "ResourceTypes": ["VOLUME"],
        "TargetTags": [{"Key": "sim2real-dlm-target", "Value": "cross-region-check"}],
        "Schedules": [
            {
                "Name": "sim2real-cross-region-sched",
                "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
                "RetainRule": {"Count": 1},
                "CrossRegionCopyRules": [
                    {
                        "Target": target_region,
                        "Encrypted": False,
                        "RetainRule": {"Interval": 7, "IntervalUnit": "DAYS"},
                    }
                ],
            }
        ],
    }
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=policy_details,
        tags={"sim2real": CHECK},
    )
    stored_schedule = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]["PolicyDetails"][
        "Schedules"
    ][0]
    stored_rule = stored_schedule["CrossRegionCopyRules"][0]
    assert stored_rule["Target"] == target_region, (
        f"expected CrossRegionCopyRule.Target={target_region!r}, got {stored_rule.get('Target')!r}"
    )
    assert stored_rule["Encrypted"] is False, (
        f"expected CrossRegionCopyRule.Encrypted=False, got {stored_rule.get('Encrypted')!r}"
    )
    expected_retain_rule = {"Interval": 7, "IntervalUnit": "DAYS"}
    assert stored_rule["RetainRule"] == expected_retain_rule, (
        f"expected CrossRegionCopyRule.RetainRule={expected_retain_rule!r}, "
        f"got {stored_rule.get('RetainRule')!r}"
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
