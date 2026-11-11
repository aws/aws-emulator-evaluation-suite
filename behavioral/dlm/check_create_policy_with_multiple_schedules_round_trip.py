"""create-policy-with-multiple-schedules-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-policy-with-multiple-schedules-round-trip"
GROUP = "state"
SERVICES = ["dlm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy created with two distinct Schedules (a policy can have up to four) persists both,
    in order, with their own CreateRule/RetainRule settings intact -- not collapsed into one."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    policy_details = {
        "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
        "ResourceTypes": ["VOLUME"],
        "TargetTags": [{"Key": "sim2real-dlm-target", "Value": "multi-schedule-check"}],
        "Schedules": [
            {
                "Name": "sim2real-sched-daily",
                "CreateRule": {"Interval": 12, "IntervalUnit": "HOURS", "Times": ["03:00"]},
                "RetainRule": {"Count": 2},
            },
            {
                "Name": "sim2real-sched-weekly",
                "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["04:00"]},
                "RetainRule": {"Count": 5},
            },
        ],
    }
    policy_id = _create_lifecycle_policy(
        ctx,
        dlm,
        role_arn=role_arn,
        description=ctx.unique_name("sim2real-dlm-desc-"),
        state="ENABLED",
        policy_details=policy_details,
        tags={"sim2real-managed": "true"},
    )
    stored_schedules = dlm.get_lifecycle_policy(PolicyId=policy_id)["Policy"]["PolicyDetails"][
        "Schedules"
    ]
    assert len(stored_schedules) == 2, (
        f"expected 2 stored schedules, got {len(stored_schedules)}: {stored_schedules!r}"
    )
    assert stored_schedules[0]["Name"] == "sim2real-sched-daily", (
        f"expected schedule 0 name 'sim2real-sched-daily', got {stored_schedules[0]['Name']!r}"
    )
    assert stored_schedules[0]["CreateRule"]["Interval"] == 12, (
        f"expected schedule 0 interval 12, got {stored_schedules[0]['CreateRule']['Interval']!r}"
    )
    assert stored_schedules[0]["RetainRule"]["Count"] == 2, (
        f"expected schedule 0 retain count 2, got {stored_schedules[0]['RetainRule']['Count']!r}"
    )
    assert stored_schedules[1]["Name"] == "sim2real-sched-weekly", (
        f"expected schedule 1 name 'sim2real-sched-weekly', got {stored_schedules[1]['Name']!r}"
    )
    assert stored_schedules[1]["CreateRule"]["Interval"] == 24, (
        f"expected schedule 1 interval 24, got {stored_schedules[1]['CreateRule']['Interval']!r}"
    )
    assert stored_schedules[1]["RetainRule"]["Count"] == 5, (
        f"expected schedule 1 retain count 5, got {stored_schedules[1]['RetainRule']['Count']!r}"
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
        Tags=[{"Key": "sim2real-managed", "Value": "true"}],
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
