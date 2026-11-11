"""concurrent-policy-creation-unique-ids."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-policy-creation-unique-ids"
GROUP = "concurrency"
SERVICES = ["dlm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateLifecyclePolicy calls return a distinct PolicyId per call, each readable via
    GetLifecyclePolicy (read per id, as GetLifecyclePolicies honors only the last of several PolicyIds)."""
    dlm = ctx.client("dlm")
    role_arn = _create_execution_role(ctx)
    racer_count = 5

    def _racer(i):
        return _create_lifecycle_policy(
            ctx,
            dlm,
            role_arn=role_arn,
            description=ctx.unique_name(f"sim2real-dlm-race-{i}-"),
            state="ENABLED",
            policy_details=_snapshot_policy_details("sim2real-dlm-target", f"race-{i}"),
        )

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        policy_ids = list(pool.map(_racer, range(racer_count)))

    assert len(policy_ids) == racer_count, f"expected={racer_count} got={len(policy_ids)}"
    assert len(set(policy_ids)) == racer_count, (
        f"expected {racer_count} distinct PolicyIds, got {len(set(policy_ids))}: {policy_ids}"
    )

    fetched_ids = {
        dlm.get_lifecycle_policy(PolicyId=pid)["Policy"]["PolicyId"] for pid in policy_ids
    }
    assert fetched_ids == set(policy_ids), f"n_fetched={len(fetched_ids)} n_wanted={len(policy_ids)}"


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
