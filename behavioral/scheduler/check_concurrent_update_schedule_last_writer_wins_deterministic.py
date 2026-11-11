"""concurrent-update-schedule-last-writer-wins-deterministic."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-schedule-last-writer-wins-deterministic"
GROUP = "concurrency"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent full-replace UpdateSchedule calls both succeed, and the final GetSchedule
    matches exactly one submitted Description/Target.Input pair, never a mix of both."""
    scheduler = ctx.client("scheduler")

    target = _create_sqs_queue(ctx, "sim2real-behav-concur-tgt-")
    role_arn = _create_scheduler_role(
        ctx,
        "sim2real-behav-concur-role-",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": target["arn"]}],
    )

    schedule_name = ctx.unique_name("sim2real-behav-concur-sched-")
    base_target = {"Arn": target["arn"], "RoleArn": role_arn}

    _create_schedule_retrying(
        scheduler,
        Name=schedule_name,
        ScheduleExpression="rate(1 day)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Description="initial",
        Target={**base_target, "Input": "initial-payload"},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))

    payloads = {
        "payload-A": "input-A",
        "payload-B": "input-B",
    }

    def _update(description: str, target_input: str):
        return scheduler.update_schedule(
            Name=schedule_name,
            ScheduleExpression="rate(1 day)",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Description=description,
            Target={**base_target, "Input": target_input},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, desc, inp) for desc, inp in payloads.items()]
        results = []
        for fut in futures:
            try:
                results.append(("ok", fut.result()))
            except Exception as exc:  # noqa: BLE001 - a losing writer may legitimately conflict
                results.append(("error", exc))

    successes = [r for kind, r in results if kind == "ok"]
    assert len(successes) == 2, (
        f"expected both concurrent UpdateSchedule calls to succeed (full-replacement update has "
        f"no optimistic-lock/version field to conflict on): {results}"
    )

    final = scheduler.get_schedule(Name=schedule_name)
    final_description = final["Description"]
    final_input = final["Target"]["Input"]

    assert final_description in payloads, f"unexpected final Description {final_description!r}"
    assert final_input == payloads[final_description], (
        f"final state mixes fields from both payloads: Description={final_description!r} "
        f"paired with Target.Input={final_input!r}, expected {payloads[final_description]!r}"
    )


def _create_sqs_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn, "name": name}


def _create_scheduler_role(ctx, prefix: str, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name(prefix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_schedule_retrying(scheduler, max_wait_s: float = 60.0, interval_s: float = 3.0, **kwargs):
    """IAM role/policy propagation to Scheduler's trust-policy assumability check can lag
    CreateRole/PutRolePolicy by tens of seconds; retry the bounded window instead of sleeping
    blind."""
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
