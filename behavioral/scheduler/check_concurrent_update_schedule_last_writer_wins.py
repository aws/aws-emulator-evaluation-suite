"""concurrent-update-schedule-last-writer-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-schedule-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["scheduler"]

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateSchedule calls on the same schedule resolve
    deterministically to exactly one writer's FULL state -- never a mix of
    fields from both writers (UpdateSchedule is a full-replacement update)."""
    scheduler = ctx.client("scheduler")
    _, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])

    name = ctx.unique_name("sim2real-sched-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        Description="init",
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    writer_a = {
        "Name": name,
        "Description": "writer-A",
        "ScheduleExpression": "rate(3 minutes)",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "State": "ENABLED",
        "Target": {"Arn": queue_arn, "RoleArn": role_arn},
    }
    writer_b = {
        "Name": name,
        "Description": "writer-B",
        "ScheduleExpression": "rate(4 minutes)",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "State": "DISABLED",
        "Target": {"Arn": queue_arn, "RoleArn": role_arn},
    }

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(scheduler.update_schedule, **writer_a)
        fut_b = pool.submit(scheduler.update_schedule, **writer_b)
        fut_a.result()
        fut_b.result()

    final = scheduler.get_schedule(Name=name)
    final_tuple = (final["Description"], final["ScheduleExpression"], final["State"])
    tuple_a = (writer_a["Description"], writer_a["ScheduleExpression"], writer_a["State"])
    tuple_b = (writer_b["Description"], writer_b["ScheduleExpression"], writer_b["State"])

    assert final_tuple in (tuple_a, tuple_b), (
        f"final state {final_tuple} does not fully match either writer "
        f"({tuple_a} or {tuple_b}) -- field-level corruption from concurrent updates"
    )


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=dict(_MANAGED_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_scheduler_role(ctx, allowed_queue_arns):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": list(allowed_queue_arns)}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    """IAM role trust is eventually consistent; retry CreateSchedule briefly."""
    last_exc = None
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
