"""schedule-target-input-base64-blob-round-trip."""
from __future__ import annotations

import base64
import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-target-input-base64-blob-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Target Input containing base64-encoded binary survives create/get byte-for-byte."""
    scheduler = ctx.client("scheduler")

    queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)

    blob = base64.b64encode(os.urandom(256)).decode("ascii")
    payload = json.dumps({"marker": ctx.unique_name("blob-"), "blob": blob})

    schedule_name = ctx.unique_name("sim2real-sched-")
    _create_schedule_with_retry(
        scheduler,
        Name=schedule_name,
        ScheduleExpression="rate(1 day)",
        State="DISABLED",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": payload},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))

    fetched = scheduler.get_schedule(Name=schedule_name)
    fetched_input = fetched["Target"]["Input"]
    assert fetched_input == payload, f"expected Target.Input {payload!r}, got {fetched_input!r}"
    fetched_blob = json.loads(fetched_input)["blob"]
    assert fetched_blob == blob, f"expected round-tripped blob {blob!r}, got {fetched_blob!r}"


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_scheduler_role(ctx, queue_arn):
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
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_with_retry(scheduler, retries=10, delay=3, **kwargs):
    last_exc = None
    for _ in range(retries):
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
