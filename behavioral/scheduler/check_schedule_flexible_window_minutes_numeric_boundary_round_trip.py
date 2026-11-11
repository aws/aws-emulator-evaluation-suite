"""schedule-flexible-window-minutes-numeric-boundary-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-flexible-window-minutes-numeric-boundary-round-trip"
GROUP = "representation"
SERVICES = ["scheduler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaximumWindowInMinutes at its documented boundaries (1 and 1440) round-trips exactly."""
    scheduler = ctx.client("scheduler")

    queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)

    schedule_name = ctx.unique_name("sim2real-sched-")
    common_kwargs = dict(
        Name=schedule_name,
        ScheduleExpression="rate(1 day)",
        State="DISABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "unused"},
    )

    _create_schedule_with_retry(
        scheduler,
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1},
        **common_kwargs,
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))

    fetched = scheduler.get_schedule(Name=schedule_name)
    lower = fetched["FlexibleTimeWindow"]["MaximumWindowInMinutes"]
    assert lower == 1, f"expected MaximumWindowInMinutes == 1 (lower boundary), got {lower!r}"
    assert isinstance(lower, int), f"expected MaximumWindowInMinutes to round-trip as int, got {type(lower).__name__} ({lower!r})"

    scheduler.update_schedule(
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 1440},
        **common_kwargs,
    )

    fetched = scheduler.get_schedule(Name=schedule_name)
    upper = fetched["FlexibleTimeWindow"]["MaximumWindowInMinutes"]
    assert upper == 1440, f"expected MaximumWindowInMinutes == 1440 (upper boundary), got {upper!r}"
    assert isinstance(upper, int), f"expected MaximumWindowInMinutes to round-trip as int, got {type(upper).__name__} ({upper!r})"


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real": CHECK})["QueueUrl"]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
