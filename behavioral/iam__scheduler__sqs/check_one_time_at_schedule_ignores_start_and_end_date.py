"""one-time-at-schedule-ignores-start-and-end-date."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "one-time-at-schedule-ignores-start-and-end-date"
GROUP = "schedule-expressions"
SERVICES = ["iam", "scheduler", "sqs"]

_FIRE_OFFSET_S = 90
_END_OFFSET_S = 30
_DELIVERY_TIMEOUT_S = 240
_CREATE_TIMEOUT_S = 150

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A one-time at() schedule whose EndDate elapses before its own nominal fire instant is
    created and still fires at that instant: EventBridge Scheduler ignores EndDate
    for a one-time schedule's own occurrence, which the EndDate only bounds for a recurring one.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
    """
    queue = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue["arn"])
    marker = ctx.unique_name("marker-")

    name, nominal, end_date = _create_at_schedule(
        ctx,
        fire_offset_s=_FIRE_OFFSET_S,
        end_offset_s=_END_OFFSET_S,
        target=_target(queue["arn"], role_arn, marker),
    )
    assert end_date < nominal, (
        f"the test setup is invalid: EndDate {end_date.isoformat()} must precede the nominal fire "
        f"instant {nominal.isoformat()} to prove EndDate is ignored"
    )

    got = ctx.client("scheduler").get_schedule(Name=name)
    assert got["State"] == "ENABLED", (
        f"the accepted at() schedule with an EndDate before its own fire instant reports State "
        f"{got['State']!r}, expected ENABLED"
    )

    seen: list[dict] = []
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline and not seen:
        _drain_into(ctx, queue["url"], marker, seen)
    assert seen, (
        f"the at() schedule {name}, whose EndDate ({end_date.isoformat()}) elapses before its "
        f"nominal fire instant ({nominal.isoformat()}), delivered nothing within "
        f"{_DELIVERY_TIMEOUT_S}s"
    )
    assert len(seen) == 1, (
        f"the one-time schedule {name} delivered {len(seen)} times, expected exactly one"
    )


def _target(queue_arn: str, role_arn: str, marker: str) -> dict:
    return {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps({"marker": marker}),
    }


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-atendq-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _scheduler_role(ctx, queue_arn: str) -> str:
    """An IAM role EventBridge Scheduler can assume, permitted to send to exactly this queue."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
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
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduler-target",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        ),
    )
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_at_schedule(ctx, *, fire_offset_s: int, end_offset_s: int, target: dict):
    """Create a one-time at() schedule, re-anchoring the fire instant and EndDate to each
    attempt's own clock, so an IAM-propagation retry cannot push the fire instant into the past.
    Only the role-propagation ValidationException is retried; any other refusal raises immediately.
    Returns (name, nominal fire instant, EndDate).
    """
    sch = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-behav-sched-atend-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        nominal = now + datetime.timedelta(seconds=fire_offset_s)
        end_date = now + datetime.timedelta(seconds=end_offset_s)
        try:
            sch.create_schedule(
                Name=name,
                ScheduleExpression=f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="ENABLED",
                EndDate=end_date,
                Target=target,
            )
            break
        except ClientError as exc:
            last = exc
            err = exc.response.get("Error", {})
            if err.get("Code") != "ValidationException" or "role" not in err.get("Message", "").lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return name, nominal, end_date


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _drain_into(ctx, queue_url: str, marker: str, seen: list[dict]) -> None:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        try:
            body = json.loads(msg.get("Body", ""))
        except ValueError:
            continue
        if isinstance(body, dict) and body.get("marker") == marker:
            seen.append(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
