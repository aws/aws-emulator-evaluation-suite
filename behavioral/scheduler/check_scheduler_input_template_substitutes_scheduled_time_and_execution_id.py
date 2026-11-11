"""scheduler-input-template-substitutes-scheduled-time-and-execution-id."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-input-template-substitutes-scheduled-time-and-execution-id"
GROUP = 'data-plane'
SERVICES = ['scheduler']

# Two occurrences of a rate(1 minute) schedule, whose first occurrence can be a full period out.
_DELIVERY_TIMEOUT_S = 360

_TOKENS = {
    "at": "<aws.scheduler.scheduled-time>",
    "exec": "<aws.scheduler.execution-id>",
    "arn": "<aws.scheduler.schedule-arn>",
    "attempt": "<aws.scheduler.attempt-number>",
}


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Scheduler substitutes its reserved Input tokens at invocation: scheduled-time is a zoned
    ISO-8601 instant, execution-id differs per invocation, schedule-arn is the schedule's ARN and
    attempt-number is the attempt; the stored Input keeps the literal tokens.
    """
    sch = ctx.client("scheduler")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue_arn)

    marker = ctx.unique_name("marker-")
    payload = dict(_TOKENS, marker=marker)
    name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": json.dumps(payload)},
    )
    schedule_arn = sch.get_schedule(Name=name)["Arn"]

    stored_input = sch.get_schedule(Name=name)["Target"]["Input"]
    assert _TOKENS["exec"] in stored_input, (
        f"GetSchedule pre-substituted the stored Input, which it must not -- the template is "
        f"expanded at invocation time only: {stored_input!r}"
    )

    deliveries = _collect_bodies(
        ctx,
        queue_url,
        lambda b: b.get("marker") == marker,
        want=2,
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=f"two templated invocations of {name}",
    )
    first, second = deliveries[0], deliveries[1]

    at = _parse_iso(first["at"])
    assert at.tzinfo is not None, (
        f"<aws.scheduler.scheduled-time> is not a timezone-aware ISO-8601 instant: "
        f"{first['at']!r}"
    )
    assert first["arn"] == schedule_arn, (
        f"<aws.scheduler.schedule-arn> was substituted with {first['arn']!r}, expected the "
        f"schedule's own ARN {schedule_arn!r}"
    )
    assert first["exec"] != second["exec"], (
        f"two separate invocations shared an <aws.scheduler.execution-id>: {first['exec']!r}"
    )
    assert first["attempt"] == "1", (
        f"the first delivery attempt of a target that accepts the message must be attempt 1, "
        f"got {first['attempt']!r}"
    )
    for body in deliveries:
        assert "<aws.scheduler" not in json.dumps(body), (
            f"a reserved template token was delivered unsubstituted: {body!r}"
        )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. _create_schedule's BOUNDED RETRY is the wait.
_CREATE_TIMEOUT_S = 180


def _parse_iso(value: str) -> datetime.datetime:
    """Parse the scheduled-time Scheduler substitutes, e.g. 'YYYY-MM-DDTHH:MM:SSZ'."""
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


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


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound.

    The cleanup is registered from the name passed to the accepted call -- never re-looked-up.
    """
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name, kwargs.get("GroupName")))
    return name


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _collect_bodies(ctx, queue_url, predicate, *, want, timeout_s, description):
    """Poll SQS until `want` DISTINCT matching JSON bodies have arrived, oldest first."""
    sqs = ctx.client("sqs")
    found: list[dict] = []
    seen_keys: set[str] = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(found) < want:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(body, dict) or not predicate(body):
                continue
            key = json.dumps(body, sort_keys=True)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            found.append(body)
    if len(found) < want:
        raise AssertionError(
            f"{description}: only {len(found)} of {want} arrived within {timeout_s}s. "
            f"Bodies seen: {found!r}"
        )
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
