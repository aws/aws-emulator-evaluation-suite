"""scheduler-cron-expression-fires-once-on-the-derived-minute-boundary."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-cron-expression-fires-once-on-the-derived-minute-boundary"
GROUP = "data-plane"
SERVICES = ["scheduler"]

# Lead time from "now" to the pinned minute: enough for IAM propagation and CreateSchedule to
# finish, so the boundary cannot elapse mid-creation.
_MIN_LEAD_S = 100
_LATE_SLACK_S = 90
_EARLY_SLACK_S = 5
_DELIVERY_TIMEOUT_S = 300
# Must stay ABOVE one minute: a target that ignores the cron fields and treats every expression as
# "fire every minute" would deliver again inside this window, which is exactly what it catches.
_QUIET_WINDOW_S = 90


# timing:real-time — schedule: 100 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A cron expression pinning a live-clock-derived minute fires once at that boundary: the
    reported scheduled-time equals it with second 0, SQS SentTimestamp brackets it, and nothing
    further arrives for longer than the one-minute cadence a cron-ignoring target would use.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
    """
    sch = ctx.client("scheduler")

    queue = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue["arn"])

    # Derived from the live clock AFTER provisioning, so IAM propagation cannot eat the lead.
    boundary = _next_minute_boundary_at_least(_MIN_LEAD_S)
    expression = (
        f"cron({boundary.minute} {boundary.hour} {boundary.day} {boundary.month} ? {boundary.year})"
    )

    marker = ctx.unique_name("cron-")
    name = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker, "at": "<aws.scheduler.scheduled-time>"}),
        },
    )

    described = sch.get_schedule(Name=name)
    assert described["ScheduleExpression"] == expression, (
        f"GetSchedule reports ScheduleExpression {described['ScheduleExpression']!r}, expected the "
        f"live-clock-derived expression {expression!r} unchanged"
    )

    body, sent_at = _await_marker(
        ctx,
        queue["url"],
        marker,
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=(
            f"the cron schedule {name} with expression {expression}, which pins the single instant "
            f"{boundary.isoformat()}"
        ),
    )

    reported = _parse_iso(body["at"])
    assert reported.tzinfo is not None, (
        f"<aws.scheduler.scheduled-time> was substituted without a timezone: {body['at']!r}"
    )
    assert reported == boundary, (
        f"the cron fields pin minute={boundary.minute} hour={boundary.hour} day={boundary.day} "
        f"month={boundary.month} year={boundary.year}, so the reported scheduled time must be "
        f"{boundary.isoformat()}; got {reported.isoformat()} (raw {body['at']!r})"
    )
    assert reported.second == 0 and reported.microsecond == 0, (
        f"a cron occurrence lands on the minute boundary, so the reported scheduled time must have "
        f"second 0; got {reported.isoformat()}"
    )

    early = (boundary - sent_at).total_seconds()
    late = (sent_at - boundary).total_seconds()
    assert early <= _EARLY_SLACK_S, (
        f"the message was stamped by SQS at {sent_at.isoformat()}, {early:.1f}s BEFORE the pinned "
        f"cron minute {boundary.isoformat()}; a Mode=OFF schedule cannot fire early"
    )
    assert late <= _LATE_SLACK_S, (
        f"the message was stamped by SQS at {sent_at.isoformat()}, {late:.1f}s after the pinned cron "
        f"minute {boundary.isoformat()}, beyond the {_LATE_SLACK_S}s delivery slack"
    )

    # Once-only: the expression pins a single year/month/day/hour/minute, so there is no second
    # occurrence. The window is longer than the 60s cadence a target that ignored the fields would
    # use, and the delivery just observed on this same wiring is its positive control.
    extra = _drain_marker(ctx, queue["url"], marker, window_s=_QUIET_WINDOW_S)
    assert extra == [], (
        f"the cron expression {expression} names one instant, but {len(extra)} further "
        f"invocation(s) arrived over the following {_QUIET_WINDOW_S}s, which is longer than the "
        f"one-minute cadence a target that ignored the fields would use: {extra!r}"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. The BOUNDED RETRY is the wait; the short sleep only
# makes it cheaper.
_ROLE_PROPAGATION_WAIT_S = 12
_CREATE_TIMEOUT_S = 180


def _next_minute_boundary_at_least(lead_s: int) -> datetime.datetime:
    """The first whole UTC minute at least `lead_s` seconds from now."""
    target = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=lead_s)
    return target.replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)


def _parse_iso(value: str) -> datetime.datetime:
    """Scheduler substitutes scheduled-time as an ISO 8601 UTC string ending in 'Z'."""
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-cron-q-"), tags=_MANAGED_TAGS
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
    time.sleep(_ROLE_PROPAGATION_WAIT_S)
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException; return its name."""
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


def _await_marker(ctx, queue_url: str, marker: str, *, timeout_s: float, description: str):
    """Poll until the JSON body carrying `marker` arrives; return (body, SQS SentTimestamp).

    SentTimestamp comes from SQS's clock, so timing measures delivery rather than polling.
    """
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageSystemAttributeNames=["SentTimestamp"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            raw = msg.get("Body", "")
            try:
                body = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                seen.append(raw)
                continue
            if isinstance(body, dict) and body.get("marker") == marker:
                sent_ms = int(msg["Attributes"]["SentTimestamp"])
                return body, datetime.datetime.fromtimestamp(
                    sent_ms / 1000.0, datetime.timezone.utc
                )
            seen.append(raw)
    raise AssertionError(
        f"{description}: nothing carrying {marker!r} arrived within {timeout_s}s. Bodies seen: "
        f"{seen!r}"
    )


def _drain_marker(ctx, queue_url: str, marker: str, *, window_s: float) -> list[str]:
    """Every body carrying `marker` seen over a bounded window."""
    sqs = ctx.client("sqs")
    hits: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            raw = msg.get("Body", "")
            if marker in raw:
                hits.append(raw)
    return hits


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
