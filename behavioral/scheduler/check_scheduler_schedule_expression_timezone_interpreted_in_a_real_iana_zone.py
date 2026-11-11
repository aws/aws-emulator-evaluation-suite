"""scheduler-schedule-expression-timezone-interpreted-in-a-real-iana-zone."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-schedule-expression-timezone-interpreted-in-a-real-iana-zone"
GROUP = "data-plane"
SERVICES = ["scheduler"]

# Half-hour offset, east of UTC (misreading the literal as UTC schedules it 5h30m in the future
# rather than rejecting it as past-dated), and DST-free so the expected offset is constant and the
# expectation needs no runner tzdata.
_ZONE_NAME = "Asia/Kolkata"
_ZONE_OFFSET = datetime.timedelta(hours=5, minutes=30)

_FIRE_OFFSET_S = 20
_LATE_SLACK_S = 90
_EARLY_SLACK_S = 5
_DELIVERY_TIMEOUT_S = 300


# timing:real-time — schedule: 20 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An at() literal in Asia/Kolkata wall-clock time fires at the UTC instant it denotes there,
    checked against a UTC-expressed twin due at the same instant on the same queue and role.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
    """
    sch = ctx.client("scheduler")

    zone = datetime.timezone(_ZONE_OFFSET, _ZONE_NAME)
    queue = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue["arn"])
    _await_role_assumable(ctx, queue["arn"], role_arn)

    # Anchor the instant AFTER provisioning: IAM propagation can hold CreateSchedule off, and an
    # at() instant computed before that could already be in the past when the call is accepted.
    nominal = datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(seconds=_FIRE_OFFSET_S)
    local = nominal.astimezone(zone)

    zoned_expression = f"at({local.strftime('%Y-%m-%dT%H:%M:%S')})"
    utc_expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"

    zoned_marker = ctx.unique_name("kolkata-")
    utc_marker = ctx.unique_name("utc-")
    zoned_name = _create_schedule(
        ctx,
        ScheduleExpression=zoned_expression,
        ScheduleExpressionTimezone=_ZONE_NAME,
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": zoned_marker, "at": "<aws.scheduler.scheduled-time>"}),
        },
    )
    utc_name = _create_schedule(
        ctx,
        ScheduleExpression=utc_expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": utc_marker, "at": "<aws.scheduler.scheduled-time>"}),
        },
    )

    described = sch.get_schedule(Name=zoned_name)
    assert described["ScheduleExpressionTimezone"] == _ZONE_NAME, (
        f"GetSchedule reports ScheduleExpressionTimezone "
        f"{described['ScheduleExpressionTimezone']!r}, expected {_ZONE_NAME!r}"
    )
    assert described["ScheduleExpression"] == zoned_expression, (
        f"GetSchedule reports ScheduleExpression {described['ScheduleExpression']!r}, expected the "
        f"local wall-clock literal {zoned_expression!r} unchanged (Scheduler must not rewrite the "
        f"expression into UTC on the way in)"
    )

    delivery_bound_s = _budget_s(ctx, _DELIVERY_TIMEOUT_S)
    arrivals = _collect_markers(
        ctx,
        queue["url"],
        {zoned_marker, utc_marker},
        timeout_s=delivery_bound_s,
        description=(
            f"the {_ZONE_NAME}-expressed schedule {zoned_name} ({zoned_expression}) and its "
            f"UTC-expressed twin {utc_name} ({utc_expression}), both denoting "
            f"{nominal.isoformat()}"
        ),
    )

    if set(arrivals) != {zoned_marker, utc_marker} and _budget_spent(ctx):
        raise TimeoutError("both schedules' deliveries: the run budget ended first; not graded")
    assert utc_marker in arrivals, (
        f"the UTC-expressed twin due at {nominal.isoformat()} never delivered within "
        f"{delivery_bound_s:.0f}s, so nothing can be attributed to the timezone: saw "
        f"{sorted(arrivals)!r}"
    )
    assert zoned_marker in arrivals, (
        f"the schedule expressed as {zoned_expression} in {_ZONE_NAME} (= {nominal.isoformat()} "
        f"UTC) never delivered within {delivery_bound_s:.0f}s while its UTC twin due at the same "
        f"absolute instant did: ScheduleExpressionTimezone was ignored and the literal was read as "
        f"UTC, which would place the firing {_ZONE_OFFSET} later. Saw {sorted(arrivals)!r}"
    )

    zoned_body, zoned_sent = arrivals[zoned_marker]
    utc_body, utc_sent = arrivals[utc_marker]

    early = (nominal - zoned_sent).total_seconds()
    late = (zoned_sent - nominal).total_seconds()
    assert early <= _EARLY_SLACK_S, (
        f"the {_ZONE_NAME} schedule was sent at {zoned_sent.isoformat()}, {early:.1f}s BEFORE the "
        f"instant {nominal.isoformat()} its local literal denotes; a zone-aware scheduler cannot "
        f"fire early"
    )
    assert late <= _LATE_SLACK_S, (
        f"the {_ZONE_NAME} schedule was sent at {zoned_sent.isoformat()}, {late:.1f}s after the "
        f"instant {nominal.isoformat()} its local literal denotes, beyond the {_LATE_SLACK_S}s "
        f"delivery slack; its UTC twin was sent at {utc_sent.isoformat()}"
    )

    assert _as_instant(zoned_body["at"], zone) == nominal, (
        f"<aws.scheduler.scheduled-time> for the {_ZONE_NAME} schedule resolved to "
        f"{_as_instant(zoned_body['at'], zone).isoformat()} (raw {zoned_body['at']!r}), expected "
        f"the instant its local literal denotes, {nominal.isoformat()}"
    )
    assert _as_instant(utc_body["at"], datetime.timezone.utc) == nominal, (
        f"<aws.scheduler.scheduled-time> for the UTC twin resolved to "
        f"{_as_instant(utc_body['at'], datetime.timezone.utc).isoformat()} (raw "
        f"{utc_body['at']!r}), expected {nominal.isoformat()}"
    )
    assert _as_instant(zoned_body["at"], zone) == _as_instant(
        utc_body["at"], datetime.timezone.utc
    ), (
        f"the two schedules denote the SAME absolute instant, so their reported scheduled times "
        f"must resolve equal: {zoned_body['at']!r} in {_ZONE_NAME} vs {utc_body['at']!r} in UTC"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. The bounded retry is the wait.
_CREATE_TIMEOUT_S = 180


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_role_assumable(ctx, queue_arn: str, role_arn: str) -> None:
    """Create and delete a schedule due a day out, so IAM propagation is absorbed before the
    tested instant is anchored."""
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    name = _create_schedule(
        ctx,
        ScheduleExpression=f"at({later.strftime('%Y-%m-%dT%H:%M:%S')})",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": "{}"},
    )
    _delete_schedule(ctx, name)


def _as_instant(rendered: str, zone) -> datetime.datetime:
    """Resolve `<aws.scheduler.scheduled-time>` to an absolute instant.

    Accepts a Z/offset-bearing rendering or a naive one read in `zone`; both give the same instant.
    """
    parsed = datetime.datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=zone)
    return parsed


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-tz-q-"), tags=_MANAGED_TAGS
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


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    create_bound_s = _budget_s(ctx, _CREATE_TIMEOUT_S)
    deadline = time.monotonic() + create_bound_s
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
                if _budget_spent(ctx):
                    raise TimeoutError("CreateSchedule to be accepted: the run budget ended first; not graded") from last
                raise AssertionError(
                    f"CreateSchedule still refused after {create_bound_s:.0f}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name, kwargs.get("GroupName")))
    return name


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _collect_markers(ctx, queue_url: str, wanted: set[str], *, timeout_s: float, description: str):
    """Return {marker: (body, SentTimestamp)} for markers seen before the budget runs out.

    SentTimestamp is the server's clock, so timing asserts do not measure the poll interval.
    Raises only when nothing arrived; the caller asserts on which markers are missing.
    """
    sqs = ctx.client("sqs")
    found: dict[str, tuple[dict, datetime.datetime]] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and set(found) != wanted:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1,
            MessageSystemAttributeNames=["SentTimestamp"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(body, dict):
                continue
            marker = body.get("marker")
            if marker in wanted and marker not in found:
                sent_ms = int(msg["Attributes"]["SentTimestamp"])
                found[marker] = (
                    body,
                    datetime.datetime.fromtimestamp(sent_ms / 1000.0, datetime.timezone.utc),
                )
    if not found:
        if _budget_spent(ctx):
            raise TimeoutError(f"{description}: the run budget ended first; not graded")
        raise AssertionError(
            f"{description}: neither schedule delivered anything within {timeout_s}s"
        )
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
