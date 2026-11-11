"""events-scheduler-semantics-cron-in-a-half-hour-offset-zone-fires-at-the-zone-resolved-minute."""
from __future__ import annotations

import datetime
import json
import time
import zoneinfo

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-scheduler-semantics-cron-in-a-half-hour-offset-zone-fires-at-the-zone-resolved-minute"
GROUP = "data-plane"
SERVICES = ["scheduler"]

# Half-hour offset, east of UTC, no DST: misreading the cron fields as UTC moves the occurrence
# 5h30m into the future (silence inside any budget), and the MINUTE field itself differs by 30
# between the two readings, so a whole-hour-only zone model also fails.
_ZONE_NAME = "Asia/Kolkata"
_ZONE_OFFSET = datetime.timedelta(hours=5, minutes=30)
_MIN_LEAD_S = 150
_DELIVERY_BUDGET_S = 420


# timing:real-time — schedule: 210 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A cron() evaluated in ScheduleExpressionTimezone=Asia/Kolkata fires at the UTC instant its
    local fields denote, and its <aws.scheduler.scheduled-time> reports that instant, alongside a
    UTC twin whose fields spell the same instant in UTC.
    """
    zone = zoneinfo.ZoneInfo(_ZONE_NAME)
    queue = _create_queue(ctx, "sim2real-behav-sched-cron-tz-q-")
    role_arn = _scheduler_role(ctx, [queue["arn"]])

    now = datetime.datetime.now(datetime.timezone.utc)
    nominal = (now + datetime.timedelta(seconds=_MIN_LEAD_S + 60)).replace(second=0, microsecond=0)
    local = nominal.astimezone(zone)
    if local.utcoffset() != _ZONE_OFFSET:
        raise AssertionError(
            f"the runner's tzdata reports {_ZONE_NAME} at {nominal.isoformat()} as offset "
            f"{local.utcoffset()!r}; {_ZONE_OFFSET!r} is required to derive the expectation"
        )
    assert local.minute != nominal.minute, (
        f"precondition: the local and UTC minute fields must differ for a half-hour zone, got "
        f"{local.minute} and {nominal.minute}"
    )

    # Year-pinned fields make each cron a single occurrence; no latency is asserted.
    zoned_expr = f"cron({local.minute} {local.hour} {local.day} {local.month} ? {local.year})"
    utc_expr = f"cron({nominal.minute} {nominal.hour} {nominal.day} {nominal.month} ? {nominal.year})"
    zoned_marker = ctx.unique_name("kolkata-cron-")
    utc_marker = ctx.unique_name("utc-cron-")

    zoned_name = _create_schedule(
        ctx,
        ScheduleExpression=zoned_expr,
        ScheduleExpressionTimezone=_ZONE_NAME,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_target(queue["arn"], role_arn, zoned_marker),
    )
    utc_name = _create_schedule(
        ctx,
        ScheduleExpression=utc_expr,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=_target(queue["arn"], role_arn, utc_marker),
    )

    seen: dict[str, list[dict]] = {zoned_marker: [], utc_marker: []}
    deadline = _deadline(ctx, _DELIVERY_BUDGET_S)
    while time.monotonic() < deadline and not (seen[zoned_marker] and seen[utc_marker]):
        _drain_into(ctx, queue["url"], seen)

    # The UTC twin is the calibration: once it lands, the instant has passed on the same dispatcher,
    # so a missing zoned delivery means the zone was ignored.
    assert seen[utc_marker], (
        f"the UTC twin {utc_name} ({utc_expr}) never delivered within {_DELIVERY_BUDGET_S}s, so "
        f"nothing can be attributed to the zone; zoned deliveries: {seen[zoned_marker]!r}"
    )
    assert seen[zoned_marker], (
        f"the {_ZONE_NAME} cron {zoned_name} ({zoned_expr}, = {nominal.isoformat()} UTC) never "
        f"delivered while its UTC twin at the same instant did: the cron fields were not "
        f"evaluated in the declared zone"
    )

    zoned_times = sorted({_as_instant(m["t"], zone) for m in seen[zoned_marker]})
    utc_times = sorted({_as_instant(m["t"], datetime.timezone.utc) for m in seen[utc_marker]})
    assert zoned_times == [nominal], (
        f"the {_ZONE_NAME} cron's invocation reported scheduled time(s) "
        f"{[t.isoformat() for t in zoned_times]!r} (raw {[m['t'] for m in seen[zoned_marker]]!r}); "
        f"its local fields {zoned_expr} denote {nominal.isoformat()}"
    )
    assert utc_times == [nominal], (
        f"the UTC twin reported scheduled time(s) {[t.isoformat() for t in utc_times]!r}, expected "
        f"{nominal.isoformat()}"
    )
    local_seen = zoned_times[0].astimezone(zone)
    assert (local_seen.hour, local_seen.minute) == (local.hour, local.minute), (
        f"the zoned invocation's timestamp reads {local_seen.strftime('%H:%M')} in {_ZONE_NAME}, "
        f"but the cron fields name {local.strftime('%H:%M')}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
_CREATE_TIMEOUT_S = 180


def _target(queue_arn: str, role_arn: str, marker: str) -> dict:
    return {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps({"marker": marker, "t": "<aws.scheduler.scheduled-time>"}),
    }


def _as_instant(rendered: str, zone) -> datetime.datetime:
    """Resolve a `<aws.scheduler.scheduled-time>` rendering to an absolute UTC instant. A zoned
    rendering (Z or offset) is taken as-is; a naive one is read in the schedule's own zone."""
    parsed = datetime.datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(datetime.timezone.utc)


def _create_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _scheduler_role(ctx, queue_arns: list[str]) -> str:
    """An IAM role EventBridge Scheduler can assume, permitted to send to exactly these queues."""
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
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arns}],
            }
        ),
    )
    # IAM propagates asynchronously: _create_schedule retries the propagation error until it clears.
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _deadline(ctx, timeout_s: float) -> float:
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying ONLY the IAM-propagation ValidationException (its message names
    the role) within a bound. Cleanup is registered from the name passed to the accepted call."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = _deadline(ctx, _CREATE_TIMEOUT_S)
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "ValidationException" or "role" not in err.get("Message", "").lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM propagation: {exc!r}"
                ) from exc
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


def _drain_into(ctx, queue_url: str, seen: dict[str, list[dict]]) -> None:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        try:
            body = json.loads(msg.get("Body", ""))
        except ValueError:
            continue
        if isinstance(body, dict) and body.get("marker") in seen:
            seen[body["marker"]].append(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
