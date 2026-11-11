"""scheduler-end-date-stops-a-recurring-series."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-end-date-stops-a-recurring-series"
GROUP = 'data-plane'
SERVICES = ['scheduler']

_START_OFFSET_S = 60
# 2.5 cadence periods, deliberately NOT a whole multiple: occurrences fall at +0/+60/+120 from
# StartDate and the next would be at +180, so no occurrence lands exactly ON EndDate and the
# strict `< EndDate` comparison below is unambiguous.
_WINDOW_S = 150
# Total observation budget: reach StartDate, span the window, then keep watching a full cadence
# period past EndDate for a late-scheduled occurrence. A poll BUDGET, never an asserted deadline.
_SERIES_TIMEOUT_S = 480
_QUIET_WINDOW_TIMEOUT_S = 90


# timing:real-time — schedule: 210 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1",
      "timing:real-time")
def run(ctx) -> None:
    """StartDate and EndDate bound a rate(1 minute) series: it delivers inside its window, every
    delivered scheduled-time lies within [StartDate, EndDate), and nothing is scheduled after it.
    Assertions use the scheduled time in the payload, so late delivery cannot fail the check.
    """
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue_arn)

    # Anchor the window AFTER provisioning: IAM propagation can hold CreateSchedule off for a
    # while, and a StartDate computed before that could already be in the past by the time the
    # call is accepted.
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    start_date = now + datetime.timedelta(seconds=_START_OFFSET_S)
    end_date = start_date + datetime.timedelta(seconds=_WINDOW_S)

    marker = ctx.unique_name("marker-")
    name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        StartDate=start_date,
        EndDate=end_date,
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps(
                {"marker": marker, "at": "<aws.scheduler.scheduled-time>"}
            ),
        },
    )

    # Drain continuously from before StartDate until a full cadence period past EndDate.
    hard_stop = min(
        time.monotonic() + _SERIES_TIMEOUT_S,
        time.monotonic()
        + (end_date - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        + _QUIET_WINDOW_TIMEOUT_S,
    )
    bodies = _drain_until(ctx, queue_url, lambda b: b.get("marker") == marker, hard_stop)
    times = sorted(_parse_iso(b["at"]) for b in bodies)

    assert times, (
        f"the schedule {name} never delivered inside its Start/End window "
        f"[{start_date.isoformat()}, {end_date.isoformat()}) -- EndDate cannot be shown to bound "
        f"a series that never ran"
    )
    assert all(t >= start_date for t in times), (
        f"a delivery has a scheduled-time BEFORE StartDate {start_date.isoformat()!r}: "
        f"{[t.isoformat() for t in times]!r}"
    )
    assert all(t < end_date for t in times), (
        f"a delivery has a scheduled-time at or after EndDate {end_date.isoformat()!r}: "
        f"{[t.isoformat() for t in times]!r}"
    )

    # A full cadence period past EndDate has now elapsed. Anything scheduled at or after EndDate
    # that Scheduler still had queued would have arrived by now; watch once more explicitly.
    late = [
        b
        for b in _drain_until(
            ctx,
            queue_url,
            lambda b: b.get("marker") == marker,
            time.monotonic() + _QUIET_WINDOW_TIMEOUT_S,
        )
        if _parse_iso(b["at"]) >= end_date
    ]
    assert not late, (
        f"{len(late)} invocation(s) were SCHEDULED at or after EndDate "
        f"{end_date.isoformat()!r}: {late!r}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. `_create_schedule`'s bounded retry below is the
# wait -- there is no separate unconditional sleep for propagation.
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


def _drain_until(ctx, queue_url, predicate, monotonic_stop):
    """Drain a queue until `monotonic_stop`, returning every matching JSON body seen."""
    sqs = ctx.client("sqs")
    found: list[dict] = []
    while time.monotonic() < monotonic_stop:
        wait = max(1, min(5, int(monotonic_stop - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(body, dict) and predicate(body):
                found.append(body)
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
