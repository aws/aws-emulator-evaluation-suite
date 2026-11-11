"""scheduler-flexible-time-window-delivers-with-the-nominal-scheduled-time."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-flexible-time-window-delivers-with-the-nominal-scheduled-time"
GROUP = 'data-plane'
SERVICES = ['scheduler']

#: Lead from the provisioned role to the at() instant; at() takes the instant to the second.
_FIRE_OFFSET_S = 30
_WINDOW_MINUTES = 1
# The nominal instant plus the full flexible window plus Scheduler's own delivery slack. A poll
# BUDGET, never an asserted deadline.
_DELIVERY_TIMEOUT_S = 420


# timing:real-time — schedule: 30 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-flexible-time-windows.html
@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1",
      "timing:real-time")
def run(ctx) -> None:
    """A Mode=FLEXIBLE schedule (1-minute window) delivers, reports the NOMINAL scheduled-time,
    and never arrives before that instant; a Mode=OFF twin on the same queue is the control.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-flexible-time-windows.html
    """
    sch = ctx.client("scheduler")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue_arn)

    # Anchor the instant AFTER provisioning: IAM propagation can hold CreateSchedule off, and an
    # at() instant computed before that could already be in the past when the call is accepted.
    nominal = datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(seconds=_FIRE_OFFSET_S)
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"

    flex_marker = ctx.unique_name("flexible-")
    off_marker = ctx.unique_name("fixed-")
    flex_name = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": _WINDOW_MINUTES},
        State="ENABLED",
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps(
                {"marker": flex_marker, "at": "<aws.scheduler.scheduled-time>"}
            ),
        },
    )
    off_name = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": off_marker, "at": "<aws.scheduler.scheduled-time>"}),
        },
    )

    got = sch.get_schedule(Name=flex_name)["FlexibleTimeWindow"]
    assert got == {"Mode": "FLEXIBLE", "MaximumWindowInMinutes": _WINDOW_MINUTES}, (
        f"the flexible window did not round-trip through GetSchedule: {got!r}"
    )

    arrivals = _collect_markers(
        ctx,
        queue_url,
        {flex_marker, off_marker},
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=f"the FLEXIBLE schedule {flex_name} and its Mode=OFF twin {off_name}",
    )

    assert off_marker in arrivals, (
        f"the Mode=OFF control twin due at {nominal.isoformat()} never delivered, so nothing can "
        f"be attributed to the flexible window: saw {sorted(arrivals)!r}"
    )
    assert flex_marker in arrivals, (
        f"a Mode=FLEXIBLE schedule with MaximumWindowInMinutes={_WINDOW_MINUTES} never delivered "
        f"within {_DELIVERY_TIMEOUT_S}s, while its Mode=OFF twin due at the same instant did: "
        f"saw {sorted(arrivals)!r}"
    )

    flex_body, flex_received_at = arrivals[flex_marker]
    off_body, _ = arrivals[off_marker]
    assert _parse_iso(off_body["at"]) == nominal, (
        f"the Mode=OFF twin reported scheduled-time {off_body['at']!r}, expected the nominal "
        f"instant {nominal.isoformat()!r}"
    )
    assert _parse_iso(flex_body["at"]) == nominal, (
        f"a FLEXIBLE schedule must report the NOMINAL scheduled-time, not the jittered delivery "
        f"time: got {flex_body['at']!r}, expected {nominal.isoformat()!r}"
    )
    # The queue is polled continuously, so the observation time is an upper bound on delivery
    # within a few seconds: an implementation that fires a flexible schedule on creation instead of
    # inside its window is caught here, and a merely SLOW one cannot be.
    assert flex_received_at >= nominal, (
        f"the flexible window opens forward only, but the invocation was already observed on the "
        f"queue at {flex_received_at.isoformat()!r}, BEFORE its nominal instant "
        f"{nominal.isoformat()!r}"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. _create_schedule's bounded retry is the wait.
_CREATE_TIMEOUT_S = 180


def _parse_iso(value: str) -> datetime.datetime:
    """Parse Scheduler's substituted scheduled-time, an ISO-8601 UTC string ending in 'Z'."""
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
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound."""
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


def _collect_markers(ctx, queue_url, wanted, *, timeout_s, description):
    """Poll until every marker in `wanted` is seen or the budget runs out.

    Returns {marker: (body, received_at)}; a partial result is returned for the caller to assert on.
    """
    sqs = ctx.client("sqs")
    found: dict[str, tuple[dict, datetime.datetime]] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and set(found) != set(wanted):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
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
                found[marker] = (body, datetime.datetime.now(datetime.timezone.utc))
    if not found:
        raise AssertionError(
            f"{description}: neither schedule delivered anything within {timeout_s}s"
        )
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
