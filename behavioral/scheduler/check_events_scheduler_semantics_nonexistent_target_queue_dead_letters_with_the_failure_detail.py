"""events-scheduler-semantics-nonexistent-target-queue-dead-letters-with-the-failure-detail."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-scheduler-semantics-nonexistent-target-queue-dead-letters-with-the-failure-detail"
GROUP = "error-propagation"
SERVICES = ["scheduler"]

#: Lead from the provisioned role to the at() instant, covering role propagation before the
#: dispatch assumes it; at() takes the instant to the second.
_FIRE_OFFSET_S = 45
_DELIVERY_BUDGET_S = 300
_SETTLE_S = 20


# timing:real-time — schedule: 45 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With MaximumRetryAttempts=0, a schedule whose target queue does not exist dead-letters with
    ERROR_CODE=AWS.SimpleQueueService.NonExistentQueue, its TARGET_ARN, SCHEDULE_ARN, SCHEDULED_TIME
    and EXECUTION_ID; a twin aimed at a live queue under the same role delivers.
    """
    sch = ctx.client("scheduler")
    account = ctx.client("sts").get_caller_identity()["Account"]
    live = _create_queue(ctx, "sim2real-behav-sched-live-q-")
    dlq = _create_queue(ctx, "sim2real-behav-sched-dlq-")
    # Never created: a unique name nobody else can occupy, in this account and region.
    ghost_arn = f"arn:aws:sqs:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-sched-ghost-')}"
    role_arn = _scheduler_role(ctx, [live["arn"], ghost_arn, dlq["arn"]])

    nominal = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + datetime.timedelta(
        seconds=_FIRE_OFFSET_S
    )
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    ghost_marker = ctx.unique_name("ghost-")
    live_marker = ctx.unique_name("live-")
    # CreateSchedule does not validate that the target exists; the failure surfaces at dispatch.
    retry = {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}

    ghost_name = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=dict(
            _target(ghost_arn, role_arn, ghost_marker),
            DeadLetterConfig={"Arn": dlq["arn"]},
            RetryPolicy=retry,
        ),
    )
    ghost_schedule_arn = sch.get_schedule(Name=ghost_name)["Arn"]
    _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=dict(
            _target(live["arn"], role_arn, live_marker),
            DeadLetterConfig={"Arn": dlq["arn"]},
            RetryPolicy=retry,
        ),
    )

    live_msgs: list[dict] = []
    dead: list[dict] = []
    deadline = _deadline(ctx, _DELIVERY_BUDGET_S)
    while time.monotonic() < deadline and not (live_msgs and dead):
        live_msgs += _drain(ctx, live["url"])
        dead += _drain(ctx, dlq["url"])
    settle = time.monotonic() + _SETTLE_S
    while time.monotonic() < settle:
        live_msgs += _drain(ctx, live["url"])
        dead += _drain(ctx, dlq["url"])

    live_bodies = [_json(m["Body"]) for m in live_msgs]
    assert any(b.get("marker") == live_marker for b in live_bodies), (
        f"positive control: the twin aimed at the live queue never delivered within "
        f"{_DELIVERY_BUDGET_S}s under the same role; live queue saw {live_bodies!r}"
    )
    assert dead, (
        f"the schedule {ghost_name} aimed at the nonexistent queue {ghost_arn} produced no "
        f"dead-letter message within {_DELIVERY_BUDGET_S}s"
    )

    ghost_dead = []
    for m in dead:
        inner = _json(_json(m["Body"]).get("MessageBody", "")) if isinstance(_json(m["Body"]), dict) else {}
        if inner.get("marker") == live_marker:
            raise AssertionError(f"the live twin's successful invocation was dead-lettered: {m!r}")
        if inner.get("marker") == ghost_marker:
            ghost_dead.append((m, inner))
    assert ghost_dead, (
        f"no dead-letter message wraps the ghost schedule's payload (marker {ghost_marker!r}); "
        f"dead letters were {[m['Body'][:300] for m in dead]!r}"
    )

    msg, inner = ghost_dead[0]
    attrs = {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}
    assert attrs.get("ERROR_CODE") == "AWS.SimpleQueueService.NonExistentQueue", (
        f"dead-letter ERROR_CODE is {attrs.get('ERROR_CODE')!r}, expected "
        f"'AWS.SimpleQueueService.NonExistentQueue'; attrs={attrs!r}"
    )
    assert attrs.get("TARGET_ARN") == ghost_arn, (
        f"dead-letter TARGET_ARN is {attrs.get('TARGET_ARN')!r}, expected {ghost_arn!r}"
    )
    assert attrs.get("SCHEDULE_ARN") == ghost_schedule_arn, (
        f"dead-letter SCHEDULE_ARN is {attrs.get('SCHEDULE_ARN')!r}, expected {ghost_schedule_arn!r}"
    )
    assert _as_utc(attrs.get("SCHEDULED_TIME", "")) == nominal, (
        f"dead-letter SCHEDULED_TIME is {attrs.get('SCHEDULED_TIME')!r}, expected {nominal.isoformat()}"
    )
    assert attrs.get("EXECUTION_ID") == inner.get("x"), (
        f"dead-letter EXECUTION_ID {attrs.get('EXECUTION_ID')!r} differs from the execution id "
        f"rendered into the failed payload {inner.get('x')!r}"
    )
    assert _as_utc(inner.get("t", "")) == nominal, (
        f"the dead-lettered payload's rendered scheduled-time is {inner.get('t')!r}, expected "
        f"{nominal.isoformat()}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
_CREATE_TIMEOUT_S = 150


def _json(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return {}


def _target(queue_arn: str, role_arn: str, marker: str) -> dict:
    return {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps(
            {
                "marker": marker,
                "t": "<aws.scheduler.scheduled-time>",
                "x": "<aws.scheduler.execution-id>",
            }
        ),
    }


def _as_utc(rendered: str) -> datetime.datetime:
    parsed = datetime.datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None, f"timestamp {rendered!r} carries no zone designator"
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


def _drain(ctx, queue_url: str) -> list[dict]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
    )
    msgs = resp.get("Messages", [])
    for msg in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return msgs


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
