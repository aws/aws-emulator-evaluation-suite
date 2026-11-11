"""events-scheduler-semantics-one-time-at-schedule-fires-one-occurrence-and-persists-under-action-none."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-scheduler-semantics-one-time-at-schedule-fires-one-occurrence-and-persists-under-action-none"
GROUP = "state-machine"
SERVICES = ["scheduler"]

_FIRE_OFFSET_S = 90
_DELIVERY_BUDGET_S = 300
_DELETE_BUDGET_S = 180
# After both have fired, keep draining long enough to catch a second OCCURRENCE if a dispatcher
# treated the at() like a recurring rate — a poll window, not a latency claim.
_AFTER_FIRE_WATCH_S = 75


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A one-time at() schedule fires one occurrence carrying its instant as scheduled time; under
    ActionAfterCompletion=NONE it persists ENABLED with its expression unchanged, while its DELETE
    twin due at the same instant is removed.
    """
    sch = ctx.client("scheduler")
    queue = _create_queue(ctx, "sim2real-behav-sched-at-q-")
    role_arn = _scheduler_role(ctx, [queue["arn"]])

    # Anchor after provisioning: IAM propagation may hold CreateSchedule off.
    nominal = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + datetime.timedelta(
        seconds=_FIRE_OFFSET_S
    )
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    keep_marker = ctx.unique_name("keep-")
    gone_marker = ctx.unique_name("gone-")

    keep_name = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        ActionAfterCompletion="NONE",
        Target=_target(queue["arn"], role_arn, keep_marker),
    )
    gone_name = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        ActionAfterCompletion="DELETE",
        Target=_target(queue["arn"], role_arn, gone_marker),
    )

    seen: dict[str, list[dict]] = {keep_marker: [], gone_marker: []}
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while time.monotonic() < deadline and not (seen[keep_marker] and seen[gone_marker]):
        _drain_into(ctx, queue["url"], seen)
    assert seen[keep_marker], (
        f"the ActionAfterCompletion=NONE at() schedule {keep_name} ({expression}) never delivered "
        f"within {_DELIVERY_BUDGET_S}s; saw gone-twin deliveries {seen[gone_marker]!r}"
    )
    assert seen[gone_marker], (
        f"the ActionAfterCompletion=DELETE at() schedule {gone_name} ({expression}) never delivered "
        f"within {_DELIVERY_BUDGET_S}s while its NONE twin did: {seen[keep_marker]!r}"
    )

    # The DELETE twin is removed after completion; poll for the absence. It also proves the at()
    # completed, so the NONE schedule's persistence is not a lag.
    gone_error = None
    deadline = time.monotonic() + _DELETE_BUDGET_S
    while time.monotonic() < deadline:
        try:
            sch.get_schedule(Name=gone_name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            gone_error = (err.get("Code"), err.get("Message"))
            break
        _drain_into(ctx, queue["url"], seen)
    if gone_error is None:
        raise AssertionError(
            f"the DELETE twin {gone_name} still resolved {_DELETE_BUDGET_S}s after it delivered; "
            "ActionAfterCompletion=DELETE must remove it"
        )
    assert gone_error == ("ResourceNotFoundException", f"Schedule {gone_name} does not exist."), (
        f"the DELETE twin {gone_name} failed with {gone_error!r} instead of the not-found refusal"
    )

    # Keep watching for a second occurrence of the NONE schedule.
    watch_until = time.monotonic() + _AFTER_FIRE_WATCH_S
    while time.monotonic() < watch_until:
        _drain_into(ctx, queue["url"], seen)

    keep_times = sorted({_as_utc(m["t"]) for m in seen[keep_marker]})
    assert keep_times == [nominal], (
        f"the NONE at() schedule produced occurrences scheduled at "
        f"{[t.isoformat() for t in keep_times]!r}; a one-time schedule must produce exactly the one "
        f"occurrence at {nominal.isoformat()}"
    )
    gone_times = sorted({_as_utc(m["t"]) for m in seen[gone_marker]})
    assert gone_times == [nominal], (
        f"the DELETE at() twin delivered scheduled times {[t.isoformat() for t in gone_times]!r}, "
        f"expected only {nominal.isoformat()}"
    )

    # Scheduler has no "completed" State: a fired NONE at() still reads ENABLED.
    kept = sch.get_schedule(Name=keep_name)
    assert kept["State"] == "ENABLED", (
        f"the fired NONE at() schedule reads State={kept['State']!r}; real AWS leaves it ENABLED "
        f"(Scheduler has no completed state)"
    )
    assert kept["ActionAfterCompletion"] == "NONE", (
        f"ActionAfterCompletion changed to {kept['ActionAfterCompletion']!r} after completion"
    )
    assert kept["ScheduleExpression"] == expression, (
        f"the fired schedule's expression became {kept['ScheduleExpression']!r}, expected "
        f"{expression!r} unchanged"
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


def _as_utc(rendered: str) -> datetime.datetime:
    parsed = datetime.datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None, f"scheduled-time {rendered!r} carries no zone designator"
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
    # IAM exposes no propagation condition; the bounded retry in _create_schedule is the wait.
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying ONLY the IAM-propagation ValidationException (its message names
    the role) within a bound. Cleanup is registered from the name passed to the accepted call."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
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
