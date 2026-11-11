"""events-scheduler-semantics-update-to-a-past-end-date-rejected-and-the-series-keeps-firing."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-scheduler-semantics-update-to-a-past-end-date-rejected-and-the-series-keeps-firing"
GROUP = "validation"
SERVICES = ["scheduler"]

_FIRST_BUDGET_S = 180
_AFTER_BUDGET_S = 180


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Updating a live rate(1 minute) series with an already-past EndDate (no StartDate) is refused
    with ValidationException; the schedule keeps no EndDate and keeps delivering after the refusal.
    """
    sch = ctx.client("scheduler")
    queue = _create_queue(ctx, "sim2real-behav-sched-upd-end-q-")
    role_arn = _scheduler_role(ctx, [queue["arn"]])
    marker = ctx.unique_name("series-")
    target = _target(queue["arn"], role_arn, marker)
    name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=target,
    )

    seen: dict[str, list[dict]] = {marker: []}
    deadline = time.monotonic() + _FIRST_BUDGET_S
    while time.monotonic() < deadline and not seen[marker]:
        _drain_into(ctx, queue["url"], seen)
    assert seen[marker], (
        f"positive control: the live rate(1 minute) schedule {name} delivered nothing within "
        f"{_FIRST_BUDGET_S}s, so a later refusal cannot be shown to leave it running"
    )

    refused_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    past_end = refused_at - datetime.timedelta(minutes=1)
    err = _error(
        lambda: sch.update_schedule(
            Name=name,
            ScheduleExpression="rate(1 minute)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target=target,
            EndDate=past_end,
        )
    )
    code = err.get("Code")
    assert code == "ValidationException", (
        f"UpdateSchedule with EndDate {past_end.isoformat()} (already past, no StartDate) returned "
        f"{code!r}, expected ValidationException"
    )
    # AWS compares EndDate against an implicit StartDate of "now", so the message names StartDate.
    expected_message = "The StartDate you specify must come before the EndDate."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    after = sch.get_schedule(Name=name)
    assert "EndDate" not in after, (
        f"the refused update still stored EndDate={after.get('EndDate')!r} on {name}"
    )
    assert after["State"] == "ENABLED", f"the refused update left State={after['State']!r}"

    deadline = time.monotonic() + _AFTER_BUDGET_S

    def _post_refusal() -> list[str]:
        return [m["t"] for m in seen[marker] if _as_utc(m["t"]) > refused_at]

    while time.monotonic() < deadline and not _post_refusal():
        _drain_into(ctx, queue["url"], seen)
    assert _post_refusal(), (
        f"no occurrence scheduled after the refused update at {refused_at.isoformat()} arrived "
        f"within {_AFTER_BUDGET_S}s; the series stopped as if the past EndDate had been applied. "
        f"Seen: {sorted(m['t'] for m in seen[marker])!r}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
_CREATE_TIMEOUT_S = 150


def _error(fn) -> dict:
    """The botocore Error dict (Code, Message) fn raised. An unexpected SUCCESS fails loudly rather
    than returning a falsy sentinel that would read like a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("the call was expected to be refused but SUCCEEDED")


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
