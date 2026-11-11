"""events-scheduler-semantics-create-with-a-past-end-date-and-no-start-date-rejected."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-scheduler-semantics-create-with-a-past-end-date-and-no-start-date-rejected"
GROUP = "validation"
SERVICES = ["scheduler"]

_DELIVERY_BUDGET_S = 180
_SETTLE_S = 15


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CreateSchedule with a past EndDate and no StartDate fails ValidationException (EndDate is
    compared against an implicit StartDate of now), the schedule does not exist and delivers nothing,
    while the identical request with a future EndDate is accepted and delivers."""
    sch = ctx.client("scheduler")
    queue = _create_queue(ctx, "sim2real-behav-sched-past-end-q-")
    role_arn = _scheduler_role(ctx, [queue["arn"]])
    rejected_marker = ctx.unique_name("refused-")
    control_marker = ctx.unique_name("control-")
    rejected_name = ctx.unique_name("sim2real-behav-sched-past-end-")

    # Positive control first: it proves the role is usable, so the refusal below cannot be the
    # IAM-propagation ValidationException in disguise.
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    control_name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        EndDate=now + datetime.timedelta(minutes=10),
        Target=_target(queue["arn"], role_arn, control_marker),
    )

    past_end = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) - datetime.timedelta(
        minutes=2
    )
    # The message names a StartDate the caller never sent; both requests target one queue, so a
    # stray delivery carrying the refused marker would show the request was actually accepted.
    try:
        sch.create_schedule(
            Name=rejected_name,
            ScheduleExpression="rate(1 minute)",
            FlexibleTimeWindow={"Mode": "OFF"},
            EndDate=past_end,
            Target=_target(queue["arn"], role_arn, rejected_marker),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    else:
        # Wrongly accepted: register its cleanup before asserting so it cannot leak.
        ctx.on_cleanup(lambda: _delete_schedule(ctx, rejected_name))
        code, message = "<accepted>", ""
    assert code == "ValidationException", (
        f"CreateSchedule with EndDate {past_end.isoformat()} (already past) and no StartDate "
        f"returned {code!r}, expected ValidationException"
    )
    expected = "The StartDate you specify must come before the EndDate."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    missing, missing_message = _error(lambda: sch.get_schedule(Name=rejected_name))
    assert missing == "ResourceNotFoundException", (
        f"GetSchedule for the refused schedule returned {missing!r}; nothing may have been stored"
    )
    expected_missing = f"Schedule {rejected_name} does not exist."
    assert missing_message == expected_missing, (
        f"expected message {expected_missing!r}, got {missing_message!r}"
    )

    seen: dict[str, list[dict]] = {rejected_marker: [], control_marker: []}
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while time.monotonic() < deadline and not seen[control_marker]:
        _drain_into(ctx, queue["url"], seen)
    assert seen[control_marker], (
        f"positive control: {control_name} (future EndDate, otherwise identical) delivered nothing "
        f"within {_DELIVERY_BUDGET_S}s"
    )
    settle = time.monotonic() + _SETTLE_S
    while time.monotonic() < settle:
        _drain_into(ctx, queue["url"], seen)
    assert seen[rejected_marker] == [], (
        f"the refused schedule's payload reached the target: {seen[rejected_marker]!r}"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
_CREATE_TIMEOUT_S = 150


def _error(fn) -> tuple[str, str | None]:
    """The (code, message) fn was refused with; an unexpected SUCCESS fails loudly."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message")
    raise AssertionError("the call was expected to fail but SUCCEEDED")


def _target(queue_arn: str, role_arn: str, marker: str) -> dict:
    return {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps({"marker": marker, "t": "<aws.scheduler.scheduled-time>"}),
    }


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
