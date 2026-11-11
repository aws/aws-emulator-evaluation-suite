"""scheduler-unauthorized-target-role-routes-invocation-to-the-dead-letter-queue."""
from __future__ import annotations

import datetime
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-unauthorized-target-role-routes-invocation-to-the-dead-letter-queue"
GROUP = 'data-plane'
SERVICES = ['scheduler', 'sqs']

_FIRE_OFFSET_S = 30
# The nominal instant plus Scheduler's attempt, failure and dead-letter composition. A poll
# BUDGET, never an asserted deadline.
_DELIVERY_TIMEOUT_S = 420
_EFFECT_ABSENT_TIMEOUT_S = 30
# Measured on real AWS: the dead-letter event's ERROR_CODE for an IAM denial on the target.
_EXPECTED_ERROR_CODE = "AccessDenied"


# timing:real-time — schedule: 30 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A schedule whose role is denied on its target queue dead-letters the invocation with the
    original payload, ERROR_CODE=AccessDenied, TARGET_ARN and SCHEDULE_ARN, while a concurrent
    permitted twin delivers and neither the denied queue nor the twin's DLQ receives anything.
    """
    sch = ctx.client("scheduler")
    sqs = ctx.client("sqs")

    target_url, target_arn = _create_queue(ctx)
    dlq_url, dlq_arn = _create_queue(ctx)
    control_url, control_arn = _create_queue(ctx)
    control_dlq_url, control_dlq_arn = _create_queue(ctx)

    # The single broken thing: sqs:SendMessage everywhere the check observes, EXCEPT target_arn.
    role_arn = _scheduler_role(ctx, [dlq_arn, control_arn, control_dlq_arn])

    # The instant is re-anchored on every CreateSchedule attempt: IAM propagation can hold the
    # call off, and an at() instant computed before that could be in the past when it is accepted.
    anchor: dict = {}

    def _anchored_expression() -> str:
        anchor["nominal"] = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0
        ) + datetime.timedelta(seconds=_FIRE_OFFSET_S)
        return f"at({anchor['nominal'].strftime('%Y-%m-%dT%H:%M:%S')})"

    denied_marker = ctx.unique_name("denied-")
    control_marker = ctx.unique_name("permitted-")
    denied_input = json.dumps({"marker": denied_marker})

    denied_name = _create_schedule(
        ctx,
        expression=_anchored_expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target_arn,
            "RoleArn": role_arn,
            "Input": denied_input,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 900},
            "DeadLetterConfig": {"Arn": dlq_arn},
        },
    )
    denied_arn = sch.get_schedule(Name=denied_name)["Arn"]
    nominal = anchor["nominal"]
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    control_name = _create_schedule(
        ctx,
        expression=lambda: expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": control_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": control_marker}),
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 900},
            "DeadLetterConfig": {"Arn": control_dlq_arn},
        },
    )

    # (2) The barrier and the control: an identically-shaped permitted schedule delivers.
    control_msg = _await_message(
        ctx,
        control_url,
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=f"the permitted control schedule {control_name} delivering",
    )
    assert json.loads(control_msg["Body"])["marker"] == control_marker, (
        f"the permitted control leg delivered the wrong payload: {control_msg['Body']!r}"
    )

    # (3) The dead-letter event.
    dead_letter = _await_message(
        ctx,
        dlq_url,
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=f"the denied invocation of {denied_name} reaching its configured DLQ",
    )
    payload = json.loads(dead_letter["Body"])
    assert payload["MessageBody"] == denied_input, (
        f"the dead-letter event lost the original payload: carried {payload.get('MessageBody')!r}, "
        f"expected the schedule's Input {denied_input!r}"
    )
    assert payload["QueueUrl"] == target_url, (
        f"the dead-letter event names the wrong target queue: {payload.get('QueueUrl')!r}, "
        f"expected {target_url!r}"
    )
    attrs = {k: v.get("StringValue") for k, v in (dead_letter.get("MessageAttributes") or {}).items()}
    assert attrs.get("ERROR_CODE") == _EXPECTED_ERROR_CODE, (
        f"the dead-letter event's ERROR_CODE is {attrs.get('ERROR_CODE')!r}, expected "
        f"{_EXPECTED_ERROR_CODE!r}; all attributes were {attrs!r}"
    )
    # message varies: ERROR_MESSAGE names the assumed-role session, whose name is a fresh
    # 32-hex token per invocation that the check cannot know in advance; every other part of
    # the message is graded exactly.
    account = role_arn.split(":")[4]
    role_name = role_arn.split("/")[-1]
    error_message = attrs.get("ERROR_MESSAGE") or ""
    expected_message = (
        re.escape(f"User: arn:aws:sts::{account}:assumed-role/{role_name}/")
        + "[0-9a-f]{32}"
        + re.escape(
            f" is not authorized to perform: sqs:sendmessage on resource: {target_arn} because "
            "no identity-based policy allows the sqs:sendmessage action"
        )
    )
    assert re.fullmatch(expected_message, error_message), (
        f"the dead-letter event's ERROR_MESSAGE is {error_message!r}, expected the IAM denial of "
        f"sqs:sendmessage on {target_arn!r} for the schedule's role session"
    )
    assert attrs.get("TARGET_ARN") == target_arn, (
        f"the dead-letter event's TARGET_ARN is {attrs.get('TARGET_ARN')!r}, expected the queue "
        f"the invocation was denied on ({target_arn!r})"
    )
    assert attrs.get("SCHEDULE_ARN") == denied_arn, (
        f"the dead-letter event's SCHEDULE_ARN is {attrs.get('SCHEDULE_ARN')!r}, expected the "
        f"failing schedule's own ARN ({denied_arn!r})"
    )

    # (4) The effect is absent, twice.
    stray = sqs.receive_message(
        QueueUrl=target_url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=_EFFECT_ABSENT_TIMEOUT_S // 2,
    ).get("Messages")
    assert not stray, (
        f"the denied target queue received the invocation anyway -- delivery did not actually "
        f"fail: {stray!r}"
    )
    control_stray = sqs.receive_message(
        QueueUrl=control_dlq_url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=_EFFECT_ABSENT_TIMEOUT_S // 2,
    ).get("Messages")
    assert not control_stray, (
        f"the permitted control leg was ALSO dead-lettered, so dead-lettering is not attributable "
        f"to the missing permission: {control_stray!r}"
    )


# ===== helpers =====

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. _create_schedule's bounded retry is the wait.
_CREATE_TIMEOUT_S = 180


def _deadline(ctx, cap_s: float) -> float:
    """A monotonic deadline `cap_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (cap_s if left is None else min(cap_s, max(left - 5, 0)))


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-sched-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _scheduler_role(ctx, allowed_arns: list[str]) -> str:
    """A role EventBridge Scheduler can assume, permitted to send to `allowed_arns` and nothing
    else -- so any queue outside that list is denied."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-sched-role-")
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
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": allowed_arns}
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


def _create_schedule(ctx, *, expression, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound.

    `expression` is called on every attempt, so an at() instant can be re-anchored per attempt.
    """
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-xsvc-sched-")
    deadline = _deadline(ctx, _CREATE_TIMEOUT_S)
    last = None
    while True:
        try:
            sch.create_schedule(Name=name, ScheduleExpression=expression(), **kwargs)
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
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return name


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_message(ctx, queue_url, *, timeout_s, description):
    """Poll SQS until any message arrives; returns it with all attributes."""
    sqs = ctx.client("sqs")
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]
    raise AssertionError(f"{description}: nothing arrived within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
