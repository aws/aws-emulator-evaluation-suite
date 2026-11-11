"""scheduler-universal-target-operation-name-case-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-universal-target-operation-name-case-rejected"
GROUP = 'error-semantics'
SERVICES = ['scheduler']

_DELIVERY_TIMEOUT_S = 300
_EFFECT_ABSENT_TIMEOUT_S = 75

_GOOD_ARN = "arn:aws:scheduler:::aws-sdk:sqs:sendMessage"
# The identical ARN with the operation segment capitalised. Every other segment is byte-identical.
_BAD_ARN = "arn:aws:scheduler:::aws-sdk:sqs:SendMessage"


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A universal target's operation segment is case-sensitive: aws-sdk:sqs:SendMessage is refused
    with ValidationException, leaving no schedule and no delivery, while aws-sdk:sqs:sendMessage is
    accepted and delivers.
    """
    sch = ctx.client("scheduler")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue_arn)

    good_marker = ctx.unique_name("accepted-")
    bad_marker = ctx.unique_name("refused-")

    # (1) The barrier and the positive control: the accepted spelling really issues the SDK call.
    # IAM propagation also raises ValidationException, so the role must be proven live first.
    good_name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": _GOOD_ARN,
            "RoleArn": role_arn,
            "Input": json.dumps({"QueueUrl": queue_url, "MessageBody": good_marker}),
        },
    )
    _await_body_text(
        ctx,
        queue_url,
        lambda body: body == good_marker,
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=f"the correctly-cased universal target {good_name} issuing sqs:sendMessage",
    )

    # (2) Break exactly one thing: capitalise the operation segment. No retry -- the barrier above
    # has already proven the role propagated, so any refusal here is about the ARN.
    bad_name = ctx.unique_name("sim2real-behav-sched-badcase-")
    err = _error(
        lambda: sch.create_schedule(
            Name=bad_name,
            ScheduleExpression="rate(1 minute)",
            ScheduleExpressionTimezone="UTC",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Target={
                "Arn": _BAD_ARN,
                "RoleArn": role_arn,
                "Input": json.dumps({"QueueUrl": queue_url, "MessageBody": bad_marker}),
            },
        )
    )
    code = err.get("Code")
    assert code == "ValidationException", (
        f"CreateSchedule accepted the universal target ARN {_BAD_ARN!r}, whose operation segment "
        f"differs from the accepted {_GOOD_ARN!r} only in case, or refused it with {code!r}"
    )
    expected_message = (
        "Invalid RequestJson provided. Reason The api SendMessage is not valid for the service "
        "aws-sdk:sqs."
    )
    assert err.get("Message") == expected_message, (
        f"expected CreateSchedule message {expected_message!r}, got {err.get('Message')!r}"
    )

    # (3) The effect is absent on the control plane: no schedule was created.
    get_err = _error(lambda: sch.get_schedule(Name=bad_name))
    assert get_err.get("Code") == "ResourceNotFoundException", (
        f"the refused CreateSchedule left the schedule {bad_name} behind ({get_err.get('Code')!r})"
    )
    expected_get_message = f"Schedule {bad_name} does not exist."
    assert get_err.get("Message") == expected_get_message, (
        f"expected GetSchedule message {expected_get_message!r}, got {get_err.get('Message')!r}"
    )

    # (4) And absent on the data plane: nothing is ever delivered for the refused spelling, while
    # the accepted one keeps delivering on the same queue in the same window.
    bodies = _collect_all_text(ctx, queue_url, window_s=_EFFECT_ABSENT_TIMEOUT_S)
    assert bad_marker not in bodies, (
        f"the refused universal target delivered anyway: {bodies!r}"
    )
    assert good_marker in bodies, (
        f"the accepted universal target stopped delivering, so the absence of {bad_marker!r} "
        f"proves nothing: bodies seen were {bodies!r}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. _create_schedule's own bounded retry (below) is the
# wait for that propagation -- there is no separate blind sleep here.
_CREATE_TIMEOUT_S = 180


def _error(fn):
    """The botocore Error dict (Code, Message) a call raised. Raises if the call unexpectedly
    SUCCEEDS, so an emulator accepting input real AWS rejects can never read as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("the call was expected to fail but succeeded")


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
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return name


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_body_text(ctx, queue_url, predicate, *, timeout_s, description):
    """Poll SQS until a raw (non-JSON) body satisfying predicate arrives."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            seen.append(body)
            if predicate(body):
                return body
    raise AssertionError(
        f"{description}: nothing matching arrived within {timeout_s}s. Bodies seen: {seen!r}"
    )


def _collect_all_text(ctx, queue_url, *, window_s):
    """Every raw body seen over a bounded window. Never raises -- the caller asserts on it."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
