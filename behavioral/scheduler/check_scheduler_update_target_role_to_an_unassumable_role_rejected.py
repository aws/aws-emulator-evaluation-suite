"""scheduler-update-target-role-to-an-unassumable-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-update-target-role-to-an-unassumable-role-rejected"
GROUP = 'overly-permissive'
SERVICES = ['scheduler']

_FIRST_DELIVERY_TIMEOUT_S = 300
_CONTROL_DELIVERY_TIMEOUT_S = 300


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """UpdateSchedule refuses to swap a working Target.RoleArn for a role Scheduler cannot assume
    (ValidationException), the stored role is unchanged, and the schedule keeps delivering its
    original payload.
    """
    sch = ctx.client("scheduler")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue_arn)
    account = queue_arn.split(":")[4]

    marker = ctx.unique_name("marker-")
    target = {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps({"marker": marker}),
    }
    name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target=target,
    )

    # (1) The barrier: a real delivery proves the role has propagated and the schedule works, so a
    # later ValidationException cannot be IAM propagation wearing the refusal's error code.
    _await_body(
        ctx,
        queue_url,
        lambda b: b.get("marker") == marker,
        timeout_s=_FIRST_DELIVERY_TIMEOUT_S,
        description=f"the schedule {name} delivering with its original role",
    )

    # (2) Break exactly one thing: point Target.RoleArn at a role Scheduler cannot assume.
    unassumable = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-behav-absent-role-')}"
    err = _error(
        lambda: sch.update_schedule(
            Name=name,
            ScheduleExpression="rate(1 minute)",
            ScheduleExpressionTimezone="UTC",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Target=dict(target, RoleArn=unassumable),
        )
    )
    code = err.get("Code")
    assert code == "ValidationException", (
        f"UpdateSchedule refused an unassumable Target.RoleArn with {code!r}, expected "
        f"ValidationException"
    )
    expected_message = (
        "The execution role you provide must allow AWS EventBridge Scheduler to assume the role."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # (3) The effect is absent: the refused update did not mutate the stored configuration.
    got = sch.get_schedule(Name=name)
    assert got["Target"]["RoleArn"] == role_arn, (
        f"the refused UpdateSchedule mutated the stored Target.RoleArn to "
        f"{got['Target']['RoleArn']!r}, expected the original {role_arn!r}"
    )

    # (4) The positive control, in the same file: the schedule is still delivering.
    _drain_to_empty(ctx, queue_url, timeout_s=30)
    delivered_after = _await_body(
        ctx,
        queue_url,
        lambda b: b.get("marker") == marker,
        timeout_s=_CONTROL_DELIVERY_TIMEOUT_S,
        description=f"the schedule {name} still delivering after the refused update",
    )
    assert delivered_after["marker"] == marker, (
        f"the post-refusal delivery carries the wrong payload: {delivered_after!r}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. _create_schedule's bounded retry is the wait.
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
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name, kwargs.get("GroupName")))
    return name


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_body(ctx, queue_url, predicate, *, timeout_s, description):
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
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
            seen.append(body)
            if predicate(body):
                return body
    raise AssertionError(
        f"{description} not delivered within {timeout_s}s. Bodies seen: {seen!r}"
    )


def _drain_to_empty(ctx, queue_url, *, timeout_s, consecutive_empty=2):
    """Drain so the control leg's delivery is a NEW invocation, not a backlog message that
    arrived before the refused update."""
    sqs = ctx.client("sqs")
    empties = 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and empties < consecutive_empty:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        if not msgs:
            empties += 1
            continue
        empties = 0
        for msg in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
