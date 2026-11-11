"""scheduler-updated-retry-attempt-count-governs-the-next-occurrence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-updated-retry-attempt-count-governs-the-next-occurrence"
GROUP = "server-side"
SERVICES = ["scheduler"]

_CADENCE = "rate(1 minute)"
_GEN_ONE_CAP = 0
_GEN_TWO_CAP = 3
# An AccessDenied-family target failure is permanent, so Scheduler dead-letters on the first
# attempt regardless of the configured cap.
_EXPECTED_ATTEMPTS = 0
# The model MAXIMUM (com.amazonaws.scheduler#MaximumEventAgeInSeconds range [60, 86400]), so age can
# never be the binding bound in either generation and the configured cap is the only variable.
_EVENT_AGE_MAX_S = 86400
_DLQ_TIMEOUT_S = 240


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A permanent (AccessDenied) target failure dead-letters with RETRY_ATTEMPTS=0 at cap 0, and
    still 0 after UpdateSchedule raises MaximumRetryAttempts to 3, though GetSchedule shows 3.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
    """
    sch = ctx.client("scheduler")

    target = _create_queue(ctx, "sim2real-behav-sched-retryupd-tgt-")
    dlq = _create_queue(ctx, "sim2real-behav-sched-retryupd-dlq-")
    # The role may write to the DLQ and NOT to the target queue, so every target attempt fails with
    # AccessDenied while the dead-letter delivery that carries the evidence still succeeds.
    role_arn = _scheduler_role(
        ctx, [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]}]
    )

    gen_one = ctx.unique_name("gen-one-")
    gen_two = ctx.unique_name("gen-two-")

    name = _create_schedule(
        ctx,
        ScheduleExpression=_CADENCE,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"gen": gen_one}),
            "RetryPolicy": {
                "MaximumRetryAttempts": _GEN_ONE_CAP,
                "MaximumEventAgeInSeconds": _EVENT_AGE_MAX_S,
            },
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )

    first = _await_dlq_event(
        ctx,
        dlq["url"],
        gen_one,
        timeout_s=_DLQ_TIMEOUT_S,
        description=(
            f"the first occurrence of {name} with MaximumRetryAttempts={_GEN_ONE_CAP}"
        ),
    )
    first_code = first["MessageAttributes"]["ERROR_CODE"]["StringValue"]
    assert "AccessDenied" in first_code, (
        f"generation one's dead-letter event reports ERROR_CODE={first_code!r}, expected an "
        f"AccessDenied-family code from the role that deliberately lacks sqs:SendMessage on the "
        f"target queue; the retry count is not attributable otherwise"
    )
    first_n = int(first["MessageAttributes"]["RETRY_ATTEMPTS"]["StringValue"])
    assert first_n == _EXPECTED_ATTEMPTS, (
        f"with MaximumRetryAttempts={_GEN_ONE_CAP} and the model-maximum event age "
        f"({_EVENT_AGE_MAX_S}s, so age cannot bind), an AccessDenied-family target failure is "
        f"permanent and must not be retried, so RETRY_ATTEMPTS must be {_EXPECTED_ATTEMPTS}; got "
        f"{first_n!r}"
    )

    # UpdateSchedule is a full replace: the retry cap and the Input generation marker change together,
    # so a late generation-one occurrence cannot be mistaken for generation two.
    _update_schedule(
        ctx,
        Name=name,
        ScheduleExpression=_CADENCE,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"gen": gen_two}),
            "RetryPolicy": {
                "MaximumRetryAttempts": _GEN_TWO_CAP,
                "MaximumEventAgeInSeconds": _EVENT_AGE_MAX_S,
            },
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )
    described = sch.get_schedule(Name=name)
    assert described["Target"]["RetryPolicy"]["MaximumRetryAttempts"] == _GEN_TWO_CAP, (
        f"GetSchedule reports MaximumRetryAttempts "
        f"{described['Target']['RetryPolicy']['MaximumRetryAttempts']!r} after the update, expected "
        f"{_GEN_TWO_CAP} — the CONFIGURATION must have changed even though the observed behaviour "
        f"below must not"
    )

    second = _await_dlq_event(
        ctx,
        dlq["url"],
        gen_two,
        timeout_s=_DLQ_TIMEOUT_S,
        description=(
            f"an occurrence of {name} dispatched after MaximumRetryAttempts was raised to "
            f"{_GEN_TWO_CAP}"
        ),
    )
    second_code = second["MessageAttributes"]["ERROR_CODE"]["StringValue"]
    assert "AccessDenied" in second_code, (
        f"generation two's dead-letter event reports ERROR_CODE={second_code!r}, expected the same "
        f"AccessDenied-family failure generation one saw ({first_code!r}) — the wiring must not have "
        f"changed, only the retry cap"
    )
    second_n = int(second["MessageAttributes"]["RETRY_ATTEMPTS"]["StringValue"])
    assert second_n == _EXPECTED_ATTEMPTS, (
        f"after UpdateSchedule raised MaximumRetryAttempts from {_GEN_ONE_CAP} to {_GEN_TWO_CAP} "
        f"(event age still the model maximum {_EVENT_AGE_MAX_S}s, so age cannot bind), the next "
        f"occurrence's AccessDenied-family failure is still permanent and still must not be retried, "
        f"so RETRY_ATTEMPTS must still be {_EXPECTED_ATTEMPTS}; got {second_n!r}"
    )
    assert second_n == first_n, (
        f"the observed attempt count must be UNCHANGED across the update ({first_n} -> {second_n}) "
        f"despite the configured cap changing ({_GEN_ONE_CAP} -> {_GEN_TWO_CAP}); a target that "
        f"echoes the currently-configured cap into RETRY_ATTEMPTS instead of classifying the failure "
        f"as permanent would report {_GEN_ONE_CAP} then {_GEN_TWO_CAP}, diverging from real AWS here"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException; the bounded retry waits out that propagation.
_CREATE_TIMEOUT_S = 180


def _create_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _scheduler_role(ctx, statements: list[dict]) -> str:
    """An IAM role EventBridge Scheduler can assume, carrying exactly `statements`."""
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
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
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


def _update_schedule(ctx, **kwargs) -> None:
    """UpdateSchedule, retrying the same IAM-propagation ValidationException within a bound."""
    sch = ctx.client("scheduler")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            sch.update_schedule(**kwargs)
            return
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"UpdateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(3)


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_dlq_event(ctx, queue_url: str, generation: str, *, timeout_s: float, description: str):
    """Poll the DLQ until an event whose payload carries `generation` arrives; raise on timeout.

    Events from the other generation are consumed and DISCARDED rather than returned, so a late
    in-flight occurrence cannot be mistaken for the one under test.
    """
    sqs = ctx.client("sqs")
    discarded: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=20,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if generation in msg.get("Body", ""):
                return msg
            discarded.append(msg.get("Body", ""))
    raise AssertionError(
        f"no dead-letter event for {description} arrived within {timeout_s}s. Events from other "
        f"generations seen and discarded: {discarded!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
