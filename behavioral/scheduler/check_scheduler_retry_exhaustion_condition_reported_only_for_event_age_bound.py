"""scheduler-retry-exhaustion-condition-reported-only-for-event-age-bound."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-retry-exhaustion-condition-reported-only-for-event-age-bound"
GROUP = "server-side"
SERVICES = ["scheduler"]

# Model constants (com.amazonaws.scheduler, smithy.api#range), not account quotas.
_ATTEMPTS_MAX = 185
_EVENT_AGE_MIN_S = 60
_EVENT_AGE_MAX_S = 86400

_ATTEMPT_CAPPED_RETRIES = 1
_FIRE_OFFSET_S = 90
_DLQ_TIMEOUT_S = 300
# Long enough for one whole attempt cycle of the age-capped arm to have been observed already, so
# "the target queue is empty" is a calibrated absence rather than a bare wait.
_TARGET_QUIET_TIMEOUT_S = 30


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """EXHAUSTED_RETRY_CONDITION appears on the dead-letter event only when MaximumEventAgeInSeconds
    is exceeded: two schedules on identical failing wiring, differing only in which RetryPolicy
    bound is tight, diverge on whether the attribute appears and never name MaximumRetryAttempts.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-dlq.html
    """
    target_attempts = _create_queue(ctx, "sim2real-behav-sched-rx-tgt-a-")
    target_age = _create_queue(ctx, "sim2real-behav-sched-rx-tgt-b-")
    dlq_attempts = _create_queue(ctx, "sim2real-behav-sched-rx-dlq-a-")
    dlq_age = _create_queue(ctx, "sim2real-behav-sched-rx-dlq-b-")

    # One role for both schedules: it may write to BOTH dead-letter queues and to NEITHER target
    # queue, so every target attempt fails with AccessDenied while dead-letter delivery succeeds.
    role_arn = _scheduler_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": [dlq_attempts["arn"], dlq_age["arn"]],
            }
        ],
    )

    # Anchor the instant AFTER provisioning: IAM propagation can hold CreateSchedule off, and an
    # at() instant computed before that could already be in the past when the call is accepted.
    nominal = datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(seconds=_FIRE_OFFSET_S)
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"

    attempts_arn = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target_attempts["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": ctx.unique_name("attempt-capped-")}),
            "RetryPolicy": {
                "MaximumRetryAttempts": _ATTEMPT_CAPPED_RETRIES,
                # The model MAXIMUM: age can never be the binding bound for this arm.
                "MaximumEventAgeInSeconds": _EVENT_AGE_MAX_S,
            },
            "DeadLetterConfig": {"Arn": dlq_attempts["arn"]},
        },
    )
    age_arn = _create_schedule(
        ctx,
        ScheduleExpression=expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target_age["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": ctx.unique_name("age-capped-")}),
            "RetryPolicy": {
                # The model MAXIMUM attempts against the model MINIMUM age: ordinary processing lag
                # from SCHEDULED_TIME to the single failed attempt exceeds 60s, so age governs.
                "MaximumRetryAttempts": _ATTEMPTS_MAX,
                "MaximumEventAgeInSeconds": _EVENT_AGE_MIN_S,
            },
            "DeadLetterConfig": {"Arn": dlq_age["arn"]},
        },
    )

    attempts_msg = _await_dlq_message(
        ctx,
        dlq_attempts["url"],
        timeout_s=_DLQ_TIMEOUT_S,
        description=(
            f"the attempt-capped schedule {attempts_arn.rsplit('/', 1)[-1]} "
            f"(MaximumRetryAttempts={_ATTEMPT_CAPPED_RETRIES}, "
            f"MaximumEventAgeInSeconds={_EVENT_AGE_MAX_S})"
        ),
    )
    age_msg = _await_dlq_message(
        ctx,
        dlq_age["url"],
        timeout_s=_DLQ_TIMEOUT_S,
        description=(
            f"the age-capped schedule {age_arn.rsplit('/', 1)[-1]} "
            f"(MaximumRetryAttempts={_ATTEMPTS_MAX}, MaximumEventAgeInSeconds={_EVENT_AGE_MIN_S})"
        ),
    )

    attempts_attrs = attempts_msg["MessageAttributes"]
    age_attrs = age_msg["MessageAttributes"]

    # Both arms must have failed for the ONE reason the wiring engineered, or the exhaustion
    # reporting below would be attributable to something else.
    for label, attrs in (("attempt-capped", attempts_attrs), ("age-capped", age_attrs)):
        code = attrs["ERROR_CODE"]["StringValue"]
        assert "AccessDenied" in code, (
            f"the {label} arm's dead-letter event reports ERROR_CODE={code!r}, expected an "
            f"AccessDenied-family code from the role that deliberately lacks sqs:SendMessage on its "
            f"target queue; the exhaustion reporting is not attributable otherwise"
        )

    assert attempts_attrs["SCHEDULE_ARN"]["StringValue"] == attempts_arn, (
        f"the attempt-capped DLQ carried SCHEDULE_ARN "
        f"{attempts_attrs['SCHEDULE_ARN']['StringValue']!r}, expected {attempts_arn!r} — the two "
        f"arms' events must not be crossed"
    )
    assert age_attrs["SCHEDULE_ARN"]["StringValue"] == age_arn, (
        f"the age-capped DLQ carried SCHEDULE_ARN {age_attrs['SCHEDULE_ARN']['StringValue']!r}, "
        f"expected {age_arn!r} — the two arms' events must not be crossed"
    )

    # A target that fails on its first attempt is never retried, so MaximumRetryAttempts is never
    # the reported cause; the attribute appears only once processing lag exceeds the event age.
    assert "EXHAUSTED_RETRY_CONDITION" not in attempts_attrs, (
        f"the attempt-capped arm (MaximumRetryAttempts={_ATTEMPT_CAPPED_RETRIES}, model-maximum "
        f"MaximumEventAgeInSeconds={_EVENT_AGE_MAX_S}) carried EXHAUSTED_RETRY_CONDITION="
        f"{attempts_attrs['EXHAUSTED_RETRY_CONDITION']['StringValue']!r}, but the target fails on its "
        f"very first attempt and is never actually retried, so no RetryPolicy bound is ever exhausted "
        f"and the attribute must be absent — full attrs={attempts_attrs}"
    )
    age_reason = age_attrs["EXHAUSTED_RETRY_CONDITION"]["StringValue"]
    assert age_reason == "MaximumEventAgeInSeconds", (
        f"with the model-maximum MaximumRetryAttempts={_ATTEMPTS_MAX} and the model-minimum "
        f"MaximumEventAgeInSeconds={_EVENT_AGE_MIN_S}, ordinary processing lag from SCHEDULED_TIME to "
        f"the single failed attempt exceeds {_EVENT_AGE_MIN_S}s, so the exhaustion condition must be "
        f"'MaximumEventAgeInSeconds'; got {age_reason!r}"
    )

    attempts_n = int(attempts_attrs["RETRY_ATTEMPTS"]["StringValue"])
    age_n = int(age_attrs["RETRY_ATTEMPTS"]["StringValue"])
    assert attempts_n == 0, (
        f"the attempt-capped arm's target fails on its very first attempt and is never actually "
        f"retried (no EXHAUSTED_RETRY_CONDITION was reported), so RETRY_ATTEMPTS must be 0; got "
        f"{attempts_n!r}"
    )
    assert age_n < _ATTEMPTS_MAX, (
        f"the age-capped arm gave up on age after {age_n} retries, which must be strictly below its "
        f"configured cap of {_ATTEMPTS_MAX} — reaching the cap would contradict the reported reason "
        f"{age_reason!r}"
    )

    # The dead-letter events already observed on the same wiring calibrate this absence.
    for label, queue in (("attempt-capped", target_attempts), ("age-capped", target_age)):
        leftover = _drain(ctx, queue["url"], window_s=_TARGET_QUIET_TIMEOUT_S)
        assert leftover == [], (
            f"the {label} arm's target queue received {len(leftover)} message(s) even though its "
            f"role has no sqs:SendMessage on it and its event was dead-lettered: {leftover!r}"
        )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException; `_create_schedule` retries within this bound.
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
    """Create a schedule, retrying the IAM-propagation ValidationException; return its ARN."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            arn = sch.create_schedule(Name=name, **kwargs)["ScheduleArn"]
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
    return arn


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_dlq_message(ctx, queue_url: str, *, timeout_s: float, description: str) -> dict:
    """Poll one dead-letter queue until an event arrives. RAISES on timeout."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=20,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg
    raise AssertionError(
        f"no dead-letter event for {description} arrived within {timeout_s}s, so its retry policy "
        f"was never observed to be exhausted"
    )


def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Every raw body seen over a bounded window."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
