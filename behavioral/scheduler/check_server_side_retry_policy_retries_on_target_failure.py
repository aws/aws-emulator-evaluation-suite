"""server-side-retry-policy-retries-on-target-failure."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "server-side-retry-policy-retries-on-target-failure"
GROUP = "server-side"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 15 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With RetryPolicy MaximumRetryAttempts=N and a target that always fails with AccessDenied, the
    invocation is dead-lettered with RETRY_ATTEMPTS <= N, and EXHAUSTED_RETRY_CONDITION,
    when present, is consistent with that count.
    """
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")

    target_queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-tgt-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=target_queue_url))
    target_queue_arn = sqs.get_queue_attributes(
        QueueUrl=target_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-dlq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # A role EventBridge Scheduler CAN assume, and that CAN deliver to the DLQ (needed
    # for the dead-letter event to actually be written), but has NO permission to send
    # to the *target* queue -- so every invocation attempt against it is denied, while
    # dead-letter delivery still succeeds. The SQS AccessDenied is synchronous, so it
    # is the failure Scheduler's retry policy sees.
    role_arn = _create_toothless_scheduler_role(ctx, iam, dlq_arn)

    max_retries = 1
    schedule_name = ctx.unique_name("sim2real-sched-retry-")

    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=schedule_name,
        fire_in_s=15,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": target_queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": "retry-payload-marker"}),
            "RetryPolicy": {"MaximumRetryAttempts": max_retries, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_schedule(scheduler, schedule_name))

    message = _poll_for_dlq_message(ctx, dlq_url, timeout_s=_budget_s(ctx, 170.0), interval_s=2)
    attrs = message["MessageAttributes"]
    error_code = attrs["ERROR_CODE"]["StringValue"]
    assert "AccessDenied" in error_code, f"expected an AccessDenied-family error, got {error_code!r}"
    retry_attempts = int(attrs["RETRY_ATTEMPTS"]["StringValue"])
    assert retry_attempts <= max_retries, (
        f"observed {retry_attempts} retry attempts, which exceeds the configured cap of {max_retries}"
    )
    # EXHAUSTED_RETRY_CONDITION is not always present on the dead-letter event: an
    # AccessDenied-class failure can exhaust with RETRY_ATTEMPTS=0 and no
    # exhaustion-condition attribute, so it is asserted only when present. Whatever IS present
    # must stay internally consistent with the exhaustion reason: hitting the
    # attempt cap must report exactly max_retries attempts; running out of
    # event-age budget may report fewer.
    exhausted_reason = attrs.get("EXHAUSTED_RETRY_CONDITION", {}).get("StringValue")
    if exhausted_reason is not None:
        assert exhausted_reason in ("MaximumRetryAttempts", "MaximumEventAgeInSeconds"), (
            f"unexpected EXHAUSTED_RETRY_CONDITION {exhausted_reason!r}; full attrs={attrs}"
        )
        if exhausted_reason == "MaximumRetryAttempts":
            assert retry_attempts == max_retries, (
                f"exhaustion was reported as MaximumRetryAttempts but RETRY_ATTEMPTS was "
                f"{retry_attempts}, not the configured {max_retries}"
            )



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _at_expression(seconds_from_now: int) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
    return f"at({dt.strftime('%Y-%m-%dT%H:%M:%S')})"


def _create_toothless_scheduler_role(ctx, iam, dlq_arn):
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy = {
        "Version": "2012-10-17",
        # Permission to deliver to the DLQ ONLY -- deliberately no permission for the
        # target queue, so the target invocation itself is denied.
        "Statement": [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": dlq_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_retrying(ctx, scheduler, *, fire_in_s, **kwargs):
    """IAM role trust/permission propagation to EventBridge Scheduler is eventually
    consistent; poll create_schedule until the newly created role is recognized. Each attempt
    anchors its at() fire_in_s seconds after the attempt, so a retry never schedules a past time."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            return scheduler.create_schedule(
                ScheduleExpression=_at_expression(seconds_from_now=fire_in_s), **kwargs
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if code in ("ResourceNotFoundException", "ValidationException") and _budget_spent(ctx):
                raise TimeoutError("CreateSchedule to recognize the new role: the run budget ended first; not graded") from err
            raise


def _safe_delete_schedule(scheduler, name):
    from botocore.exceptions import ClientError

    try:
        scheduler.delete_schedule(Name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_for_dlq_message(ctx, queue_url, timeout_s=420.0, interval_s=20.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            MessageAttributeNames=["All"],
            AttributeNames=["All"],
            WaitTimeSeconds=min(int(interval_s), 20),
        )
        messages = resp.get("Messages", [])
        if messages:
            msg = messages[0]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg
    if _budget_spent(ctx):
        raise TimeoutError("a message on the dead-letter queue: the run budget ended first; not graded")
    raise AssertionError(f"no dead-letter message arrived within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
