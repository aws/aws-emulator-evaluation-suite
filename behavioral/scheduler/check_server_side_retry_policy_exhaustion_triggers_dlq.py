"""server-side-retry-policy-exhaustion-triggers-dlq."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-retry-policy-exhaustion-triggers-dlq"
GROUP = "server-side"
SERVICES = ["scheduler"]
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


# timing:real-time — schedule: 59 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Scheduler itself retries an undeliverable target per RetryPolicy and dead-letters the
    event only after exhausting the attempts; the unreachable target queue receives nothing."""
    scheduler = ctx.client("scheduler")
    target_url, target_arn = _create_queue(ctx, "target")
    dlq_url, dlq_arn = _create_queue(ctx, "dlq")
    # Role can send to the DLQ but is deliberately NOT granted sqs:SendMessage on
    # the target queue, so every invocation attempt fails and must exhaust
    # RetryPolicy before landing in the dead-letter queue.
    role_arn = _create_scheduler_role(ctx, [dlq_arn])

    name = ctx.unique_name("sim2real-sched-")
    max_retry_attempts = 1
    resp = _create_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        ScheduleExpression="rate(2 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target_arn,
            "RoleArn": role_arn,
            "RetryPolicy": {"MaximumRetryAttempts": max_retry_attempts, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))
    schedule_arn = resp["ScheduleArn"]

    dlq_messages = _poll_until(
        lambda: _receive_all(ctx, dlq_url),
        lambda msgs: len(msgs) >= 1,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert len(dlq_messages) >= 1, f"expected >=1 dead-letter message, got {len(dlq_messages)}"

    # The DLQ message's own attributes are EventBridge Scheduler's server-reported
    # account of *how* it gave up -- without reading them, a target that dead-letters
    # on the very first failure (skipping RetryPolicy entirely) would pass identically
    # to one that genuinely retries and exhausts. This is the actual "exhaustion"
    # claim in this check's name.
    attrs = dlq_messages[0]["MessageAttributes"]
    assert attrs["SCHEDULE_ARN"]["StringValue"] == schedule_arn, (
        f"dead-letter SCHEDULE_ARN {attrs['SCHEDULE_ARN']['StringValue']!r} != {schedule_arn!r}"
    )
    error_code = attrs["ERROR_CODE"]["StringValue"]
    assert "AccessDenied" in error_code, f"expected an AccessDenied-family ERROR_CODE, got {error_code!r}"
    retry_attempts = int(attrs["RETRY_ATTEMPTS"]["StringValue"])
    assert retry_attempts <= max_retry_attempts, (
        f"observed {retry_attempts} retry attempts, exceeding the configured cap {max_retry_attempts}"
    )
    exhausted_reason = attrs["EXHAUSTED_RETRY_CONDITION"]["StringValue"]
    if exhausted_reason == "MaximumRetryAttempts":
        assert retry_attempts == max_retry_attempts, (
            f"exhaustion reported as MaximumRetryAttempts but RETRY_ATTEMPTS was "
            f"{retry_attempts}, not the configured {max_retry_attempts}"
        )
    else:
        assert exhausted_reason == "MaximumEventAgeInSeconds", (
            f"unexpected EXHAUSTED_RETRY_CONDITION {exhausted_reason!r}"
        )

    stray = _receive_all(ctx, target_url)
    assert stray == [], f"target queue (unreachable by IAM) received {len(stray)} stray message(s)"


def _create_queue(ctx, tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(f"sim2real-sched-{tag}-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_all(ctx, queue_url):
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=5,
        AttributeNames=["All"],
        MessageAttributeNames=["All"],
    )
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return msgs


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_scheduler_role(ctx, allowed_queue_arns):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": list(allowed_queue_arns)}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    """IAM role trust is eventually consistent; retry CreateSchedule briefly."""
    last_exc = None
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
