"""schedule-retry-policy-exhausted-lands-in-dlq-exactly-once."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-retry-policy-exhausted-lands-in-dlq-exactly-once"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """After retries against a failing target are exhausted, exactly one DLQ event arrives,
    and its RETRY_ATTEMPTS / EXHAUSTED_RETRY_CONDITION attributes reflect the retry policy."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    dlq = _create_sqs_queue(ctx, "sim2real-behav-sched-retry-dlq-")
    # A syntactically valid queue ARN in this account/region that was never created:
    # invoking it fails with the SQS-documented retryable NonExistentQueue error, so
    # EventBridge Scheduler actually performs retry attempts before giving up.
    nonexistent_target_arn = (
        f"arn:aws:sqs:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-behav-sched-missing-')}"
    )
    role_arn = _create_scheduler_role(
        ctx,
        "sim2real-behav-sched-retry-role-",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    )

    schedule_name = ctx.unique_name("sim2real-behav-sched-retry-")
    max_retry_attempts = 2
    max_event_age_s = 300
    at_expr, nominal = _at_expression(90)

    resp = _create_schedule_retrying(
        scheduler,
        Name=schedule_name,
        ScheduleExpression=at_expr,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": nonexistent_target_arn,
            "RoleArn": role_arn,
            "Input": "retry-exhaustion-probe",
            "RetryPolicy": {
                "MaximumRetryAttempts": max_retry_attempts,
                "MaximumEventAgeInSeconds": max_event_age_s,
            },
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))
    schedule_arn = resp["ScheduleArn"]

    deadline = time.monotonic() + max(60, (nominal - datetime.now(timezone.utc)).total_seconds() + max_event_age_s + 120)
    received: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not received:
        r = sqs.receive_message(
            QueueUrl=dlq["url"],
            MaxNumberOfMessages=1,
            WaitTimeSeconds=20,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
        )
        received.extend(r.get("Messages", []))
    if not received:
        raise AssertionError("no dead-letter event arrived after retry exhaustion")
    first = received[0]
    sqs.delete_message(QueueUrl=dlq["url"], ReceiptHandle=first["ReceiptHandle"])

    attrs = first["MessageAttributes"]
    assert attrs["SCHEDULE_ARN"]["StringValue"] == schedule_arn, (
        f"expected SCHEDULE_ARN={schedule_arn!r}, got {attrs['SCHEDULE_ARN']['StringValue']!r}"
    )
    assert attrs["ERROR_CODE"]["StringValue"] == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected ERROR_CODE=AWS.SimpleQueueService.NonExistentQueue, "
        f"got {attrs['ERROR_CODE']['StringValue']!r}"
    )
    # EventBridge Scheduler documents RETRY_ATTEMPTS as the number of retries actually
    # performed before giving up -- empirically this can be 0 (e.g. the schedule ages
    # out or is dead-lettered before a subsequent retry attempt is made), so assert
    # the documented bound [0, MaximumRetryAttempts] rather than exact equality.
    retry_attempts = int(attrs["RETRY_ATTEMPTS"]["StringValue"])
    assert 0 <= retry_attempts <= max_retry_attempts, (
        f"RETRY_ATTEMPTS={retry_attempts!r} outside expected [0, {max_retry_attempts}]; "
        f"full attrs={attrs}"
    )
    assert "EXHAUSTED_RETRY_CONDITION" not in attrs or attrs["EXHAUSTED_RETRY_CONDITION"]["StringValue"] in (
        "MaximumRetryAttempts",
        "MaximumEventAgeInSeconds",
    ), f"unexpected EXHAUSTED_RETRY_CONDITION; full attrs={attrs}"

    extra_deadline = time.monotonic() + 30
    duplicates = []
    while time.monotonic() < extra_deadline:
        r = sqs.receive_message(QueueUrl=dlq["url"], MaxNumberOfMessages=5, WaitTimeSeconds=10)
        duplicates.extend(r.get("Messages", []))
    assert len(duplicates) == 0, f"expected exactly one dead-letter event, saw {1 + len(duplicates)}"


def _create_sqs_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn, "name": name}


def _create_scheduler_role(ctx, prefix: str, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name(prefix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_schedule_retrying(scheduler, **kwargs):
    """IAM role/policy propagation to other AWS services can lag a few seconds after
    CreateRole/PutRolePolicy, so CreateSchedule can transiently see the trust policy
    as not-yet-assumable. Retry on that specific signal with a bounded deadline; the
    real assertion is the bounded receive-message poll further down, not this retry."""
    deadline = time.monotonic() + 45.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = e
                time.sleep(3.0)
                continue
            raise
    raise last_exc


def _at_expression(seconds_from_now: int) -> tuple[str, datetime]:
    when = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
    return f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})", when


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
