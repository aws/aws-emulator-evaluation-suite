"""server-side-dead-letter-queue-receives-failed-event-payload."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "server-side-dead-letter-queue-receives-failed-event-payload"
GROUP = "server-side"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 15 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """When a schedule's target invocation permanently fails, the exact Input string is delivered
    unchanged as the dead-letter event body to the DeadLetterConfig queue.
    """
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = scheduler.meta.region_name

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-dlq-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_arn = _create_scheduler_role(ctx, iam)

    # A valid ARN for a queue never created: every attempt fails with NonExistentQueue, and
    # MaximumRetryAttempts=0 dead-letters the first failure.
    ghost_queue_name = ctx.unique_name("sim2real-sched-ghost-")
    ghost_queue_arn = f"arn:aws:sqs:{region}:{account_id}:{ghost_queue_name}"

    marker = ctx.unique_name("payload-marker-")
    original_input = json.dumps({"marker": marker})
    schedule_name = ctx.unique_name("sim2real-sched-dlqpayload-")

    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=schedule_name,
        fire_in_s=15,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": ghost_queue_arn,
            "RoleArn": role_arn,
            "Input": original_input,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_schedule(scheduler, schedule_name))

    message = _poll_for_dlq_message(ctx, dlq_url, timeout_s=_budget_s(ctx, 300.0), interval_s=2)
    body = json.loads(message["Body"])
    assert body["MessageBody"] == original_input, (
        f"dead-letter payload was altered: {body['MessageBody']!r} != {original_input!r}"
    )
    assert ghost_queue_name in body["QueueUrl"], (
        f"dead-letter event names the wrong target queue: {body['QueueUrl']!r} does not "
        f"contain {ghost_queue_name!r}"
    )

    attrs = message["MessageAttributes"]
    error_code = attrs["ERROR_CODE"]["StringValue"]
    assert error_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected the documented NonExistentQueue error code, got {error_code!r}"
    )
    retry_attempts = attrs["RETRY_ATTEMPTS"]["StringValue"]
    assert retry_attempts == "0", (
        f"expected RETRY_ATTEMPTS=0 for MaximumRetryAttempts=0, got {retry_attempts!r}"
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


def _create_scheduler_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_schedule_retrying(ctx, scheduler, *, fire_in_s, **kwargs):
    """IAM role trust/permission propagation to EventBridge Scheduler is eventually
    consistent; poll create_schedule until the newly created role is recognized. Each attempt
    anchors its at() fire_in_s seconds after the attempt, so a retry never schedules a past time."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _budget_s(ctx, 30.0)
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


def _poll_for_dlq_message(ctx, queue_url, timeout_s=300.0, interval_s=20.0):
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
