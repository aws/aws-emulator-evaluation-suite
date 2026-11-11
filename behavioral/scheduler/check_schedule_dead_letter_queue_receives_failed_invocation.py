"""schedule-dead-letter-queue-receives-failed-invocation."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "schedule-dead-letter-queue-receives-failed-invocation"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/configuring-schedule-dlq.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule whose target invocation fails (role lacks send permission on the
    target queue) actually routes the failed event to the configured DeadLetterConfig
    queue at invocation time -- not merely accepted at CreateSchedule time."""
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")

    target = _create_sqs_queue(ctx, "sim2real-behav-sched-tgt-")
    dlq = _create_sqs_queue(ctx, "sim2real-behav-sched-dlq-")

    # Role can deliver to the DLQ but has NO permission to send to the target queue,
    # so target invocation must fail while DLQ delivery must still succeed.
    role_arn = _create_scheduler_role(
        ctx,
        "sim2real-behav-sched-role-",
        [
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": dlq["arn"],
            }
        ],
    )

    marker = ctx.unique_name("sim2real-behav-marker-")
    schedule_name = ctx.unique_name("sim2real-behav-sched-")
    at_expr, nominal = _at_expression(90)

    resp = _create_schedule_retrying(
        ctx,
        scheduler,
        Name=schedule_name,
        ScheduleExpression=at_expr,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": target["arn"],
            "RoleArn": role_arn,
            "Input": marker,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))
    schedule_arn = resp["ScheduleArn"]

    deadline = time.monotonic() + max(30, (nominal - datetime.now(timezone.utc)).total_seconds() + 180)
    dlq_messages: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not dlq_messages:
        r = sqs.receive_message(
            QueueUrl=dlq["url"],
            MaxNumberOfMessages=1,
            WaitTimeSeconds=20,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
        )
        dlq_messages.extend(r.get("Messages", []))
    if not dlq_messages:
        raise AssertionError("no dead-letter event arrived on the DLQ within the retry/backoff window")
    msg = dlq_messages[0]
    sqs.delete_message(QueueUrl=dlq["url"], ReceiptHandle=msg["ReceiptHandle"])

    attrs = msg["MessageAttributes"]
    assert attrs["SCHEDULE_ARN"]["StringValue"] == schedule_arn, (
        f"dead-letter event SCHEDULE_ARN={attrs['SCHEDULE_ARN']['StringValue']!r} != {schedule_arn!r}"
    )
    assert attrs["RETRY_ATTEMPTS"]["StringValue"] == "0", (
        f"expected RETRY_ATTEMPTS='0' (MaximumRetryAttempts=0), "
        f"got {attrs['RETRY_ATTEMPTS']['StringValue']!r}"
    )
    error_code = attrs["ERROR_CODE"]["StringValue"]
    assert error_code == "AccessDenied", (
        f"expected the dead-letter event to record the role's missing sqs:SendMessage "
        f"permission on the target queue as ERROR_CODE='AccessDenied', got {error_code!r}"
    )
    body = json.loads(msg["Body"])
    assert body["QueueUrl"] == target["url"], (
        f"dead-letter event QueueUrl={body['QueueUrl']!r} != target queue url {target['url']!r}"
    )
    assert body["MessageBody"] == marker, (
        f"dead-letter event MessageBody={body['MessageBody']!r} != original Input {marker!r}"
    )

    # The target queue must never have received the message: the failure was real,
    # not a fabricated success that also happened to populate the DLQ.
    leftover = sqs.receive_message(QueueUrl=target["url"], MaxNumberOfMessages=5, WaitTimeSeconds=2)
    leftover_messages = leftover.get("Messages", [])
    assert len(leftover_messages) == 0, (
        f"target queue received {len(leftover_messages)} message(s) despite the role lacking "
        f"sqs:SendMessage on it -- the invocation should have failed, not partially succeeded"
    )


def _mgmt_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _create_sqs_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(prefix)
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.tag_queue(QueueUrl=url, Tags=_mgmt_tags())
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.tag_role(RoleName=role_name, Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()])
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_schedule_retrying(ctx, scheduler, **kwargs):
    """IAM role trust/permission propagation to EventBridge Scheduler is eventually
    consistent; poll create_schedule until the newly created role is recognized."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while True:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _at_expression(seconds_from_now: int) -> tuple[str, datetime]:
    when = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
    return f"at({when.strftime('%Y-%m-%dT%H:%M:%S')})", when


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
