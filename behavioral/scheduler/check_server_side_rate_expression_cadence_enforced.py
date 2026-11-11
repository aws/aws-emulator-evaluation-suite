"""server-side-rate-expression-cadence-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-rate-expression-cadence-enforced"
GROUP = "server-side"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A rate(1 minute) schedule's consecutive invocations are spaced by the
    SERVER per the configured cadence, independent of how often (or rarely)
    the client polls for the resulting SQS messages."""
    scheduler = ctx.client("scheduler")
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])

    name = ctx.unique_name("sim2real-sched-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    sent_timestamps_ms = _collect_sent_timestamps(ctx, queue_url, count=2, timeout_s=210.0)
    assert len(sent_timestamps_ms) == 2, (
        f"expected 2 SQS deliveries from the rate(1 minute) schedule {name} within 210s, "
        f"got {len(sent_timestamps_ms)}: {sent_timestamps_ms!r}"
    )
    gap_s = (sent_timestamps_ms[1] - sent_timestamps_ms[0]) / 1000.0
    # Nominal cadence is 60s; allow generous slack for scheduling jitter but
    # this must NOT be near-zero (which would indicate the client, not the
    # server, is pacing invocations) nor wildly off from the configured rate.
    assert 40.0 <= gap_s <= 110.0, f"unexpected inter-invocation gap: {gap_s}s"


# ===== helpers =====


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _deadline(ctx, timeout_s):
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


def _collect_sent_timestamps(ctx, queue_url, count, timeout_s):
    sqs = ctx.client("sqs")
    seen = {}
    deadline = _deadline(ctx, timeout_s)
    while len(seen) < count and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=15,
            AttributeNames=["SentTimestamp"],
        )
        for m in resp.get("Messages", []):
            seen[m["MessageId"]] = int(m["Attributes"]["SentTimestamp"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return sorted(seen.values())


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    deadline = _deadline(ctx, 45.0)
    while time.monotonic() < deadline:
        try:
            return scheduler.create_schedule(**kwargs)
        except ClientError as e:
            last_exc = e
            if e.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                time.sleep(2.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
