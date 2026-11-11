"""flexible-time-window-invocation-jitter-within-bounds."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flexible-time-window-invocation-jitter-within-bounds"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]

_MAX_WINDOW_MINUTES = 1
_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_TAGS = {"sim2real:managed": "true"}


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-flexible-time-windows.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """FlexibleTimeWindow=FLEXIBLE fires within [scheduledTime, scheduledTime+window], never before."""
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)
    group_name = _create_group(ctx)
    schedule_name = ctx.unique_name("sim2real-sched-flex-")
    marker = ctx.unique_name("flex-")

    scheduled_time = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60)
    scheduled_time = scheduled_time.replace(microsecond=0)
    at_expression = f"at({scheduled_time.strftime('%Y-%m-%dT%H:%M:%S')})"

    scheduler = ctx.client("scheduler")
    # Scheduler's TagResource accepts only a schedule-GROUP ARN ("You can only assign tags to
    # schedule groups" per its own docs) -- an individual schedule's ScheduleArn is rejected with
    # ValidationException, so the group tag (below) is the only tagging available for this tree.
    scheduler.create_schedule(
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression=at_expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": _MAX_WINDOW_MINUTES},
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker}),
        },
    )
    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, schedule_name, group_name))

    scheduled_epoch = scheduled_time.timestamp()
    # It can legitimately fire anywhere inside [scheduledTime, scheduledTime + window]; give
    # generous slack past the window close for delivery/processing latency.
    timeout_s = 60 + _MAX_WINDOW_MINUTES * 60 + 90
    sent_epoch = _wait_for_marker_timestamp(ctx, queue_url, marker, timeout_s=timeout_s, poll_interval=10)
    assert sent_epoch is not None, "expected an invocation to eventually land within the flexible window"

    delta = sent_epoch - scheduled_epoch
    assert delta >= -5, f"invocation observed {-delta:.1f}s before its scheduledTime"
    assert delta <= _MAX_WINDOW_MINUTES * 60 + 60, (
        f"invocation observed {delta:.1f}s after scheduledTime, beyond the "
        f"{_MAX_WINDOW_MINUTES}-minute flexible window plus delivery slack"
    )


# ===== helpers =====

def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sched-q-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_scheduler_role(ctx, queue_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sched-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sched-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    _wait_for_role_ready(ctx, role["Arn"], queue_arn)
    return role["Arn"]


def _deadline(ctx, timeout_s):
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


def _wait_for_role_ready(ctx, role_arn, queue_arn, max_wait_s=90, interval_s=2):
    """Probe with a throwaway schedule until Scheduler accepts the freshly-created execution
    role (IAM trust-policy propagation can lag CreateRole by tens of seconds)."""
    scheduler = ctx.client("scheduler")
    probe_name = ctx.unique_name("sim2real-sched-warmup-")
    deadline = _deadline(ctx, max_wait_s)
    while True:
        try:
            scheduler.create_schedule(
                Name=probe_name,
                GroupName="default",
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": json.dumps({"marker": "warmup"})},
            )
            scheduler.delete_schedule(Name=probe_name, GroupName="default")
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_group(ctx):
    scheduler = ctx.client("scheduler")
    name = ctx.unique_name("sim2real-sched-grp-")
    scheduler.create_schedule_group(Name=name, Tags=_TAGS_KV)
    ctx.on_cleanup(lambda: _delete_group_safe(ctx, name))
    return name


def _delete_schedule_safe(ctx, name, group_name):
    scheduler = ctx.client("scheduler")
    try:
        scheduler.delete_schedule(Name=name, GroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_group_safe(ctx, name):
    scheduler = ctx.client("scheduler")
    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_marker_timestamp(ctx, queue_url, marker, timeout_s, poll_interval=10):
    """Poll until a message carrying `marker` is seen; return its SQS SentTimestamp (epoch s)."""
    sqs = ctx.client("sqs")
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=min(poll_interval, 20),
            MessageSystemAttributeNames=["SentTimestamp"],
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("marker") == marker:
                return int(m["Attributes"]["SentTimestamp"]) / 1000.0
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
