"""e2e-disable-schedule-halts-invocation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-disable-schedule-halts-invocation"
GROUP = "e2e"
SERVICES = ["scheduler"]

_ABSENCE_WINDOW_S = 150
_DRAIN_TIMEOUT_S = 45


# timing:real-time — schedule: 60 s
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An enabled schedule delivers messages; flipping State to DISABLED halts further delivery."""
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)
    group_name = _create_group(ctx)
    schedule_name = ctx.unique_name("sim2real-sched-dis-")
    marker = ctx.unique_name("disable-")

    scheduler = ctx.client("scheduler")
    target = {
        "Arn": queue_arn,
        "RoleArn": role_arn,
        "Input": json.dumps({"marker": marker}),
    }
    _retry_role_not_ready(lambda: scheduler.create_schedule(
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=target,
        State="ENABLED",
    ))
    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, schedule_name, group_name))

    delivered = _wait_for_marker(ctx, queue_url, marker, timeout_s=120, poll_interval=10)
    assert delivered, "expected the enabled schedule to deliver at least one message"

    scheduler.update_schedule(
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target=target,
        State="DISABLED",
    )

    # Confirm the schedule actually flipped to DISABLED.
    got = scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
    assert got["State"] == "DISABLED", f"expected State=DISABLED after UpdateSchedule, got {got.get('State')!r}"

    # Retire anything already in flight at the instant the disable landed, so the strict watch below
    # cannot be confused by a fire that was queued a moment before UpdateSchedule took effect.
    _drain_to_empty(ctx, queue_url, timeout_s=_DRAIN_TIMEOUT_S)

    # Strict watch: two full rate(1 minute) cadence periods plus delivery slack.
    still_arriving = _wait_for_marker(ctx, queue_url, marker, timeout_s=_ABSENCE_WINDOW_S, poll_interval=10)
    assert not still_arriving, (
        f"message carrying marker {marker!r} still arrived on the target queue within "
        f"{_ABSENCE_WINDOW_S}s of disabling the schedule"
    )

    # Second, independent observable: the queue's own reported depth agrees with the direct receive.
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"expected ApproximateNumberOfMessages=0 on {queue_url} after the disabled-schedule watch, "
        f"got {attrs['ApproximateNumberOfMessages']!r}"
    )


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _wait_for_role_ready(ctx, role_arn, queue_arn, max_wait_s=45, interval_s=5):
    """Probe with a throwaway schedule until Scheduler accepts the freshly-created execution
    role (IAM trust-policy propagation can lag CreateRole by tens of seconds)."""
    scheduler = ctx.client("scheduler")
    probe_name = ctx.unique_name("sim2real-sched-warmup-")
    deadline = time.monotonic() + max_wait_s
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
    scheduler.create_schedule_group(
        Name=name, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
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


def _retry_role_not_ready(fn, max_wait_s=90, interval_s=5):
    """Retry fn() while Scheduler reports the freshly-created execution role isn't usable yet
    (IAM trust-policy propagation delay), up to max_wait_s. Any other error is re-raised."""
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _drain_to_empty(ctx, queue_url, *, timeout_s, consecutive_empty=2):
    """Receive-and-delete until `consecutive_empty` receives in a row see nothing, or timeout_s
    elapses. Retires messages already in flight before a strict absence watch begins."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    empties = 0
    while time.monotonic() < deadline and empties < consecutive_empty:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        if not messages:
            empties += 1
            continue
        empties = 0
        for m in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])


def _wait_for_marker(ctx, queue_url, marker, timeout_s, poll_interval=10):
    """Poll the queue up to timeout_s; return True as soon as a message carrying `marker` is seen,
    or False once the full window has elapsed with no such message. Returning immediately on a hit
    keeps a passing positive-control call from burning the rest of its window for no reason, without
    weakening the negative case: absence still requires the marker to stay unseen for timeout_s."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(poll_interval, 20)
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("marker") == marker:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
