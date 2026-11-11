"""schedule-start-date-defers-first-invocation."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-start-date-defers-first-invocation"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A future StartDate is enforced: no invocation before it, one shortly after."""
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)
    group_name = _create_group(ctx)
    schedule_name = ctx.unique_name("sim2real-sched-start-")
    marker = ctx.unique_name("startdate-")

    start_date = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=90)

    scheduler = ctx.client("scheduler")
    scheduler.create_schedule(
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        StartDate=start_date,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker}),
        },
    )
    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, schedule_name, group_name))

    # Phase 1: poll for the remaining time until StartDate; no invocation should land yet.
    remaining = (start_date - dt.datetime.now(dt.timezone.utc)).total_seconds()
    early_markers = _collect_markers(ctx, queue_url, duration_s=max(remaining - 5, 0), poll_interval=10)
    assert marker not in early_markers, "schedule invoked its target before its StartDate"

    # Phase 2: once StartDate has passed, the first invocation should show up promptly.
    delivered = _wait_for_marker(ctx, queue_url, marker, timeout_s=150, poll_interval=10)
    assert delivered, "expected an invocation shortly after StartDate elapsed"


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real:managed": "true"}
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
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


def _wait_for_role_ready(ctx, role_arn, queue_arn, max_wait_s=90, interval_s=5):
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
    scheduler.create_schedule_group(Name=name, Tags=_MANAGED_TAGS_KV)
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


def _collect_markers(ctx, queue_url, duration_s, poll_interval=10):
    """Drain the queue for duration_s, returning the list of markers observed."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    seen = []
    if duration_s <= 0:
        return seen
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(poll_interval, 20)
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            if "marker" in body:
                seen.append(body["marker"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return seen


def _wait_for_marker(ctx, queue_url, marker, timeout_s, poll_interval=10):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    found = False
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(poll_interval, 20)
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            if body.get("marker") == marker:
                found = True
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
