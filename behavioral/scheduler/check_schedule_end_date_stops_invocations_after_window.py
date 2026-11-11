"""schedule-end-date-stops-invocations-after-window."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-end-date-stops-invocations-after-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A recurring schedule invokes its target before its EndDate and never after: every invocation's scheduled time
    (from <aws.scheduler.scheduled-time>) is before EndDate, so late delivery of an earlier tick is not a violation.
    """
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)
    group_name = _create_group(ctx)
    schedule_name = ctx.unique_name("sim2real-sched-end-")
    marker = ctx.unique_name("enddate-")

    end_date = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=90)

    scheduler = ctx.client("scheduler")
    scheduler.create_schedule(
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        EndDate=end_date,
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker, "at": "<aws.scheduler.scheduled-time>"}),
        },
    )
    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, schedule_name, group_name))

    # Phase 1: the schedule should fire at least once before EndDate elapses.
    scheduled_at = _collect_marker_times(ctx, queue_url, marker, timeout_s=130, poll_interval=10)
    assert scheduled_at, "expected at least one invocation before EndDate"
    assert all(t < end_date for t in scheduled_at), (
        f"an invocation delivered during phase 1 was itself SCHEDULED at or after "
        f"EndDate {end_date.isoformat()!r}: {[t.isoformat() for t in scheduled_at]!r}"
    )

    # Phase 2: regardless of exactly when phase 1 completed, keep watching for more than one
    # whole interval past EndDate. A tick scheduled before EndDate is allowed to arrive late;
    # only a tick SCHEDULED at or after EndDate proves the series was not actually stopped.
    late = _collect_marker_times(ctx, queue_url, marker, timeout_s=150, poll_interval=10)
    overrun = [t for t in late if t >= end_date]
    assert not overrun, (
        f"{len(overrun)} invocation(s) were SCHEDULED at or after EndDate "
        f"{end_date.isoformat()!r}: {[t.isoformat() for t in overrun]!r}"
    )


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
    scheduler.create_schedule_group(Name=name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
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


def _parse_iso(value: str) -> dt.datetime:
    """Scheduler substitutes scheduled-time as e.g. '2026-09-11T04:00:20Z'."""
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _collect_marker_times(ctx, queue_url, marker, timeout_s, poll_interval=10):
    """Drain the queue for `timeout_s`, returning the SCHEDULED time of every delivery whose
    marker matches -- arrival order and arrival delay are deliberately not observed here."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    times = []
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
                times.append(_parse_iso(body["at"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return times


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
