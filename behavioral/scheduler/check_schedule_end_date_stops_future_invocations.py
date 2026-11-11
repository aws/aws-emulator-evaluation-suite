"""schedule-end-date-stops-future-invocations."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-end-date-stops-future-invocations"
GROUP = "visibility-timeout-ttl"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A rate(2 minutes) schedule whose EndDate falls between its immediate t=0 tick and its t=120
    tick delivers exactly one invocation: rate schedules without a StartDate fire at once, and
    no tick fires after EndDate."""
    scheduler = ctx.client("scheduler")
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, [queue_arn])
    # IAM role-trust propagation can hold CreateSchedule off for tens of seconds. Burn that
    # wait on a disabled throwaway schedule FIRST, so the real EndDate clock below only starts
    # once the role is usable and propagation never eats the margin around EndDate.
    _wait_for_role_ready(ctx, scheduler, role_arn, queue_arn)

    # EndDate sits 60 s after the immediate t=0 tick and 60 s before the t=120 tick.
    end_date = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=60)

    name = ctx.unique_name("sim2real-sched-")
    scheduler.create_schedule(
        Name=name,
        ScheduleExpression="rate(2 minutes)",
        EndDate=end_date,
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn},
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=name))

    # Poll continuously across the window that spans both the allowed (t=0) tick and the
    # forbidden (t=120) tick, plus 80 s for delivery lag.
    seen_ids = set()
    deadline = time.monotonic() + 200.0
    while time.monotonic() < deadline:
        for m in _receive_all(ctx, queue_url):
            seen_ids.add(m["MessageId"])
        time.sleep(2)

    assert len(seen_ids) == 1, (
        f"expected exactly one invocation (the pre-EndDate t=0 tick), "
        f"got {len(seen_ids)} distinct invocations -- the t=120 tick after "
        f"EndDate should have been suppressed"
    )


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _receive_all(ctx, queue_url):
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return msgs


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


def _wait_for_role_ready(ctx, scheduler, role_arn, queue_arn, max_wait_s=90.0, interval_s=5.0):
    """Probe with a disabled throwaway schedule until Scheduler accepts the freshly-created
    execution role (IAM trust-policy propagation can lag CreateRole by tens of seconds). Kept
    off the real schedule's EndDate clock so propagation delay never eats into the window this
    check measures."""
    probe_name = ctx.unique_name("sim2real-sched-warmup-")
    deadline = time.monotonic() + max_wait_s
    while True:
        try:
            scheduler.create_schedule(
                Name=probe_name,
                ScheduleExpression="rate(1 hour)",
                FlexibleTimeWindow={"Mode": "OFF"},
                State="DISABLED",
                Target={"Arn": queue_arn, "RoleArn": role_arn},
            )
            scheduler.delete_schedule(Name=probe_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
