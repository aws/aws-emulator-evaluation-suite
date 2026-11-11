"""server-side-cascade-delete-halts-future-invocations."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "server-side-cascade-delete-halts-future-invocations"
GROUP = "server-side"
SERVICES = ["scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """After DeleteScheduleGroup cascades a delete of its schedules, no further
    target invocations occur even though the recurring schedule's next occurrence
    would otherwise still be due."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    scheduler = ctx.client("scheduler")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sched-cascade-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_arn = _create_scheduler_role(ctx, iam)

    group_name = ctx.unique_name("sim2real-sched-cascade-grp-")
    scheduler.create_schedule_group(Name=group_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    group_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if group_deleted["done"] else _safe_delete_group(scheduler, group_name))

    # Scheduler's own delivery is at-least-once: a single invocation can legitimately land in
    # the queue more than once (a retried SendMessage, a redelivered SQS receipt). Tag every
    # delivery with the invocation's own <aws.scheduler.execution-id> so a benign duplicate of
    # an invocation we already saw can never be confused with a genuinely NEW invocation:
    # a redelivered pre-delete invocation can arrive after the drain and must not be read
    # as a post-delete leak.
    schedule_name = ctx.unique_name("sim2real-sched-cascade-")
    _create_schedule_retrying(
        ctx,
        scheduler,
        Name=schedule_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 minute)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"exec": "<aws.scheduler.execution-id>"}),
        },
    )

    # Confirm the schedule is actually firing before we cascade-delete it.
    seen_execs: set[str] = set()
    first_exec = _poll_for_exec(ctx, queue_url, seen_execs, timeout_s=150, interval_s=15)
    assert first_exec is not None, "schedule never fired before the cascade-delete test could proceed"
    # Drain to two consecutive empty receives, recording every execution-id seen: this is the
    # baseline of invocations that happened BEFORE the delete, any redelivery of which is not a
    # leak.
    _drain_collecting_execs(ctx, queue_url, seen_execs)

    scheduler.delete_schedule_group(Name=group_name)

    # Wait for the cascade to fully converge: the group must disappear entirely.
    _poll_until_group_gone(ctx, scheduler, group_name, timeout_s=180, interval_s=5)
    group_deleted["done"] = True

    # The underlying schedule must be gone too, not just the group.
    from botocore.exceptions import ClientError

    try:
        scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
        raise AssertionError("schedule still exists after its group was cascade-deleted")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        expected_message = f"Schedule group {group_name} does not exist."
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Now confirm no NEW invocation lands. The schedule fires every 60s (rate(1 minute)), so the
    # silence window must clear at least two full cadence periods plus Scheduler's own delivery
    # slack -- shorter, and it cannot distinguish "the cascade delete stopped it" from "the next
    # fire just hasn't happened yet". A delivery whose execution-id is already in `seen_execs` is
    # a late duplicate of a pre-delete invocation, not a leak.
    leaked_exec = _poll_for_new_exec(ctx, queue_url, seen_execs, timeout_s=150, interval_s=15)
    assert leaked_exec is None, (
        f"a target invocation (execution-id {leaked_exec!r}) occurred after the schedule group "
        f"was cascade-deleted"
    )


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


def _create_schedule_retrying(ctx, scheduler, **kwargs):
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


def _safe_delete_group(scheduler, name):
    from botocore.exceptions import ClientError

    try:
        scheduler.delete_schedule_group(Name=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _exec_id(msg) -> str:
    return json.loads(msg["Body"])["exec"]


def _drain_collecting_execs(ctx, queue_url, seen_execs: set, consecutive_empty=2):
    sqs = ctx.client("sqs")
    empties = 0
    while empties < consecutive_empty:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        messages = resp.get("Messages", [])
        if not messages:
            empties += 1
            continue
        empties = 0
        for msg in messages:
            seen_execs.add(_exec_id(msg))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _poll_for_exec(ctx, queue_url, seen_execs: set, timeout_s=150.0, interval_s=15.0):
    """Poll until any delivery arrives; record its execution-id and return it."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=min(int(interval_s), 20)
        )
        messages = resp.get("Messages", [])
        if messages:
            msg = messages[0]
            exec_id = _exec_id(msg)
            seen_execs.add(exec_id)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return exec_id
    return None


def _poll_for_new_exec(ctx, queue_url, seen_execs: set, timeout_s=150.0, interval_s=15.0):
    """Poll for a delivery whose execution-id is NOT already in `seen_execs`. A delivery that
    replays an already-seen execution-id is deleted and ignored (a benign duplicate), and the
    poll continues -- it must not consume the watch window budget or be mistaken for a leak."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(int(interval_s), 20)
        )
        for msg in resp.get("Messages", []):
            exec_id = _exec_id(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if exec_id not in seen_execs:
                return exec_id
            seen_execs.add(exec_id)
    return None


def _poll_until_group_gone(ctx, scheduler, group_name, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            scheduler.get_schedule_group(Name=group_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"schedule group {group_name} did not fully disappear within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
