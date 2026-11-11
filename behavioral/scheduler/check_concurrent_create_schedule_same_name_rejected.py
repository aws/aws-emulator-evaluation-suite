"""concurrent-create-schedule-same-name-rejected."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-schedule-same-name-rejected"
GROUP = "concurrency"
SERVICES = ["scheduler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateSchedule calls for the same Name: exactly one wins, the other is rejected."""
    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_scheduler_role(ctx, queue_arn)
    group_name = _create_group(ctx)
    schedule_name = ctx.unique_name("sim2real-sched-dupe-")

    scheduler = ctx.client("scheduler")

    def _create(version: str):
        scheduler.create_schedule(
            Name=schedule_name,
            GroupName=group_name,
            ScheduleExpression="rate(1 hour)",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={
                "Arn": queue_arn,
                "RoleArn": role_arn,
                "Input": json.dumps({"marker": f"dupe-{version}"}),
            },
        )
        return version

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_create, "A")
        fut_b = pool.submit(_create, "B")
        results = {}
        for label, fut in (("A", fut_a), ("B", fut_b)):
            try:
                results[label] = ("ok", fut.result())
            except ClientError as exc:
                results[label] = ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, schedule_name, group_name))

    successes = [label for label, (kind, _) in results.items() if kind == "ok"]
    errors = [(label, val) for label, (kind, val) in results.items() if kind == "error"]

    assert len(successes) == 1, f"expected exactly one racer to succeed, got {results}"
    assert len(errors) == 1, f"expected exactly one racer to be rejected, got {results}"
    rejected_code, rejected_message = errors[0][1]
    assert rejected_code == "ConflictException", f"expected ConflictException, got {rejected_code!r}"
    expected = f"Schedule {schedule_name} already exists."
    assert rejected_message == expected, f"expected {expected!r}, got {rejected_message!r}"

    # Effect: the persisted schedule matches the winner, not a merge of both attempts.
    winner = successes[0]
    got = scheduler.get_schedule(Name=schedule_name, GroupName=group_name)
    persisted_marker = json.loads(got["Target"]["Input"])["marker"]
    assert persisted_marker == f"dupe-{winner}", (
        f"expected persisted target to match racer {winner!r}'s input, got marker {persisted_marker!r}"
    )

    # Positive control: CreateSchedule with a fresh, non-colliding name still works normally.
    control_name = ctx.unique_name("sim2real-sched-ctrl-")
    scheduler.create_schedule(
        Name=control_name,
        GroupName=group_name,
        ScheduleExpression="rate(1 hour)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": queue_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": "control"}),
        },
    )
    ctx.on_cleanup(lambda: _delete_schedule_safe(ctx, control_name, group_name))
    control = scheduler.get_schedule(Name=control_name, GroupName=group_name)
    assert control["Name"] == control_name, (
        f"expected control schedule {control_name!r} to be readable by its own name, got {control['Name']!r}"
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
    scheduler.create_schedule_group(
        Name=name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
