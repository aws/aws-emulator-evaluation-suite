"""update-schedule-creation-date-fixed-last-modification-advances."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schedule-creation-date-fixed-last-modification-advances"
GROUP = "lifecycle-timestamps"
SERVICES = ["iam", "scheduler", "sqs"]

_ASSUME_ROLE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "scheduler.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _delivery_role(ctx):
    """Create a role Scheduler can assume, able to send to any SQS queue the check made."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-exec-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ASSUME_ROLE_TRUST),
    )["Role"]

    def _remove_role():
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_remove_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-scheduler-send-to-queue",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
        }),
    )
    return role["Arn"]


def _queue_arn(ctx, name):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]

    def _remove_queue():
        try:
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
                raise

    ctx.on_cleanup(_remove_queue)
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_with_role_wait(sch, *, deadline_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """CreateSchedule validates the execution role at call time; retry only while IAM has not
    yet propagated a freshly created role, never any other failure."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return sch.create_schedule(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume the role" in message and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedule replaces expression, flexible window, target, state and description;
    CreationDate stays fixed and LastModificationDate advances past its prior value.
    """
    sch = ctx.client("scheduler")
    role_arn = _delivery_role(ctx)
    name = ctx.unique_name("sim2real-behav-timekeeper-")
    opening_queue = _queue_arn(ctx, ctx.unique_name("sim2real-behav-sched-open-"))
    closing_queue = _queue_arn(ctx, ctx.unique_name("sim2real-behav-sched-close-"))

    _create_with_role_wait(
        sch,
        Name=name,
        ScheduleExpression="cron(15 10 * * ? *)",
        FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 20},
        Target={"Arn": opening_queue, "RoleArn": role_arn, "Input": json.dumps({"phase": "opening"})},
        State="ENABLED",
        Description="opening configuration",
    )
    ctx.on_cleanup(lambda: sch.delete_schedule(Name=name))

    opening = sch.get_schedule(Name=name)

    sch.update_schedule(
        Name=name,
        ScheduleExpression="rate(10 minutes)",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={"Arn": closing_queue, "RoleArn": role_arn, "Input": json.dumps({"phase": "closing"})},
        State="DISABLED",
        Description="closing configuration",
    )
    closing = sch.get_schedule(Name=name)

    assert closing["ScheduleExpression"] == "rate(10 minutes)", (
        f"expected the replaced ScheduleExpression 'rate(10 minutes)', got "
        f"{closing['ScheduleExpression']!r}"
    )
    assert closing["State"] == "DISABLED", (
        f"expected the replaced State 'DISABLED', got {closing['State']!r}"
    )
    assert closing["Description"] == "closing configuration", (
        f"expected the replaced Description 'closing configuration', got {closing.get('Description')!r}"
    )
    assert closing["Target"]["Arn"] == closing_queue, (
        f"expected the replaced Target.Arn {closing_queue!r}, got {closing['Target']['Arn']!r}"
    )
    assert closing["Target"]["RoleArn"] == role_arn, (
        f"expected Target.RoleArn to stay {role_arn!r}, got {closing['Target']['RoleArn']!r}"
    )
    assert closing["Target"].get("Input") == json.dumps({"phase": "closing"}), (
        f"expected the replaced Target.Input '{{\"phase\": \"closing\"}}', got "
        f"{closing['Target'].get('Input')!r}"
    )
    assert closing["FlexibleTimeWindow"] == {"Mode": "OFF"}, (
        f"switching FlexibleTimeWindow to Mode 'OFF' must drop MaximumWindowInMinutes, "
        f"got {closing['FlexibleTimeWindow']!r}"
    )
    assert closing["CreationDate"] == opening["CreationDate"], (
        f"CreationDate must stay {opening['CreationDate']!r} across an update, got "
        f"{closing['CreationDate']!r}"
    )
    assert closing["LastModificationDate"] > opening["LastModificationDate"], (
        f"expected LastModificationDate to advance past {opening['LastModificationDate']!r}, "
        f"got {closing['LastModificationDate']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
