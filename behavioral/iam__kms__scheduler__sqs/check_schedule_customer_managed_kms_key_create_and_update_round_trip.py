"""schedule-customer-managed-kms-key-create-and-update-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schedule-customer-managed-kms-key-create-and-update-round-trip"
GROUP = "data-plane"
SERVICES = ["iam", "kms", "scheduler", "sqs"]

_CREATE_TIMEOUT_S = 180
_DELIVERY_TIMEOUT_S = 300
_MANAGED_TAGS_KV = [{"Key": "sim2real", "Value": "true"}]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation",
    "dp:api", "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """CreateSchedule and UpdateSchedule each accept a customer managed KmsKeyArn, GetSchedule
    echoes the key back, and the schedule keeps invoking its target under either key.
    """
    kms = ctx.client("kms")
    sch = ctx.client("scheduler")
    sqs = ctx.client("sqs")

    key1 = _create_key(ctx, kms, "first")
    key2 = _create_key(ctx, kms, "second")

    queue_url, queue_arn = _create_queue(ctx, sqs)
    role_arn = _execution_role(ctx, queue_arn, (key1, key2))

    marker1 = ctx.unique_name("marker-")
    name = _create_schedule(
        ctx, sch,
        KmsKeyArn=key1,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": marker1},
    )

    created = sch.get_schedule(Name=name)
    assert created["KmsKeyArn"] == key1, (
        f"GetSchedule returned KmsKeyArn {created['KmsKeyArn']!r} right after CreateSchedule, "
        f"expected the key passed to CreateSchedule ({key1!r})"
    )

    _await_message(
        sqs, queue_url, lambda body: body == marker1, timeout_s=_DELIVERY_TIMEOUT_S,
        description="the schedule, with its first KmsKeyArn, invoking its SQS target",
    )

    marker2 = ctx.unique_name("marker-")
    sch.update_schedule(
        Name=name,
        KmsKeyArn=key2,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": queue_arn, "RoleArn": role_arn, "Input": marker2},
    )

    updated = sch.get_schedule(Name=name)
    assert updated["KmsKeyArn"] == key2, (
        f"GetSchedule returned KmsKeyArn {updated['KmsKeyArn']!r} after UpdateSchedule switched "
        f"it to the second key ({key2!r})"
    )

    _await_message(
        sqs, queue_url, lambda body: body == marker2, timeout_s=_DELIVERY_TIMEOUT_S,
        description="the schedule, with its KmsKeyArn switched by UpdateSchedule, invoking its SQS target",
    )


def _create_key(ctx, kms, label: str) -> str:
    """A symmetric encrypt/decrypt KMS key; CreateSchedule and UpdateSchedule take its ARN."""
    key_id = kms.create_key(
        Description=ctx.unique_name(f"sim2real-behav-sched-{label}-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]


def _create_queue(ctx, sqs) -> tuple[str, str]:
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-q-"), tags={"sim2real": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _execution_role(ctx, queue_arn: str, key_arns: tuple[str, str]) -> str:
    """The role EventBridge Scheduler assumes: send to the queue, decrypt under either key."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sched-role-")
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
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduler-target-and-kms",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
                    {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": list(key_arns)},
                ],
            }
        ),
    )
    return arn


def _delete_role(iam, role_name: str) -> None:
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_schedule(ctx, sch, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound."""
    name = ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(3)
    ctx.on_cleanup(lambda: _delete_schedule(sch, name))
    return name


def _delete_schedule(sch, name: str) -> None:
    try:
        sch.delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_message(sqs, queue_url: str, predicate, *, timeout_s: float, description: str) -> None:
    """Poll SQS until a message satisfying predicate arrives."""
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if predicate(msg.get("Body")):
                return
            seen.append(msg.get("Body", ""))
    raise AssertionError(f"{description}: nothing matching arrived within {timeout_s}s; saw {seen!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
