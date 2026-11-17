"""create-schedule-nonexistent-kms-key-arn-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schedule-nonexistent-kms-key-arn-rejected"
GROUP = "data-plane"
SERVICES = ["iam", "kms", "scheduler", "sqs"]

_CREATE_TIMEOUT_S = 180


@tags(
    "axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """CreateSchedule rejects a KmsKeyArn naming a key that does not exist, and a schedule with a
    key this check actually created is accepted right after.
    """
    kms = ctx.client("kms")
    sch = ctx.client("scheduler")
    sqs = ctx.client("sqs")

    key_arn = _create_key(ctx, kms)
    queue_url, queue_arn = _create_queue(ctx, sqs)
    role_arn = _execution_role(ctx, queue_arn, key_arn)

    target = {"Arn": queue_arn, "RoleArn": role_arn, "Input": ctx.unique_name("marker-")}
    common = dict(
        ScheduleExpression="rate(1 hour)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target=target,
    )

    # The positive control is created first so the role's trust policy has already propagated by
    # the time the negative call below reaches CreateSchedule's own KmsKeyArn validation.
    name = _create_schedule(ctx, sch, KmsKeyArn=key_arn, **common)
    created = sch.get_schedule(Name=name)
    assert created["KmsKeyArn"] == key_arn, (
        f"the positive control's GetSchedule returned KmsKeyArn {created['KmsKeyArn']!r}, "
        f"expected the key this check created ({key_arn!r})"
    )

    missing_key_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:key/{uuid.uuid4()}"
    code, message = _error(lambda: sch.create_schedule(
        Name=ctx.unique_name("sim2real-behav-sched-"), KmsKeyArn=missing_key_arn, **common,
    ))
    assert code == "ValidationException", (
        f"CreateSchedule with a KmsKeyArn naming a nonexistent key returned {code!r}, expected "
        f"ValidationException"
    )
    assert message == (
        f"Unable to access the KMS key {missing_key_arn}. Check that the key exists, and that "
        f"the IAM principal you use to call EventBridge Scheduler has permission to access the "
        f"key, then try again."
    ), f"unexpected ValidationException message: {message!r}"

    pages = sch.get_paginator("list_schedules").paginate()
    names = {s["Name"] for page in pages for s in page["Schedules"]}
    assert name in names, "the positive control's schedule vanished"
    assert not any(
        n != name and n.startswith("sim2real-behav-sched-") for n in names
    ), "the rejected CreateSchedule call left a second schedule behind"


def _error(fn) -> tuple[str, str]:
    """The Error (Code, Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_key(ctx, kms) -> str:
    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-sched-neg-key-"),
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


def _execution_role(ctx, queue_arn: str, key_arn: str) -> str:
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
                    {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key_arn},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
