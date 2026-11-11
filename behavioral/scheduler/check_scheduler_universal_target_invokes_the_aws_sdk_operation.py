"""scheduler-universal-target-invokes-the-aws-sdk-operation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-universal-target-invokes-the-aws-sdk-operation"
GROUP = 'data-plane'
SERVICES = ['scheduler']

_DELIVERY_TIMEOUT_S = 300
# Measured on real AWS: the operation segment is the SDK's own lowerCamelCase name. The
# capitalised 'SendMessage' is refused with ValidationException.
_UNIVERSAL_ARN = "arn:aws:scheduler:::aws-sdk:sqs:sendMessage"


# timing:real-time — schedule: 50 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """A universal target (arn:aws:scheduler:::aws-sdk:sqs:sendMessage) makes Scheduler issue that
    SDK call with the Input as request body: the message body arrives byte-exact and the
    MessageAttributes map survives.
    """
    sch = ctx.client("scheduler")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _scheduler_role(ctx, queue_arn)

    marker = ctx.unique_name("marker-")
    attr_value = ctx.unique_name("attr-")
    request = {
        "QueueUrl": queue_url,
        "MessageBody": marker,
        "MessageAttributes": {
            "fidelity": {"DataType": "String", "StringValue": attr_value}
        },
    }
    name = _create_schedule(
        ctx,
        ScheduleExpression="rate(1 minute)",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={"Arn": _UNIVERSAL_ARN, "RoleArn": role_arn, "Input": json.dumps(request)},
    )

    got = sch.get_schedule(Name=name)
    assert got["Target"]["Arn"] == _UNIVERSAL_ARN, (
        f"the universal target ARN did not round-trip through GetSchedule: "
        f"{got['Target']['Arn']!r}"
    )

    msg = _await_message(
        ctx,
        queue_url,
        lambda m: m.get("Body") == marker,
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=f"the universal target of {name} issuing sqs:sendMessage",
    )
    assert msg["Body"] == marker, (
        f"the universal target delivered {msg['Body']!r}, expected the exact MessageBody from "
        f"the Input request body ({marker!r})"
    )
    delivered_attrs = msg.get("MessageAttributes") or {}
    assert delivered_attrs.get("fidelity", {}).get("StringValue") == attr_value, (
        f"the universal target dropped or mangled the MessageAttributes from its Input request "
        f"body: {delivered_attrs!r}"
    )



_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. The bounded retry in _create_schedule is the wait --
# there is no separate sleep here.
_CREATE_TIMEOUT_S = 180


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sched-q-"), tags=_MANAGED_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _scheduler_role(ctx, queue_arn: str) -> str:
    """An IAM role EventBridge Scheduler can assume, permitted to send to exactly this queue."""
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
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduler-target",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        ),
    )
    return arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound.

    The cleanup is registered from the name passed to the accepted call -- never re-looked-up.
    """
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
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
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name, kwargs.get("GroupName")))
    return name


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _await_message(ctx, queue_url, predicate, *, timeout_s, description):
    """Poll SQS until a message satisfying predicate arrives; returns the raw message."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if predicate(msg):
                return msg
            seen.append(msg.get("Body", ""))
    raise AssertionError(
        f"{description}: nothing matching arrived within {timeout_s}s. Bodies seen: {seen!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
