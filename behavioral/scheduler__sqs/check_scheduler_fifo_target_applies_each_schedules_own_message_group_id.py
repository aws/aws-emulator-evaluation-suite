"""scheduler-fifo-target-applies-each-schedules-own-message-group-id."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-fifo-target-applies-each-schedules-own-message-group-id"
GROUP = "event-propagation"
SERVICES = ["scheduler", "sqs"]

_FIRE_OFFSET_S = 30
_DELIVERY_TIMEOUT_S = 240


# timing:real-time — schedule: 30 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Two schedules due at one instant against one FIFO queue, with different
    SqsParameters.MessageGroupId values, each deliver a message carrying their own group id and a
    SequenceNumber, so the group id is applied per schedule on the real FIFO path.
    """
    sch = ctx.client("scheduler")

    queue = _create_fifo_queue(ctx)
    role_arn = _scheduler_role(ctx, queue["arn"])

    group_a = ctx.unique_name("mgid-a-")
    group_b = ctx.unique_name("mgid-b-")
    # The bodies MUST differ: the queue has content-based deduplication enabled, so two identical
    # payloads inside the dedup interval would legitimately collapse into one message.
    marker_a = ctx.unique_name("payload-a-")
    marker_b = ctx.unique_name("payload-b-")

    # The instant is re-anchored on every CreateSchedule attempt: IAM propagation can hold the
    # call off, and an at() instant computed before that could be in the past when it is accepted.
    anchor: dict = {}

    def _anchored_expression() -> str:
        anchor["nominal"] = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0
        ) + datetime.timedelta(seconds=_FIRE_OFFSET_S)
        return f"at({anchor['nominal'].strftime('%Y-%m-%dT%H:%M:%S')})"

    name_a = _create_schedule(
        ctx,
        expression=_anchored_expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker_a}),
            "SqsParameters": {"MessageGroupId": group_a},
        },
    )
    nominal = anchor["nominal"]
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    name_b = _create_schedule(
        ctx,
        expression=lambda: expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": queue["arn"],
            "RoleArn": role_arn,
            "Input": json.dumps({"marker": marker_b}),
            "SqsParameters": {"MessageGroupId": group_b},
        },
    )

    echoed = sch.get_schedule(Name=name_a)["Target"]["SqsParameters"]["MessageGroupId"]
    assert echoed == group_a, (
        f"GetSchedule reports SqsParameters.MessageGroupId {echoed!r} for {name_a}, expected "
        f"{group_a!r}"
    )

    delivered = _collect_markers(
        ctx,
        queue["url"],
        {marker_a: group_a, marker_b: group_b},
        timeout_s=_DELIVERY_TIMEOUT_S,
        description=(
            f"schedules {name_a} (MessageGroupId={group_a}) and {name_b} "
            f"(MessageGroupId={group_b}), both due at {nominal.isoformat()} on FIFO queue "
            f"{queue['url']}"
        ),
    )

    for marker, expected_group, other_name in (
        (marker_a, group_a, name_b),
        (marker_b, group_b, name_a),
    ):
        assert marker in delivered, (
            f"the schedule configured with MessageGroupId={expected_group!r} never delivered "
            f"{marker!r} within {_DELIVERY_TIMEOUT_S}s; markers seen: {sorted(delivered)!r}"
        )
        attrs = delivered[marker]
        actual_group = attrs.get("MessageGroupId")
        assert actual_group == expected_group, (
            f"the message carrying {marker!r} arrived with MessageGroupId {actual_group!r}; the "
            f"schedule that produced it configured {expected_group!r} (the other schedule "
            f"{other_name} configured a different value, so a constant or cross-assigned group id "
            f"is caught here)"
        )
        assert attrs.get("SequenceNumber"), (
            f"the message carrying {marker!r} has no SequenceNumber system attribute, which every "
            f"FIFO delivery carries; the delivery did not traverse the FIFO path. Attributes: "
            f"{attrs!r}"
        )

    assert delivered[marker_a]["MessageGroupId"] != delivered[marker_b]["MessageGroupId"], (
        f"both deliveries reported the same MessageGroupId "
        f"{delivered[marker_a]['MessageGroupId']!r}; the field is being taken from somewhere other "
        f"than each schedule's own SqsParameters"
    )


# ===== helpers =====

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. The bounded retry is the wait.
_CREATE_TIMEOUT_S = 180


def _deadline(ctx, cap_s: float) -> float:
    """A monotonic deadline `cap_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (cap_s if left is None else min(cap_s, max(left - 5, 0)))


def _create_fifo_queue(ctx) -> dict[str, str]:
    """A FIFO queue with content-based deduplication, which the SqsParameters contract requires."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sched-fifo-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags=_MANAGED_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    got = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn", "FifoQueue", "ContentBasedDeduplication"]
    )["Attributes"]
    assert got["FifoQueue"] == "true" and got["ContentBasedDeduplication"] == "true", (
        f"the target queue must be FIFO with content-based deduplication before Scheduler is aimed "
        f"at it, or the delivery would fail for the wrong reason; SQS reports {got!r}"
    )
    return {"url": url, "arn": got["QueueArn"]}


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


def _create_schedule(ctx, *, expression, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException within a bound.

    `expression` is called on every attempt, so an at() instant can be re-anchored per attempt.
    """
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = _deadline(ctx, _CREATE_TIMEOUT_S)
    last = None
    while True:
        try:
            sch.create_schedule(Name=name, ScheduleExpression=expression(), **kwargs)
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
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name, kwargs.get("GroupName")))
    return name


def _delete_schedule(ctx, name: str, group: str | None = None) -> None:
    extra = {"GroupName": group} if group else {}
    try:
        ctx.client("scheduler").delete_schedule(Name=name, **extra)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _collect_markers(ctx, queue_url: str, wanted: dict[str, str], *, timeout_s: float,
                     description: str) -> dict[str, dict]:
    """Poll until every marker in `wanted` has been seen; return {marker: system attributes}.

    Reads ALL system attributes, which is where SQS reports MessageGroupId and SequenceNumber -- the
    fields the schedule's SqsParameters is supposed to have driven. Does NOT raise on a partial
    result: WHICH markers are missing is the finding, and the caller asserts on it with a readable
    message. It DOES raise when nothing at all arrived.
    """
    sqs = ctx.client("sqs")
    found: dict[str, dict] = {}
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline and set(found) != set(wanted):
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageSystemAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            raw = msg.get("Body", "")
            for marker in wanted:
                if marker in raw and marker not in found:
                    found[marker] = dict(msg["Attributes"])
    if not found:
        raise AssertionError(
            f"{description}: neither schedule delivered anything within {timeout_s}s"
        )
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
