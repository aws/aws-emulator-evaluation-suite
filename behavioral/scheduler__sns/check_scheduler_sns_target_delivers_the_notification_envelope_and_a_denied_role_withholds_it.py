"""scheduler-sns-target-delivers-the-notification-envelope-and-a-denied-role-withholds-it."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-sns-target-delivers-the-notification-envelope-and-a-denied-role-withholds-it"
GROUP = "event-propagation"
SERVICES = ["scheduler", "sns"]

_CADENCE = "rate(1 minute)"
_FIRST_DELIVERY_TIMEOUT_S = 240
_DLQ_TIMEOUT_S = 240
# Held after the dead-letter event proves the denied schedule dispatched and was refused.
_EXTRA_ABSENCE_S = 60
_RESTORE_TIMEOUT_S = 240
# Scheduler documents no lateness bound, so the slack is generous.
_LATE_SLACK_S = 300


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A schedule targeting an SNS topic delivers an SNS Notification envelope carrying its Input;
    a role without sns:Publish is dead-lettered with AuthorizationError and delivers nothing until
    the permission is granted.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-templated.html
    """
    topic_arn = _create_topic(ctx)
    inbox = _create_queue(ctx, "sim2real-behav-sched-sns-inbox-")
    dlq = _create_queue(ctx, "sim2real-behav-sched-sns-dlq-")
    _subscribe(ctx, topic_arn, inbox)

    allowed_role = _scheduler_role(
        ctx,
        "sim2real-behav-sched-sns-allow-",
        [
            {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]},
        ],
    )
    # Can reach the DLQ (so the refusal is observable) and NOT the topic.
    denied_role, denied_role_name = _scheduler_role(
        ctx,
        "sim2real-behav-sched-sns-deny-",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": dlq["arn"]}],
        return_name=True,
    )

    allowed_marker = ctx.unique_name("permitted-")
    denied_marker = ctx.unique_name("withheld-")

    allowed_schedule = _create_schedule(
        ctx,
        ScheduleExpression=_CADENCE,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": topic_arn,
            "RoleArn": allowed_role,
            "Input": json.dumps(
                {"marker": allowed_marker, "at": "<aws.scheduler.scheduled-time>"}
            ),
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )
    denied_schedule = _create_schedule(
        ctx,
        ScheduleExpression=_CADENCE,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": topic_arn,
            "RoleArn": denied_role,
            "Input": json.dumps({"marker": denied_marker, "at": "<aws.scheduler.scheduled-time>"}),
            "DeadLetterConfig": {"Arn": dlq["arn"]},
        },
    )

    envelopes = _collect_envelopes(
        ctx,
        inbox["url"],
        {allowed_marker, denied_marker},
        timeout_s=_FIRST_DELIVERY_TIMEOUT_S,
        stop_when=lambda seen: allowed_marker in seen,
    )
    assert allowed_marker in envelopes, (
        f"the permitted schedule {allowed_schedule} published nothing the subscriber received within "
        f"{_FIRST_DELIVERY_TIMEOUT_S}s, so no absence can be attributed to the denied role; "
        f"envelopes seen for markers {sorted(envelopes)!r}"
    )
    envelope = envelopes[allowed_marker]
    assert envelope["Type"] == "Notification", (
        f"the subscriber received Type {envelope['Type']!r}, expected 'Notification' — the schedule's "
        f"publish did not arrive as an SNS notification envelope"
    )
    assert envelope["TopicArn"] == topic_arn, (
        f"the envelope names TopicArn {envelope['TopicArn']!r}, expected {topic_arn!r}"
    )
    assert envelope["MessageId"], (
        f"the envelope carries no MessageId, which every SNS notification assigns: {envelope!r}"
    )
    published = json.loads(envelope["Message"])
    assert published["marker"] == allowed_marker, (
        f"the envelope's Message carries marker {published.get('marker')!r}, expected "
        f"{allowed_marker!r}"
    )
    assert "<aws.scheduler" not in envelope["Message"], (
        f"a reserved context-attribute token survived unsubstituted into the published message: "
        f"{envelope['Message']!r}"
    )
    scheduled = _parse_iso(published["at"])
    sns_stamp = _parse_iso(envelope["Timestamp"])
    early = (scheduled - sns_stamp).total_seconds()
    late = (sns_stamp - scheduled).total_seconds()
    assert early <= 5, (
        f"SNS stamped the notification at {sns_stamp.isoformat()}, {early:.1f}s BEFORE the instant "
        f"Scheduler reported as its scheduled time ({scheduled.isoformat()}); a Mode=OFF schedule "
        f"cannot publish early"
    )
    assert late <= _LATE_SLACK_S, (
        f"SNS stamped the notification at {sns_stamp.isoformat()}, {late:.1f}s after the scheduled "
        f"instant {scheduled.isoformat()}, beyond the {_LATE_SLACK_S}s slack"
    )

    # The dead-letter event proves the denied occurrence was dispatched and refused.
    dlq_event = _await_dlq_event(
        ctx,
        dlq["url"],
        denied_marker,
        timeout_s=_DLQ_TIMEOUT_S,
        description=(
            f"the denied schedule {denied_schedule}, whose role {denied_role} carries no sns:Publish"
        ),
    )
    refusal = dlq_event["MessageAttributes"]["ERROR_CODE"]["StringValue"]
    assert refusal == "AuthorizationError", (
        f"the denied schedule's dead-letter event reports ERROR_CODE={refusal!r}; expected "
        f"AuthorizationError, the publish refused for lack of sns:Publish"
    )
    # message varies: ERROR_MESSAGE names the assumed-role session, whose name is a fresh
    # 32-hex token per invocation that the check cannot know in advance.
    assert dlq_event["MessageAttributes"]["SCHEDULE_ARN"]["StringValue"] == denied_schedule, (
        f"the dead-letter event names SCHEDULE_ARN "
        f"{dlq_event['MessageAttributes']['SCHEDULE_ARN']['StringValue']!r}, expected the denied "
        f"schedule {denied_schedule!r} — the two arms' events must not be crossed"
    )

    watched = _collect_envelopes(
        ctx,
        inbox["url"],
        {allowed_marker, denied_marker},
        timeout_s=_EXTRA_ABSENCE_S,
        stop_when=lambda seen: False,
    )
    assert denied_marker not in watched, (
        f"the denied schedule's payload {denied_marker!r} reached the subscriber even though its "
        f"role has no sns:Publish and its occurrence was dead-lettered with {refusal!r}: "
        f"{watched[denied_marker]!r}"
    )
    assert allowed_marker in watched, (
        f"the permitted schedule stopped delivering during the absence window, so the window proves "
        f"nothing about the denied schedule: markers seen {sorted(watched)!r}"
    )

    ctx.client("iam").put_role_policy(
        RoleName=denied_role_name,
        PolicyName="scheduler-target-restored",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn}
                ],
            }
        ),
    )
    restored = _collect_envelopes(
        ctx,
        inbox["url"],
        {denied_marker},
        timeout_s=_RESTORE_TIMEOUT_S,
        stop_when=lambda seen: denied_marker in seen,
    )
    assert denied_marker in restored, (
        f"after granting sns:Publish on {topic_arn} to {denied_role_name} and changing nothing else, "
        f"the previously withheld schedule {denied_schedule} still delivered nothing within "
        f"{_RESTORE_TIMEOUT_S}s; the absence above cannot be attributed to the permission"
    )
    restored_body = json.loads(restored[denied_marker]["Message"])
    assert restored_body["marker"] == denied_marker, (
        f"the restored delivery carries marker {restored_body.get('marker')!r}, expected "
        f"{denied_marker!r}"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAGS = {"sim2real:managed": "true"}
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException; the bounded retry is the wait.
_CREATE_TIMEOUT_S = 180


def _parse_iso(value: str) -> datetime.datetime:
    """Parse an ISO-8601 UTC instant with a trailing Z (Scheduler scheduled-time, SNS Timestamp)."""
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sched-topic-"), Tags=_MANAGED_TAGS_KV
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, prefix: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags=_MANAGED_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _subscribe(ctx, topic_arn: str, queue: dict[str, str]) -> None:
    """Subscribe the queue to the topic, with the queue policy SNS needs to deliver into it.

    RawMessageDelivery stays off: raw delivery would strip the envelope this check reads.
    """
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    sqs.set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue["arn"],
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue["arn"])[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))


def _scheduler_role(ctx, prefix: str, statements: list[dict], *, return_name: bool = False):
    """An IAM role EventBridge Scheduler can assume, carrying exactly `statements`."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
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
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return (arn, role_name) if return_name else arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _deadline(ctx, timeout_s: float) -> float:
    """Monotonic deadline ``timeout_s`` ahead, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException; return its ARN."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = _deadline(ctx, _CREATE_TIMEOUT_S)
    last = None
    while True:
        try:
            arn = sch.create_schedule(Name=name, **kwargs)["ScheduleArn"]
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
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return arn


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _collect_envelopes(ctx, queue_url: str, wanted: set[str], *, timeout_s: float, stop_when):
    """Poll the subscriber queue for SNS envelopes, keyed by the marker inside `Message`.

    `stop_when=lambda seen: False` makes it a fixed observation window. Never raises.
    """
    sqs = ctx.client("sqs")
    found: dict[str, dict] = {}
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                envelope = json.loads(msg.get("Body", ""))
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(envelope, dict):
                continue
            message = envelope.get("Message") or ""
            for marker in wanted:
                if marker in message and marker not in found:
                    found[marker] = envelope
        if stop_when(set(found)):
            return found
    return found


def _await_dlq_event(ctx, queue_url: str, marker: str, *, timeout_s: float, description: str):
    """Poll the DLQ until an event carrying `marker` arrives; raise on timeout.

    Events with any other marker are discarded, so they cannot pass for the denied arm's refusal.
    """
    sqs = ctx.client("sqs")
    discarded: list[str] = []
    deadline = _deadline(ctx, timeout_s)
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=20,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg.get("Body", ""):
                return msg
            discarded.append(msg.get("Body", ""))
    raise AssertionError(
        f"no dead-letter event for {description} arrived within {timeout_s}s, so its publish was "
        f"never OBSERVED being refused and any absence at the subscriber would be unattributable. "
        f"Other events seen and discarded: {discarded!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
