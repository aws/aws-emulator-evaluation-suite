"""message-structure-json-selects-the-protocol-body-and-falls-back-to-default."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "message-structure-json-selects-the-protocol-body-and-falls-back-to-default"
GROUP = "publish-semantics"
SERVICES = ["sns"]

_SCENARIO = "sns-json-structure"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """MessageStructure=json delivers the "sqs" body to an SQS subscriber when present, else
    "default"; an unrecognised top-level key is ignored, not rejected.

    Reference: https://docs.aws.amazon.com/sns/latest/api/API_Publish.html
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    # Not RawMessageDelivery: reading the envelope keeps the raw-delivery interaction out.
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    # Leg 1 — a protocol key present for this subscription's protocol wins over default.
    sqs_wins = ctx.unique_name("sim2real-behav-jsonstruct-sqs-branch-")
    default_loses = ctx.unique_name("sim2real-behav-jsonstruct-default-loses-")
    # Leg 2 — no key for this protocol, so default is the fallback.
    default_wins = ctx.unique_name("sim2real-behav-jsonstruct-default-wins-")
    email_never = ctx.unique_name("sim2real-behav-jsonstruct-email-never-")
    # Leg 3 — an unrecognised top-level key is ignored, and the sqs key still wins.
    sqs_wins_again = ctx.unique_name("sim2real-behav-jsonstruct-sqs-again-")
    default_loses_again = ctx.unique_name("sim2real-behav-jsonstruct-default-loses-again-")
    bogus_never = ctx.unique_name("sim2real-behav-jsonstruct-bogus-never-")

    payloads = [
        {"default": default_loses, "sqs": sqs_wins},
        {"default": default_wins, "email": email_never},
        {"default": default_loses_again, "sqs": sqs_wins_again,
         "not-a-transport-protocol": bogus_never},
    ]
    for payload in payloads:
        resp = sns.publish(TopicArn=topic_arn, Message=json.dumps(payload),
                           MessageStructure="json")
        assert resp.get("MessageId"), (
            f"expected a MessageId for the json-structured publish {sorted(payload)}; got "
            f"{resp!r} — leg 3's unrecognised key must be IGNORED, not rejected"
        )

    expected = {sqs_wins, default_wins, sqs_wins_again}
    forbidden = {default_loses, email_never, default_loses_again, bogus_never}
    envelopes = _await_envelopes(
        ctx, queue_url, expected, timeout_s=120.0,
        description=(
            "MessageStructure=json must deliver the sqs branch when present (leg 1 and 3) and "
            "the default branch when it is not (leg 2); any of the discarded branches arriving "
            "instead is a wrong selection, not a slow one"
        ),
        forbidden=forbidden,
    )

    for marker in sorted(expected):
        # Message == marker holds by construction; selection exactness is carried by
        # `expected` / `forbidden` above.
        envelope = envelopes[marker]
        assert envelope["Type"] == "Notification", (
            f"expected Type 'Notification' on the delivered envelope for {marker!r}, got "
            f"{envelope['Type']!r}"
        )
        assert envelope["TopicArn"] == topic_arn, (
            f"expected TopicArn {topic_arn!r} on the envelope for {marker!r}, got "
            f"{envelope['TopicArn']!r}"
        )

    # Nothing else may arrive: a target that delivers BOTH branches of a json payload would
    # otherwise satisfy every assertion above.
    leaked = _drain(ctx, queue_url, window_s=30.0)
    assert leaked == [], (
        "exactly three notifications must result from three json-structured publishes; a 30s "
        f"window after all three arrived produced {leaked!r}"
    )


def _await_envelopes(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                     description: str, forbidden: set[str]) -> dict[str, dict]:
    """Long-poll until a notification envelope has arrived for every wanted Message value.

    RAISES on the deadline, and RAISES immediately on a forbidden Message value — a wrong
    branch is a failure, not something to keep waiting through.
    """
    sqs = ctx.client("sqs")
    found: dict[str, dict] = {}
    outstanding = set(wanted)
    others: list[str] = []
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            envelope = json.loads(msg["Body"])
            message = envelope.get("Message")
            if message in forbidden:
                raise AssertionError(
                    f"{description}: the discarded branch {message!r} was delivered"
                )
            if message in outstanding:
                outstanding.discard(message)
                found[message] = envelope
            else:
                others.append(str(message)[:60])
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s; "
                f"other Message values seen: {others!r}"
            )
    return found


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    arn = sns.create_topic(
        Name=name, Attributes=dict(attributes or {}), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    url = sqs.create_queue(
        QueueName=name,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None,
                           timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"subscription {sub_arn} leaves PendingConfirmation",
    )
    return sub_arn


def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}"
            )
        time.sleep(interval_s)
        value = fn()
    return value


def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll for the whole window and return every body seen."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
