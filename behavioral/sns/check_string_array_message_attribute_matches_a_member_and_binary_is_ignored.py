"""string-array-message-attribute-matches-a-member-and-binary-is-ignored."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "string-array-message-attribute-matches-a-member-and-binary-is-ignored"
GROUP = "publish-semantics"
SERVICES = ["sns"]

_SCENARIO = "sns-attr-types"

_ARRAY_MATCHING = ["urgent", "billing"]
_ARRAY_MISSING = ["urgent", "shipping"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A String.Array attribute matches a filter policy on any member; a Binary one is ignored.

    The Binary attribute is still delivered, and both keep their declared types in the envelope.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/subscription-filter-policy-constraints.html
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)

    control_url, control_arn = _create_queue_for_topic(ctx, topic_arn)
    filtered_url, filtered_arn = _create_queue_for_topic(ctx, topic_arn)

    _subscribe_and_confirm(ctx, topic_arn, control_arn)
    filtered_sub = _subscribe_and_confirm(
        ctx, topic_arn, filtered_arn,
        attributes={"FilterPolicy": json.dumps({"tags": ["billing"]})},
    )

    member_match = ctx.unique_name("sim2real-behav-strarray-member-match-")
    member_miss = ctx.unique_name("sim2real-behav-strarray-member-miss-")
    binary_ignored = ctx.unique_name("sim2real-behav-strarray-binary-ignored-")
    binary_bytes = json.dumps(_ARRAY_MATCHING).encode("utf-8")

    started = time.monotonic()
    sns.publish(TopicArn=topic_arn, Message=member_match, MessageAttributes={
        "tags": {"DataType": "String.Array", "StringValue": json.dumps(_ARRAY_MATCHING)}})
    sns.publish(TopicArn=topic_arn, Message=member_miss, MessageAttributes={
        "tags": {"DataType": "String.Array", "StringValue": json.dumps(_ARRAY_MISSING)}})
    sns.publish(TopicArn=topic_arn, Message=binary_ignored, MessageAttributes={
        "tags": {"DataType": "Binary", "BinaryValue": binary_bytes}})

    # ---- barrier + representation, both on the unfiltered twin ---------------------------
    envelopes = _await_envelopes(
        ctx, control_url, {member_match, member_miss, binary_ignored}, timeout_s=120.0,
        description=("the unfiltered twin must receive all three messages; without this the "
                     "absences at the filtered arm prove nothing"),
        forbidden=set(),
    )
    latency = max(max(e[1] for e in envelopes.values()) - started, 1.0)

    array_attr = envelopes[member_match][0]["MessageAttributes"]["tags"]
    assert array_attr["Type"] == "String.Array", (
        "expected the delivered envelope to declare Type 'String.Array' for an array "
        f"attribute, got {array_attr['Type']!r}"
    )
    assert json.loads(array_attr["Value"]) == _ARRAY_MATCHING, (
        f"expected the array attribute Value to parse back to {_ARRAY_MATCHING!r} in order, "
        f"got {array_attr['Value']!r}"
    )

    binary_attr = envelopes[binary_ignored][0]["MessageAttributes"]["tags"]
    assert binary_attr["Type"] == "Binary", (
        "expected the Binary attribute to be DELIVERED with Type 'Binary' — the point of the "
        f"leg below is that it is delivered but not filtered on; got {binary_attr['Type']!r}"
    )
    assert base64.b64decode(binary_attr["Value"]) == binary_bytes, (
        f"expected the Binary attribute bytes preserved as {binary_bytes!r}, got "
        f"{base64.b64decode(binary_attr['Value'])!r}"
    )

    # ---- the filtered arm: exactly the member match ---------------------------------------
    _await_envelopes(
        ctx, filtered_url, {member_match}, timeout_s=max(60.0, 3.0 * latency + 20.0),
        description=("a String.Array attribute must satisfy {\"tags\": [\"billing\"]} when "
                     "'billing' is one of its members"),
        forbidden={member_miss, binary_ignored},
    )
    window = max(3.0 * latency, 15.0)
    leaked = _drain(ctx, filtered_url, window_s=window)
    assert leaked == [], (
        f"neither the non-member array nor the Binary attribute may satisfy "
        f"{{\"tags\": [\"billing\"]}}: a {window:.0f}s window (>=3x the measured control "
        f"latency of {latency:.1f}s), begun after the matching message had already arrived, "
        f"produced {leaked!r}"
    )
    approx = int(sqs.get_queue_attributes(
        QueueUrl=filtered_url, AttributeNames=["ApproximateNumberOfMessages"],
    )["Attributes"]["ApproximateNumberOfMessages"])
    assert approx == 0, (
        "second independent observable for the absence: expected ApproximateNumberOfMessages "
        f"== 0 on the filtered queue, got {approx}"
    )

    # ---- repair exactly one thing: name a member the other array DOES carry ---------------
    _set_filter_policy(ctx, filtered_sub, {"tags": ["shipping"]})
    _republish_until_delivered(
        ctx, topic_arn, filtered_url, member_miss,
        {"tags": {"DataType": "String.Array",
                  "StringValue": json.dumps(_ARRAY_MISSING)}},
        attempts=3, per_attempt_s=max(30.0, 2.0 * latency),
        description=("once the policy names 'shipping', the identical array attribute must "
                     "match on that member and be delivered — this proves member matching "
                     "rather than the array type suppressing everything"),
    )


def _set_filter_policy(ctx, sub_arn: str, policy: dict, *, timeout_s: float = 60.0) -> None:
    """Replace a subscription's FilterPolicy and poll until an independent read matches."""
    sns = ctx.client("sns")
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicy",
        AttributeValue=json.dumps(policy))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("FilterPolicy"),
        lambda raw: bool(raw) and json.loads(raw) == policy,
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"GetSubscriptionAttributes reflects the FilterPolicy {policy!r}",
    )


def _await_envelopes(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                     description: str,
                     forbidden: set[str]) -> dict[str, tuple[dict, float]]:
    """Long-poll until an envelope arrives for every wanted Message; return {Message: (env, t)}.

    Raises on the deadline, and immediately on a forbidden Message.
    """
    sqs = ctx.client("sqs")
    found: dict[str, tuple[dict, float]] = {}
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
                    f"{description}: {message!r} must not have been delivered here"
                )
            if message in outstanding:
                outstanding.discard(message)
                found[message] = (envelope, time.monotonic())
            else:
                others.append(str(message)[:60])
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s; "
                f"other Message values seen: {others!r}"
            )
    return found


def _republish_until_delivered(ctx, topic_arn: str, queue_url: str, marker: str,
                               attributes: dict, *, attempts: int, per_attempt_s: float,
                               description: str) -> None:
    """Republish the same marker up to `attempts` times until it lands; raise if it never does.

    A FilterPolicy update is eventually consistent on the delivery path, hence the retry."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    seen: list[str] = []
    for _ in range(attempts):
        sns.publish(TopicArn=topic_arn, Message=marker, MessageAttributes=attributes)
        deadline = time.monotonic() + per_attempt_s
        while time.monotonic() < deadline:
            resp = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                seen.append(json.loads(msg["Body"]).get("Message"))
            if marker in seen:
                return
    raise AssertionError(
        f"{description}: {marker!r} was never delivered across {attempts} republishes of "
        f"{per_attempt_s:.0f}s each; Message values seen: {seen!r}"
    )


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
