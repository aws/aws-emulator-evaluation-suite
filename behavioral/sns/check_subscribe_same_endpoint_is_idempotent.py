"""subscribe-same-endpoint-is-idempotent."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "subscribe-same-endpoint-is-idempotent"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']


def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn


def _fake_queue_arn(topic_arn, name=None):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs
    subscriptions without verifying the queue exists, keeping this single-service)."""
    parts = topic_arn.split(":")
    name = name or f"sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"


def _subscribe(client, ctx, topic_arn, queue_arn, attributes=None):
    """Subscribe an sqs endpoint; register unsubscribe cleanup; return the SubscriptionArn."""
    kwargs = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = client.subscribe(**kwargs)["SubscriptionArn"]
    if sub_arn and sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: client.unsubscribe(SubscriptionArn=sub_arn))
    return sub_arn


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(val); raise AssertionError on deadline miss."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _error(fn):
    """(code, message) for a refused call; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _sub_arns(client, topic_arn):
    return [s["SubscriptionArn"] for s in
            client.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A repeat Subscribe on the same (topic, protocol, endpoint) returns the same SubscriptionArn
    without a second subscription; identical or omitted Attributes are accepted, different ones are
    refused with InvalidParameter and not applied, and a different endpoint gets a new subscription.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-subidem-"))
    endpoint = _fake_queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-subidem-q-"))

    first = _subscribe(sns, ctx, topic_arn, endpoint)
    assert first and first != "pending confirmation", (
        f"expected an auto-confirmed sqs SubscriptionArn, got {first!r}"
    )

    second = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=endpoint)["SubscriptionArn"]
    assert second == first, (
        "a repeat Subscribe with the identical (topic, protocol, endpoint) triple must "
        f"return the same SubscriptionArn; got {second!r} != {first!r}"
    )

    arns = _poll(
        lambda: _sub_arns(sns, topic_arn),
        lambda a: len(a) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
        what="the subscription is listed",
    )
    assert arns == [first], (
        f"expected exactly one subscription on the topic after two Subscribe calls, got {arns}"
    )

    # Attributes are part of the idempotency key, so a repeat with different ones is refused.
    # SNS stores a filter policy with insignificant whitespace stripped, so submit the compact
    # form to make the read-back a byte comparison.
    filter_policy = json.dumps({"event": ["created"]}, separators=(",", ":"))
    code, message = _error(
        lambda: sns.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=endpoint,
            Attributes={"FilterPolicy": filter_policy},
        )
    )
    assert code == "InvalidParameter", (
        f"a repeat Subscribe on an existing triple carrying DIFFERENT Attributes must "
        f"be refused with InvalidParameter, not silently accepted; got {code!r}"
    )
    assert message == "Invalid parameter: Attributes Reason: Subscription already exists with different attributes", (
        f"the refusal must say the existing subscription differs in its attributes -- "
        f"InvalidParameter alone is what every malformed Subscribe yields, so the "
        f"message is the only thing that identifies this cause; got {message!r}"
    )
    arns_after = _sub_arns(sns, topic_arn)
    assert arns_after == [first], (
        f"expected still exactly one subscription after three Subscribe calls, got {arns_after}"
    )
    stored = sns.get_subscription_attributes(SubscriptionArn=first)["Attributes"]
    assert "FilterPolicy" not in stored, (
        f"the refused Subscribe must not have set a FilterPolicy on the existing "
        f"subscription, got {stored.get('FilterPolicy')!r}"
    )

    # The refusal is keyed on a difference, not on the presence of Attributes.
    attr_endpoint = _fake_queue_arn(
        topic_arn, ctx.unique_name("sim2real-behav-sns-subidem-q3-")
    )
    attr_first = _subscribe(
        sns, ctx, topic_arn, attr_endpoint, attributes={"FilterPolicy": filter_policy}
    )
    same_attrs = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=attr_endpoint,
        Attributes={"FilterPolicy": filter_policy},
    )["SubscriptionArn"]
    assert same_attrs == attr_first, (
        f"a repeat Subscribe carrying the IDENTICAL Attributes must be accepted and "
        f"return {attr_first!r}, got {same_attrs!r}"
    )
    omitted_attrs = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=attr_endpoint
    )["SubscriptionArn"]
    assert omitted_attrs == attr_first, (
        f"omitting Attributes on a repeat is not a difference and must be accepted, "
        f"returning {attr_first!r}, got {omitted_attrs!r}"
    )
    surviving = sns.get_subscription_attributes(SubscriptionArn=attr_first)[
        "Attributes"
    ].get("FilterPolicy")
    assert surviving == filter_policy, (
        f"the repeat that omitted Attributes must not have cleared or rewritten the "
        f"FilterPolicy; expected {filter_policy!r}, got {surviving!r}"
    )

    # A different endpoint mints a new subscription, so the identity above is endpoint-keyed.
    other_endpoint = _fake_queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-subidem-q2-"))
    other = _subscribe(sns, ctx, topic_arn, other_endpoint)
    assert other != first, (
        f"a distinct endpoint must produce a distinct SubscriptionArn, got {other!r} == {first!r}"
    )
    assert other != attr_first, (
        f"a distinct endpoint must produce a distinct SubscriptionArn, got "
        f"{other!r} == {attr_first!r}"
    )
    # One subscription per endpoint, however many times each was subscribed.
    expected = sorted([first, attr_first, other])
    listed = _poll(
        lambda: _sub_arns(sns, topic_arn),
        lambda a: len(a) >= 3,
        timeout_s=30.0,
        interval_s=2.0,
        what="all three distinct subscriptions are listed",
    )
    assert sorted(listed) == expected, (
        f"expected exactly the three distinct subscriptions {expected} after seven "
        f"accepted Subscribe calls on three endpoints, got {sorted(listed)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
