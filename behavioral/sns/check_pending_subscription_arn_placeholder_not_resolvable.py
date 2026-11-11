"""pending-subscription-arn-placeholder-not-resolvable."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "pending-subscription-arn-placeholder-not-resolvable"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']


def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic (tagged) + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {
        "Name": name,
        "Tags": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    }
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


def _subs(client, topic_arn):
    return client.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Subscribe on email returns "pending confirmation", ListSubscriptionsByTopic lists the entry as
    "PendingConfirmation", and that placeholder is refused as a SubscriptionArn (InvalidParameter)
    by Get/SetSubscriptionAttributes while the pending and a confirmed subscription stay intact.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-pending-"))

    # A confirmed control subscription first, so the topic is not trivially empty.
    confirmed = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs",
        Endpoint=_fake_queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-pending-q-")),
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=confirmed))
    assert confirmed.startswith(topic_arn + ":"), (
        f"expected a real SubscriptionArn for the sqs control subscription, got {confirmed!r}"
    )

    # `email` requires out-of-band confirmation, so it stays pending for the life of the check;
    # @example.com is IANA-reserved, so no third party is contacted.
    pending_resp = sns.subscribe(
        TopicArn=topic_arn, Protocol="email", Endpoint="sim2real-behav-sns@example.com"
    )
    assert pending_resp["SubscriptionArn"] == "pending confirmation", (
        "Subscribe on a confirmation-requiring protocol must return the lowercase literal "
        f"'pending confirmation', got {pending_resp['SubscriptionArn']!r}"
    )

    listed = _poll(
        lambda: _subs(sns, topic_arn),
        lambda subs: any(s.get("Protocol") == "email" for s in subs),
        timeout_s=30.0,
        interval_s=2.0,
        what="the pending email subscription appears in ListSubscriptionsByTopic",
    )
    email_entries = [s for s in listed if s.get("Protocol") == "email"]
    assert len(email_entries) == 1, f"expected exactly one email subscription, got {email_entries}"
    placeholder = email_entries[0]["SubscriptionArn"]
    assert placeholder == "PendingConfirmation", (
        "ListSubscriptionsByTopic must report the PascalCase literal 'PendingConfirmation' "
        f"as the SubscriptionArn of an unconfirmed subscription, got {placeholder!r}"
    )
    assert email_entries[0].get("TopicArn") == topic_arn, (
        f"expected the pending entry to carry the real TopicArn, got {email_entries[0]}"
    )
    assert email_entries[0].get("Endpoint") == "sim2real-behav-sns@example.com", (
        f"expected the pending entry to carry the real Endpoint, got {email_entries[0]}"
    )

    # SNS refuses the placeholder with InvalidParameter, not NotFound.
    code_get, msg_get = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=placeholder))
    assert code_get == "InvalidParameter", (
        f"expected InvalidParameter for GetSubscriptionAttributes('{placeholder}'), got {code_get}"
    )
    expected = 'Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not 1'
    assert msg_get == expected, f"expected message {expected!r}, got {msg_get!r}"
    code_set, msg_set = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=placeholder, AttributeName="RawMessageDelivery", AttributeValue="true"
    ))
    assert code_set == "InvalidParameter", (
        f"expected InvalidParameter for SetSubscriptionAttributes('{placeholder}'), got {code_set}"
    )
    expected = 'Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not 1'
    assert msg_set == expected, f"expected message {expected!r}, got {msg_set!r}"

    still = [s for s in _subs(sns, topic_arn) if s.get("Protocol") == "email"]
    assert len(still) == 1 and still[0]["SubscriptionArn"] == "PendingConfirmation", (
        f"the pending subscription must be untouched by the rejected calls, got {still}"
    )

    # The confirmed subscription still resolves, so the refusals were about the placeholder.
    attrs = sns.get_subscription_attributes(SubscriptionArn=confirmed)["Attributes"]
    assert attrs.get("PendingConfirmation") == "false", (
        f"expected the sqs control subscription to report PendingConfirmation=false, got {attrs.get('PendingConfirmation')!r}"
    )
    assert attrs.get("TopicArn") == topic_arn, (
        f"expected the control subscription's TopicArn == {topic_arn}, got {attrs.get('TopicArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
