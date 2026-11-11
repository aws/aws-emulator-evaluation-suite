"""filter-policy-scope-constrains-policy-shape."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "filter-policy-scope-constrains-policy-shape"
GROUP = 'overly-permissive'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name, "Tags": [{"Key": "sim2real", "Value": "true"}]}
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


def _subscribe_fake_queue(client, ctx, topic_arn, queue_arn=None, attributes=None):
    """Subscribe an sqs-protocol endpoint; register unsubscribe cleanup; return the SubscriptionArn."""
    if queue_arn is None:
        queue_arn = _fake_queue_arn(topic_arn)
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


def _sub_attrs(client, sub_arn):
    return client.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]


def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FilterPolicyScope accepts only MessageAttributes/MessageBody, and a nested FilterPolicy is
    refused under MessageAttributes scope but accepted once the scope is MessageBody.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-fpscope-"))

    # Valid setup: a flat attribute-scope policy, the SNS default.
    baseline = {"event": ["created"]}
    sub_arn = _subscribe_fake_queue(
        sns, ctx, topic_arn, attributes={"FilterPolicy": json.dumps(baseline)}
    )
    attrs = _poll(
        lambda: _sub_attrs(sns, sub_arn),
        lambda a: a.get("FilterPolicy"),
        timeout_s=30.0,
        interval_s=2.0,
        what="baseline FilterPolicy readable",
    )
    assert json.loads(attrs["FilterPolicy"]) == baseline, (
        f"expected the baseline policy stored, got {attrs.get('FilterPolicy')!r}"
    )
    assert attrs.get("FilterPolicyScope", "MessageAttributes") == "MessageAttributes", (
        f"expected the default FilterPolicyScope=MessageAttributes, got {attrs.get('FilterPolicyScope')!r}"
    )

    # 1. Break exactly one thing: an out-of-vocabulary scope value. The Smithy model has no
    # enum trait on FilterPolicyScope, so this closed vocabulary is server-side only.
    code_scope, msg_scope = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicyScope", AttributeValue="MessageHeaders"
    ))
    assert code_scope == "InvalidParameter", (
        f"expected InvalidParameter for FilterPolicyScope=MessageHeaders, got {code_scope}"
    )
    expected = 'Invalid parameter: FilterPolicyScope: Invalid value [MessageHeaders]. Please use either MessageBody or MessageAttributes'
    assert msg_scope == expected, f"expected message {expected!r}, got {msg_scope!r}"
    # Effect absent: the scope is still the default.
    scope_after = _sub_attrs(sns, sub_arn).get("FilterPolicyScope", "MessageAttributes")
    assert scope_after == "MessageAttributes", (
        f"a rejected FilterPolicyScope must not be persisted, got {scope_after!r}"
    )

    # 2. Break exactly one thing: a nested policy while the scope is MessageAttributes
    # (attributes are a flat name->value map, so a nested policy cannot be evaluated).
    nested = {"store": {"city": ["seattle"]}}
    code_nested, msg_nested = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="FilterPolicy",
        AttributeValue=json.dumps(nested),
    ))
    assert code_nested == "InvalidParameter", (
        "expected InvalidParameter for a nested policy under MessageAttributes scope "
        f"(attributes are a flat map and cannot be descended), got {code_nested}"
    )
    expected = 'Invalid parameter: Filter policy scope MessageAttributes does not support nested filter policy'
    assert msg_nested == expected, f"expected message {expected!r}, got {msg_nested!r}"
    # Effect absent: the flat baseline policy survived the rejected nested write.
    policy_after = json.loads(_sub_attrs(sns, sub_arn).get("FilterPolicy") or "{}")
    assert policy_after == baseline, (
        f"a rejected nested FilterPolicy must not be persisted; expected {baseline}, got {policy_after}"
    )

    # Control: the SAME nested policy becomes legal once the scope really is MessageBody,
    # proving the rejection above was the scope/shape coupling and not the policy itself.
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicyScope", AttributeValue="MessageBody"
    )
    _poll(
        lambda: _sub_attrs(sns, sub_arn).get("FilterPolicyScope"),
        lambda v: v == "MessageBody",
        timeout_s=30.0,
        interval_s=2.0,
        what="FilterPolicyScope switched to MessageBody",
    )
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="FilterPolicy",
        AttributeValue=json.dumps(nested),
    )
    final = _poll(
        lambda: json.loads(_sub_attrs(sns, sub_arn).get("FilterPolicy") or "{}"),
        lambda p: "store" in p,
        timeout_s=30.0,
        interval_s=2.0,
        what="nested FilterPolicy accepted under MessageBody scope",
    )
    assert final == nested, (
        f"expected the nested policy accepted under MessageBody scope, got {final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
