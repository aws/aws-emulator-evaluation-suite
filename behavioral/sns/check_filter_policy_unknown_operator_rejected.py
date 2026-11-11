"""filter-policy-unknown-operator-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "filter-policy-unknown-operator-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']


def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
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
    """Poll fn() until pred(val); raise AssertionError on deadline miss (never a bare sleep)."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _filter_policy(client, sub_arn):
    attrs = client.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    return json.loads(attrs.get("FilterPolicy") or "{}")


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
    """SetSubscriptionAttributes refuses a FilterPolicy with an operator SNS lacks, InvalidParameter
    with a reason-specific message, leaving the stored policy unchanged; cidr/wildcard are accepted.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(
        sns, ctx, ctx.unique_name("sim2real-behav-sns-fpbadop-"),
        tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )

    # Valid setup: a policy that really is accepted, so the negative below differs from
    # the control by exactly one thing -- the operator name.
    baseline = {"price": [{"numeric": [">", 5]}]}
    sub_arn = _subscribe_fake_queue(
        sns, ctx, topic_arn, attributes={"FilterPolicy": json.dumps(baseline)}
    )
    stored = _poll(
        lambda: _filter_policy(sns, sub_arn),
        lambda p: p != {},
        timeout_s=30.0,
        interval_s=2.0,
        what="baseline FilterPolicy readable",
    )
    assert stored == baseline, f"expected the baseline policy stored, got {stored}"

    # `cidr` and `wildcard` are part of the SNS vocabulary (not EventBridge-only) and are
    # stored verbatim, so they must be accepted.
    implemented = [
        ("cidr", {"source_ip": [{"cidr": "10.0.0.0/24"}]}),
        ("wildcard", {"host": [{"wildcard": "*.example.com"}]}),
        ("anything-but + wildcard", {"host": [{"anything-but": {"wildcard": "*.test.com"}}]}),
        ("prefix + equals-ignore-case", {"host": [{"prefix": {"equals-ignore-case": "ABC"}}]}),
    ]
    for name, policy in implemented:
        submitted = json.dumps(policy, separators=(",", ":"))
        # The operator is implemented by SNS: a refusal raises here.
        sns.set_subscription_attributes(
            SubscriptionArn=sub_arn, AttributeName="FilterPolicy", AttributeValue=submitted
        )
        applied = _poll(
            lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn)[
                "Attributes"
            ].get("FilterPolicy"),
            lambda raw: raw == submitted,
            timeout_s=30.0,
            interval_s=2.0,
            what=f"the {name} policy became readable",
        )
        assert applied == submitted, (
            f"the {name} policy must round-trip byte-for-byte, got {applied!r}"
        )

    # Back to the baseline so each refusal below is provably a no-op against a known
    # document.
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="FilterPolicy",
        AttributeValue=json.dumps(baseline),
    )
    _poll(
        lambda: _filter_policy(sns, sub_arn),
        lambda p: p == baseline,
        timeout_s=30.0,
        interval_s=2.0,
        what="baseline FilterPolicy restored before the refusal legs",
    )

    # Every leg is InvalidParameter, so the message is the only signal of the reason.
    refused = [
        (
            "a match type SNS does not implement",
            {"price": [{"greater-than": 5}]},
            'Invalid parameter: FilterPolicy: Unrecognized match type greater-than\n at [Source: (String)"{"price":[{"greater-than":5}]}"; line: 1, column: 28]',
        ),
        (
            "$and, which SNS does not have even though it has $or",
            {"$and": [{"a": ["1"]}, {"b": ["2"]}]},
            'Invalid parameter: FilterPolicy: Unrecognized match type a\n at [Source: (String)"{"$and":[{"a":["1"]},{"b":["2"]}]}"; line: 1, column: 16]',
        ),
        (
            "the != numeric range operator",
            {"price": [{"numeric": ["!=", 5]}]},
            'Invalid parameter: FilterPolicy: Unrecognized numeric range operator: !=\n at [Source: (String)"{"price":[{"numeric":["!=",5]}]}"; line: 1, column: 29]',
        ),
        (
            "anything-but wrapping cidr -- cidr alone is accepted, negated it is not",
            {"ip": [{"anything-but": {"cidr": "10.0.0.0/8"}}]},
            'Invalid parameter: FilterPolicy: Unsupported anything-but pattern: cidr\n at [Source: (String)"{"ip":[{"anything-but":{"cidr":"10.0.0.0/8"}}]}"; line: 1, column: 33]',
        ),
        (
            "a non-boolean exists pattern",
            {"coupon": [{"exists": "yes"}]},
            'Invalid parameter: FilterPolicy: exists match pattern must be either true or false.\n at [Source: (String)"{"coupon":[{"exists":"yes"}]}"; line: 1, column: 23]',
        ),
    ]
    for description, policy, expected_text in refused:
        code, message = _error(
            lambda p=policy: sns.set_subscription_attributes(
                SubscriptionArn=sub_arn,
                AttributeName="FilterPolicy",
                AttributeValue=json.dumps(p),
            )
        )
        assert code == "InvalidParameter", (
            f"{description} must be refused with InvalidParameter, not stored; got {code!r}"
        )
        assert message == expected_text, (
            f"{description}: the refusal must say {expected_text!r} -- all five legs share "
            f"InvalidParameter, so the message is the only thing that proves the refusal "
            f"was for this reason; got {message!r}"
        )
        # Effect absent, after EVERY leg: a rejected write leaves the document alone.
        after = _filter_policy(sns, sub_arn)
        assert after == baseline, (
            f"{description} was refused but changed the stored FilterPolicy; expected "
            f"{baseline}, got {after}"
        )

    # Control: the same code path still accepts a legal replacement, so the rejections
    # above were about the operator and not about the subscription being unwritable.
    control = {"price": [{"numeric": [">=", 10, "<", 20]}], "event": ["ship"]}
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="FilterPolicy",
        AttributeValue=json.dumps(control),
    )
    final = _poll(
        lambda: _filter_policy(sns, sub_arn),
        lambda p: "event" in p,
        timeout_s=30.0,
        interval_s=2.0,
        what="control FilterPolicy applied",
    )
    assert final == control, f"expected the control policy to be accepted, got {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
