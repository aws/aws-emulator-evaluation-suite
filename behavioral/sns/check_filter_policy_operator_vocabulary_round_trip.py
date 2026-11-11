"""filter-policy-operator-vocabulary-round-trip."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-policy-operator-vocabulary-round-trip"
GROUP = 'subscription-lifecycle'
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
    """A well-formed SQS queue ARN in the topic's account/region.

    SNS confirms an sqs-protocol subscription without verifying the queue exists, so this
    keeps the whole check single-service: no SQS resource is ever created.
    """
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


def _filter_policy(client, sub_arn):
    attrs = client.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    return json.loads(attrs.get("FilterPolicy") or "{}")


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every filter-policy operator round-trips byte-exact via Subscribe and $or via
    SetSubscriptionAttributes, a 6-key policy fails InvalidParameter, and {} clears the policy.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-subscription-filter-policies.html
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(
        sns, ctx, ctx.unique_name("sim2real-behav-sns-fpops-"),
        tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )

    # Every documented MessageAttributes-scope operator. Keys are ANDed, values within
    # a key are ORed. Split into groups of at most 5 keys, the per-policy ceiling.
    groups = [
        {
            "event": ["order_placed", "order_cancelled"],       # exact string, OR within key
            "store": [{"prefix": "sea"}],                       # prefix
            "region": [{"suffix": "-west-2"}],                   # suffix
            "customer_tier": [{"anything-but": "free"}],         # anything-but, scalar
            "channel": [{"anything-but": ["fax", "pager"]}],      # anything-but, list
        },
        {
            "sku": [{"anything-but": {"prefix": "TEST-"}}],       # anything-but + prefix
            "attempt": [{"anything-but": [1, 2]}],                # anything-but, numeric list
            "price": [{"numeric": [">", 0, "<=", 100]}],          # numeric range
            "quantity": [{"numeric": ["=", 5]}],                  # numeric equality
            "coupon": [{"exists": False}],                        # exists: false
        },
        {
            "order_id": [{"exists": True}],                       # exists: true
            "status": [{"equals-ignore-case": "PENDING"}],         # case-insensitive
        },
    ]

    first_sub_arn = None
    for index, policy in enumerate(groups):
        assert len(policy) <= 5, f"group {index} exceeds the measured 5-key ceiling"
        # SNS stores the policy with whitespace stripped but otherwise byte-exact, so the
        # compact form is sent and compared byte for byte.
        submitted = json.dumps(policy, separators=(",", ":"))
        sub_arn = _subscribe_fake_queue(
            sns, ctx, topic_arn, attributes={"FilterPolicy": submitted}
        )
        assert sub_arn and sub_arn != "pending confirmation", (
            f"expected an auto-confirmed sqs subscription for group {index}, got {sub_arn!r}"
        )
        first_sub_arn = first_sub_arn or sub_arn

        stored_raw = _poll(
            lambda a=sub_arn: sns.get_subscription_attributes(SubscriptionArn=a)[
                "Attributes"
            ].get("FilterPolicy"),
            lambda raw: bool(raw),
            timeout_s=30.0,
            interval_s=2.0,
            what=f"Subscribe-time FilterPolicy for group {index} became readable",
        )
        assert stored_raw == submitted, (
            f"the operator vocabulary supplied at Subscribe time must round-trip "
            f"BYTE-for-byte once whitespace is already absent (measured); group "
            f"{index} expected {submitted!r}, got {stored_raw!r}"
        )
        stored = json.loads(stored_raw)
        # Implicit AND across keys: every key survives, none is collapsed or dropped,
        # and key ORDER is preserved (json.loads keeps insertion order).
        assert list(stored) == list(policy), (
            f"expected all {len(policy)} ANDed keys retained in submitted order, got "
            f"{list(stored)}"
        )

    # Value-array order is part of the document, asserted as a sequence (not a set).
    group0 = json.loads(
        sns.get_subscription_attributes(SubscriptionArn=first_sub_arn)["Attributes"][
            "FilterPolicy"
        ]
    )
    assert group0["event"] == ["order_placed", "order_cancelled"], (
        f"expected the value array order preserved as a list, got {group0['event']!r}"
    )
    assert group0["channel"][0]["anything-but"] == ["fax", "pager"], (
        f"expected the anything-but list order preserved, got {group0['channel']!r}"
    )

    # The 5-key ceiling itself: a SIXTH top-level key is refused, and the refusal
    # names the limit.
    six_keys = dict(groups[0], overflow=["anything"])
    code, message = _error(
        lambda: sns.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=_fake_queue_arn(
                topic_arn, ctx.unique_name("sim2real-behav-sns-fpops-q6-")
            ),
            Attributes={"FilterPolicy": json.dumps(six_keys, separators=(",", ":"))},
        )
    )
    assert code == "InvalidParameter", (
        f"a 6-key filter policy must be refused with InvalidParameter; got {code!r}"
    )
    expected = 'Invalid parameter: Attributes Reason: FilterPolicy: Filter policy can not have more than 5 keys'
    assert message == expected, (
        f"the refusal must name the 5-key ceiling -- InvalidParameter alone is what "
        f"every malformed Subscribe attribute yields; expected {expected!r}, got {message!r}"
    )

    sub_arn = first_sub_arn

    # The SetSubscriptionAttributes path must accept the same vocabulary, including $or,
    # which can only appear at the top level of a policy.
    or_policy = {
        "$or": [
            {"metric_name": ["CPUUtilization"]},
            {"namespace": ["AWS/EC2"], "period": [{"numeric": [">=", 60]}]},
        ],
        "severity": [{"anything-but": {"prefix": "INFO"}}],
    }
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="FilterPolicy",
        AttributeValue=json.dumps(or_policy),
    )
    replaced = _poll(
        lambda: _filter_policy(sns, sub_arn),
        lambda p: "$or" in p,
        timeout_s=30.0,
        interval_s=2.0,
        what="$or FilterPolicy replaced the previous policy",
    )
    assert replaced == or_policy, (
        f"expected the $or policy to replace and round-trip unchanged, got {replaced}"
    )
    assert len(replaced["$or"]) == 2 and "metric_name" in replaced["$or"][0], (
        f"expected the $or branch list order preserved as a sequence, got {replaced['$or']}"
    )
    assert "event" not in replaced, (
        "SetSubscriptionAttributes replaces the FilterPolicy wholesale; the previous "
        f"policy's keys must be gone, got {sorted(replaced)}"
    )

    # An empty policy object clears filtering: the previous document must not linger.
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicy", AttributeValue="{}"
    )
    cleared = _poll(
        lambda: _filter_policy(sns, sub_arn),
        lambda p: "$or" not in p,
        timeout_s=30.0,
        interval_s=2.0,
        what="FilterPolicy cleared to {}",
    )
    assert cleared == {}, f"expected FilterPolicy cleared to an empty policy, got {cleared}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
