"""confirmed-sqs-subscription-attributes-and-listing-agree-field-for-field."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirmed-sqs-subscription-attributes-and-listing-agree-field-for-field"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-confirmed-sqs-subscription-attributes-an"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A confirmed SQS subscription's attributes are exactly nine fields, its listing entry five
    agreeing fields, and a raw sibling differs only in RawMessageDelivery; setting a FilterPolicy
    adds FilterPolicy and FilterPolicyScope=MessageAttributes, and clearing it removes both.
    """
    sns = ctx.client("sns")
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    topic_arn = _create_topic(ctx)
    _, plain_q = _create_queue_for_topic(ctx, topic_arn)
    _, raw_q = _create_queue_for_topic(ctx, topic_arn)
    plain = _subscribe_and_confirm(ctx, topic_arn, plain_q)
    raw = _subscribe_and_confirm(ctx, topic_arn, raw_q, attributes={"RawMessageDelivery": "true"})

    base = {
        "SubscriptionArn": plain, "TopicArn": topic_arn, "Endpoint": plain_q,
        "Protocol": "sqs", "Owner": ctx.account, "SubscriptionPrincipal": caller,
        "PendingConfirmation": "false", "ConfirmationWasAuthenticated": "true",
        "RawMessageDelivery": "false",
    }
    got = sns.get_subscription_attributes(SubscriptionArn=plain)["Attributes"]
    assert got == base, (
        f"a confirmed plain sqs subscription must report exactly {sorted(base)!r} with these "
        f"values; got keys {sorted(got)!r}, mismatched "
        f"{sorted(k for k in base if got.get(k) != base[k])!r}"
    )
    got_raw = sns.get_subscription_attributes(SubscriptionArn=raw)["Attributes"]
    want_raw = dict(base, SubscriptionArn=raw, Endpoint=raw_q, RawMessageDelivery="true")
    assert got_raw == want_raw, (
        f"the raw sibling must differ only in RawMessageDelivery; mismatched "
        f"{sorted(k for k in set(want_raw) | set(got_raw) if got_raw.get(k) != want_raw.get(k))!r}"
    )

    listed: dict[str, dict] = {}
    for page in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic_arn):
        for sub in page["Subscriptions"]:
            listed[sub["SubscriptionArn"]] = sub
    assert set(listed) == {plain, raw}, (
        f"the topic must list exactly its two subscriptions, got {len(listed)} entries"
    )
    for arn, attrs in ((plain, base), (raw, want_raw)):
        want_entry = {k: attrs[k] for k in
                      ("SubscriptionArn", "Owner", "Protocol", "Endpoint", "TopicArn")}
        assert listed[arn] == want_entry, (
            f"the listing entry must be exactly the five shared fields and agree with "
            f"GetSubscriptionAttributes; mismatched "
            f"{sorted(k for k in set(want_entry) | set(listed[arn]) if listed[arn].get(k) != want_entry.get(k))!r}"
        )

    policy = {"tier": ["gold"]}
    sns.set_subscription_attributes(SubscriptionArn=plain, AttributeName="FilterPolicy",
                                    AttributeValue=json.dumps(policy))
    with_policy = _poll_until(
        lambda: sns.get_subscription_attributes(SubscriptionArn=plain)["Attributes"],
        lambda a: "FilterPolicy" in a, timeout_s=30.0, interval_s=1.0,
        description="the FilterPolicy becomes readable")
    assert set(with_policy) - set(base) == {"FilterPolicy", "FilterPolicyScope"}, (
        f"setting a FilterPolicy must add exactly FilterPolicy and FilterPolicyScope, added "
        f"{sorted(set(with_policy) - set(base))!r}"
    )
    assert (json.loads(with_policy["FilterPolicy"]), with_policy["FilterPolicyScope"]) == (
        policy, "MessageAttributes"), (
        f"expected the stored policy {policy!r} under the default scope 'MessageAttributes', got "
        f"{with_policy['FilterPolicy']!r} / {with_policy['FilterPolicyScope']!r}"
    )

    sns.set_subscription_attributes(SubscriptionArn=plain, AttributeName="FilterPolicy",
                                    AttributeValue="")
    cleared = _poll_until(
        lambda: sns.get_subscription_attributes(SubscriptionArn=plain)["Attributes"],
        lambda a: "FilterPolicy" not in a, timeout_s=30.0, interval_s=1.0,
        description="the cleared FilterPolicy disappears")
    assert cleared == base, (
        f"clearing the FilterPolicy must restore exactly the original field set (no stale "
        f"FilterPolicyScope); extra {sorted(set(cleared) - set(base))!r}, missing "
        f"{sorted(set(base) - set(cleared))!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]

def _create_topic(ctx, *, fifo: bool = False) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs: dict[str, str] = {}
    if fifo:
        name += ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn

def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name += ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: _delete_queue_if_present(ctx, u))
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


def _delete_queue_if_present(ctx, url: str) -> None:
    """DeleteQueue; a queue the check itself already deleted is the one tolerated outcome."""
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise

def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None, timeout_s: float = 60.0) -> str:
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
        timeout_s=timeout_s, interval_s=1.0,
        description="the sqs subscription leaves PendingConfirmation",
    )
    return sub_arn

def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
