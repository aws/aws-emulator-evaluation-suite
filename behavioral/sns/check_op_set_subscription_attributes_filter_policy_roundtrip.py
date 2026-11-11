"""op-set-subscription-attributes-filter-policy-roundtrip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-set-subscription-attributes-filter-policy-roundtrip"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_sqs_queue_for_sns(ctx, name_prefix="sqs-target-", fifo=False):
    """Create an SQS queue with a policy allowing SNS to deliver to it.

    Returns (queue_url, queue_arn).
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    attrs = {}
    if fifo:
        if not name.endswith(".fifo"):
            name += ".fifo"
        attrs["FifoQueue"] = "true"
    queue_url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSNS",
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetSubscriptionAttributes persists FilterPolicy and FilterPolicyScope readable via Get."""
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-subattr-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    _, queue_arn = _create_sqs_queue_for_sns(ctx, "subattr-q-")
    sub_arn = sns.subscribe(TopicArn=arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert "FilterPolicy" not in attrs, f"a fresh subscription must have no FilterPolicy, got {attrs}"

    policy = {"tier": ["gold", "silver"]}
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicy", AttributeValue=json.dumps(policy)
    )
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="FilterPolicyScope",
        AttributeValue="MessageAttributes",
    )

    def probe():
        return sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]

    attrs = _poll_until(probe, lambda a: "FilterPolicy" in a, timeout_s=30, interval_s=2)
    assert json.loads(attrs["FilterPolicy"]) == policy, attrs["FilterPolicy"]
    assert attrs.get("FilterPolicyScope") == "MessageAttributes", attrs

    # Clearing with an empty string removes the policy.
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicy", AttributeValue=""
    )
    attrs = _poll_until(
        probe, lambda a: "FilterPolicy" not in a, timeout_s=30, interval_s=2
    )
    assert "FilterPolicy" not in attrs, attrs


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
