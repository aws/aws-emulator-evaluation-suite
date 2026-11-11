"""delete-topic-cascades-subscriptions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-topic-cascades-subscriptions"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']


def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    queue_url = sqs.create_queue(QueueName=name, Attributes=attrs)["QueueUrl"]
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTopic makes the topic NotFound for GetTopicAttributes, ListSubscriptionsByTopic and
    Subscribe and drops it from ListTopics; its subscription is either still readable or NotFound.
    """
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-cascade-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    # DeleteTopic below is the subject of the check; registering teardown anyway
    # keeps a mid-check failure from leaking the topic (DeleteTopic is idempotent).
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    queue_url, queue_arn = _create_sqs_queue_for_sns(ctx, "cascade-q-")
    sub_arn = sns.subscribe(TopicArn=arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    assert sub_arn.startswith(arn), sub_arn

    sns.delete_topic(TopicArn=arn)

    # AWS cascades asynchronously: the orphaned subscription stays readable for 120s or more.
    try:
        try:
            sns.get_subscription_attributes(SubscriptionArn=sub_arn)
        except ClientError as exc:
            raise AssertionError(
                "GetSubscriptionAttributes on the orphaned subscription immediately after "
                f"DeleteTopic: expected success (cascade is async), got {exc.response.get('Error')}"
            ) from exc
    except AssertionError:
        # DeleteTopic "Deletes a topic and all its subscriptions" (Smithy), so a synchronous
        # cascade is equally valid: then the subscription is gone with the exact NotFound.
        code, message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn))
        assert (code, message) == ("NotFound", "Subscription does not exist"), (
            f"orphaned subscription after DeleteTopic: expected it readable or NotFound "
            f"'Subscription does not exist', got {code!r} {message!r}"
        )

    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=arn))
    assert code == "NotFound", f"GetTopicAttributes after delete: expected NotFound, got {code}"
    assert message == "Topic does not exist", (
        f"GetTopicAttributes after delete: unexpected message {message!r}"
    )

    code, message = _error(lambda: sns.list_subscriptions_by_topic(TopicArn=arn))
    assert code == "NotFound", (
        f"ListSubscriptionsByTopic after delete: expected NotFound, got {code}"
    )
    assert message == "Topic does not exist", (
        f"ListSubscriptionsByTopic after delete: unexpected message {message!r}"
    )

    code, message = _error(lambda: sns.subscribe(TopicArn=arn, Protocol="sqs", Endpoint=queue_arn))
    assert code == "NotFound", f"Subscribe to a deleted topic: expected NotFound, got {code}"
    assert message == "Topic does not exist", (
        f"Subscribe to a deleted topic: unexpected message {message!r}"
    )

    def all_topics():
        found = set()
        for page in sns.get_paginator("list_topics").paginate():
            found.update(t["TopicArn"] for t in page["Topics"])
        return found

    topics = _poll_until(all_topics, lambda s: arn not in s, timeout_s=60, interval_s=3)
    assert arn not in topics, "deleted topic must disappear from ListTopics"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
