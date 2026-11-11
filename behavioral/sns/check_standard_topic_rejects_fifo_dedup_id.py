"""standard-topic-rejects-fifo-dedup-id."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "standard-topic-rejects-fifo-dedup-id"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-standard-rejects-dedup-id"

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A standard topic rejects MessageDeduplicationId but accepts MessageGroupId without assigning
    a SequenceNumber; only the accepted publish reaches a subscribed SQS queue."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn, attributes={"RawMessageDelivery": "true"})

    run_id = ctx.unique_name("sim2real-behav-sns-stdfifo-")
    accepted_marker = f"{run_id}-accepted"

    code, message = _error(lambda: sns.publish(
        TopicArn=topic_arn, Message=f"{run_id}-rejected",
        MessageDeduplicationId=f"{run_id}-dedup"))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for MessageDeduplicationId on a standard topic, got {code!r}"
    )
    assert message == "Invalid parameter: MessageDeduplicationId Reason: The request includes MessageDeduplicationId parameter that is not valid for this topic type", (
        f"unexpected refusal message for MessageDeduplicationId on a standard topic: {message!r}"
    )

    # MessageGroupId, by contrast, is accepted on a standard topic.
    resp = sns.publish(TopicArn=topic_arn, Message=accepted_marker, MessageGroupId=f"{run_id}-group")
    assert resp.get("MessageId"), (
        "real SNS accepts MessageGroupId on a standard topic; it must not be rejected"
    )
    assert "SequenceNumber" not in resp, (
        f"a standard topic must not return a SequenceNumber, got {resp}"
    )

    bodies = _poll_until_message(ctx, queue_url, timeout_s=60.0)
    assert bodies == [accepted_marker], (
        f"expected exactly the accepted MessageGroupId publish to arrive at the subscriber, got {bodies!r}"
    )
    extra = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", [])
    assert not extra, (
        f"the refused MessageDeduplicationId publish must never have been delivered, but "
        f"unexpected message(s) arrived: {[m.get('Body') for m in extra]!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS error (Code, Message) raised by fn(). Raises if fn SUCCEEDS -- an unexpected success is
    the strongest possible signal."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx) -> str:
    """CreateTopic (tagged + prefix-named, standard/non-FIFO) and register DeleteTopic; returns
    the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-stdfifo-")
    arn = sns.create_topic(Name=name, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-stdfifo-q-")
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
                           attributes: dict | None = None, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"subscription {sub_arn!r} was still PendingConfirmation={pending!r} after {timeout_s}s"
    )


def _poll_until_message(ctx, queue_url: str, *, timeout_s: float = 60.0) -> list[str]:
    """Bounded long-poll retry for the queue's first batch of messages; raises on timeout rather
    than returning an empty/partial result."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        messages = resp.get("Messages", [])
        if messages:
            for msg in messages:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return [m.get("Body", "") for m in messages]
    raise AssertionError(f"no message arrived at {queue_url!r} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
