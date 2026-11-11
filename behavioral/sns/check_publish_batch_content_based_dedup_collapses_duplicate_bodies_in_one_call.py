"""publish-batch-content-based-dedup-collapses-duplicate-bodies-in-one-call."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "publish-batch-content-based-dedup-collapses-duplicate-bodies-in-one-call"
GROUP = "fifo"
SERVICES = ["sns"]

_SCENARIO = "sns-batch-content-dedup"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """With ContentBasedDeduplication on a FIFO topic, two same-group entries with identical
    bodies in one PublishBatch both report Successful but deliver one copy; a distinct entry
    in the same call is delivered once.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx, attributes={"ContentBasedDeduplication": "true"})
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn, attributes={"RawMessageDelivery": "true"})

    run_id = ctx.unique_name("sim2real-behav-sns-cbd-")
    group = f"{run_id}-group"
    duplicated_body = f"{run_id}-duplicated"
    distinct_body = f"{run_id}-distinct"
    sentinel_body = f"{run_id}-sentinel"

    resp = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "dup-a", "Message": duplicated_body, "MessageGroupId": group},
        {"Id": "dup-b", "Message": duplicated_body, "MessageGroupId": group},
        {"Id": "distinct", "Message": distinct_body, "MessageGroupId": group},
    ])
    assert resp.get("Failed", []) == [], f"the batch reported failures: {resp.get('Failed')!r}"
    successful_ids = sorted(e["Id"] for e in resp.get("Successful", []))
    assert successful_ids == ["distinct", "dup-a", "dup-b"], (
        f"content-based dedup is silent -- both duplicate entries must still report Successful, "
        f"got {resp.get('Successful')!r}"
    )

    # The sentinel, published after and into the same group, bounds the read: once it has
    # arrived, nothing ahead of it in group order is still in flight.
    sns.publish(TopicArn=topic_arn, Message=sentinel_body, MessageGroupId=group)
    before_sentinel = _drain_until_body(ctx, queue_url, sentinel_body, timeout_s=90.0)

    dup_count = before_sentinel.count(duplicated_body)
    assert dup_count == 1, (
        f"two batch entries with an identical body and ContentBasedDeduplication enabled must "
        f"deliver exactly one copy, got {dup_count} copies; messages seen before the sentinel: "
        f"{before_sentinel!r}"
    )
    assert before_sentinel.count(distinct_body) == 1, (
        f"the distinct-body entry in the same batch must be delivered exactly once, got "
        f"{before_sentinel.count(distinct_body)}; messages seen: {before_sentinel!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, attributes: dict | None = None) -> str:
    """CreateTopic (FIFO, tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-cbd-") + ".fifo"
    attrs = dict(attributes or {})
    attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real FIFO SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-cbd-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name, Attributes={"FifoQueue": "true"},
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


def _drain_until_body(ctx, queue_url: str, sentinel: str, *, timeout_s: float = 90.0) -> list[str]:
    """Receive until the sentinel body arrives; returns everything seen BEFORE it, in order."""
    sqs = ctx.client("sqs")
    before: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            if body == sentinel:
                return before
            before.append(body)
    raise AssertionError(f"the sentinel {sentinel!r} never arrived within {timeout_s}s; saw {before!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
