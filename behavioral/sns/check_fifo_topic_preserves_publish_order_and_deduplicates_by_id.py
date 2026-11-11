"""fifo-topic-preserves-publish-order-and-deduplicates-by-id."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "fifo-topic-preserves-publish-order-and-deduplicates-by-id"
GROUP = 'ordering'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-ordering"


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Ten messages published sequentially into one MessageGroupId of a FIFO topic arrive at the
    FIFO queue in exactly that order, and five concurrent publishes sharing one
    MessageDeduplicationId yield exactly one delivered message.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx, fifo=True,
                             attributes={"ContentBasedDeduplication": "false"})
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    run_id = ctx.unique_name("sim2real-behav-sns-fifo-")
    group = f"{run_id}-order"
    sent = [f"{run_id}-{i:02d}" for i in range(10)]
    for i, body in enumerate(sent):
        sns.publish(TopicArn=topic_arn, Message=body, MessageGroupId=group,
                    MessageDeduplicationId=f"{run_id}-dedup-{i:02d}")

    received = _drain_messages(ctx, queue_url, want=10, timeout_s=120.0)
    assert len(received) == 10, (
        f"the FIFO queue did not receive every message: {received!r}"
    )
    assert received == sent, f"FIFO order was not preserved: {received!r} != {sent!r}"

    dedup_group = f"{run_id}-dedup-group"
    dedup_id = f"{run_id}-shared-dedup"
    dedup_bodies = [f"{run_id}-dup-{i}" for i in range(5)]

    def _publish(body: str):
        try:
            sns.publish(TopicArn=topic_arn, Message=body, MessageGroupId=dedup_group,
                        MessageDeduplicationId=dedup_id)
            return None
        except Exception as exc:  # noqa: BLE001 — captured so the assertion can name it
            return f"{body}: {type(exc).__name__}: {exc}"

    with ThreadPoolExecutor(max_workers=5) as pool:
        dedup_errors = [e for e in pool.map(_publish, dedup_bodies) if e is not None]
    assert dedup_errors == [], (
        f"a deduplicated publish failed instead of being collapsed: {dedup_errors!r}"
    )

    # FIFO order within the group makes the sentinel arrive last, bounding the drain.
    sentinel = f"{run_id}-sentinel"
    sns.publish(TopicArn=topic_arn, Message=sentinel, MessageGroupId=dedup_group,
                MessageDeduplicationId=f"{run_id}-sentinel-dedup")
    after = _drain_until_body(ctx, queue_url, sentinel, timeout_s=120.0)
    delivered_duplicates = [b for b in after if b in dedup_bodies]
    dedup_count = len(delivered_duplicates)
    assert dedup_count == 1, (
        f"a shared MessageDeduplicationId produced {dedup_count} deliveries, expected exactly 1: "
        f"{delivered_duplicates!r} (everything seen before the sentinel was {after!r})"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs = dict(attributes or {})
    if fifo:
        name = name + ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name = name + ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
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


def _inner_message(body: str) -> str:
    """Unwrap the SNS Notification envelope and return its Message, or the body if it is not one."""
    try:
        envelope = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body
    if isinstance(envelope, dict) and envelope.get("Type") == "Notification":
        inner = envelope.get("Message")
        if isinstance(inner, str):
            return inner
    return body


def _drain_messages(ctx, queue_url: str, *, want: int, timeout_s: float = 120.0) -> list[str]:
    """Receive until `want` messages arrive; returns the inner Messages in arrival order."""
    sqs = ctx.client("sqs")
    collected: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and len(collected) < want:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            collected.append(_inner_message(msg.get("Body", "")))
    return collected


def _drain_until_body(ctx, queue_url: str, sentinel: str, *,
                      timeout_s: float = 120.0) -> list[str]:
    """Receive until the sentinel body arrives; returns everything seen BEFORE it, in order."""
    sqs = ctx.client("sqs")
    before: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            inner = _inner_message(msg.get("Body", ""))
            if inner == sentinel:
                return before
            before.append(inner)
    raise AssertionError(
        f"the FIFO sentinel {sentinel!r} never arrived within {timeout_s}s, so the deduplication "
        f"count is not bounded; messages seen were {before!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
