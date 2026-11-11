"""publish-batch-one-invalid-fifo-entry-rejected-and-no-sibling-delivered."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "publish-batch-one-invalid-fifo-entry-rejected-and-no-sibling-delivered"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-publish-batch-atomicity"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """One FIFO entry missing MessageGroupId fails the whole PublishBatch with InvalidParameter and
    none of its valid siblings is delivered; repairing that entry publishes and delivers all four.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx, fifo=True, attributes={"ContentBasedDeduplication": "false"})
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn, attributes={"RawMessageDelivery": "true"})

    run_id = ctx.unique_name("sim2real-behav-sns-batch-")
    group = f"{run_id}-group"
    ids = ["e0", "e1", "e2", "e3"]
    markers = {i: f"{run_id}-{i}" for i in ids}
    broken_id = "e2"

    def _entries(*, repair: bool, dedup_suffix: str) -> list[dict]:
        out = []
        for i in ids:
            entry = {"Id": i, "Message": markers[i],
                     "MessageDeduplicationId": f"{run_id}-{dedup_suffix}-{i}"}
            if repair or i != broken_id:
                entry["MessageGroupId"] = group
            out.append(entry)
        return out

    # AWS rejects the whole request, not with a per-entry Failed list.
    code, message = _error(lambda: sns.publish_batch(
        TopicArn=topic_arn, PublishBatchRequestEntries=_entries(repair=False, dedup_suffix="a")))
    assert code == "InvalidParameter", (
        f"a PublishBatch with one FIFO entry missing MessageGroupId was not rejected with "
        f"InvalidParameter: {code!r}"
    )
    expected_message = "Invalid parameter: The MessageGroupId parameter is required for FIFO topics"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # FIFO ordering within the group makes the sentinel arrive last, bounding the absence check.
    sentinel = f"{run_id}-sentinel"
    sns.publish(TopicArn=topic_arn, Message=sentinel, MessageGroupId=group,
                MessageDeduplicationId=f"{run_id}-dedup-sentinel")
    before = _drain_until_body(ctx, queue_url, sentinel, timeout_s=120.0)
    strays = _receive_any(ctx, queue_url, rounds=1, wait_s=20)
    leaked = [b for b in before + strays if b in markers.values()]
    assert leaked == [], (
        f"the batch was rejected as a whole, so none of its entries may be delivered — but "
        f"{leaked!r} arrived (everything seen: {(before + strays)!r})"
    )

    repaired = sns.publish_batch(
        TopicArn=topic_arn, PublishBatchRequestEntries=_entries(repair=True, dedup_suffix="b"))
    assert repaired.get("Failed", []) == [], (
        f"the repaired batch reported failures: {repaired.get('Failed')!r}"
    )
    assert sorted(e["Id"] for e in repaired["Successful"]) == sorted(ids), (
        f"the repaired batch did not report every entry Successful: {repaired['Successful']!r}"
    )
    delivered = _drain_until_all(ctx, queue_url, list(markers.values()), timeout_s=120.0)
    assert sorted(delivered) == sorted(markers.values()), (
        f"the repaired batch did not deliver every entry: {delivered!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS error (Code, Message) raised by fn(); raises AssertionError if fn succeeds."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
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
            body = msg.get("Body", "")
            if body == sentinel:
                return before
            before.append(body)
    raise AssertionError(
        f"the FIFO sentinel {sentinel!r} never arrived within {timeout_s}s, so the absence of the "
        f"rejected batch's entries is not bounded; messages seen were {before!r}"
    )


def _drain_until_all(ctx, queue_url: str, wanted: list[str], *,
                     timeout_s: float = 120.0) -> list[str]:
    """Long-poll the queue until every wanted marker has been seen; returns the markers collected."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and outstanding:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            if body in outstanding:
                outstanding.discard(body)
                seen.append(body)
    if outstanding:
        raise AssertionError(
            f"{sorted(outstanding)!r} never arrived within {timeout_s}s; received {seen!r}"
        )
    return seen


def _receive_any(ctx, queue_url: str, *, rounds: int, wait_s: int) -> list[str]:
    """Long-poll a queue `rounds` times and return every body it produced (expected: none)."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
