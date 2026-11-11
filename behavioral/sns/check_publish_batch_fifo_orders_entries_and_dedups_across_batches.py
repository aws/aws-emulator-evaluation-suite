"""publish-batch-fifo-orders-entries-and-dedups-across-batches."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-fifo-orders-entries-and-dedups-across-batches"
GROUP = "fifo"
SERVICES = ["sns"]

_SCENARIO = "sns-fifo-batch-order"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A ten-entry PublishBatch into one FIFO message group is sequenced and delivered in entry
    order, and a later entry reusing an earlier MessageDeduplicationId is Successful but never
    delivered.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx, fifo=True)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn,
                           attributes={"RawMessageDelivery": "true"})

    group = "orders"
    bodies = [ctx.unique_name(f"sim2real-behav-fifobatch-{i:02d}-") for i in range(1, 11)]
    dedups = [ctx.unique_name(f"dedup-{i:02d}-") for i in range(1, 11)]
    first = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": f"e{i:02d}", "Message": body, "MessageGroupId": group,
         "MessageDeduplicationId": dedup}
        for i, (body, dedup) in enumerate(zip(bodies, dedups), start=1)
    ])
    assert first.get("Failed", []) == [], f"first batch had Failed entries {first['Failed']!r}"
    by_id = {e["Id"]: e for e in first["Successful"]}
    assert sorted(by_id) == [f"e{i:02d}" for i in range(1, 11)], (
        f"first batch must report all ten entries Successful, got ids {sorted(by_id)!r}"
    )
    seqs = [int(by_id[f"e{i:02d}"]["SequenceNumber"]) for i in range(1, 11)]
    assert all(a < b for a, b in zip(seqs, seqs[1:])), (
        f"SequenceNumbers must strictly increase in entry order, got {seqs!r}"
    )

    duplicate = ctx.unique_name("sim2real-behav-fifobatch-duplicate-")
    sentinel = ctx.unique_name("sim2real-behav-fifobatch-sentinel-")
    second = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "dup", "Message": duplicate, "MessageGroupId": group,
         "MessageDeduplicationId": dedups[2]},
        {"Id": "sentinel", "Message": sentinel, "MessageGroupId": group,
         "MessageDeduplicationId": ctx.unique_name("dedup-sentinel-")},
    ])
    assert second.get("Failed", []) == [] and sorted(
        e["Id"] for e in second["Successful"]) == ["dup", "sentinel"], (
        f"the second batch must report both entries Successful (deduplication is silent); "
        f"Successful {[e['Id'] for e in second.get('Successful', [])]!r}, "
        f"Failed {second.get('Failed')!r}"
    )

    # The sentinel follows the duplicate in the same group, so its arrival proves the
    # duplicate is not in flight.
    received: list[str] = []
    deadline = time.monotonic() + 120.0
    while sentinel not in received:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            received.append(msg["Body"])
        if sentinel not in received and time.monotonic() >= deadline:
            raise AssertionError(
                f"the sentinel never arrived within 120s; received {len(received)} bodies")

    assert duplicate not in received, (
        "the entry reusing an earlier MessageDeduplicationId inside the deduplication window "
        "must not be delivered, but it arrived"
    )
    assert received == bodies + [sentinel], (
        f"the queue must receive the ten entries in entry order and then the sentinel; got "
        f"{received!r}"
    )


def _s(value: str) -> dict:
    """A String-typed message attribute value."""
    return {"DataType": "String", "StringValue": value}


def _n(value: str) -> dict:
    """A Number-typed message attribute value."""
    return {"DataType": "Number", "StringValue": value}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-") + (".fifo" if fifo else "")
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False,
                            attributes: dict | None = None) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-") + (".fifo" if fifo else "")
    attrs = dict(attributes or {})
    if fifo:
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
                           attributes: dict | None = None,
                           timeout_s: float = 60.0) -> str:
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
        timeout_s=timeout_s, interval_s=2.0,
        description="the new subscription leaves PendingConfirmation",
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


def _await_bodies(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                  description: str, forbidden: set[str] | None = None) -> dict[str, float]:
    """Long-poll until every wanted body is seen; RAISES on the deadline.

    Returns {body: monotonic time first seen}. A body in `forbidden` that arrives raises at
    once: it is a leak, and swallowing it would hide what the caller is about to assert.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            if forbidden and body in forbidden:
                raise AssertionError(
                    f"{description}: a body that must never be delivered arrived: {body!r}")
            if body in outstanding:
                outstanding.discard(body)
                seen[body] = time.monotonic()
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s")
    return seen


def _drain(ctx, queues: dict[str, str], *, window_s: float) -> dict[str, list[str]]:
    """Alternate long polls across the queues for one shared window and return every body
    each produced. The empty lists feed an equality-to-empty assertion."""
    sqs = ctx.client("sqs")
    out: dict[str, list[str]] = {label: [] for label in queues}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for label, url in queues.items():
            resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=2)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
                out[label].append(msg["Body"])
    return out


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises. An unexpected success
    raises too, naming what came back, so it can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
