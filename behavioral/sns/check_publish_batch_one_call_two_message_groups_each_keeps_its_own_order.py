"""publish-batch-one-call-two-message-groups-each-keeps-its-own-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "publish-batch-one-call-two-message-groups-each-keeps-its-own-order"
GROUP = "fifo"
SERVICES = ["sns"]

_SCENARIO = "sns-batch-two-groups"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """One PublishBatch interleaving entries for two MessageGroupIds on a FIFO topic delivers each
    group in its own entry order, read from each message's MessageGroupId system attribute.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn, attributes={"RawMessageDelivery": "true"})

    run_id = ctx.unique_name("sim2real-behav-sns-2grp-")
    group_a = f"{run_id}-group-a"
    group_b = f"{run_id}-group-b"
    bodies_a = [f"{run_id}-a{i}" for i in range(3)]
    bodies_b = [f"{run_id}-b{i}" for i in range(3)]

    entries = []
    for i in range(3):
        entries.append({"Id": f"a{i}", "Message": bodies_a[i], "MessageGroupId": group_a,
                        "MessageDeduplicationId": f"{run_id}-dedup-a{i}"})
        entries.append({"Id": f"b{i}", "Message": bodies_b[i], "MessageGroupId": group_b,
                        "MessageDeduplicationId": f"{run_id}-dedup-b{i}"})

    resp = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=entries)
    assert resp.get("Failed", []) == [], f"the batch reported failures: {resp.get('Failed')!r}"
    by_id = {e["Id"]: e for e in resp.get("Successful", [])}
    expected_ids = sorted(e["Id"] for e in entries)
    assert sorted(by_id) == expected_ids, (
        f"expected all six entries Successful, got {sorted(by_id)!r}"
    )
    seqs_a = [int(by_id[f"a{i}"]["SequenceNumber"]) for i in range(3)]
    seqs_b = [int(by_id[f"b{i}"]["SequenceNumber"]) for i in range(3)]
    assert all(x < y for x, y in zip(seqs_a, seqs_a[1:])), (
        f"group A's SequenceNumbers must strictly increase in entry order, got {seqs_a!r}"
    )
    assert all(x < y for x, y in zip(seqs_b, seqs_b[1:])), (
        f"group B's SequenceNumbers must strictly increase in entry order, got {seqs_b!r}"
    )

    received = _drain_until_count(ctx, queue_url, total=6, timeout_s=90.0)
    by_group: dict[str, list[str]] = {group_a: [], group_b: []}
    for body, msg_group_id in received:
        assert msg_group_id in by_group, (
            f"message {body!r} carried MessageGroupId {msg_group_id!r}, neither of this run's "
            f"two groups"
        )
        by_group[msg_group_id].append(body)

    assert by_group[group_a] == bodies_a, (
        f"group A must be delivered in its own entry order {bodies_a!r}, got {by_group[group_a]!r}"
    )
    assert by_group[group_b] == bodies_b, (
        f"group B must be delivered in its own entry order {bodies_b!r}, got {by_group[group_b]!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx) -> str:
    """CreateTopic (FIFO, tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-2grp-") + ".fifo"
    arn = sns.create_topic(
        Name=name, Attributes={"FifoTopic": "true"}, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real FIFO SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-2grp-q-") + ".fifo"
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


def _drain_until_count(ctx, queue_url: str, *, total: int, timeout_s: float) -> list[tuple[str, str]]:
    """Long-poll until `total` messages have been seen; returns [(body, MessageGroupId), ...]
    in receipt order. RAISES on the deadline."""
    sqs = ctx.client("sqs")
    out: list[tuple[str, str]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < total:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            AttributeNames=["MessageGroupId"],
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            out.append((msg["Body"], msg["Attributes"]["MessageGroupId"]))
        if len(out) < total and time.monotonic() >= deadline:
            raise AssertionError(
                f"only {len(out)}/{total} messages arrived within {timeout_s}s: {out!r}"
            )
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
