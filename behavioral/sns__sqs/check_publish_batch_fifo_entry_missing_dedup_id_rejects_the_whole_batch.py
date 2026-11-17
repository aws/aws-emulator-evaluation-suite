"""publish-batch-fifo-entry-missing-dedup-id-rejects-the-whole-batch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-fifo-entry-missing-dedup-id-rejects-the-whole-batch"
GROUP = "overly-permissive"
SERVICES = ["sns", "sqs"]

_SCENARIO = "sns-batch-nodedup"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_topic(ctx) -> str:
    """CreateTopic (FIFO, no content-based dedup, tagged) and register DeleteTopic; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-batchnodedup-") + ".fifo"
    arn = sns.create_topic(
        Name=name,
        Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "false"},
        Tags=_tags_kv(),
    )["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real FIFO SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-batchnodedup-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name, Attributes={"FifoQueue": "true"},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(
        lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"
    ))
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


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue (raw delivery) and poll GetSubscriptionAttributes until confirmed."""
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub_arn), "NotFound"))
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


def _drain_until_body(ctx, queue_url: str, sentinel: str, timeout_s: float = 120.0) -> list[str]:
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
    raise AssertionError(f"the FIFO sentinel {sentinel!r} never arrived within {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a FIFO topic without ContentBasedDeduplication, a PublishBatch with one entry missing
    MessageDeduplicationId is rejected whole with InvalidParameter and delivers no entry, while
    the same batch with every entry's dedup id present is accepted and delivered.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    run_id = ctx.unique_name("sim2real-behav-sns-batchnodedup-")
    group = f"{run_id}-group"
    good_marker = f"{run_id}-good"
    broken_marker = f"{run_id}-broken"

    code, message = _error(lambda: sns.publish_batch(
        TopicArn=topic_arn,
        PublishBatchRequestEntries=[
            {"Id": "good", "Message": good_marker, "MessageGroupId": group,
             "MessageDeduplicationId": f"{run_id}-dedup-good"},
            {"Id": "broken", "Message": broken_marker, "MessageGroupId": group},
        ],
    ))
    assert code == "InvalidParameter", (
        "expected InvalidParameter for a PublishBatch with one FIFO entry missing "
        f"MessageDeduplicationId on a non-content-based-dedup topic, got {code}"
    )
    expected = (
        "Invalid parameter: The topic should either have ContentBasedDeduplication enabled "
        "or MessageDeduplicationId provided explicitly"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    sentinel = f"{run_id}-sentinel"
    sns.publish(TopicArn=topic_arn, Message=sentinel, MessageGroupId=group,
                MessageDeduplicationId=f"{run_id}-dedup-sentinel")
    before = _drain_until_body(ctx, queue_url, sentinel, timeout_s=120.0)
    assert before == [], (
        f"the batch was rejected as a whole, so neither entry may be delivered, but {before!r} "
        f"arrived before the sentinel"
    )

    resp = sns.publish_batch(
        TopicArn=topic_arn,
        PublishBatchRequestEntries=[
            {"Id": "good", "Message": good_marker, "MessageGroupId": group,
             "MessageDeduplicationId": f"{run_id}-dedup-good2"},
            {"Id": "broken", "Message": broken_marker, "MessageGroupId": group,
             "MessageDeduplicationId": f"{run_id}-dedup-broken2"},
        ],
    )
    assert not resp.get("Failed"), f"expected no Failed entries, got {resp.get('Failed')}"
    successful_ids = {e["Id"] for e in resp.get("Successful", [])}
    assert successful_ids == {"good", "broken"}, (
        f"expected both repaired entries in Successful, got {resp.get('Successful')}"
    )

    sentinel2 = f"{run_id}-sentinel2"
    sns.publish(TopicArn=topic_arn, Message=sentinel2, MessageGroupId=group,
                MessageDeduplicationId=f"{run_id}-dedup-sentinel2")
    delivered = _drain_until_body(ctx, queue_url, sentinel2, timeout_s=120.0)
    assert sorted(delivered) == sorted([good_marker, broken_marker]), (
        f"expected both repaired entries to have been delivered, got {delivered!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
