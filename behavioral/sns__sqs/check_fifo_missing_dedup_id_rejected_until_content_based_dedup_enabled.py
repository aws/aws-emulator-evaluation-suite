"""fifo-missing-dedup-id-rejected-until-content-based-dedup-enabled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-missing-dedup-id-rejected-until-content-based-dedup-enabled"
GROUP = "overly-permissive"
SERVICES = ["sns", "sqs"]

_SCENARIO = "sns-sqs-cbd-flip"

_MISSING_DEDUP_ID = (
    "InvalidParameter",
    "Invalid parameter: The topic should either have ContentBasedDeduplication enabled "
    "or MessageDeduplicationId provided explicitly",
)


def _resource_tags() -> list[dict[str, str]]:
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


def expect_error(fn, code: str, message: str) -> None:
    """Assert that calling ``fn`` raises exactly (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        actual = (err.get("Code"), err.get("Message"))
        assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"
        return
    raise AssertionError(
        f"expected the call to be refused with {(code, message)!r}, but it succeeded: {result!r}"
    )


def _make_topic(ctx) -> str:
    """Create a FIFO topic without content-based dedup and register its deletion."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-cbdflip-") + ".fifo"
    arn = sns.create_topic(
        Name=name,
        Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "false"},
        Tags=_resource_tags(),
    )["TopicArn"]
    ctx.on_cleanup(_teardown(lambda: sns.delete_topic(TopicArn=arn), "NotFound"))
    return arn


def _make_bound_queue(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a FIFO queue whose policy admits only this topic, and register its deletion."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-cbdflip-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name, Attributes={"FifoQueue": "true"},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(
        lambda: sqs.delete_queue(QueueUrl=url), "AWS.SimpleQueueService.NonExistentQueue"
    ))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, queue_arn


def _confirm_subscription(ctx, topic_arn: str, queue_arn: str, deadline_s: float = 60.0) -> None:
    """Subscribe the queue with raw delivery and poll until the subscription is confirmed."""
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(_teardown(lambda: sns.unsubscribe(SubscriptionArn=sub_arn), "NotFound"))
    deadline = time.monotonic() + deadline_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return
        time.sleep(1.0)
    raise AssertionError(
        f"subscription {sub_arn!r} still reports PendingConfirmation={pending!r} after {deadline_s}s"
    )


def _bodies_ahead_of_marker(ctx, queue_url: str, marker: str, deadline_s: float = 120.0) -> list[str]:
    """Receive and delete messages up to and including ``marker``; return everything seen first."""
    sqs = ctx.client("sqs")
    ahead: list[str] = []
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        page = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in page.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            if body == marker:
                return ahead
            ahead.append(body)
    raise AssertionError(f"marker {marker!r} never reached the queue within {deadline_s}s")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a FIFO topic without ContentBasedDeduplication, Publish and a PublishBatch entry that
    omit MessageDeduplicationId are both refused; enabling ContentBasedDeduplication via
    SetTopicAttributes lets the identical calls through and both land on the bound queue.
    """
    sns = ctx.client("sns")
    topic_arn = _make_topic(ctx)
    queue_url, queue_arn = _make_bound_queue(ctx, topic_arn)
    _confirm_subscription(ctx, topic_arn, queue_arn)

    run_id = ctx.unique_name("sim2real-behav-sns-cbdflip-")
    group_id = f"{run_id}-group"
    single_body = f"{run_id}-single"
    batch_body = f"{run_id}-batch"

    expect_error(
        lambda: sns.publish(TopicArn=topic_arn, Message=single_body, MessageGroupId=group_id),
        *_MISSING_DEDUP_ID,
    )
    expect_error(
        lambda: sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=[
                {"Id": "entry", "Message": batch_body, "MessageGroupId": group_id},
            ],
        ),
        *_MISSING_DEDUP_ID,
    )

    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="ContentBasedDeduplication", AttributeValue="true"
    )
    live = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["ContentBasedDeduplication"]
    assert live == "true", f"expected ContentBasedDeduplication to read back 'true', got {live!r}"

    sns.publish(TopicArn=topic_arn, Message=single_body, MessageGroupId=group_id)

    batch_resp = sns.publish_batch(
        TopicArn=topic_arn,
        PublishBatchRequestEntries=[
            {"Id": "entry", "Message": batch_body, "MessageGroupId": group_id},
        ],
    )
    assert batch_resp.get("Failed") == [], f"expected no Failed entries, got {batch_resp.get('Failed')}"
    succeeded_ids = {e["Id"] for e in batch_resp.get("Successful", [])}
    assert succeeded_ids == {"entry"}, f"expected entry 'entry' to succeed, got {succeeded_ids!r}"

    marker = f"{run_id}-marker"
    sns.publish(
        TopicArn=topic_arn, Message=marker, MessageGroupId=group_id,
        MessageDeduplicationId=f"{run_id}-marker-dedup",
    )
    delivered = _bodies_ahead_of_marker(ctx, queue_url, marker)
    assert delivered == [single_body, batch_body], (
        f"expected exactly the two accepted publishes, in order, got {delivered!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
