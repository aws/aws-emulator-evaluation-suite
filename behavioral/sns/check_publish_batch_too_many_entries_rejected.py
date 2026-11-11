"""publish-batch-too-many-entries-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-too-many-entries-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-publish-batch-too-many-entries"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PublishBatch rejects an 11-entry request wholesale with TooManyEntriesInBatchRequest and
    delivers none of it to a subscriber, while an identical batch trimmed to the 10-entry
    maximum succeeds in full and every entry actually arrives at the destination."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    run_id = ctx.unique_name("sim2real-behav-sns-batchmax-")
    oversized_markers = [f"{run_id}-over-{i}" for i in range(11)]
    oversized_entries = [{"Id": f"e{i}", "Message": m} for i, m in enumerate(oversized_markers)]

    code, message = _error(lambda: sns.publish_batch(
        TopicArn=topic_arn, PublishBatchRequestEntries=oversized_entries))
    assert code == "TooManyEntriesInBatchRequest", (
        f"expected TooManyEntriesInBatchRequest for an 11-entry batch, got {code!r}"
    )
    expected_message = "The batch request contains more entries than permissible."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    leaked = _receive_any(ctx, queue_url, rounds=1, wait_s=10)
    stray = [b for b in leaked if b in oversized_markers]
    assert stray == [], (
        f"the 11-entry batch was rejected wholesale, so none of it may be delivered — but "
        f"{stray!r} arrived"
    )

    valid_markers = [f"{run_id}-ok-{i}" for i in range(10)]
    valid_entries = [{"Id": f"ok{i}", "Message": m} for i, m in enumerate(valid_markers)]
    resp = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=valid_entries)
    assert not resp.get("Failed"), f"expected no Failed entries, got {resp.get('Failed')}"
    assert len(resp.get("Successful", [])) == 10, (
        f"expected a 10-entry batch to be accepted in full, got {resp.get('Successful')}"
    )

    delivered = _drain_until_all(ctx, queue_url, valid_markers, timeout_s=90.0)
    assert sorted(delivered) == sorted(valid_markers), (
        f"the accepted 10-entry batch did not deliver every entry: {delivered!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS error (Code, Message) raised by fn(). Raises if fn SUCCEEDS — an unexpected success is
    the strongest possible signal."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _create_topic(ctx) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-batchmax-")
    arn = sns.create_topic(
        Name=name,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-batchmax-q-")
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


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue (raw delivery) and poll GetSubscriptionAttributes until confirmed."""
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
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


def _drain_until_all(ctx, queue_url: str, wanted: list[str], *, timeout_s: float = 90.0) -> list[str]:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
