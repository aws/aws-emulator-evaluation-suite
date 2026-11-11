"""publish-batch-validation-is-request-level."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-validation-is-request-level"
GROUP = 'publish-semantics'
SERVICES = ['sns']

_SCENARIO = "sns-publish-batch-validation-is-request-level"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, name: str) -> str:
    """CreateTopic (tagged) and register DeleteTopic; returns the ARN."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-batchreq-q-")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": _SCENARIO, "sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
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


def _drain_until_body(ctx, queue_url: str, target: str, timeout_s: float = 60.0) -> list[str]:
    """Receive until `target`'s body arrives; returns everything seen (including target)."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            seen.append(body)
            if body == target:
                return seen
    raise AssertionError(f"{target!r} never arrived within {timeout_s}s; saw {seen!r}")


def _poll_for_leak(ctx, queue_url: str, markers: set[str], window_s: float) -> list[str]:
    """Long-poll for `window_s` and return any received body that is one of `markers`."""
    sqs = ctx.client("sqs")
    leaked: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            if body in markers:
                leaked.append(body)
    return leaked


def _drain_until_all(ctx, queue_url: str, wanted: list[str], timeout_s: float = 60.0) -> list[str]:
    """Long-poll until every wanted marker has been seen; returns the markers collected."""
    sqs = ctx.client("sqs")
    outstanding = set(wanted)
    seen: list[str] = []
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """One malformed entry fails the whole PublishBatch with ParameterValueInvalid (not a
    per-entry Failed result) and its siblings are never delivered; the repaired batch is.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx, ctx.unique_name("sim2real-behav-sns-batchreq-"))
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    run_id = ctx.unique_name("sim2real-behav-sns-batchreq-run-")
    good1 = f"{run_id}-good-1"
    good2 = f"{run_id}-good-2"

    # Measure positive-control latency L on this exact wiring before breaking anything.
    calib = f"{run_id}-calib"
    t0 = time.monotonic()
    sns.publish(TopicArn=topic_arn, Message=calib)
    _drain_until_body(ctx, queue_url, calib, timeout_s=60.0)
    latency_s = time.monotonic() - t0

    code = message = None
    try:
        sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=[
                {"Id": "good-1", "Message": good1},
                {"Id": "bad-1", "Message": "bad-attrs", "MessageAttributes": {
                    "broken": {"DataType": "Number", "StringValue": "not-a-number"}}},
                {"Id": "good-2", "Message": good2},
            ],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            "a PublishBatch with a malformed Number attribute was expected to be rejected, "
            "but it SUCCEEDED"
        )
    assert code == "ParameterValueInvalid", (
        f"expected request-level ParameterValueInvalid for a malformed entry, got {code}"
    )
    expected_message = "Could not cast message attribute 'broken' value to number."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Absence of delivery is bounded by >=3x the measured latency, then confirmed by queue depth.
    window_s = max(3.0 * latency_s, 15.0)
    leaked = _poll_for_leak(ctx, queue_url, {good1, good2}, window_s)
    assert leaked == [], (
        f"the batch was rejected as a whole, so neither sibling entry may be delivered — but "
        f"{leaked!r} arrived within a {window_s:.1f}s window (>=3x the {latency_s:.1f}s "
        f"positive-control latency measured on the same wiring)"
    )
    remaining = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"].get("ApproximateNumberOfMessages")
    assert remaining == "0", (
        f"expected an empty queue after the bounded absence window, got "
        f"ApproximateNumberOfMessages={remaining!r}"
    )

    resp = sns.publish_batch(
        TopicArn=topic_arn,
        PublishBatchRequestEntries=[
            {"Id": "good-1", "Message": good1},
            {"Id": "good-2", "Message": good2},
        ],
    )
    successful_ids = {e["Id"] for e in resp.get("Successful", [])}
    assert successful_ids == {"good-1", "good-2"}, (
        f"expected both entries in Successful, got {resp.get('Successful')}"
    )
    assert not resp.get("Failed"), f"expected no Failed entries, got {resp.get('Failed')}"
    msg_ids = {e["MessageId"] for e in resp["Successful"]}
    assert len(msg_ids) == 2, f"expected a distinct MessageId per entry, got {msg_ids}"

    delivered = _drain_until_all(ctx, queue_url, [good1, good2], timeout_s=60.0)
    assert sorted(delivered) == sorted([good1, good2]), (
        f"the repaired batch did not deliver both entries at the destination, got {delivered!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
