"""publish-batch-duplicate-ids-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-duplicate-ids-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-publish-batch-duplicate-ids"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PublishBatch refuses a request whose two entries share an Id with BatchEntryIdsNotDistinct
    and delivers neither entry, while the same entries with distinct Ids succeed and both arrive.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx, ctx.unique_name("sim2real-behav-sns-batchdup-"))
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn, "sim2real-behav-sns-batchdup-q-")
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    run_id = ctx.unique_name("sim2real-behav-sns-batchdup-run-")
    control_markers = [f"{run_id}-control-a", f"{run_id}-control-b"]

    control_start = time.monotonic()
    resp = sns.publish_batch(
        TopicArn=topic_arn,
        PublishBatchRequestEntries=[
            {"Id": "a", "Message": control_markers[0]},
            {"Id": "b", "Message": control_markers[1]},
        ],
    )
    assert resp.get("Failed", []) == [], (
        f"positive control reported failures: {resp.get('Failed')!r}"
    )
    assert sorted(e["Id"] for e in resp.get("Successful", [])) == ["a", "b"], (
        f"positive control did not report both entries Successful: {resp.get('Successful')!r}"
    )
    _drain_until_all(ctx, queue_url, control_markers, timeout_s=60.0)
    control_latency_s = time.monotonic() - control_start
    # The absence wait is bounded by the control's own measured delivery latency.
    absence_window_s = max(3.0 * control_latency_s, 20.0)

    broken_markers = [f"{run_id}-broken-a", f"{run_id}-broken-b"]
    code = _error_code(lambda: sns.publish_batch(
        TopicArn=topic_arn,
        PublishBatchRequestEntries=[
            {"Id": "dup", "Message": broken_markers[0]},
            {"Id": "dup", "Message": broken_markers[1]},
        ],
    ))
    assert code == "BatchEntryIdsNotDistinct", (
        f"expected BatchEntryIdsNotDistinct for a batch with two entries sharing Id 'dup', got {code!r}"
    )

    leaked = _receive_for(ctx, queue_url, duration_s=absence_window_s)
    leaked_bodies = [m["Body"] for m in leaked]
    assert not any(b in broken_markers for b in leaked_bodies), (
        f"the duplicate-Id batch was rejected as a whole, so neither entry may be delivered — "
        f"but {[b for b in leaked_bodies if b in broken_markers]!r} arrived within "
        f"{absence_window_s:.1f}s (>= 3x the {control_latency_s:.1f}s control latency)"
    )
    visible = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert visible == "0", (
        f"expected ApproximateNumberOfMessages == '0' after the rejected batch, got {visible!r}"
    )

    repaired = sns.publish_batch(
        TopicArn=topic_arn,
        PublishBatchRequestEntries=[
            {"Id": "a2", "Message": broken_markers[0]},
            {"Id": "b2", "Message": broken_markers[1]},
        ],
    )
    assert repaired.get("Failed", []) == [], (
        f"repaired batch (distinct Ids) reported failures: {repaired.get('Failed')!r}"
    )
    assert sorted(e["Id"] for e in repaired.get("Successful", [])) == ["a2", "b2"], (
        f"repaired batch did not report both entries Successful: {repaired.get('Successful')!r}"
    )
    _drain_until_all(ctx, queue_url, broken_markers, timeout_s=60.0)


def _error_code(fn) -> str:
    """The AWS error Code raised by fn(); raises if fn succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _create_topic(ctx, name: str) -> str:
    """CreateTopic (tagged) + register DeleteTopic cleanup; returns the ARN."""
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=name,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, name_prefix: str) -> tuple[str, str]:
    """Create a REAL, tagged SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name(name_prefix)
    url = sqs.create_queue(
        QueueName=name,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
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


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue (raw delivery) and poll until it is confirmed; returns the SubscriptionArn."""
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


def _drain_until_all(ctx, queue_url: str, wanted: list[str], *, timeout_s: float = 60.0) -> list[str]:
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


def _receive_for(ctx, queue_url: str, *, duration_s: float) -> list[dict]:
    """Long-poll a queue for at least duration_s, deleting and returning everything received."""
    sqs = ctx.client("sqs")
    messages: list[dict] = []
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        remaining = max(1, min(20, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        batch = resp.get("Messages", [])
        if batch:
            sqs.delete_message_batch(
                QueueUrl=queue_url,
                Entries=[{"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(batch)],
            )
        messages.extend(batch)
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
