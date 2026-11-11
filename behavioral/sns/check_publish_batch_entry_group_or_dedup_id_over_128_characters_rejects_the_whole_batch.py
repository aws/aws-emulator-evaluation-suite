"""publish-batch-entry-group-or-dedup-id-over-128-characters-rejects-the-whole-batch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-entry-group-or-dedup-id-over-128-characters-rejects-the-whole-batch"
GROUP = "publish-batch-limits"
SERVICES = ["sns"]

_SCENARIO = "sns-publish-batch-groupdedup-len"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A 129-character MessageGroupId or MessageDeduplicationId on one PublishBatch entry fails the
    whole batch with InvalidParameter and its siblings are never delivered; at 128 characters the
    batch is accepted and every body arrives.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn, attributes={"RawMessageDelivery": "true"})

    run_id = ctx.unique_name("sim2real-behav-sns-groupdedup-")
    group = f"{run_id}-group"

    def _dedup_id(n: int) -> str:
        """A distinct, well-formed (<=128-character) MessageDeduplicationId."""
        stem = f"{run_id}-d{n}-"
        return stem + "d" * (128 - len(stem))

    dedup129 = _dedup_id(0) + "x"
    good1 = f"{run_id}-good-1"
    good2 = f"{run_id}-good-2"

    code, message = _error(lambda: sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "good-1", "Message": good1, "MessageGroupId": group,
         "MessageDeduplicationId": _dedup_id(1)},
        {"Id": "bad", "Message": "too-long-dedup", "MessageGroupId": group,
         "MessageDeduplicationId": dedup129},
        {"Id": "good-2", "Message": good2, "MessageGroupId": group,
         "MessageDeduplicationId": _dedup_id(2)},
    ]))
    assert code == "InvalidParameter", (
        f"a PublishBatch with one 129-character MessageDeduplicationId gave {code!r}, "
        f"expected 'InvalidParameter'; message {message!r}"
    )
    expected_message = (
        "Invalid parameter: The MessageDeduplicationId parameter can only include "
        "alphanumeric and punctuation characters. 1 to 128 in length"
    )
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    group129 = (f"{run_id}-g-" + "g" * 128)[:129]
    good3 = f"{run_id}-good-3"
    good4 = f"{run_id}-good-4"
    code, message = _error(lambda: sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "good-3", "Message": good3, "MessageGroupId": group,
         "MessageDeduplicationId": _dedup_id(7)},
        {"Id": "bad", "Message": "too-long-group", "MessageGroupId": group129,
         "MessageDeduplicationId": _dedup_id(8)},
        {"Id": "good-4", "Message": good4, "MessageGroupId": group,
         "MessageDeduplicationId": _dedup_id(9)},
    ]))
    assert code == "InvalidParameter", (
        f"a PublishBatch with one 129-character MessageGroupId gave {code!r}, "
        f"expected 'InvalidParameter'; message {message!r}"
    )
    expected_message = (
        "Invalid parameter: The MessageGroupId parameter can only include "
        "alphanumeric and punctuation characters. 1 to 128 in length"
    )
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # The positive control's delivery latency bounds the absence window below.
    control_body = f"{run_id}-control"
    started = time.monotonic()
    ctrl = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "ctrl", "Message": control_body, "MessageGroupId": group,
         "MessageDeduplicationId": _dedup_id(3)}])
    assert ctrl.get("Failed", []) == [] and len(ctrl.get("Successful", [])) == 1, (
        f"the positive control (one legal entry alone) must be accepted, got {ctrl!r}"
    )
    seen = _await_bodies(ctx, queue_url, {control_body}, timeout_s=60.0,
                         description="the positive control is delivered")
    latency_s = seen[control_body] - started
    window_s = max(3.0 * latency_s, 20.0)

    leaked = _drain(ctx, queue_url, window_s=window_s)
    assert not {good1, good2, good3, good4} & set(leaked), (
        f"the batch was rejected as a whole, so its well-formed siblings must not be delivered "
        f"-- but queue produced {leaked!r} within a {window_s:.1f}s window (>=3x the "
        f"{latency_s:.1f}s control latency)"
    )

    # Repair: trim the offending id to the 128-character boundary; every entry now succeeds
    # and is delivered carrying the group id it was published with.
    dedup128_boundary = _dedup_id(4)
    assert len(dedup128_boundary) == 128, f"boundary dedup id is {len(dedup128_boundary)} characters"
    repaired = sns.publish_batch(TopicArn=topic_arn, PublishBatchRequestEntries=[
        {"Id": "good-1", "Message": good1, "MessageGroupId": group,
         "MessageDeduplicationId": _dedup_id(5)},
        {"Id": "fixed", "Message": "fixed-dedup", "MessageGroupId": group,
         "MessageDeduplicationId": dedup128_boundary},
        {"Id": "good-2", "Message": good2, "MessageGroupId": group,
         "MessageDeduplicationId": _dedup_id(6)},
    ])
    assert repaired.get("Failed", []) == [] and sorted(
        e["Id"] for e in repaired.get("Successful", [])) == ["fixed", "good-1", "good-2"], (
        f"the repaired batch must report all three entries Successful, got {repaired!r}"
    )
    delivered = _await_bodies(ctx, queue_url, {good1, good2, "fixed-dedup"}, timeout_s=90.0,
                              description="the repaired batch is delivered")
    assert set(delivered) == {good1, good2, "fixed-dedup"}, (
        f"the repaired batch must deliver every entry, got {sorted(delivered)!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx) -> str:
    """CreateTopic (FIFO, tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-groupdedup-") + ".fifo"
    arn = sns.create_topic(
        Name=name, Attributes={"FifoTopic": "true"}, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real FIFO SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-groupdedup-q-") + ".fifo"
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


def _await_bodies(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                  description: str) -> dict[str, float]:
    """Long-poll until every wanted body is seen; RAISES on the deadline. Returns {body: time
    first seen}."""
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            if body in outstanding:
                outstanding.discard(body)
                seen[body] = time.monotonic()
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s")
    return seen


def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll a queue for window_s and return every body it produced."""
    sqs = ctx.client("sqs")
    out: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            out.append(msg["Body"])
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
