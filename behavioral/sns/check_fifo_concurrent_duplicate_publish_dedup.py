"""fifo-concurrent-duplicate-publish-dedup."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-concurrent-duplicate-publish-dedup"
GROUP = 'fifo-topic'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-concurrent-dedup"


def _create_topic(ctx) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-fifoconc-") + ".fifo"
    arn = sns.create_topic(
        Name=name,
        Attributes={"FifoTopic": "true"},
        Tags=[{"Key": "sim2real", "Value": _SCENARIO},
              {"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS FIFO queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-fifoconc-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true"},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
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
    """Subscribe the real queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn))
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


def _drain_until_body(ctx, queue_url: str, sentinel: str, timeout_s: float = 120.0) -> list[str]:
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


def _run_concurrent(fns):
    """Run callables in parallel; return results 1:1 in submission order (exceptions captured, not raised)."""
    results = [None] * len(fns)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns))) as ex:
        fut_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(fut_to_idx):
            i = fut_to_idx[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                results[i] = exc
    return results


def _error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Five concurrent Publish calls sharing a MessageDeduplicationId collapse to exactly one
    message: all succeed with one SequenceNumber and MessageId, and the queue receives one copy.
    """
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    sns = ctx.client("sns")
    run_id = ctx.unique_name("sim2real-behav-sns-fifoconc-")
    group = f"{run_id}-group"
    dedup_id = f"{run_id}-dedup"
    racer_bodies = [f"{run_id}-racer-{i}" for i in range(5)]

    def publisher(body: str):
        return sns.publish(
            TopicArn=topic_arn, Message=body, MessageGroupId=group,
            MessageDeduplicationId=dedup_id,
        )

    results = _run_concurrent([lambda b=b: publisher(b) for b in racer_bodies])
    n_ok = sum(1 for r in results if not isinstance(r, BaseException))
    assert n_ok == 5, (
        f"expected all 5 racing Publish calls to be accepted, got {n_ok} "
        f"(errors: {_error_codes(results)})"
    )

    oks = [r for r in results if not isinstance(r, BaseException)]
    seqs = {r["SequenceNumber"] for r in oks}
    msg_ids = {r["MessageId"] for r in oks}
    assert len(seqs) == 1, (
        f"expected dedup to collapse concurrent duplicates to one SequenceNumber, got {seqs}"
    )
    assert len(msg_ids) == 1, (
        f"expected dedup to collapse concurrent duplicates to one MessageId, got {msg_ids}"
    )

    # FIFO order within the group makes the sentinel arrive last, bounding the drain.
    sentinel = f"{run_id}-sentinel"
    sns.publish(
        TopicArn=topic_arn, Message=sentinel, MessageGroupId=group,
        MessageDeduplicationId=f"{run_id}-sentinel-dedup",
    )
    before_sentinel = _drain_until_body(ctx, queue_url, sentinel, timeout_s=120.0)
    delivered_racers = [b for b in before_sentinel if b in racer_bodies]
    assert len(delivered_racers) == 1, (
        f"a shared MessageDeduplicationId produced {len(delivered_racers)} deliveries at the "
        f"queue, expected exactly 1: {delivered_racers!r} (seen before sentinel: {before_sentinel!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
