"""subscription-filter-policy-delivery."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "subscription-filter-policy-delivery"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

_SCENARIO = "sns-subscription-filter-policy-delivery"

def _tags_kv():
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]

def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _create_sqs_queue_for_sns(ctx, topic_arn, fifo=False):
    """Create a REAL SQS queue whose policy lets the topic publish to it; returns (queue_url, queue_arn)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attributes = {}
    if fifo:
        name = name + ".fifo"
        attributes["FifoQueue"] = "true"
    queue_url = sqs.create_queue(
        QueueName=name, Attributes=attributes,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=queue_url: ctx.client("sqs").delete_queue(QueueUrl=u))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
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
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, queue_arn

def _await_message(ctx, queue_url, needle, timeout_s=60.0, interval_s=2):
    """Long-poll until a body equal to needle arrives; returns (elapsed_seconds, other_bodies_seen)."""
    sqs = ctx.client("sqs")
    start = time.monotonic()
    deadline = start + timeout_s
    others = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=int(interval_s))
        for m in resp.get("Messages", []):
            body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body == needle:
                return time.monotonic() - start, others
            others.append(body)
    raise AssertionError(f"matching message {needle!r} never arrived within {timeout_s}s; saw {others!r}")

def _drain_for(ctx, queue_url, duration_s, interval_s=2):
    """Long-poll for exactly duration_s, deleting as it drains; returns every body seen."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + duration_s
    bodies = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=int(interval_s))
        for m in resp.get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return bodies

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))

def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    budget_s = _budget_s(ctx, cap_s)
    start = time.monotonic()
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected}; last observed {observed}")
        time.sleep(3)

@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A subscription FilterPolicy delivers the matching message and withholds the non-matching one
    for >=3x the matching delivery latency (floor 15s), after which the queue depth polls to 0."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-filter-"), tags=_tags_kv())
    queue_url, queue_arn = _create_sqs_queue_for_sns(ctx, topic_arn)

    sub_arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={
            "RawMessageDelivery": "true",
            "FilterPolicy": json.dumps({"category": ["match-me"]}),
        },
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    matching = f"matched-{uuid.uuid4()}"
    nonmatching = f"skipped-{uuid.uuid4()}"

    r1 = sns.publish(
        TopicArn=topic_arn,
        Message=matching,
        MessageAttributes={"category": {"DataType": "String", "StringValue": "match-me"}},
    )
    assert r1.get("MessageId"), "Publish of the matching message returned no MessageId"

    positive_latency, stray = _await_message(ctx, queue_url, matching, timeout_s=60.0)
    assert not stray, f"unexpected messages arrived before the matching one: {stray!r}"

    r2 = sns.publish(
        TopicArn=topic_arn,
        Message=nonmatching,
        MessageAttributes={"category": {"DataType": "String", "StringValue": "other"}},
    )
    assert r2.get("MessageId"), "Publish of the non-matching message returned no MessageId"

    absence_window = max(3 * positive_latency, 15.0)
    seen = _drain_for(ctx, queue_url, absence_window)
    assert nonmatching not in seen, f"filter policy should have dropped {nonmatching!r}, got {seen!r}"

    _poll_queue_counters(
        ctx, sqs, queue_url, {"ApproximateNumberOfMessages": "0", "ApproximateNumberOfMessagesNotVisible": "0"}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
