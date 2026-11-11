"""unsubscribe-stops-delivery."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsubscribe-stops-delivery"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

_TAGS_KV = [{"Key": "sim2real", "Value": "sns-unsubscribe"}, {"Key": "sim2real:managed", "Value": "true"}]

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
        tags={t["Key"]: t["Value"] for t in _TAGS_KV},
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

def _drain_for(ctx, queue_url, duration_s, until=None):
    """Long-poll a queue across duration_s wall-clock seconds, or until ``until`` is among the
    bodies; deletes and returns every body seen."""
    sqs = ctx.client("sqs")
    bodies = []
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline and (until is None or until not in bodies):
        wait = int(min(20, max(1, deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            bodies.append(m["Body"])
    return bodies

def _queue_depth(ctx, queue_url):
    """ApproximateNumberOfMessages, as an independent observable alongside an empty receive."""
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"])

@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A publish before Unsubscribe reaches the SQS subscriber and one after it does not (an empty receive
    and ApproximateNumberOfMessages 0 for at least 3x the baseline latency); GetSubscriptionAttributes on
    the removed subscription answers NotFound "Subscription does not exist".
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-unsub-"), tags=_TAGS_KV)
    queue_url, queue_arn = _create_sqs_queue_for_sns(ctx, topic_arn)

    sub_arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    assert sub_arn.startswith(topic_arn + ":"), f"expected an auto-confirmed SubscriptionArn, got {sub_arn!r}"

    baseline_payload = f"baseline-{uuid.uuid4()}"
    baseline_start = time.monotonic()
    sns.publish(TopicArn=topic_arn, Message=baseline_payload)
    baseline_bodies = _drain_for(ctx, queue_url, duration_s=30, until=baseline_payload)
    baseline_latency_s = time.monotonic() - baseline_start
    assert baseline_payload in baseline_bodies, (
        f"the subscription never delivered a baseline publish, so the absence checked below "
        f"would prove nothing: got {baseline_bodies!r}"
    )

    sns.unsubscribe(SubscriptionArn=sub_arn)

    payload = f"should-not-arrive-{uuid.uuid4()}"
    sns.publish(TopicArn=topic_arn, Message=payload)

    hold_s = max(20.0, baseline_latency_s * 3)
    bodies = _drain_for(ctx, queue_url, duration_s=hold_s)
    assert payload not in bodies, "message was delivered to a queue after its subscription was removed"
    depth = _queue_depth(ctx, queue_url)
    assert depth == 0, f"queue reports {depth} message(s) still pending after the withheld publish"

    try:
        result = sns.get_subscription_attributes(SubscriptionArn=sub_arn)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"GetSubscriptionAttributes on the unsubscribed arn SUCCEEDED: {result!r}")
    assert code == "NotFound", f"expected NotFound for unsubscribed arn, got {code}"
    assert message == "Subscription does not exist", f"unexpected NotFound message for unsubscribed arn: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
