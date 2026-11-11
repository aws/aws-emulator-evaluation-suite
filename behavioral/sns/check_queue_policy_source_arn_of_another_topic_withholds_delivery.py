"""queue-policy-source-arn-of-another-topic-withholds-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "queue-policy-source-arn-of-another-topic-withholds-delivery"
GROUP = "authorization"
SERVICES = ["sns"]

_ROUNDS = 3


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SNS presents the publishing topic's ARN as `aws:SourceArn`: a queue whose policy admits only
    topic A receives A's messages and none from subscribed, confirmed topic B, while a control queue
    admitting B receives them; adding B's ARN to the condition makes the same queue receive B."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_a = _create_topic(ctx, "sim2real-behav-sns-srca-")
    topic_b = _create_topic(ctx, "sim2real-behav-sns-srcb-")
    shared_url, shared_arn = _create_queue(ctx, "sim2real-behav-sns-shared-")
    control_url, control_arn = _create_queue(ctx, "sim2real-behav-sns-ctl-")

    _set_queue_policy(sqs, shared_url, shared_arn, [topic_a])
    _set_queue_policy(sqs, control_url, control_arn, [topic_b])

    for topic, queue in ((topic_a, shared_arn), (topic_b, shared_arn), (topic_b, control_arn)):
        sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub: sns.unsubscribe(SubscriptionArn=s))
        pending = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]["PendingConfirmation"]
        assert pending == "false", f"an sqs subscription must be confirmed at once; PendingConfirmation={pending!r}"

    seen_shared: list[tuple[str, str]] = []
    for i in range(_ROUNDS):
        body_b = ctx.unique_name(f"sim2real-b{i}-")
        body_a = ctx.unique_name(f"sim2real-a{i}-")
        mid_b = sns.publish(TopicArn=topic_b, Message=body_b)["MessageId"]
        assert mid_b, "Publish to topic B must return a MessageId even though one subscriber will not get it"
        got = _drain_until(sqs, control_url, {body_b}, 60)
        assert got == [(topic_b, body_b)], f"control queue must receive B's round-{i} message, got {got!r}"
        sns.publish(TopicArn=topic_a, Message=body_a)
        seen_shared += _drain_until(sqs, shared_url, {body_a}, 60)
        assert (topic_a, body_a) in seen_shared, (
            f"the shared queue must receive topic A's round-{i} message; it received {seen_shared!r}"
        )
    leaked = [m for m in seen_shared if m[0] == topic_b]
    assert leaked == [], (
        "the shared queue's policy admits only topic A as aws:SourceArn, yet it received "
        f"{len(leaked)} message(s) published to topic B"
    )
    assert sorted(t for t, _ in seen_shared) == [topic_a] * _ROUNDS, (
        f"the shared queue must hold exactly {_ROUNDS} messages from topic A, got {len(seen_shared)}"
    )

    # Repair: admit B too. The same queue then receives B's next message.
    _set_queue_policy(sqs, shared_url, shared_arn, [topic_a, topic_b])
    deadline = time.monotonic() + 120
    delivered: list[tuple[str, str]] = []
    while time.monotonic() < deadline:
        body = ctx.unique_name("sim2real-b-repair-")
        sns.publish(TopicArn=topic_b, Message=body)
        delivered = _drain_until(sqs, shared_url, {body}, 20)
        if (topic_b, body) in delivered:
            break
    else:
        raise AssertionError(
            "after the queue policy admitted topic B, no message published to B reached the "
            f"shared queue within the deadline; last drain {delivered!r}"
        )


def _create_topic(ctx, prefix: str) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name(prefix),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name(prefix), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _set_queue_policy(sqs, url: str, arn: str, topics: list[str]) -> None:
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topics}},
        }],
    })
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": policy})
    deadline = time.monotonic() + 60
    while _norm(json.loads(sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])
                           ["Attributes"].get("Policy", "{}"))) != _norm(json.loads(policy)):
        assert time.monotonic() < deadline, "the queue policy never read back as set"
        time.sleep(2)


def _norm(doc):
    """A policy document with every one-element list collapsed to its element and every list
    sorted, the form SQS stores; two documents are equal when their normal forms are."""
    if isinstance(doc, dict):
        return {k: _norm(v) for k, v in doc.items()}
    if isinstance(doc, list):
        items = [_norm(v) for v in doc]
        return items[0] if len(items) == 1 else sorted(items, key=json.dumps)
    return doc


def _drain_until(sqs, url: str, wanted: set[str], timeout_s: float) -> list[tuple[str, str]]:
    """Receive and delete until every body in ``wanted`` has arrived or the deadline passes;
    returns (TopicArn, Message) for every notification drained."""
    out: list[tuple[str, str]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= {m for _, m in out}:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            env = json.loads(msg["Body"])
            out.append((env["TopicArn"], env["Message"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
