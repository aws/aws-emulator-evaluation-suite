"""e2e-topic-fanout-filter-teardown-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-topic-fanout-filter-teardown-flow"
GROUP = "state-machine"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two differently-filtered subscriptions each receive only their matching message; after
    unsubscribe and DeleteTopic both read NotFound by ARN and leave their listings, and Publish
    to the deleted topic is refused NotFound while a fresh topic still accepts Publish."""
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-fanout-topic-"), Tags=_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_topic(ctx, topic_arn))

    queue_a = _create_queue_with_sns_policy(ctx, topic_arn)
    queue_b = _create_queue_with_sns_policy(ctx, topic_arn)

    sub_a = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_a["arn"])["SubscriptionArn"]
    sub_b = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_b["arn"])["SubscriptionArn"]
    sns.set_subscription_attributes(
        SubscriptionArn=sub_a, AttributeName="FilterPolicy", AttributeValue='{"team": ["a"]}'
    )
    sns.set_subscription_attributes(
        SubscriptionArn=sub_b, AttributeName="FilterPolicy", AttributeValue='{"team": ["b"]}'
    )
    sns.set_subscription_attributes(SubscriptionArn=sub_a, AttributeName="RawMessageDelivery", AttributeValue="true")
    sns.set_subscription_attributes(SubscriptionArn=sub_b, AttributeName="RawMessageDelivery", AttributeValue="true")

    marker_a = ctx.unique_name("sim2real-marker-a-")
    marker_b = ctx.unique_name("sim2real-marker-b-")
    sns.publish(
        TopicArn=topic_arn,
        Message=marker_a,
        MessageAttributes={"team": {"DataType": "String", "StringValue": "a"}},
    )
    sns.publish(
        TopicArn=topic_arn,
        Message=marker_b,
        MessageAttributes={"team": {"DataType": "String", "StringValue": "b"}},
    )

    # Each queue is drained until its own marker arrives, then once more, so a stray copy of the
    # other marker that arrives alongside it is caught; the twin queue is the delivery control.
    bodies_a = _drain_until(ctx, queue_a["url"], marker_a, timeout_s=120.0)
    bodies_b = _drain_until(ctx, queue_b["url"], marker_b, timeout_s=120.0)
    bodies_a += _drain_once(ctx, queue_a["url"])
    bodies_b += _drain_once(ctx, queue_b["url"])
    assert marker_a in bodies_a, f"queue A missing its matching message: {bodies_a}"
    assert marker_b not in bodies_a, f"queue A received the other filter's message: {bodies_a}"
    assert marker_b in bodies_b, f"queue B missing its matching message: {bodies_b}"
    assert marker_a not in bodies_b, f"queue B received the other filter's message: {bodies_b}"

    sns.unsubscribe(SubscriptionArn=sub_a)
    sns.unsubscribe(SubscriptionArn=sub_b)

    sub_err = _poll_error(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_a), "NotFound")
    _assert_not_found(sub_err, f"GetSubscriptionAttributes on unsubscribed {sub_a}")
    _poll_until(lambda: {s["SubscriptionArn"] for s in _list_subs(sns, topic_arn)},
                lambda arns: not ({sub_a, sub_b} & arns), timeout_s=120.0,
                description="the unsubscribed subscriptions leaving ListSubscriptionsByTopic")

    sns.delete_topic(TopicArn=topic_arn)

    attrs_err = _poll_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn), "NotFound")
    _assert_not_found(attrs_err, f"GetTopicAttributes on deleted topic {topic_arn}")

    _poll_until(lambda: _list_topic_arns(sns), lambda arns: topic_arn not in arns,
                timeout_s=120.0, description=f"deleted topic {topic_arn} leaving ListTopics")

    publish_err = _poll_error(lambda: sns.publish(TopicArn=topic_arn, Message="after-delete"), "NotFound")
    _assert_not_found(publish_err, f"Publish on deleted topic {topic_arn}")

    other_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-fanout-control-"), Tags=_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=other_arn))
    resp = sns.publish(TopicArn=other_arn, Message="control-ok")
    assert "MessageId" in resp, f"control publish to a live topic returned no MessageId: {resp!r}"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": "sns-fanout-teardown"}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_queue_with_sns_policy(ctx, topic_arn: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-fanout-q-"),
        tags={"sim2real": "sns-fanout-teardown", "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _drain_once(ctx, queue_url: str) -> list[str]:
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        bodies.append(msg["Body"])
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return bodies


def _drain_until(ctx, queue_url: str, marker: str, timeout_s: float) -> list[str]:
    """Receive (and delete) until `marker` is among the bodies; raise on timeout."""
    bodies: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        bodies += _drain_once(ctx, queue_url)
        if marker in bodies:
            return bodies
    raise AssertionError(f"{marker!r} never arrived at {queue_url} within {timeout_s}s; got {bodies}")


def _poll_until(probe, predicate, *, timeout_s: float, description: str, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _poll_error(fn, code: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> dict:
    """Poll fn until it fails with `code`; return the error response. Raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = "<call succeeded>"
    while time.monotonic() < deadline:
        try:
            fn()
            last = "<call succeeded>"
        except ClientError as err:
            last = err.response["Error"]["Code"]
            if last == code:
                return err.response
        time.sleep(interval_s)
    raise AssertionError(f"expected {code}, got {last!r} after {timeout_s}s")


def _assert_not_found(response: dict, what: str) -> None:
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(status, int) and 400 <= status < 500, f"{what} returned HTTP {status!r}, expected 4xx"
    assert response["Error"].get("Message"), f"{what} returned an empty NotFound message"


def _list_topic_arns(sns) -> set[str]:
    arns: set[str] = set()
    for page in sns.get_paginator("list_topics").paginate():
        arns.update(t["TopicArn"] for t in page.get("Topics", []))
    return arns


def _list_subs(sns, topic_arn: str) -> list[dict]:
    subs: list[dict] = []
    for page in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic_arn):
        subs.extend(page.get("Subscriptions", []))
    return subs


def _best_effort_delete_topic(ctx, topic_arn: str) -> None:
    """Teardown: delete the topic; only NotFound is tolerated, every other error raises."""
    from botocore.exceptions import ClientError

    sns = ctx.client("sns")
    try:
        sns.delete_topic(TopicArn=topic_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
