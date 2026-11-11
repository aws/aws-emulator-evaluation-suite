"""overlapping-filters-fan-one-message-to-every-matching-queue-and-the-deleted-topic-refuses-publish-and-listing."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overlapping-filters-fan-one-message-to-every-matching-queue-and-the-deleted-topic-refuses-publish-and-listing"
GROUP = "state-machine"
SERVICES = ["sns"]

TOPIC_GONE = "Topic does not exist"

# Filter per queue, and the attributes of each published message.
FILTERS = {
    "control": None,
    "a": {"team": ["a", "shared"]},
    "b": {"team": ["b", "shared"]},
    "c": {"priority": [{"numeric": [">", 5]}]},
}
MESSAGES = {
    "only-a": {"team": "a", "priority": 1},
    "all-three": {"team": "shared", "priority": 9},
    "only-c": {"team": "z", "priority": 7},
    "none": {"team": "z", "priority": 5},
}
EXPECTED = {
    "control": set(MESSAGES),
    "a": {"only-a", "all-three"},
    "b": {"all-three"},
    "c": {"all-three", "only-c"},
}


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Three subscriptions with overlapping string and numeric filters each receive exactly the
    messages their policy matches (one reaches all three, one none, an unfiltered twin gets all); DeleteTopic
    then refuses Publish and ListSubscriptionsByTopic with NotFound and drops the topic from ListTopics.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-fanout-topic-"), Tags=_tags_kv())[
        "TopicArn"
    ]
    ctx.on_cleanup(lambda: _delete_topic_if_present(ctx, topic_arn))

    queues, subs = {}, {}
    for key, policy in FILTERS.items():
        queues[key] = _create_queue_with_sns_policy(ctx, topic_arn)
        subs[key] = sns.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queues[key]["arn"],
            Attributes={
                "RawMessageDelivery": "true",
                **({"FilterPolicy": json.dumps(policy)} if policy else {}),
            },
            ReturnSubscriptionArn=True,
        )["SubscriptionArn"]
        ctx.on_cleanup(lambda arn=subs[key]: _unsubscribe_if_present(ctx, arn))

    markers = {label: ctx.unique_name(f"sim2real-{label}-") for label in MESSAGES}
    for label, attrs in MESSAGES.items():
        sns.publish(
            TopicArn=topic_arn,
            Message=markers[label],
            MessageAttributes={
                "team": {"DataType": "String", "StringValue": attrs["team"]},
                "priority": {"DataType": "Number", "StringValue": str(attrs["priority"])},
            },
        )

    # The unfiltered control queue is drained first: once it holds all four, every message has been
    # dispatched, so each filtered queue is drained to its expected set and once more for strays.
    for key, want_labels in EXPECTED.items():
        want = {markers[label] for label in want_labels}
        bodies = _drain_until(ctx, queues[key]["url"], want, timeout_s=40.0)
        bodies += _drain_once(ctx, queues[key]["url"])
        got = sorted(label for label, m in markers.items() if m in bodies)
        assert got == sorted(want_labels), (
            f"queue {key} received {got}, expected {sorted(want_labels)}"
        )
        # Markers are unique per publish, so a repeated delivery is the same marker; anything else
        # is a stray.
        assert set(bodies) == {markers[label] for label in want_labels}, (
            f"queue {key} received {sorted(set(bodies))}, expected only its matching markers"
        )

    sns.delete_topic(TopicArn=topic_arn)
    attrs_err = _poll_error(lambda: sns.get_topic_attributes(TopicArn=topic_arn), "NotFound")
    _assert_not_found(attrs_err, "GetTopicAttributes on the deleted topic", TOPIC_GONE)
    _poll_until(
        lambda: _list_topic_arns(sns),
        lambda arns: topic_arn not in arns,
        timeout_s=40.0,
        description="the deleted topic leaving ListTopics",
    )
    listing_err = _poll_error(
        lambda: sns.list_subscriptions_by_topic(TopicArn=topic_arn), "NotFound"
    )
    _assert_not_found(listing_err, "ListSubscriptionsByTopic on the deleted topic", TOPIC_GONE)
    publish_err = _error(
        lambda: sns.publish(TopicArn=topic_arn, Message="after-delete"),
        "NotFound",
        "Publish on the deleted topic",
    )
    _assert_not_found(publish_err, "Publish on the deleted topic", TOPIC_GONE)


def _tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": "sns-overlap-fanout"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _create_queue_with_sns_policy(ctx, topic_arn: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-fanout-q-"),
        tags={"sim2real": "sns-overlap-fanout", "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
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


def _drain_until(ctx, queue_url: str, wanted: set[str], timeout_s: float) -> list[str]:
    """Receive (and delete) until every marker in `wanted` is among the bodies; raise on timeout."""
    bodies: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        bodies += _drain_once(ctx, queue_url)
        if wanted <= set(bodies):
            return bodies
    raise AssertionError(
        f"{sorted(wanted - set(bodies))} never arrived at {queue_url} within {timeout_s}s; got {bodies}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, description: str, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error(fn, code: str, what: str) -> dict:
    """The error response of one call failing with ``code``; any other outcome fails."""
    try:
        fn()
    except ClientError as err:
        got = err.response["Error"]["Code"]
        assert got == code, f"{what}: expected {code}, got {got!r}"
        return err.response
    raise AssertionError(f"{what}: expected {code}, the call succeeded")


def _poll_error(fn, code: str, timeout_s: float = 40.0, interval_s: float = 2.0) -> dict:
    """Poll fn until it fails with `code`; return the error response. Raise on timeout."""
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


def _assert_not_found(response: dict, what: str, message: str) -> None:
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 404, f"{what} returned HTTP {status!r}, expected 404"
    got = response["Error"].get("Message")
    assert got == message, f"{what} returned message {got!r}, expected {message!r}"


def _list_topic_arns(sns) -> set[str]:
    arns: set[str] = set()
    for page in sns.get_paginator("list_topics").paginate():
        arns.update(t["TopicArn"] for t in page.get("Topics", []))
    return arns


def _delete_topic_if_present(ctx, topic_arn: str) -> None:
    """Teardown: delete the topic; only NotFound is tolerated, every other error raises."""
    try:
        ctx.client("sns").delete_topic(TopicArn=topic_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFound":
            raise


def _unsubscribe_if_present(ctx, sub_arn: str) -> None:
    """Teardown: remove the subscription; only NotFound is tolerated."""
    try:
        ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
