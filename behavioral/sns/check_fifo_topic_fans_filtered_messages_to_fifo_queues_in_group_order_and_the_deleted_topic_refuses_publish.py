"""fifo-topic-fans-filtered-messages-to-fifo-queues-in-group-order-and-the-deleted-topic-refuses-publish."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-topic-fans-filtered-messages-to-fifo-queues-in-group-order-and-the-deleted-topic-refuses-publish"
GROUP = "state-machine"
SERVICES = ["sns"]

TOPIC_GONE = "Topic does not exist"
MESSAGE_GROUP = "orders-1"
# Publish order: team per message; "c" matches no filter.
TEAMS = ["a", "b", "b", "a", "c", "a", "b"]
FILTERS = {"control": None, "a": {"team": ["a"]}, "b": {"team": ["b"]}}


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
    """A FIFO topic's filtered FIFO-queue subscriptions each receive only their team's messages, in
    publish order and with the message group id, while an unfiltered twin receives all seven in order;
    after DeleteTopic, ListSubscriptionsByTopic and Publish on it are refused NotFound.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-fanout-topic-") + ".fifo",
        Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "false"},
        Tags=_tags_kv(),
    )["TopicArn"]
    ctx.on_cleanup(lambda: _delete_topic_if_present(ctx, topic_arn))

    queues, subs = {}, {}
    for key, policy in FILTERS.items():
        queues[key] = _create_fifo_queue_with_sns_policy(ctx, topic_arn)
        attrs = {"RawMessageDelivery": "true"}
        if policy:
            attrs["FilterPolicy"] = json.dumps(policy)
        subs[key] = sns.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queues[key]["arn"],
            Attributes=attrs,
            ReturnSubscriptionArn=True,
        )["SubscriptionArn"]
        ctx.on_cleanup(lambda arn=subs[key]: _unsubscribe_if_present(ctx, arn))

    prefix = ctx.unique_name("sim2real-ord-")
    bodies = [f"{prefix}-{n}-{team}" for n, team in enumerate(TEAMS)]
    for n, (body, team) in enumerate(zip(bodies, TEAMS, strict=True)):
        sns.publish(
            TopicArn=topic_arn,
            Message=body,
            MessageGroupId=MESSAGE_GROUP,
            MessageDeduplicationId=f"{prefix[-20:]}-{n}",
            MessageAttributes={"team": {"DataType": "String", "StringValue": team}},
        )

    # The control queue holding all seven proves every message was dispatched before the filtered
    # queues are graded for exact contents.
    want = {"control": bodies}
    for key in ("a", "b"):
        want[key] = [b for b, t in zip(bodies, TEAMS, strict=True) if t == key]
    for key in ("control", "a", "b"):
        got = _drain_in_order(ctx, queues[key]["url"], len(want[key]), timeout_s=40.0)
        got += _drain_in_order(ctx, queues[key]["url"], 0, timeout_s=0.0)
        assert [b for b, _g in got] == want[key], (
            f"queue {key} received {[b for b, _g in got]}, expected {want[key]}"
        )
        groups = {g for _b, g in got}
        assert groups == {MESSAGE_GROUP}, (
            f"queue {key} messages carried MessageGroupId {groups}, expected {MESSAGE_GROUP!r}"
        )

    sns.delete_topic(TopicArn=topic_arn)
    listing_err = _poll_error(
        lambda: sns.list_subscriptions_by_topic(TopicArn=topic_arn), "NotFound"
    )
    _assert_not_found(listing_err, "ListSubscriptionsByTopic on the deleted FIFO topic", TOPIC_GONE)
    publish_err = _error(
        lambda: sns.publish(
            TopicArn=topic_arn,
            Message="after-delete",
            MessageGroupId=MESSAGE_GROUP,
            MessageDeduplicationId="after-delete",
        ),
        "NotFound",
        "Publish on the deleted FIFO topic",
    )
    _assert_not_found(publish_err, "Publish on the deleted FIFO topic", TOPIC_GONE)


def _tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": "sns-fifo-fanout"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _create_fifo_queue_with_sns_policy(ctx, topic_arn: str) -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-fanout-q-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags={"sim2real": "sns-fifo-fanout", "sim2real:managed": "true"},
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


def _drain_in_order(ctx, queue_url: str, want: int, timeout_s: float) -> list[tuple[str, str]]:
    """Receive (and delete) in arrival order until `want` messages arrived, then one more empty-or-not
    receive when `want` is 0; return (body, MessageGroupId) pairs. Raise on timeout.
    """
    sqs = ctx.client("sqs")
    got: list[tuple[str, str]] = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageSystemAttributeNames=["MessageGroupId"],
        )
        for msg in resp.get("Messages", []):
            got.append((msg["Body"], msg["Attributes"].get("MessageGroupId")))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if want == 0 or len(got) >= want:
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{len(got)} of {want} messages arrived at {queue_url} within {timeout_s}s: {got}"
            )


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
