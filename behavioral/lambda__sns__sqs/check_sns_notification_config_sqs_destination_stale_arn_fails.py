"""sns-notification-config-sqs-destination-stale-arn-fails."""
from __future__ import annotations

import json
import time
from typing import Any

import botocore.exceptions

from behavioral_harness import tags

CHECK = "sns-notification-config-sqs-destination-stale-arn-fails"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A subscription whose SQS destination has been deleted never delivers a notification,
    while a sibling subscription on the same topic to a live queue keeps working."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)

    stale = _create_queue(ctx, "stale")
    control = _create_queue(ctx, "control")
    _allow_sns_to_send(ctx, stale["url"], stale["arn"], topic_arn)
    _allow_sns_to_send(ctx, control["url"], control["arn"], topic_arn)

    sub_stale = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=stale["arn"])[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_stale))
    sub_control = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=control["arn"]
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_control))

    # Baseline positive control: both destinations work before anything goes stale.
    sns.publish(TopicArn=topic_arn, Message="baseline")
    baseline_stale = _wait_for_message(ctx, stale["url"], "baseline", timeout_s=60)
    baseline_control = _wait_for_message(ctx, control["url"], "baseline", timeout_s=60)
    assert baseline_stale == "baseline", (
        f"expected baseline message delivered to stale-to-be queue, got {baseline_stale!r}"
    )
    assert baseline_control == "baseline", (
        f"expected baseline message delivered to control queue, got {baseline_control!r}"
    )

    # Make the `stale` destination's ARN invalid: delete the queue outright. The subscription
    # itself is untouched — its Endpoint now refers to a queue that no longer exists.
    sqs.delete_queue(QueueUrl=stale["url"])

    def queue_gone() -> bool:
        try:
            sqs.get_queue_attributes(QueueUrl=stale["url"], AttributeNames=["QueueArn"])
        except botocore.exceptions.ClientError:
            return True
        return False

    _poll_until(
        queue_gone,
        lambda gone: gone,
        timeout_s=60,
        interval_s=3.0,
        description="stale destination queue fully deleted",
    )
    code, message = _client_error(
        lambda: sqs.get_queue_attributes(QueueUrl=stale["url"], AttributeNames=["QueueArn"])
    )
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected the deleted queue to read back as not-found, got error code {code!r}"
    )
    assert message == "The specified queue does not exist.", f"got message {message!r}"

    # Publish again: the API call must still succeed (SNS publish is fire-and-forget and does
    # not validate subscriber reachability), but there is now nowhere for the stale
    # subscription's copy of the message to land.
    publish_resp = sns.publish(TopicArn=topic_arn, Message="post-deletion")
    assert "MessageId" in publish_resp, (
        f"expected Publish to a topic with a stale-ARN subscription to still succeed, got {publish_resp!r}"
    )

    # Effect absent: there is no queue left to receive the stale subscription's notification.
    stale_gone_code, stale_gone_message = _client_error(
        lambda: sqs.get_queue_attributes(
            QueueUrl=stale["url"], AttributeNames=["QueueArn"]
        )
    )
    assert stale_gone_code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected stale destination to remain not-found after the second publish, got {stale_gone_code!r}"
    )
    assert stale_gone_message == "The specified queue does not exist.", (
        f"got message {stale_gone_message!r}"
    )

    # Positive control: the sibling subscription to the still-live queue is unaffected.
    delivered_control = _wait_for_message(
        ctx, control["url"], "post-deletion", timeout_s=60
    )
    assert delivered_control == "post-deletion", (
        f"expected the live sibling subscription to still receive the post-deletion message, got {delivered_control!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-b5"}


def _create_topic(ctx) -> str:
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-b5-topic-"),
        Tags=[{"Key": k, "Value": v} for k, v in _resource_tags().items()],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, prefix="q") -> dict:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-b5-{prefix}-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_delete_queue(sqs, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return {"url": url, "arn": arn}


def _safe_delete_queue(sqs, url) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise


def _allow_sns_to_send(ctx, queue_url, queue_arn, topic_arn) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _wait_for_message(ctx, queue_url, expected_message, timeout_s=60.0) -> str | None:
    sqs = ctx.client("sqs")

    def probe() -> list[dict[str, Any]]:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        found = []
        for m in resp.get("Messages", []):
            try:
                envelope = json.loads(m["Body"])
                found.append(envelope.get("Message"))
            except (json.JSONDecodeError, ValueError):
                found.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        return found

    result = _wait_for_effect(
        probe,
        lambda msgs: expected_message in msgs,
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"message {expected_message!r} delivered to {queue_url}",
    )
    return expected_message if expected_message in result else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
