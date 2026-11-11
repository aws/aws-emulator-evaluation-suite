"""cloudfront-event-sns-topic-policy-missing-blocks-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "cloudfront-event-sns-topic-policy-missing-blocks-delivery"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A matched CloudFront event reaches the SNS topic whose policy allows events.amazonaws.com, but not the topic on
    the same rule without that statement: its subscribed queue receives nothing and reports a depth of 0."""
    rule = _create_rule(
        ctx,
        {
            "source": ["sim2real.cloudfront"],
            "detail-type": ["CloudFront Distribution State Change"],
            "detail": {"state": ["Deployed"]},
        },
    )

    allowed_topic = _create_topic_for_events(ctx, rule["arn"])
    allowed_queue = _create_queue_for_sns(ctx, allowed_topic["arn"])
    _subscribe_queue(ctx, allowed_topic["arn"], allowed_queue["arn"])

    blocked_topic = _create_plain_topic(ctx)
    blocked_queue = _create_queue_for_sns(ctx, blocked_topic["arn"])
    _subscribe_queue(ctx, blocked_topic["arn"], blocked_queue["arn"])

    _put_target(ctx, rule["name"], "allowed-sns-target", allowed_topic["arn"])
    _put_target(ctx, rule["name"], "blocked-sns-target", blocked_topic["arn"])

    marker = ctx.unique_name("dist-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "CloudFront Distribution State Change",
                "Detail": json.dumps(
                    {"distributionId": marker, "state": "Deployed", "eTag": "E6PQRSTU"}
                ),
            }
        ]
    )

    allowed_messages, positive_latency_s = _drain_queue(
        ctx, allowed_queue["url"], timeout_s=90.0
    )
    assert any(marker in m["Body"] for m in allowed_messages), (
        "positive control failed: correctly-policied topic never received the notification"
    )

    # The absence window must be derived from what this run measured, not a guessed constant:
    # a window shorter than the positive control's own latency would score a correct-but-slower
    # target as having blocked delivery.
    negative_window_s = max(15.0, 3.0 * positive_latency_s)
    blocked_messages, _ = _drain_queue(
        ctx, blocked_queue["url"], timeout_s=negative_window_s
    )
    assert not any(marker in m["Body"] for m in blocked_messages), (
        "topic without an events.amazonaws.com policy statement received the notification anyway"
    )

    depth = _queue_depth(ctx, blocked_queue["url"])
    assert depth == 0, (
        f"blocked queue ApproximateNumberOfMessages expected 0, got {depth} "
        "(independent second observable on top of the empty receive)"
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


def _create_rule(ctx, event_pattern: dict[str, Any]) -> dict[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfrule-")
    resp = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(event_pattern), State="ENABLED"
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return {"name": rule_name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, target_arn: str) -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _create_topic_for_events(ctx, rule_arn: str) -> dict[str, str]:
    sns = ctx.client("sns")
    topic_name = ctx.unique_name("sim2real-cftopic-")
    arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventsPublish",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sns.set_topic_attributes(
        TopicArn=arn, AttributeName="Policy", AttributeValue=json.dumps(policy)
    )
    return {"arn": arn, "name": topic_name}


def _create_plain_topic(ctx) -> dict[str, str]:
    """A topic with no explicit resource policy statement for events.amazonaws.com — the
    default policy only allows the topic owner account to Publish."""
    sns = ctx.client("sns")
    topic_name = ctx.unique_name("sim2real-cfplaintopic-")
    arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn, "name": topic_name}


def _create_queue_for_sns(ctx, topic_arn: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    q_name = ctx.unique_name("sim2real-cfsnsq-")
    url = sqs.create_queue(QueueName=q_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSnsSendMessage",
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


def _subscribe_queue(ctx, topic_arn: str, queue_arn: str) -> str:
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
        "SubscriptionArn"
    ]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return sub_arn


def _drain_queue(
    ctx, queue_url: str, max_messages: int = 10, timeout_s: float = 60.0
) -> tuple[list[dict[str, Any]], float]:
    """Return the collected messages and the time until the first one arrived (the delivery latency
    that sizes the absence window). Stops at the first message, since the check publishes one
    event; when nothing arrives, the full window elapses and `latency_s` is timeout_s."""
    sqs = ctx.client("sqs")
    collected: list[dict[str, Any]] = []
    start = time.monotonic()
    deadline = start + timeout_s
    latency_s = timeout_s
    while time.monotonic() < deadline and len(collected) < max_messages:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages", [])
        for m in msgs:
            collected.append(m)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        if msgs:
            latency_s = time.monotonic() - start
            break
        time.sleep(2.0)
    return collected, latency_s


def _queue_depth(ctx, queue_url: str) -> int:
    sqs = ctx.client("sqs")
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )
    return int(attrs["Attributes"]["ApproximateNumberOfMessages"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
