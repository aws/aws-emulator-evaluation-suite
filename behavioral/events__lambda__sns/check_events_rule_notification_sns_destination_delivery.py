"""events-rule-notification-sns-destination-delivery."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "events-rule-notification-sns-destination-delivery"
GROUP = "notification"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule targeting an SNS topic delivers the matched event's payload to the topic's subscribers."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    events = ctx.client("events")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-ebsns-queue-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-ebsns-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    # Allow the topic to deliver to this queue.
    queue_policy = {
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
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(queue_policy)})

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true")

    source_val = ctx.unique_name("sim2real.ebsns.source.")
    detail_type = "sim2real-match"
    rule_name = ctx.unique_name("sim2real-ebsns-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source_val], "detail-type": [detail_type]}),
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]

    events.put_targets(Rule=rule_name, Targets=[{"Id": "sns-target", "Arn": topic_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sns-target"]))

    # Grant EventBridge permission to publish to this specific topic, scoped to this rule.
    existing_policy = json.loads(sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    existing_policy["Statement"].append(
        {
            "Sid": "AllowEventBridgePublish",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": topic_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }
    )
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(existing_policy))

    marker = ctx.unique_name("sim2real-ebsns-marker-")
    events.put_events(
        Entries=[{"Source": source_val, "DetailType": detail_type, "Detail": json.dumps({"marker": marker})}]
    )

    body = _poll_for_marker(ctx, queue_url, marker, timeout_s=90)
    assert body is not None, "event matched by the rule was never delivered to the SNS-subscribed queue"
    delivered = json.loads(body)
    assert delivered.get("detail-type") == detail_type, (
        f"expected raw-delivered event detail-type {detail_type!r}, got {delivered.get('detail-type')!r} "
        f"(full body: {body!r})"
    )
    assert delivered.get("source") == source_val, (
        f"expected raw-delivered event source {source_val!r}, got {delivered.get('source')!r} "
        f"(full body: {body!r})"
    )
    assert delivered.get("detail", {}).get("marker") == marker, (
        f"expected marker {marker!r} in delivered event detail, got {delivered.get('detail')!r}"
    )


def _poll_for_marker(ctx, queue_url: str, marker: str, timeout_s: float = 90.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return msg["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
