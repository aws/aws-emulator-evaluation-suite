"""cross-region-sqs-subscription-delivers-with-the-topic-region-envelope."""
from __future__ import annotations

import json
import time
import urllib.parse

from behavioral_harness import tags

CHECK = "cross-region-sqs-subscription-delivers-with-the-topic-region-envelope"
GROUP = "cross-region"
SERVICES = ["sns"]


def _other_region(region: str) -> str:
    """A second commercial region of the same account (region-pinned by design)."""
    return "us-east-1" if region != "us-east-1" else "us-west-2"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A topic delivers to an SQS queue in another region; only the topic region lists the
    subscription, and the envelope carries the topic's ARN and an UnsubscribeURL for it.
    """
    home = ctx.region
    away = _other_region(home)
    sns = ctx.client("sns")
    sns_away = ctx.client("sns", region=away)
    sqs_away = ctx.client("sqs", region=away)

    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-xr-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    url = sqs_away.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-xr-"),
                                tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs_away.delete_queue(QueueUrl=url))
    q_arn = sqs_away.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert q_arn.split(":")[3] == away, f"the queue ARN's region is {q_arn.split(':')[3]!r}, expected {away!r}"
    sqs_away.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": q_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic}}}]})})

    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=q_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    assert sub.split(":")[3] == home and sub.startswith(topic + ":"), (
        f"the subscription ARN must extend the topic ARN in the topic's region {home!r}; "
        f"its region is {sub.split(':')[3]!r}")
    listed = [s for p in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic)
              for s in p["Subscriptions"]]
    assert [(s["SubscriptionArn"], s["Endpoint"]) for s in listed] == [(sub, q_arn)], (
        f"the topic must list exactly the cross-region subscription; listed {len(listed)}")
    away_listing = {s["SubscriptionArn"] for p in sns_away.get_paginator("list_subscriptions").paginate()
                    for s in p["Subscriptions"]}
    assert sub not in away_listing, "the queue region's ListSubscriptions lists the topic region's subscription"

    body = ctx.unique_name("sim2real-xr-body-")
    mid = sns.publish(TopicArn=topic, Message=body, Subject="cross region")["MessageId"]
    env = _receive(sqs_away, url, mid, 120)
    assert env is not None, "the notification never reached the queue in the other region"
    assert (env.get("Type"), env.get("TopicArn"), env.get("Message"), env.get("Subject")) == (
        "Notification", topic, body, "cross region"), (
        f"the delivered envelope must carry the notification as published; got Type "
        f"{env.get('Type')!r}, Subject {env.get('Subject')!r}, TopicArn matches={env.get('TopicArn') == topic}")
    unsub = urllib.parse.urlsplit(env.get("UnsubscribeURL") or "")
    query = urllib.parse.parse_qs(unsub.query)
    assert query.get("SubscriptionArn") == [sub] and query.get("Action") == ["Unsubscribe"], (
        f"the UnsubscribeURL must unsubscribe the cross-region subscription; its query names "
        f"Action {query.get('Action')!r} and {len(query.get('SubscriptionArn', []))} SubscriptionArn(s)")

def _receive(sqs, url: str, message_id: str, timeout_s: float) -> dict | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            env = json.loads(m["Body"])
            if env.get("MessageId") == message_id:
                return env
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
