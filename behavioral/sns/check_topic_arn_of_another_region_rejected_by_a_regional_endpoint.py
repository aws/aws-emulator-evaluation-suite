"""topic-arn-of-another-region-rejected-by-a-regional-endpoint."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-arn-of-another-region-rejected-by-a-regional-endpoint"
GROUP = "cross-region"
SERVICES = ["sns"]


def _other_region(region: str) -> str:
    """A second commercial region of the same account (region-pinned by design)."""
    return "us-east-1" if region != "us-east-1" else "us-west-2"


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the error ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Another region's SNS endpoint refuses a topic's ARN for GetTopicAttributes, Publish and
    Subscribe (creating no subscription), while the topic's own region serves all three calls,
    so the refusal is the region boundary and not a missing topic.
    """
    home = ctx.region
    away = _other_region(home)
    sns = ctx.client("sns")
    sns_away = ctx.client("sns", region=away)
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-xrarn-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))
    queue_arn = f"arn:aws:sqs:{away}:{ctx.account}:sim2real-behav-sns-xrarn-{uuid.uuid4().hex[:8]}"

    code, message = _error(lambda: sns_away.get_topic_attributes(TopicArn=topic))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: TopicArn"), (
        f"GetTopicAttributes in {away} for a {home} topic gave {code!r}: {message!r}")
    code, message = _error(lambda: sns_away.publish(TopicArn=topic, Message="sim2real cross-region"))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: TopicArn"), (
        f"Publish in {away} to a {home} topic gave {code!r}: {message!r}")
    code, message = _error(lambda: sns_away.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn))
    assert (code, message) == ("InvalidParameter", "Invalid parameter: TopicArn"), (
        f"Subscribe in {away} to a {home} topic gave {code!r}: {message!r}")
    subs = [s for p in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=topic)
            for s in p["Subscriptions"]]
    assert subs == [], f"the refused cross-region Subscribe left {len(subs)} subscription(s) on the topic"

    # Positive control: the topic's own region serves the same calls.
    attrs = sns.get_topic_attributes(TopicArn=topic)["Attributes"]
    assert attrs.get("TopicArn") == topic, "the home region does not serve its own topic"
    assert sns.publish(TopicArn=topic, Message="sim2real home region").get("MessageId"), (
        "Publish in the topic's own region returned no MessageId")
    sub = sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn,
                        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))
    assert sub.startswith(topic + ":"), "the home-region Subscribe did not return a subscription of the topic"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
