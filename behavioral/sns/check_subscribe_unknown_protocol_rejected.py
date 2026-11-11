"""subscribe-unknown-protocol-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscribe-unknown-protocol-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

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

def _fake_queue_arn(topic_arn, name=None):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs subs without verifying the queue exists)."""
    parts = topic_arn.split(":")
    name = name or f"sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Subscribe must reject a protocol string that is not a supported SNS protocol, while
    leaving the topic otherwise able to accept a real subscription."""
    ev = ctx.client("sns")
    topic_arn = _create_topic(ev, ctx, ctx.unique_name("sim2real-behav-sns-badproto-"))

    # Positive control: a supported protocol on the same topic must be accepted, so a
    # rejection below cannot be explained by "this topic rejects every subscribe".
    good_endpoint = _fake_queue_arn(topic_arn)
    good_sub_arn = ev.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=good_endpoint)["SubscriptionArn"]
    assert good_sub_arn, "positive control: sqs subscribe on a healthy topic must succeed"
    ctx.on_cleanup(lambda: ev.unsubscribe(SubscriptionArn=good_sub_arn))

    try:
        result = ev.subscribe(TopicArn=topic_arn, Protocol='carrier-pigeon', Endpoint='somewhere')
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"Subscribe with an unsupported protocol SUCCEEDED: {result!r}")
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for unsupported protocol, got {code}"
    )
    assert message == "Invalid parameter: Amazon SNS does not support this protocol string: carrier-pigeon", (
        f"unexpected refusal message for an unsupported protocol: {message!r}"
    )

    # Independent read at the destination: the rejected subscribe must have left no trace —
    # only the positive control's subscription is listed for this topic.
    subs = ev.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    endpoints = [s["Endpoint"] for s in subs]
    assert endpoints == [good_endpoint], (
        f"rejected subscribe must not appear in ListSubscriptionsByTopic, got endpoints {endpoints}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
