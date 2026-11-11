"""subscribe-invalid-endpoint-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscribe-invalid-endpoint-rejected"
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

def _fake_queue_arn(topic_arn):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs subs without verifying the queue exists)."""
    parts = topic_arn.split(":")
    name = f"sim2real-behav-sns-subbad-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Subscribe rejects a malformed endpoint for the sqs protocol (must be a queue ARN, not a bare
    string), while an otherwise-identical well-formed ARN on the same topic/protocol is accepted and
    the rejected call leaves no subscription behind.
    """
    ev = ctx.client("sns")
    topic_arn = _create_topic(ev, ctx, ctx.unique_name("sim2real-behav-sns-subbad-"))

    good_arn = _fake_queue_arn(topic_arn)
    good_sub_arn = ev.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=good_arn)["SubscriptionArn"]
    if good_sub_arn and good_sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: ev.unsubscribe(SubscriptionArn=good_sub_arn))
    assert good_sub_arn, (
        f"expected the well-formed control endpoint {good_arn!r} to be accepted, got {good_sub_arn!r}"
    )

    try:
        result = ev.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint='not-an-arn')
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"Subscribe with a non-ARN sqs endpoint SUCCEEDED: {result!r}")
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for non-ARN sqs endpoint, got {code}"
    )
    assert message == "Invalid parameter: SQS endpoint ARN", (
        f"unexpected refusal message for a non-ARN sqs endpoint: {message!r}"
    )

    subscribed_endpoints = {
        s["Endpoint"] for s in ev.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    }
    assert subscribed_endpoints == {good_arn}, (
        f"expected only the control endpoint {good_arn!r} subscribed to the topic after the "
        f"rejected call, got {subscribed_endpoints!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
