"""op-set-subscription-attributes-invalid-name-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-set-subscription-attributes-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_RESOURCE_TAGS = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")



def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic (tagged) + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name, "Tags": _RESOURCE_TAGS}
    if attributes:
        kwargs["Attributes"] = attributes
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _fake_queue_arn(topic_arn, name=None):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs subs without verifying the queue exists)."""
    parts = topic_arn.split(":")
    name = name or f"sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetSubscriptionAttributes must reject attribute names that are not user-settable (e.g. TopicArn)."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-subattr-bad-"))
    queue_arn = _fake_queue_arn(topic_arn)
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    if sub_arn and sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    # Positive control: a genuinely user-settable attribute must succeed on this same
    # subscription, so the rejection below can be attributed to TopicArn specifically
    # rather than to a broken subscription or a SetSubscriptionAttributes call that fails
    # unconditionally.
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"
    )
    control = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert control.get("RawMessageDelivery") == "true", (
        f"positive control failed: RawMessageDelivery not applied, got {control.get('RawMessageDelivery')!r}"
    )

    code, message = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="TopicArn", AttributeValue="hijacked"
    ))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter when setting a non-settable subscription attribute, got {code}"
    )
    expected = 'Invalid parameter: AttributeName'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert attrs["TopicArn"] == topic_arn, "rejected SetSubscriptionAttributes must not mutate state"
    assert attrs["RawMessageDelivery"] == "true", (
        "rejected SetSubscriptionAttributes must not disturb the prior, successfully-set state"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
