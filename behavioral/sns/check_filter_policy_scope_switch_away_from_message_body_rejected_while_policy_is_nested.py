"""filter-policy-scope-switch-away-from-message-body-rejected-while-policy-is-nested."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-policy-scope-switch-away-from-message-body-rejected-while-policy-is-nested"
GROUP = "server-side"
SERVICES = ["sns"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Switching FilterPolicyScope to MessageAttributes while a nested policy is stored is
    refused with InvalidParameter and its exact message, leaving scope and policy unchanged;
    the same switch succeeds once the stored policy is flat.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    sub_arn = _subscribe_fake_queue(ctx, topic_arn)

    nested = {"store": {"city": ["seattle"]}}
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="FilterPolicyScope",
                                    AttributeValue="MessageBody")
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="FilterPolicy",
                                    AttributeValue=json.dumps(nested))
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert attrs["FilterPolicyScope"] == "MessageBody", (
        f"setup must leave FilterPolicyScope=MessageBody, got {attrs['FilterPolicyScope']!r}")
    assert json.loads(attrs["FilterPolicy"]) == nested, (
        f"setup must leave the nested policy stored, got {attrs['FilterPolicy']!r}")

    code, msg = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="FilterPolicyScope",
        AttributeValue="MessageAttributes"))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter switching scope away while the policy is nested, got {code}")
    expected = ("Invalid parameter: Filter policy scope MessageAttributes does not support "
                "nested filter policy")
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    after = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert after["FilterPolicyScope"] == "MessageBody", (
        f"a refused scope switch must leave FilterPolicyScope alone, got {after['FilterPolicyScope']!r}")
    assert json.loads(after["FilterPolicy"]) == nested, (
        f"a refused scope switch must leave FilterPolicy alone, got {after['FilterPolicy']!r}")

    # A flat policy is valid under both scopes, so the same switch must now succeed.
    flat = {"event": ["created"]}
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="FilterPolicy",
                                    AttributeValue=json.dumps(flat))
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="FilterPolicyScope",
                                    AttributeValue="MessageAttributes")
    final = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert final["FilterPolicyScope"] == "MessageAttributes", (
        f"the switch must succeed once the policy is flat, got {final['FilterPolicyScope']!r}")
    assert json.loads(final["FilterPolicy"]) == flat, (
        f"the flat policy must survive the successful switch, got {final['FilterPolicy']!r}")


def _create_topic(ctx) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn

def _subscribe_fake_queue(ctx, topic_arn: str) -> str:
    """Subscribe a never-created SQS queue ARN and register Unsubscribe.

    SNS confirms sqs subscriptions without verifying that the queue exists."""
    sns = ctx.client("sns")
    parts = topic_arn.split(":")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    queue_arn = f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    return sub_arn

def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) the call raises. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
