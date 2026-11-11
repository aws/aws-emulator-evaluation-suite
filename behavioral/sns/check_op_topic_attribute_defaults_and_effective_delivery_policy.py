"""op-topic-attribute-defaults-and-effective-delivery-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-topic-attribute-defaults-and-effective-delivery-policy"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new topic exposes the documented default attribute set and an EffectiveDeliveryPolicy."""
    sns = ctx.client("sns")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-defaults-"),
        Tags=[{"Key": "env", "Value": "fidelity"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
    assert attrs["TopicArn"] == arn, attrs
    assert attrs["Owner"] == account_id, attrs
    assert attrs["SubscriptionsConfirmed"] == "0", attrs
    assert attrs["SubscriptionsPending"] == "0", attrs
    assert attrs["SubscriptionsDeleted"] == "0", attrs
    assert attrs["Policy"], attrs
    effective = json.loads(attrs["EffectiveDeliveryPolicy"])
    assert "http" in effective, effective
    assert "defaultHealthyRetryPolicy" in effective["http"], effective
    retry = effective["http"]["defaultHealthyRetryPolicy"]
    assert retry["numRetries"] == 3, retry
    assert retry["minDelayTarget"] == 20, retry
    assert retry["maxDelayTarget"] == 20, retry
    assert retry["backoffFunction"] == "linear", retry

    # A standard topic must not advertise FIFO-only attributes.
    assert "FifoTopic" not in attrs, f"a standard topic must not report FifoTopic: {attrs}"
    assert "ContentBasedDeduplication" not in attrs, attrs

    # The default resource policy is the SNS __default_policy_ID, scoped to the owner.
    policy = json.loads(attrs["Policy"])
    assert policy["Id"] == "__default_policy_ID", policy
    stmt = policy["Statement"][0]
    assert stmt["Sid"] == "__default_statement_ID", stmt
    assert stmt["Condition"]["StringEquals"]["AWS:SourceOwner"] == account_id, stmt

    # By contrast, a FIFO topic DOES advertise the FIFO attributes.
    fifo_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-defaults-fifo-") + ".fifo",
        Attributes={"FifoTopic": "true"},
        Tags=[{"Key": "env", "Value": "fidelity"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=fifo_arn))
    fifo_attrs = sns.get_topic_attributes(TopicArn=fifo_arn)["Attributes"]
    assert fifo_attrs["FifoTopic"] == "true", fifo_attrs
    assert fifo_attrs["ContentBasedDeduplication"] == "false", fifo_attrs


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
