"""fifo-topic-rejects-email-protocol."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-topic-rejects-email-protocol"
GROUP = 'overly-permissive'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")



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

def _fake_sqs_queue_arn(topic_arn, name):
    """A well-formed SQS queue ARN in the topic's own account/region -- SNS confirms sqs
    subscriptions without verifying the queue exists, so this is enough for a positive control."""
    parts = topic_arn.split(":")
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A FIFO topic refuses an email subscription with InvalidParameter and lists none, while an
    sqs subscription to the same topic succeeds."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-fifo-email-") + ".fifo"
    topic_arn = _create_topic(
        sns, ctx, name,
        attributes={"FifoTopic": "true", "ContentBasedDeduplication": "true"},
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    queue_arn = _fake_sqs_queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-fifo-email-q-"))
    sqs_sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    if sqs_sub_arn and sqs_sub_arn != "pending confirmation":
        ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sqs_sub_arn))
    assert sqs_sub_arn.startswith(topic_arn + ":"), (
        f"positive control failed: expected an immediate sqs SubscriptionArn on the FIFO topic, got {sqs_sub_arn!r}"
    )

    email_endpoint = "sim2real-behav@example.com"
    code, message = _error(
        lambda: sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email_endpoint)
    )
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for email protocol on a FIFO topic, got {code}"
    )
    expected = 'Invalid parameter: Invalid protocol type: email'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert not any(s["Protocol"] == "email" for s in subs), (
        f"a rejected email subscribe must leave no trace in ListSubscriptionsByTopic, got {subs}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
