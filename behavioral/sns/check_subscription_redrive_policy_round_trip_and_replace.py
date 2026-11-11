"""subscription-redrive-policy-round-trip-and-replace."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscription-redrive-policy-round-trip-and-replace"
GROUP = 'subscription-attributes'
SERVICES = ['sns']


def _queue_arn(topic_arn, name):
    region, account = topic_arn.split(":")[3:5]
    return f"arn:aws:sqs:{region}:{account}:{name}"


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _attrs(sns, sub_arn):
    return sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new subscription has no RedrivePolicy; a write stores the dead-letter target, a second
    write replaces it, an empty value is refused and leaves that target in place, and none of
    this disturbs RawMessageDelivery.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-redrive-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    # SNS stores the dead-letter and endpoint ARNs without contacting the queue, so none exists.
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", ReturnSubscriptionArn=True,
        Endpoint=_queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-redrive-q-")),
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    assert "RedrivePolicy" not in _attrs(sns, sub_arn), "a new subscription carries no RedrivePolicy"

    dlq1 = _queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-dlq1-"))
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RedrivePolicy",
                                    AttributeValue=json.dumps({"deadLetterTargetArn": dlq1}))
    got = json.loads(_attrs(sns, sub_arn)["RedrivePolicy"])
    assert got == {"deadLetterTargetArn": dlq1}, f"the first RedrivePolicy read back as keys {sorted(got)!r}"

    dlq2 = _queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-dlq2-"))
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RedrivePolicy",
                                    AttributeValue=json.dumps({"deadLetterTargetArn": dlq2}))
    got = json.loads(_attrs(sns, sub_arn)["RedrivePolicy"])
    assert got == {"deadLetterTargetArn": dlq2}, "the second write must replace the dead-letter target"

    code, message = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RedrivePolicy", AttributeValue=""))
    assert code == "InvalidParameter", f"an empty RedrivePolicy gave {code!r}"
    assert message == "Invalid parameter: RedrivePolicy: missing required value", (
        f"unexpected message for an empty RedrivePolicy: {message!r}"
    )
    final = _attrs(sns, sub_arn)
    got = json.loads(final["RedrivePolicy"])
    assert got == {"deadLetterTargetArn": dlq2}, "the refused empty write must leave the second target in place"
    assert final.get("RawMessageDelivery") == "true", (
        f"RedrivePolicy writes must not disturb RawMessageDelivery, got {final.get('RawMessageDelivery')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
