"""subscription-redrive-policy-non-sqs-target-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscription-redrive-policy-non-sqs-target-rejected"
GROUP = 'subscription-attributes'
SERVICES = ['sns']


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetSubscriptionAttributes refuses a RedrivePolicy whose deadLetterTargetArn names
    another SNS topic instead of an SQS queue, and stores nothing; the same policy naming a
    queue ARN is then accepted on the same subscription.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-badredrive-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    region, account = topic_arn.split(":")[3:5]
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", ReturnSubscriptionArn=True,
        Endpoint=f"arn:aws:sqs:{region}:{account}:{ctx.unique_name('sim2real-behav-sns-badredrive-q-')}",
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    code, message = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RedrivePolicy",
        AttributeValue=json.dumps({"deadLetterTargetArn": topic_arn})))
    assert code == "InvalidParameter", f"a topic ARN as dead-letter target gave {code!r}"
    assert message == "Invalid parameter: RedrivePolicy: deadLetterTargetArn must be a SQS queue", f"unexpected message for a topic ARN as dead-letter target: {message!r}"
    assert "RedrivePolicy" not in _attrs(sns, sub_arn), "the refused write must store no RedrivePolicy"

    dlq = f"arn:aws:sqs:{region}:{account}:{ctx.unique_name('sim2real-behav-sns-badredrive-dlq-')}"
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RedrivePolicy",
                                    AttributeValue=json.dumps({"deadLetterTargetArn": dlq}))
    stored = json.loads(_attrs(sns, sub_arn)["RedrivePolicy"])
    assert stored == {"deadLetterTargetArn": dlq}, "a queue ARN as dead-letter target must be stored"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
