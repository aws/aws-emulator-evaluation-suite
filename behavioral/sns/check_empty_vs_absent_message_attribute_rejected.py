"""empty-vs-absent-message-attribute-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "empty-vs-absent-message-attribute-rejected"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-empty-vs-absent-attr"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish refuses an empty-string message attribute value with ParameterValueInvalid and
    delivers nothing, while a sibling Publish omitting the attribute arrives without that key."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-emptyattr-topic-"),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-emptyattr-q-"),
        tags={"sim2real": _SCENARIO},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true")

    blank_body = ctx.unique_name("sim2real-emptyattr-blank-")
    code, message = _error(
        lambda: sns.publish(
            TopicArn=topic_arn,
            Message=blank_body,
            MessageAttributes={"marker": {"DataType": "String", "StringValue": ""}},
        )
    )
    assert code == "ParameterValueInvalid", (
        f"expected ParameterValueInvalid for an empty-string message attribute value, got {code!r}"
    )
    assert message == "The message attribute 'marker' must contain non-empty message attribute value for message attribute type 'String'.", (
        f"unexpected ParameterValueInvalid message for an empty-string attribute value: {message!r}"
    )

    # Draining until this later publish arrives bounds the absence check for the rejected one.
    omitted_body = ctx.unique_name("sim2real-emptyattr-omitted-")
    sns.publish(TopicArn=topic_arn, Message=omitted_body)

    bodies, control_msg = _drain_until_containing(ctx, queue_url, omitted_body, timeout_s=60.0)
    assert blank_body not in bodies, (
        f"the rejected publish {blank_body!r} was delivered anyway: {bodies!r}"
    )
    assert "marker" not in control_msg.get("MessageAttributes", {}), (
        f"an omitted attribute must not reappear on delivery: {control_msg.get('MessageAttributes')!r}"
    )


def _drain_until_containing(ctx, queue_url: str, needle: str, *, timeout_s: float = 60.0):
    """Long-poll until a message whose body equals needle arrives; returns every body seen up
    to and including it (so the caller can assert on what else came through) plus that message
    itself (so the caller can inspect its attributes)."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=5,
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"])
            if msg["Body"] == needle:
                return bodies, msg
    raise AssertionError(
        f"the control publish {needle!r} never arrived within {timeout_s}s, so the absence of "
        f"its sibling is not bounded; bodies seen: {bodies!r}"
    )


def _error(fn) -> tuple[str, str]:
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be rejected but SUCCEEDED, returning {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

