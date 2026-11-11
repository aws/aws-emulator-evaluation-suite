"""publish-message-structure-json-semantics."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-message-structure-json-semantics"
GROUP = 'publish-semantics'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _subscribe_raw_sqs(ctx, sns, topic_arn, name_prefix="jsonstruct-q-"):
    """Create a real SQS queue subscribed to topic_arn with RawMessageDelivery, so a
    received Body is exactly the per-protocol message text SNS resolved for the
    subscriber's protocol -- no envelope to unwrap. Returns the queue_url."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    queue_url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return queue_url


def _poll_for_body(ctx, queue_url, expected_body, timeout_s=60, interval_s=2):
    """Poll the queue (deleting what it reads) until a message with this exact Body
    arrives. Raises with the mismatched bodies seen if the deadline passes first."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=interval_s
        )
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if m["Body"] == expected_body:
                return
            seen.append(m["Body"])
    raise AssertionError(
        f"expected a delivered SQS body of {expected_body!r} within {timeout_s}s, saw {seen!r}"
    )


@tags(
    "axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing",
    "concern:negative-classes", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """MessageStructure=json requires a 'default' key; a subscriber-protocol-specific
    key overrides 'default' at delivery, and 'default' is the fallback when no such
    key is present -- both verified by an independent read at a real SQS subscriber."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-jsonstruct-"))
    queue_url = _subscribe_raw_sqs(ctx, sns, topic_arn)

    control_body = f"positive-control-{uuid.uuid4()}"
    control_resp = sns.publish(
        TopicArn=topic_arn, Message=json.dumps({"default": control_body}), MessageStructure="json"
    )
    assert control_resp.get("MessageId"), (
        f"positive control: expected MessageId for a valid json-structured publish, got {control_resp}"
    )
    _poll_for_body(ctx, queue_url, control_body)

    code, message = _error(lambda: sns.publish(
        TopicArn=topic_arn, Message=json.dumps({'email': 'only-email'}), MessageStructure='json'))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for json message missing 'default' key, got {code}"
    )
    assert message == 'Invalid parameter: Message Structure - No default entry in JSON message body', (
        f"expected the exact message 'Invalid parameter: Message Structure - No default entry in JSON message body', got {message!r}"
    )
    code2, message2 = _error(lambda: sns.publish(
        TopicArn=topic_arn, Message='not-json-at-all', MessageStructure='json'))
    assert code2 == "InvalidParameter", (
        f"expected InvalidParameter for unparseable json message body, got {code2}"
    )
    assert message2 == 'Invalid parameter: Message Structure - JSON message body failed to parse', (
        f"expected the exact message 'Invalid parameter: Message Structure - JSON message body failed to parse', got {message2!r}"
    )

    override_body = f"sqs-override-{uuid.uuid4()}"
    default_body = f"default-body-{uuid.uuid4()}"
    resp = sns.publish(
        TopicArn=topic_arn,
        Message=json.dumps({"default": default_body, "sqs": override_body, "email": "email-body"}),
        MessageStructure="json",
    )
    assert resp.get("MessageId"), f"expected MessageId for a valid json-structured publish, got {resp}"
    _poll_for_body(ctx, queue_url, override_body)

    fallback_body = f"fallback-default-{uuid.uuid4()}"
    resp2 = sns.publish(
        TopicArn=topic_arn,
        Message=json.dumps({"default": fallback_body, "email": "email-body-only"}),
        MessageStructure="json",
    )
    assert resp2.get("MessageId"), (
        f"expected MessageId for a valid json-structured publish with no sqs override, got {resp2}"
    )
    _poll_for_body(ctx, queue_url, fallback_body)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
