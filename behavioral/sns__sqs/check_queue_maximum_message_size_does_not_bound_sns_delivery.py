"""queue-maximum-message-size-does-not-bound-sns-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-maximum-message-size-does-not-bound-sns-delivery"
GROUP = "size-limits"
SERVICES = ["sns", "sqs"]

_OVERSIZE_SEND = (
    "InvalidParameterValue",
    "One or more parameters are invalid. Reason: Message must be shorter than 1024 bytes.",
)


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A topic delivers a message larger than its queue subscriber's own MaximumMessageSize
    intact, while SendMessage to that queue with the same body is refused by that attribute.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-maxmsg-t-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sns-maxmsg-q-"),
        Attributes={"MaximumMessageSize": "1024"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=queue_url),
                              "AWS.SimpleQueueService.NonExistentQueue"))

    queue_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn", "MaximumMessageSize"]
    )["Attributes"]
    queue_arn = queue_attrs["QueueArn"]
    assert queue_attrs["MaximumMessageSize"] == "1024", (
        f"positive control: expected the queue's own MaximumMessageSize to read back as "
        f"'1024', got {queue_attrs['MaximumMessageSize']!r}"
    )

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
        Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    deadline = time.monotonic() + 60.0
    pending = sns.get_subscription_attributes(
        SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
    while pending != "false":
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"subscription never left PendingConfirmation; last value {pending!r}")
        time.sleep(1.0)
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")

    marker = ctx.unique_name("sim2real-behav-sns-maxmsg-body-")
    body = marker + "x" * (4096 - len(marker))
    assert len(body) == 4096, f"test body must be exactly 4096 bytes, built {len(body)}"

    # --- break: the queue's own MaximumMessageSize refuses a direct SendMessage of this body ---
    code, message = _error(lambda: sqs.send_message(QueueUrl=queue_url, MessageBody=body))
    assert (code, message) == _OVERSIZE_SEND, (
        f"expected SendMessage to be refused with {_OVERSIZE_SEND!r}, got {(code, message)!r}"
    )
    rejected = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
    ).get("Messages", [])
    assert rejected == [], f"the refused SendMessage enqueued a message anyway: {rejected!r}"

    # --- the topic delivers the same oversize body to the same queue intact ---
    publish_resp = sns.publish(TopicArn=topic_arn, Message=body)
    assert publish_resp.get("MessageId"), f"expected a MessageId for the publish, got {publish_resp!r}"

    deadline = time.monotonic() + 90.0
    delivered = None
    while delivered is None:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if msg["Body"] == body:
                delivered = msg
            # else: an unrelated message on a shared queue would be a defect in this check's
            # isolation, not something to ignore; the queue is private to this check.
        if delivered is None and time.monotonic() >= deadline:
            raise AssertionError(
                "the SNS-delivered message carrying the 4096-byte body never arrived within 90s")

    assert delivered["Body"] == body, (
        f"the message delivered via SNS must carry the exact 4096-byte body; got "
        f"{len(delivered['Body'])} bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
