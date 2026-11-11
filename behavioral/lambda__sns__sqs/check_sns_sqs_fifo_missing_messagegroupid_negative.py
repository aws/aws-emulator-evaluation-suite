"""sns-sqs-fifo-missing-messagegroupid-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-sqs-fifo-missing-messagegroupid-negative"
GROUP = "notification"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish to an SNS FIFO topic with a deduplication id but no MessageGroupId fails with
    InvalidParameter (exact message) and nothing reaches the FIFO queue, while a well-formed
    publish on the same topic is delivered."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = _create_fifo_topic(ctx)
    queue_url, queue_arn = _create_fifo_queue(ctx)
    _allow_sns_to_send_to_queue(ctx, queue_url, queue_arn, topic_arn)

    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    rejected_marker = ctx.unique_name("no-group-id-")
    code, message = _client_error(lambda: sns.publish(
        TopicArn=topic_arn,
        Message=rejected_marker,
        MessageDeduplicationId=ctx.unique_name("dedup-reject-"),
    ))
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    expected = "Invalid parameter: The MessageGroupId parameter is required for FIFO topics"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control on the SAME topic/queue: a correctly-formed FIFO publish succeeds and
    # arrives. Draining until it arrives -- rather than a fixed short wait -- also bounds the
    # rejected publish's absence: if it had been delivered late instead of rejected, it would show
    # up among the messages collected before the control message.
    control_text = ctx.unique_name("correctly-formed-fifo-publish-")
    sns.publish(
        TopicArn=topic_arn,
        Message=control_text,
        MessageGroupId="control-group",
        MessageDeduplicationId=ctx.unique_name("dedup-control-"),
    )
    seen_before, matched = _drain_until(ctx, queue_url, control_text, timeout_s=60.0)
    assert rejected_marker not in seen_before, (
        f"the rejected publish was delivered anyway: {seen_before!r}"
    )
    assert matched == control_text, f"expected the control message {control_text!r}, got {matched!r}"


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises. Raises if fn SUCCEEDS -- an unexpected
    success is the strongest possible signal."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected but it SUCCEEDED, returning {result!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _create_fifo_topic(ctx) -> str:
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-xsvc-topic-") + ".fifo"
    arn = sns.create_topic(
        Name=name,
        Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "false"},
        Tags=_xsvc_tags_kv(),
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_fifo_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-") + ".fifo"
    url = sqs.create_queue(
        QueueName=name,
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags=_xsvc_resource_tags(),
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_sns_to_send_to_queue(ctx, queue_url: str, queue_arn: str, topic_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "SQS:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _drain_until(ctx, queue_url: str, target_message: str, *, timeout_s: float) -> tuple[list[str], str]:
    """Receive and decode SNS envelopes until one carries target_message. Returns every OTHER
    decoded Message seen first, in arrival order, plus the matching one. Raises on timeout rather
    than returning whatever was last seen."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            decoded = json.loads(msg["Body"]).get("Message")
            if decoded == target_message:
                return seen, decoded
            seen.append(decoded)
    raise AssertionError(f"no message carrying {target_message!r} delivered within {timeout_s}s; saw {seen!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
