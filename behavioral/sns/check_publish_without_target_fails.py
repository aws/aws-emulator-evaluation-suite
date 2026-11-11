"""publish-without-target-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "publish-without-target-fails"
GROUP = 'publish'
SERVICES = ['sns']

_SCENARIO = "sns-publish-no-target"


def _error(fn) -> tuple[str, str]:
    """The AWS error (Code, Message) raised by fn(). Raises if fn SUCCEEDS — an unexpected success is
    the strongest possible signal."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_wired_topic(ctx) -> tuple[str, str]:
    """Create a topic with a confirmed, raw-delivery SQS subscription; returns (TopicArn, QueueUrl)."""
    import json

    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-notarget-"), Tags=_tags_kv()
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sns-notarget-q-"),
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
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
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    deadline = time.monotonic() + 60.0
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn
        )["Attributes"].get("PendingConfirmation")
        if pending == "false":
            break
        time.sleep(1.0)
    else:
        raise AssertionError(f"subscription {sub_arn!r} still PendingConfirmation={pending!r}")

    return topic_arn, queue_url


def _receive_until(ctx, queue_url: str, marker: str, *, timeout_s: float = 60.0) -> list[str]:
    """Long-poll the queue until `marker` arrives; returns every body seen along the way."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            seen.append(msg.get("Body", ""))
        if marker in seen:
            return seen
    raise AssertionError(f"{marker!r} never arrived at the queue within {timeout_s}s; saw {seen!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish with no TopicArn/TargetArn/PhoneNumber is rejected with the specific validation
    error, while an otherwise-identical publish that DOES carry a TopicArn is delivered — the
    positive control that separates "rejects a targetless publish" from "rejects every publish".
    """
    sns = ctx.client("sns")
    topic_arn, queue_url = _create_wired_topic(ctx)

    code, message = _error(lambda: sns.publish(Message="no target specified"))
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    assert message == 'Invalid parameter: TopicArn or TargetArn Reason: no value for required parameter', (
        f"expected the exact message 'Invalid parameter: TopicArn or TargetArn Reason: no value for required parameter', got {message!r}"
    )

    marker = ctx.unique_name("sim2real-behav-sns-notarget-msg-")
    sns.publish(TopicArn=topic_arn, Message=marker)
    bodies = _receive_until(ctx, queue_url, marker)
    assert marker in bodies, f"the positive-control publish never arrived at the queue: {bodies!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
