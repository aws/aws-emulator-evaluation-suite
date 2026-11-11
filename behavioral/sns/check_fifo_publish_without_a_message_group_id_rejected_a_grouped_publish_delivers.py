"""fifo-publish-without-a-message-group-id-rejected-a-grouped-publish-delivers."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fifo-publish-without-a-message-group-id-rejected-a-grouped-publish-delivers"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-group-required"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Publish to a FIFO topic without MessageGroupId is rejected with InvalidParameter and nothing
    is delivered, while the identical publish carrying a MessageGroupId arrives in the FIFO queue.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx, fifo=True, attributes={"ContentBasedDeduplication": "false"})
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn, attributes={"RawMessageDelivery": "true"})

    run_id = ctx.unique_name("sim2real-behav-sns-grp-")
    group = f"{run_id}-group"
    rejected_marker = f"{run_id}-rejected"
    accepted_marker = f"{run_id}-accepted"

    # Keep MessageDeduplicationId so the refusal can only be about the missing group id. The AWS
    # code is InvalidParameter; InvalidParameterException is only the botocore class name.
    code, message = _error(lambda: sns.publish(
        TopicArn=topic_arn, Message=rejected_marker,
        MessageDeduplicationId=f"{run_id}-dedup-rejected"))
    assert code == "InvalidParameter", (
        f"a FIFO publish without MessageGroupId was not rejected with InvalidParameter: {code!r}"
    )
    assert message == "Invalid parameter: The MessageGroupId parameter is required for FIFO topics", (
        f"unexpected InvalidParameter message for FIFO publish missing MessageGroupId: {message!r}"
    )

    sns.publish(TopicArn=topic_arn, Message=accepted_marker, MessageGroupId=group,
                MessageDeduplicationId=f"{run_id}-dedup-accepted")
    # FIFO order within the group: once the sentinel lands, every earlier publish has too.
    sentinel = f"{run_id}-sentinel"
    sns.publish(TopicArn=topic_arn, Message=sentinel, MessageGroupId=group,
                MessageDeduplicationId=f"{run_id}-dedup-sentinel")
    bodies = _drain_until_body(ctx, queue_url, sentinel, timeout_s=120.0)
    bodies += _receive_any(ctx, queue_url, rounds=1, wait_s=20)

    assert len(bodies) == 1, f"expected exactly one delivery, got {len(bodies)}: {bodies!r}"
    assert bodies == [accepted_marker], (
        f"the queue holds something other than exactly the accepted message: {bodies!r}"
    )
    assert rejected_marker not in bodies, (
        f"the refused publish was delivered anyway: {bodies!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS error (Code, Message) raised by fn(); raises if fn succeeds."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {result!r}"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs = dict(attributes or {})
    if fifo:
        name = name + ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name = name + ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"subscription {sub_arn!r} was still PendingConfirmation={pending!r} after {timeout_s}s"
    )


def _drain_until_body(ctx, queue_url: str, sentinel: str, *,
                      timeout_s: float = 120.0) -> list[str]:
    """Receive until the sentinel body arrives; returns everything seen BEFORE it, in order."""
    sqs = ctx.client("sqs")
    before: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            if body == sentinel:
                return before
            before.append(body)
    raise AssertionError(
        f"the FIFO sentinel {sentinel!r} never arrived within {timeout_s}s, so the absence of the "
        f"refused publish is not bounded; messages seen were {before!r}"
    )


def _receive_any(ctx, queue_url: str, *, rounds: int, wait_s: int) -> list[str]:
    """Long-poll a queue `rounds` times and return every body it produced (expected: none)."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    for _ in range(rounds):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
