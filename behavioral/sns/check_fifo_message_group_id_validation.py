"""fifo-message-group-id-validation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "fifo-message-group-id-validation"
GROUP = 'overly-permissive'
SERVICES = ['sns']

_SCENARIO = "sns-fifo-group-id-validation"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO Publish without MessageGroupId fails InvalidParameter and delivers nothing, while a
    grouped one returns a SequenceNumber; a standard topic accepts and delivers a MessageGroupId
    publish without returning a SequenceNumber.
    """
    sns = ctx.client("sns")
    run_id = ctx.unique_name("sim2real-behav-sns-fifoval-")
    group = f"{run_id}-group"

    fifo_arn = _create_topic(ctx, fifo=True, attributes={"ContentBasedDeduplication": "false"})
    fifo_queue_url, fifo_queue_arn = _create_queue_for_topic(ctx, fifo_arn, fifo=True)
    _subscribe_and_confirm(ctx, fifo_arn, fifo_queue_arn)

    control_marker = f"{run_id}-control"
    control_resp = sns.publish(
        TopicArn=fifo_arn, Message=control_marker, MessageGroupId=group,
        MessageDeduplicationId=f"{run_id}-dedup-control",
    )
    assert control_resp.get("SequenceNumber"), (
        f"expected FIFO publish with MessageGroupId to return a SequenceNumber, got {control_resp}"
    )

    # Keep MessageDeduplicationId so the refusal can only be about the missing group id.
    rejected_marker = f"{run_id}-rejected"
    code, message = _error(lambda: sns.publish(
        TopicArn=fifo_arn, Message=rejected_marker,
        MessageDeduplicationId=f"{run_id}-dedup-rejected"))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for FIFO publish missing MessageGroupId, got {code!r}"
    )
    assert message == "Invalid parameter: The MessageGroupId parameter is required for FIFO topics", (
        f"unexpected InvalidParameter message for FIFO publish missing MessageGroupId: {message!r}"
    )

    # FIFO order within the group: once the sentinel lands, every earlier publish has too.
    sentinel = f"{run_id}-sentinel"
    sns.publish(TopicArn=fifo_arn, Message=sentinel, MessageGroupId=group,
                MessageDeduplicationId=f"{run_id}-dedup-sentinel")
    bodies = _drain_until_body(ctx, fifo_queue_url, sentinel, timeout_s=120.0)
    assert bodies == [control_marker], (
        f"expected only the accepted control message ahead of the sentinel, got {bodies!r}"
    )
    assert rejected_marker not in bodies, f"the refused publish was delivered anyway: {bodies!r}"

    std_arn = _create_topic(ctx, fifo=False)
    std_queue_url, std_queue_arn = _create_queue_for_topic(ctx, std_arn, fifo=False)
    _subscribe_and_confirm(ctx, std_arn, std_queue_arn)

    std_marker = f"{run_id}-std"
    std_resp = sns.publish(TopicArn=std_arn, Message=std_marker, MessageGroupId="group-x")
    assert std_resp.get("MessageId"), f"expected standard-topic publish to return a MessageId, got {std_resp}"
    assert not std_resp.get("SequenceNumber"), (
        f"expected no SequenceNumber from a standard topic, got {std_resp.get('SequenceNumber')!r}"
    )
    std_bodies = _receive_until_body(ctx, std_queue_url, std_marker, timeout_s=60.0)
    assert std_marker in std_bodies, (
        f"expected the standard-topic publish carrying MessageGroupId to actually be delivered, "
        f"got {std_bodies!r}"
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
    name = ctx.unique_name("sim2real-behav-sns-fifoval-")
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
    name = ctx.unique_name("sim2real-behav-sns-fifoval-q-")
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


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue (raw delivery) and poll GetSubscriptionAttributes until confirmed."""
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True,
        Attributes={"RawMessageDelivery": "true"},
    )["SubscriptionArn"]
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


def _drain_until_body(ctx, queue_url: str, sentinel: str, *, timeout_s: float = 120.0) -> list[str]:
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


def _receive_until_body(ctx, queue_url: str, marker: str, *, timeout_s: float = 60.0) -> list[str]:
    """Long-poll until `marker` is seen (or raise); returns every body observed along the way."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg.get("Body", ""))
        if marker in bodies:
            return bodies
    raise AssertionError(
        f"expected {marker!r} to be delivered within {timeout_s}s, got {bodies!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
