"""standard-topic-message-group-id-reaches-the-queue-as-its-message-group-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "standard-topic-message-group-id-reaches-the-queue-as-its-message-group-id"
GROUP = 'fair-queues'
SERVICES = ['sns']

_SCENARIO = "sns-standard-topic-message-group"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A standard topic forwards a published MessageGroupId (Publish and PublishBatch, raw and
    enveloped) as the SQS MessageGroupId system attribute, omits it when none was published,
    and returns no SequenceNumber. This is how SNS feeds SQS fair queues.
    """
    sns = ctx.client("sns")
    topic = _create_topic(ctx)
    raw_url, raw_arn = _create_queue_for_topics(ctx, [topic])
    env_url, env_arn = _create_queue_for_topics(ctx, [topic])
    _subscribe_and_confirm(ctx, topic, raw_arn, {"RawMessageDelivery": "true"})
    _subscribe_and_confirm(ctx, topic, env_arn)

    run_id = ctx.unique_name("sim2real-behav-sns-fairgrp-")
    expected = {
        f"{run_id}-single-grouped": "tenant-a",
        f"{run_id}-single-plain": None,
        f"{run_id}-batch-grouped": "tenant-b",
        f"{run_id}-batch-plain": None,
    }

    grouped = sns.publish(TopicArn=topic, Message=f"{run_id}-single-grouped",
                          MessageGroupId="tenant-a")
    plain = sns.publish(TopicArn=topic, Message=f"{run_id}-single-plain")
    for resp in (grouped, plain):
        assert resp.get("MessageId") and "SequenceNumber" not in resp, (
            f"a standard-topic Publish returns a MessageId and no SequenceNumber, got "
            f"{ {k: v for k, v in resp.items() if k != 'ResponseMetadata'}!r}")

    batch = sns.publish_batch(TopicArn=topic, PublishBatchRequestEntries=[
        {"Id": "grouped", "Message": f"{run_id}-batch-grouped", "MessageGroupId": "tenant-b"},
        {"Id": "plain", "Message": f"{run_id}-batch-plain"},
    ])
    assert sorted(e["Id"] for e in batch.get("Successful", [])) == ["grouped", "plain"] \
        and not batch.get("Failed"), (
        f"both PublishBatch entries must succeed, got Successful={batch.get('Successful')!r} "
        f"Failed={batch.get('Failed')!r}")

    for label, url in (("raw", raw_url), ("enveloped", env_url)):
        seen = _drain_until(ctx, url, set(expected))
        got = {k: seen[k].get("Attributes", {}).get("MessageGroupId") for k in expected}
        assert got == expected, (
            f"on the {label} subscription the MessageGroupId each message carried was {got!r}, "
            f"expected {expected!r}")
        extra = sorted(set(seen) - set(expected))
        assert not extra, f"the {label} queue received messages nobody published: {extra!r}"


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, prefix: str = "sim2real-behav-sns-t-") -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name(prefix), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: sns.delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topics(ctx, topic_arns: list[str]) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly these topics send to it."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sns-q-"),
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": list(topic_arns)}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, attributes=None,
                           timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue, register Unsubscribe, poll until PendingConfirmation is false."""
    sns = ctx.client("sns")
    kwargs = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
              "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: _unsubscribe_if_present(sns, s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"the sqs subscription was still PendingConfirmation={pending!r} after {timeout_s}s")


def _unsubscribe_if_present(sns, sub_arn: str) -> None:
    """Unsubscribe; a subscription already removed with its topic is the tolerated outcome."""
    try:
        sns.unsubscribe(SubscriptionArn=sub_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


def _key(msg) -> str:
    """The published text of a delivered SQS message: the envelope's Message, else the raw body."""
    body = msg.get("Body", "")
    try:
        env = json.loads(body)
    except ValueError:
        return body
    if isinstance(env, dict) and env.get("Type") == "Notification":
        return env.get("Message", "")
    return body


def _drain_until(ctx, url: str, wanted: set[str], timeout_s: float = 90.0) -> dict:
    """Receive (and delete) until every key in ``wanted`` has been seen; return key -> message
    for EVERY message seen on the way, so a caller can assert what else arrived."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        for msg in sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                MessageAttributeNames=["All"], MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[_key(msg)] = msg
    missing = sorted(wanted - set(seen))
    assert not missing, (
        f"within {timeout_s}s the queue never received {missing!r}; it received {sorted(seen)!r}")
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
