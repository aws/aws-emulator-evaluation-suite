"""fifo-subscription-redrive-requires-a-fifo-dlq-and-dead-letters-into-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-subscription-redrive-requires-a-fifo-dlq-and-dead-letters-into-it"
GROUP = "validation"
SERVICES = ["sns"]

_SCENARIO = "sns-fifo-subscription-redrive-requires-a-fif"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A FIFO subscription refuses a standard-queue DLQ with InvalidParameter and stores no
    RedrivePolicy; a FIFO DLQ is accepted, and once the subscribed queue is deleted the
    notification is dead-lettered into it under its original MessageGroupId.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx, fifo=True)
    std_url, std_arn = _create_queue_for_topic(ctx, topic_arn)
    dlq_url, dlq_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    end_url, end_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    sub = _subscribe_and_confirm(ctx, topic_arn, end_arn)

    code, message = _error(lambda: sns.set_subscription_attributes(
        SubscriptionArn=sub, AttributeName="RedrivePolicy",
        AttributeValue=json.dumps({"deadLetterTargetArn": std_arn})))
    assert (code, message) == (
        "InvalidParameter",
        "Invalid parameter: RedrivePolicy: must use a FIFO queue as DLQ for a FIFO "
        "Subscription to a FIFO Topic."), (
        f"a standard DLQ on a FIFO subscription must be refused, got {code!r} {message!r}"
    )
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert "RedrivePolicy" not in attrs, (
        f"the refused RedrivePolicy must not be stored, got {attrs.get('RedrivePolicy')!r}"
    )

    _set_redrive(ctx, sub, dlq_arn)
    sqs.delete_queue(QueueUrl=end_url)
    group = ctx.unique_name("sim2real-grp-")
    for _ in range(6):
        dead = ctx.unique_name("sim2real-behav-sns-dlqfifo-dead-")
        sns.publish(TopicArn=topic_arn, Message=dead, MessageGroupId=group,
                    MessageDeduplicationId=dead)
        got = _collect_keyed(ctx, dlq_url, _envelope_message, {dead}, window_s=30.0)
        if dead in got:
            msg = got[dead]
            break
    else:
        raise AssertionError(
            "no publish to the deleted FIFO endpoint reached the FIFO DLQ across 6 attempts")
    got_group = msg.get("Attributes", {}).get("MessageGroupId")
    assert got_group == group, (
        f"the dead-lettered copy must keep its MessageGroupId, got "
        f"{'a different group' if got_group else got_group!r}"
    )
    stray = _drain(ctx, std_url, window_s=5.0)
    assert stray == [], f"the refused standard DLQ must receive nothing, got {stray!r}"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]

def _create_topic(ctx, *, fifo: bool = False) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs: dict[str, str] = {}
    if fifo:
        name += ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn

def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name += ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: _delete_queue_if_present(ctx, u))
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


def _delete_queue_if_present(ctx, url: str) -> None:
    """DeleteQueue; a queue the check itself already deleted is the one tolerated outcome."""
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise

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
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s, interval_s=1.0,
        description="the sqs subscription leaves PendingConfirmation",
    )
    return sub_arn

def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}")
        time.sleep(interval_s)
        value = fn()
    return value

def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) the call raises. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")

def _receive_keyed(ctx, queue_url: str, key, wanted: set[str], *, timeout_s: float,
                   description: str) -> dict[str, dict]:
    """Long-poll until a message keyed `key(msg)` exists for every wanted key; RAISES on the
    deadline. Each message is returned whole (Body plus MessageAttributes)."""
    sqs = ctx.client("sqs")
    got: dict[str, dict] = {}
    other: list[str] = []
    deadline = time.monotonic() + timeout_s
    while not wanted <= set(got):
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            MessageAttributeNames=["All"], AttributeNames=["All"])
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            k = key(msg)
            if k in wanted and k not in got:
                got[k] = msg
            else:
                other.append(msg["Body"][:160])
        if not wanted <= set(got) and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(wanted - set(got))!r} never arrived within "
                f"{timeout_s}s; other bodies seen: {other!r}")
    return got


def _envelope_message(msg: dict) -> str | None:
    """The Message field of an SNS notification envelope, or None for a non-envelope body."""
    try:
        body = json.loads(msg["Body"])
    except ValueError:
        return None
    if isinstance(body, dict) and body.get("Type") == "Notification":
        return body.get("Message")
    return None

def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll for the whole window and return EVERY body seen, so the caller can assert on
    leakage rather than discard it."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"][:300])
    return bodies

def _set_redrive(ctx, sub_arn: str, dlq_arn: str) -> None:
    """Point the subscription's RedrivePolicy at the DLQ and wait for the read to agree."""
    sns = ctx.client("sns")
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RedrivePolicy",
        AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("RedrivePolicy"),
        lambda raw: bool(raw) and json.loads(raw) == {"deadLetterTargetArn": dlq_arn},
        timeout_s=30.0, interval_s=1.0,
        description="GetSubscriptionAttributes reflects the RedrivePolicy")


def _collect_keyed(ctx, queue_url: str, key, wanted: set[str], *, window_s: float) -> dict:
    """Long-poll until every wanted key has arrived or the window ends; returns what arrived
    (possibly partial). The caller decides whether partial is a failure."""
    sqs = ctx.client("sqs")
    got: dict[str, dict] = {}
    deadline = time.monotonic() + window_s
    while not wanted <= set(got) and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            MessageAttributeNames=["All"], AttributeNames=["All"])
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            got.setdefault(key(msg), msg)
    return got


def _dlq_key(msg: dict) -> str:
    """'env:<Message>' for an enveloped copy, 'raw:<Body>' for a raw one."""
    inner = _envelope_message(msg)
    return f"env:{inner}" if inner is not None else f"raw:{msg['Body']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
