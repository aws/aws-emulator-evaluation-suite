"""recreated-queue-with-the-same-name-resumes-delivery-on-the-old-subscription."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recreated-queue-with-the-same-name-resumes-delivery-on-the-old-subscription"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-recreated-queue-with-the-same-name-resum"

# timing:real-time — retention: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteQueue.html
@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A subscription binds to its queue by ARN: while the queue is deleted a publish goes to the
    subscription's DLQ, and once a same-named queue is recreated the unchanged subscription delivers
    to it; the message published in the gap stays in the DLQ and is not replayed."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)
    dlq_url, dlq_arn = _create_queue_for_topic(ctx, topic_arn)
    q_url, q_arn = _create_queue_for_topic(ctx, topic_arn)
    q_name = q_arn.rsplit(":", 1)[1]
    sub = _subscribe_and_confirm(ctx, topic_arn, q_arn)
    _set_redrive(ctx, sub, dlq_arn)

    sqs.delete_queue(QueueUrl=q_url)
    gap_markers: list[str] = []
    for _ in range(6):
        gap = ctx.unique_name("sim2real-behav-sns-recreate-gap-")
        gap_markers.append(gap)
        sns.publish(TopicArn=topic_arn, Message=gap)
        if gap in _collect_keyed(ctx, dlq_url, _envelope_message, {gap}, window_s=20.0):
            break
    else:
        raise AssertionError("no publish made while the queue was deleted reached the DLQ")

    def recreate():
        try:
            return sqs.create_queue(
                QueueName=q_name, tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
            )["QueueUrl"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.QueueDeletedRecently":
                raise
            return None

    new_url = _poll_until(recreate, lambda u: u is not None, timeout_s=120.0, interval_s=10.0,
                          description="a queue with the deleted queue's name can be created again")
    ctx.on_cleanup(lambda u=new_url: _delete_queue_if_present(ctx, u))
    new_arn = sqs.get_queue_attributes(
        QueueUrl=new_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert new_arn == q_arn, "a queue recreated under the same name must have the same ARN"
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
        "Action": "sqs:SendMessage", "Resource": new_arn,
        "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]}
    sqs.set_queue_attributes(QueueUrl=new_url, Attributes={"Policy": json.dumps(policy)})

    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert (attrs["Endpoint"], attrs["PendingConfirmation"]) == (q_arn, "false"), (
        f"the original subscription must still target the queue ARN and stay confirmed, got "
        f"PendingConfirmation={attrs.get('PendingConfirmation')!r}"
    )

    for _ in range(8):
        back = ctx.unique_name("sim2real-behav-sns-recreate-back-")
        sns.publish(TopicArn=topic_arn, Message=back)
        got = _collect_keyed(ctx, new_url, _envelope_message, {back}, window_s=15.0)
        if back in got:
            break
        stray = [k for k in got if k in gap_markers]
        assert stray == [], f"a gap message was replayed into the recreated queue: {stray!r}"
    else:
        raise AssertionError(
            "the original subscription never delivered to the queue recreated under its name")
    replayed = [b for b in _drain(ctx, new_url, window_s=10.0) if any(g in b for g in gap_markers)]
    assert replayed == [], (
        f"messages published while the queue was deleted must not be replayed into the "
        f"recreated queue; got {len(replayed)}"
    )


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
