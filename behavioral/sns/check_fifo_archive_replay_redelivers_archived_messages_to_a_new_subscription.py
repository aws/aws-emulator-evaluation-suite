"""fifo-archive-replay-redelivers-archived-messages-to-a-new-subscription."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-archive-replay-redelivers-archived-messages-to-a-new-subscription"
GROUP = "fifo"
SERVICES = ["sns"]

_SCENARIO = "sns-fifo-archive-replay"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A FIFO topic with an ArchivePolicy replays pre-subscription messages, in publish order, to a
    new subscription whose ReplayPolicy starts at BeginningArchiveTime (ReplayStatus Completed);
    a twin subscription without a ReplayPolicy receives only later messages.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(
        ctx, fifo=True,
        attributes={"ArchivePolicy": json.dumps({"MessageRetentionPeriod": "1"})})
    # A topic with an ArchivePolicy cannot be deleted (InvalidState), so the policy is cleared
    # first; LIFO runs this before the DeleteTopic _create_topic registered.
    ctx.on_cleanup(lambda: sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="ArchivePolicy", AttributeValue="{}"))
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert json.loads(attrs.get("ArchivePolicy", "{}")) == {"MessageRetentionPeriod": "1"}, (
        f"ArchivePolicy read back as {attrs.get('ArchivePolicy')!r}"
    )
    beginning = attrs.get("BeginningArchiveTime")
    assert beginning, f"an archiving topic must report BeginningArchiveTime, got {attrs!r}"

    group = "ledger"
    archived = [ctx.unique_name(f"sim2real-behav-replay-archived-{i}-") for i in range(1, 4)]
    for body in archived:
        sns.publish(TopicArn=topic_arn, Message=body, MessageGroupId=group,
                    MessageDeduplicationId=ctx.unique_name("dedup-"))

    replay_url, replay_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    plain_url, plain_arn = _create_queue_for_topic(ctx, topic_arn, fifo=True)
    replay_policy = {"PointType": "Timestamp", "StartingPoint": beginning}
    replay_sub = _subscribe_and_confirm(
        ctx, topic_arn, replay_arn,
        attributes={"RawMessageDelivery": "true", "ReplayPolicy": json.dumps(replay_policy)})
    _subscribe_and_confirm(ctx, topic_arn, plain_arn,
                           attributes={"RawMessageDelivery": "true"})

    # A new subscription takes a moment to join the delivery path, so the live leg republishes
    # a fresh live message (bounded) until the no-replay twin receives one. Every live message
    # is in the same group as the archived ones and published after them, so FIFO order makes
    # the first live arrival the proof that no archived message is still in flight for it.
    lives: list[str] = []
    plain: list[str] = []
    deadline = time.monotonic() + 120.0
    while not any(b in lives for b in plain):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the no-replay subscription received no live message within 120s across "
                f"{len(lives)} live publishes; it received {plain!r}")
        live = ctx.unique_name("sim2real-behav-replay-live-")
        sns.publish(TopicArn=topic_arn, Message=live, MessageGroupId=group,
                    MessageDeduplicationId=ctx.unique_name("dedup-"))
        lives.append(live)
        attempt_end = time.monotonic() + 10.0
        while time.monotonic() < attempt_end and not any(b in lives for b in plain):
            for msg in sqs.receive_message(QueueUrl=plain_url, MaxNumberOfMessages=10,
                                           WaitTimeSeconds=5).get("Messages", []):
                sqs.delete_message(QueueUrl=plain_url, ReceiptHandle=msg["ReceiptHandle"])
                plain.append(msg["Body"])
    assert [b for b in plain if b in archived] == [], (
        f"a subscription without a ReplayPolicy must not be backfilled with messages "
        f"published before it existed, but it received {[b for b in plain if b in archived]!r}"
    )
    assert set(plain) <= set(lives), f"the no-replay subscription received unknown bodies {plain!r}"

    replayed: list[str] = []
    deadline = time.monotonic() + 120.0
    while not (set(archived) <= set(replayed) and lives[-1] in replayed):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the replaying subscription did not receive the archived messages and the "
                f"last live one within 120s; received {replayed!r}")
        for msg in sqs.receive_message(QueueUrl=replay_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=replay_url, ReceiptHandle=msg["ReceiptHandle"])
            replayed.append(msg["Body"])
    assert len(replayed) == len(set(replayed)) and set(replayed) <= set(archived) | set(lives), (
        f"the replaying subscription must receive each message at most once and only "
        f"published ones, got {replayed!r}"
    )
    assert [b for b in replayed if b in archived] == archived, (
        f"archived messages must be replayed in publish order {archived!r}, got {replayed!r}"
    )

    status = _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=replay_sub)["Attributes"].get("ReplayStatus"),
        lambda v: v == "Completed", timeout_s=60.0, interval_s=2.0,
        description="the replaying subscription reports ReplayStatus Completed")
    assert status == "Completed", f"ReplayStatus is {status!r}"
    stored = sns.get_subscription_attributes(SubscriptionArn=replay_sub)["Attributes"]
    assert json.loads(stored.get("ReplayPolicy", "{}")) == replay_policy, (
        f"ReplayPolicy read back as {stored.get('ReplayPolicy')!r}, not {replay_policy!r}"
    )


def _s(value: str) -> dict:
    """A String-typed message attribute value."""
    return {"DataType": "String", "StringValue": value}


def _n(value: str) -> dict:
    """A Number-typed message attribute value."""
    return {"DataType": "Number", "StringValue": value}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-") + (".fifo" if fifo else "")
    attrs = dict(attributes or {})
    if fifo:
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False,
                            attributes: dict | None = None) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic send to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-") + (".fifo" if fifo else "")
    attrs = dict(attributes or {})
    if fifo:
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
                           attributes: dict | None = None,
                           timeout_s: float = 60.0) -> str:
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
        timeout_s=timeout_s, interval_s=2.0,
        description="the new subscription leaves PendingConfirmation",
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


def _await_bodies(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                  description: str, forbidden: set[str] | None = None) -> dict[str, float]:
    """Long-poll until every wanted body is seen; RAISES on the deadline.

    Returns {body: monotonic time first seen}. A body in `forbidden` that arrives raises at
    once: it is a leak, and swallowing it would hide what the caller is about to assert.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            if forbidden and body in forbidden:
                raise AssertionError(
                    f"{description}: a body that must never be delivered arrived: {body!r}")
            if body in outstanding:
                outstanding.discard(body)
                seen[body] = time.monotonic()
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s")
    return seen


def _drain(ctx, queues: dict[str, str], *, window_s: float) -> dict[str, list[str]]:
    """Alternate long polls across the queues for one shared window and return every body
    each produced. The empty lists feed an equality-to-empty assertion."""
    sqs = ctx.client("sqs")
    out: dict[str, list[str]] = {label: [] for label in queues}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for label, url in queues.items():
            resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=2)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
                out[label].append(msg["Body"])
    return out


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises. An unexpected success
    raises too, naming what came back, so it can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
