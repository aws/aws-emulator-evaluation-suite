"""raw-delivery-to-sqs-drops-a-message-with-more-than-ten-attributes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "raw-delivery-to-sqs-drops-a-message-with-more-than-ten-attributes"
GROUP = "delivery"
SERVICES = ["sns"]

_SCENARIO = "sns-raw-attr-limit"


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Raw delivery maps SNS message attributes onto SQS ones, which hold at most ten: an
    eleven-attribute message is not delivered to the raw subscriber but reaches the enveloped
    twin, while a ten-attribute message reaches both.
    """
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)
    raw_url, raw_arn = _create_queue_for_topic(ctx, topic_arn)
    env_url, env_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, raw_arn, attributes={"RawMessageDelivery": "true"})
    _subscribe_and_confirm(ctx, topic_arn, env_arn)

    eleven = ctx.unique_name("sim2real-behav-rawlimit-eleven-")
    ten = ctx.unique_name("sim2real-behav-rawlimit-ten-")
    started = time.monotonic()
    sns.publish(TopicArn=topic_arn, Message=eleven,
                MessageAttributes={f"a{i:02d}": _s(f"v{i}") for i in range(11)})
    sns.publish(TopicArn=topic_arn, Message=ten,
                MessageAttributes={f"a{i:02d}": _s(f"v{i}") for i in range(10)})

    enveloped: dict[str, dict] = {}
    deadline = time.monotonic() + 120.0
    while set(enveloped) != {eleven, ten}:
        for msg in sqs.receive_message(QueueUrl=env_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5).get("Messages", []):
            sqs.delete_message(QueueUrl=env_url, ReceiptHandle=msg["ReceiptHandle"])
            env = json.loads(msg["Body"])
            enveloped[env["Message"]] = env
        if set(enveloped) != {eleven, ten} and time.monotonic() >= deadline:
            raise AssertionError(f"the enveloped twin received only {sorted(enveloped)!r}")
    latency = max(time.monotonic() - started, 1.0)
    assert len(enveloped[eleven].get("MessageAttributes", {})) == 11, (
        f"the enveloped copy must carry all eleven attributes, got "
        f"{sorted(enveloped[eleven].get('MessageAttributes', {}))!r}"
    )

    raw: list[dict] = []
    deadline = time.monotonic() + max(60.0, 3.0 * latency)
    while ten not in [m["Body"] for m in raw]:
        for msg in sqs.receive_message(QueueUrl=raw_url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=5,
                                       MessageAttributeNames=["All"]).get("Messages", []):
            sqs.delete_message(QueueUrl=raw_url, ReceiptHandle=msg["ReceiptHandle"])
            raw.append(msg)
        if ten not in [m["Body"] for m in raw] and time.monotonic() >= deadline:
            raise AssertionError(
                f"the ten-attribute message never reached the raw subscriber; got "
                f"{[m['Body'] for m in raw]!r}")
    got_ten = next(m for m in raw if m["Body"] == ten)
    assert sorted(got_ten.get("MessageAttributes", {})) == [f"a{i:02d}" for i in range(10)], (
        f"the raw copy must carry the ten attributes as SQS message attributes, got "
        f"{sorted(got_ten.get('MessageAttributes', {}))!r}"
    )
    window = max(3.0 * latency, 15.0)
    late = _drain(ctx, {"raw": raw_url}, window_s=window)["raw"]
    bodies = [m["Body"] for m in raw] + late
    assert eleven not in bodies, (
        f"the eleven-attribute message must not reach the raw subscriber; within a "
        f"{window:.0f}s window it received {bodies!r}"
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
    """Bounded retry; raises on the deadline."""
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
    """Long-poll until every wanted body is seen; raises on the deadline.

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
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
