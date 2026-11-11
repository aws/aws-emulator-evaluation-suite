"""filter-policy-message-body-scope-matches-array-members-and-withholds-non-json."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-policy-message-body-scope-matches-array-members-and-withholds-non-json"
GROUP = "delivery"
SERVICES = ["sns"]

_SCENARIO = "sns-filter-body-array"


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With FilterPolicyScope=MessageBody, a policy value matches a JSON array in the body when
    ANY member matches, matches a scalar equal to it, and withholds a body that is not JSON at
    all or lacks the key.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)

    control_url, control_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, control_arn,
                           attributes={"RawMessageDelivery": "true"})

    policy = {"order": {"items": ["book"]}}
    url, arn = _create_queue_for_topic(ctx, topic_arn)
    sub = _subscribe_and_confirm(
        ctx, topic_arn, arn,
        attributes={"RawMessageDelivery": "true", "FilterPolicyScope": "MessageBody",
                    "FilterPolicy": json.dumps(policy)})
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert attrs.get("FilterPolicyScope") == "MessageBody", (
        f"FilterPolicyScope read back as {attrs.get('FilterPolicyScope')!r}, not 'MessageBody'"
    )

    # M1 (array member) and M3 (scalar) match; M2, M4 (not JSON) and M5 (no key) are withheld.
    # M4 contains the word "book" so substring matching on the raw body would wrongly deliver it.
    ids = [ctx.unique_name(f"sim2real-behav-bodyarr-m{i}-") for i in range(1, 6)]
    bodies = [
        json.dumps({"id": ids[0], "order": {"items": ["pen", "book"]}}),
        json.dumps({"id": ids[1], "order": {"items": ["pen"]}}),
        json.dumps({"id": ids[2], "order": {"items": "book"}}),
        f"{ids[3]} order items book",
        json.dumps({"id": ids[4], "order": {"total": 5}}),
    ]

    started = time.monotonic()
    for body in bodies:
        sns.publish(TopicArn=topic_arn, Message=body)

    _grade_matrix(ctx, control_url, {"body-scope": (url, {bodies[0], bodies[2]})},
                  set(bodies), started)


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


def _grade_matrix(ctx, control_url: str, arms: dict[str, tuple[str, set[str]]],
                  published: set[str], started: float) -> None:
    """Wait for the unfiltered control to receive everything, then require each arm to receive
    exactly its expected set and nothing more within a latency-calibrated window."""
    sqs = ctx.client("sqs")
    control_seen = _await_bodies(
        ctx, control_url, published, timeout_s=120.0,
        description=("the unfiltered control subscription must receive every published "
                     "message; without this barrier an absence at a filtered arm proves "
                     "nothing"),
    )
    latency = max(max(control_seen.values()) - started, 1.0)
    ceiling = max(60.0, 3.0 * latency + 20.0)
    for label, (url, expected) in arms.items():
        _await_bodies(
            ctx, url, expected, timeout_s=ceiling,
            description=f"the {label} arm must deliver exactly {sorted(expected)!r}",
            forbidden=published - expected,
        )
    window = max(3.0 * latency, 20.0)
    leaked = _drain(ctx, {label: url for label, (url, _) in arms.items()}, window_s=window)
    assert leaked == {label: [] for label in arms}, (
        f"after every arm had received its matching messages, a {window:.0f}s window (>=3x "
        f"the measured control latency of {latency:.1f}s) must yield nothing more; got "
        f"{leaked!r} -- a body here is a withheld message delivered late"
    )
    for label, (url, _) in arms.items():
        approx = int(sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]["ApproximateNumberOfMessages"])
        assert approx == 0, (
            f"second observable for the absence: the {label} queue reports "
            f"ApproximateNumberOfMessages={approx}, expected 0"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
