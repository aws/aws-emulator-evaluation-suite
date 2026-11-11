"""a-message-filtered-out-at-publish-time-is-never-redelivered-when-the-policy-is-relaxed."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "a-message-filtered-out-at-publish-time-is-never-redelivered-when-the-policy-is-relaxed"
GROUP = "event-propagation"
SERVICES = ["sns", "sqs"]

_NARROW = {"kind": ["wanted"]}
_WIDE = {"kind": ["wanted", "unwanted"]}
_POLICY_PROPAGATION_WAIT_S = 900  # AWS's own documented "up to 15 minutes"
#: Worst-case duration of one run: the propagation wait above plus setup and the absence holds.
_WORST_CASE_BUDGET_S = 1200


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_queue(ctx, name, topic_arn, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowSns",
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    """Returns the parsed nonces seen. `.get("Messages", [])` feeds a loop whose result is asserted
    by exact membership — the sanctioned polarity for an empty default."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            envelope = json.loads(msg["Body"])
            out.append(json.loads(envelope["Message"])["nonce"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _subscribe(ctx, topic_arn, queue_arn, attributes):
    sns = ctx.client("sns")
    arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes=attributes,
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").unsubscribe(SubscriptionArn=a))
    return arn


# ===== the check =====
@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A message a subscription filter rejected at publish time is never delivered, not even after
    the filter is widened to admit it — while the widened filter demonstrably admits new messages."""
    sns = ctx.client("sns")
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    topic_name = ctx.unique_name("sim2real-nd-noretro-")
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real-check", "Value": check_tag}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))

    subject_url, subject_arn = _make_queue(
        ctx, f"sim2real-nd-noretro-subj-{suffix}", topic_arn, check_tag
    )
    twin_url, twin_arn = _make_queue(
        ctx, f"sim2real-nd-noretro-twin-{suffix}", topic_arn, check_tag
    )

    subject_sub = _subscribe(
        ctx,
        topic_arn,
        subject_arn,
        {"FilterPolicy": json.dumps(_NARROW), "RawMessageDelivery": "false"},
    )
    # The twin has NO filter policy, so it does the same work at the same instant and every absence
    # on the subject is attributable to the one thing that differs.
    twin_sub = _subscribe(ctx, topic_arn, twin_arn, {"RawMessageDelivery": "false"})
    narrow_stored = sns.get_subscription_attributes(SubscriptionArn=subject_sub)["Attributes"]
    assert json.loads(narrow_stored["FilterPolicy"]) == _NARROW, (
        f"the subject subscription stored FilterPolicy={narrow_stored.get('FilterPolicy')!r}, "
        f"expected {json.dumps(_NARROW)!r} — an unfiltered subject would make the absence below "
        f"unfalsifiable"
    )
    assert "FilterPolicy" not in sns.get_subscription_attributes(SubscriptionArn=twin_sub)[
        "Attributes"
    ], (
        f"the TWIN subscription {twin_sub} carries a FilterPolicy, so it is not an unfiltered "
        f"control and cannot establish that each publish reached SNS"
    )

    def _publish(kind, nonce):
        resp = sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"nonce": nonce}),
            MessageAttributes={"kind": {"DataType": "String", "StringValue": kind}},
        )
        assert resp.get("MessageId"), f"Publish returned no MessageId for {nonce!r}: {resp!r}"
        return resp["MessageId"]

    # BEAT 1 — the narrow policy admits its own kind, on this exact wiring.
    warm = f"warm-{uuid.uuid4().hex[:10]}"
    t0 = time.monotonic()
    _publish("wanted", warm)
    got = _poll_until(
        lambda: _drain(ctx, subject_url, seconds=4),
        lambda nonces: warm in nonces,
        timeout_s=120,
        interval_s=0,
        description=(
            f"the narrow policy {json.dumps(_NARROW)} admitted kind=wanted to {subject_url} — the "
            f"positive control that makes the withholding below evidence"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    assert got == [warm], (
        f"the subject queue carried {got!r} on the warm-up, expected exactly [{warm!r}]"
    )
    _drain(ctx, twin_url, seconds=max(latency, 6.0))  # clear the twin's warm-up copy

    # BEAT 2 — the withheld message. Nothing structural stops it later; only SNS's publish-time
    # evaluation does, which is precisely the property under test.
    withheld = f"withheld-{uuid.uuid4().hex[:10]}"
    _publish("unwanted", withheld)
    twin_saw = _poll_until(
        lambda: _drain(ctx, twin_url, seconds=4),
        lambda nonces: withheld in nonces,
        timeout_s=120,
        interval_s=0,
        description=(
            f"the UNFILTERED twin received {withheld!r}, proving the publish reached SNS and fanned "
            f"out — so the subject's emptiness is the filter policy's doing"
        ),
    )
    assert withheld in twin_saw, f"the twin never received {withheld!r}: {twin_saw!r}"
    hold = max(3 * latency, 15.0)
    early = _drain(ctx, subject_url, seconds=hold)
    assert early == [], (
        f"the subject subscription received {early!r} during a {hold:.0f}s hold (3x the "
        f"{latency:.0f}s measured latency) for a message its policy {json.dumps(_NARROW)} rejects"
    )
    assert _queue_depth(ctx, subject_url) == 0, (
        f"the subject queue reports depth {_queue_depth(ctx, subject_url)} behind an empty receive — "
        f"the second independent observable disagrees with the first"
    )

    # BEAT 3 — widen the policy. Everything from here on is about the withheld message NOT coming
    # back, and about the widened policy nonetheless working.
    sns.set_subscription_attributes(
        SubscriptionArn=subject_sub, AttributeName="FilterPolicy", AttributeValue=json.dumps(_WIDE)
    )
    wide_stored = sns.get_subscription_attributes(SubscriptionArn=subject_sub)["Attributes"]
    assert json.loads(wide_stored["FilterPolicy"]) == _WIDE, (
        f"SetSubscriptionAttributes did not store the widened policy: "
        f"{wide_stored.get('FilterPolicy')!r}, expected {json.dumps(_WIDE)!r}"
    )

    # The restore beat, robust to AWS's documented 15-minute filter-policy propagation: re-publish a
    # FRESH nonce on every attempt and record everything the subject queue ever sees.
    seen: list[str] = []
    probes: list[str] = []

    def _probe():
        nonce = f"probe-{uuid.uuid4().hex[:10]}"
        probes.append(nonce)
        _publish("unwanted", nonce)
        seen.extend(_drain(ctx, subject_url, seconds=6))
        return seen

    _poll_until(
        _probe,
        lambda nonces: any(n in nonces for n in probes),
        timeout_s=_POLICY_PROPAGATION_WAIT_S,
        interval_s=10,
        description=(
            f"the widened policy {json.dumps(_WIDE)} began admitting kind=unwanted within AWS's own "
            f"documented {_POLICY_PROPAGATION_WAIT_S}s filter-policy propagation ceiling — the "
            f"restore beat, without which 'the withheld message never came back' would also hold for "
            f"a subscription that stopped delivering entirely"
        ),
    )
    assert any(n in seen for n in probes), (
        f"the widened policy never admitted any of the {len(probes)} probe publishes: seen={seen!r}"
    )

    # THE CLAIM. The message rejected at publish time is absent from EVERYTHING the queue ever
    # received, including after the widening that admits an identical message.
    seen.extend(_drain(ctx, subject_url, seconds=hold))
    assert withheld not in seen, (
        f"the message {withheld!r}, rejected by the narrow policy at publish time, was delivered "
        f"after the policy widened. Everything the subject queue received: {seen!r}. SNS evaluates a "
        f"filter policy against the INCOMING message; there is no backlog to flush, and a target that "
        f"flushes one is holding customer messages the customer was told were dropped"
    )
    assert warm not in seen, (
        f"the warm-up message {warm!r} was delivered a SECOND time after the policy widened "
        f"(everything seen: {seen!r}) — an already-delivered message must not be re-evaluated either"
    )
    assert _queue_depth(ctx, subject_url) == 0, (
        f"the subject queue reports depth {_queue_depth(ctx, subject_url)} at the end of the check — "
        f"something is still in flight, so the absence of {withheld!r} is not yet stable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
