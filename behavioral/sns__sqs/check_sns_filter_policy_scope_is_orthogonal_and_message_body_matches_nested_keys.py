"""sns-filter-policy-scope-is-orthogonal-and-message-body-matches-nested-keys."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sns-filter-policy-scope-is-orthogonal-and-message-body-matches-nested-keys"
GROUP = "event-propagation"
SERVICES = ["sns", "sqs"]

_SCENARIO = "sns-filter-scope"


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The same policy under MessageAttributes and MessageBody scope selects disjoint halves of the
    same two messages (neither scope falls back to the other), and a MessageBody policy evaluates a
    nested key with a numeric operator: order.total=150 is delivered and 100 is withheld."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)

    control_url, control_arn = _create_queue_for_topic(ctx, topic_arn)
    attr_url, attr_arn = _create_queue_for_topic(ctx, topic_arn)
    body_url, body_arn = _create_queue_for_topic(ctx, topic_arn)

    flat_policy = {"kind": ["wanted"]}
    _subscribe_and_confirm(ctx, topic_arn, control_arn,
                           attributes={"RawMessageDelivery": "true"})
    attr_sub = _subscribe_and_confirm(
        ctx, topic_arn, attr_arn,
        attributes={"RawMessageDelivery": "true",
                    "FilterPolicy": json.dumps(flat_policy),
                    "FilterPolicyScope": "MessageAttributes"},
    )
    body_sub = _subscribe_and_confirm(
        ctx, topic_arn, body_arn,
        attributes={"RawMessageDelivery": "true",
                    "FilterPolicy": json.dumps(flat_policy),
                    "FilterPolicyScope": "MessageBody"},
    )
    for label, sub_arn, expected_scope in (("attribute", attr_sub, "MessageAttributes"),
                                           ("body", body_sub, "MessageBody")):
        got = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("FilterPolicyScope")
        assert got == expected_scope, (
            f"the {label} arm must be configured with FilterPolicyScope {expected_scope!r} or "
            f"the whole matrix below is meaningless; GetSubscriptionAttributes read {got!r}"
        )

    # ---- phase 1 --------------------------------------------------------------------------
    ma = ctx.unique_name("sim2real-behav-scope-attr-only-")
    mb = ctx.unique_name("sim2real-behav-scope-body-only-")
    started = time.monotonic()
    sns.publish(
        TopicArn=topic_arn,
        Message=json.dumps({"kind": "unwanted", "marker": ma}),
        MessageAttributes={"kind": {"DataType": "String", "StringValue": "wanted"}},
    )
    sns.publish(
        TopicArn=topic_arn,
        Message=json.dumps({"kind": "wanted", "marker": mb}),
    )

    control_seen = _await_markers(
        ctx, control_url, {ma, mb}, timeout_s=90.0,
        description=("the unfiltered barrier subscription must receive both messages; without "
                     "it neither absence below means anything"),
        forbidden=set(),
    )
    latency = max(max(control_seen.values()) - started, 1.0)
    ceiling = max(60.0, 3.0 * latency + 20.0)

    _await_markers(
        ctx, attr_url, {ma}, timeout_s=ceiling,
        description=("MessageAttributes scope must match the ATTRIBUTE kind=wanted and must NOT "
                     "match the body key of the same name"),
        forbidden={mb},
    )
    _await_markers(
        ctx, body_url, {mb}, timeout_s=ceiling,
        description=("MessageBody scope must match the BODY key kind=wanted and must NOT match "
                     "the message attribute of the same name"),
        forbidden={ma},
    )
    window = max(3.0 * latency, 15.0)
    leaked = _drain_both(ctx, {"attribute arm": attr_url, "body arm": body_url},
                         window_s=window)
    assert leaked == {"attribute arm": [], "body arm": []}, (
        f"the two scopes must select DISJOINT halves: a {window:.0f}s window (>=3x the measured "
        f"barrier latency of {latency:.1f}s), begun after each arm had received its own "
        f"message, produced {leaked!r} — a late arrival here is a cross-scope match, not "
        "slowness"
    )
    for label, url in (("attribute", attr_url), ("body", body_url)):
        approx = int(sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]["ApproximateNumberOfMessages"])
        assert approx == 0, (
            "second independent observable for the absence: expected "
            f"ApproximateNumberOfMessages == 0 on the {label} arm, got {approx}"
        )

    # ---- phase 2: a nested key with a numeric operator, still under MessageBody scope -------
    nested = {"order": {"total": [{"numeric": [">", 100]}]}}
    sns.set_subscription_attributes(
        SubscriptionArn=body_sub, AttributeName="FilterPolicy",
        AttributeValue=json.dumps(nested))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=body_sub)["Attributes"].get("FilterPolicy"),
        lambda raw: bool(raw) and json.loads(raw) == nested,
        timeout_s=60.0,
        interval_s=2.0,
        description="GetSubscriptionAttributes reflects the nested MessageBody FilterPolicy",
    )
    scope_after = sns.get_subscription_attributes(
        SubscriptionArn=body_sub)["Attributes"].get("FilterPolicyScope")
    assert scope_after == "MessageBody", (
        "replacing the FilterPolicy must not silently reset FilterPolicyScope; expected "
        f"'MessageBody', got {scope_after!r}"
    )

    above = ctx.unique_name("sim2real-behav-scope-nested-151-")
    at_boundary = ctx.unique_name("sim2real-behav-scope-nested-100-")
    phase2_started = time.monotonic()
    # Boundary-first, so in-order delivery would surface the withheld message first.
    sns.publish(TopicArn=topic_arn,
                Message=json.dumps({"order": {"total": 100}, "marker": at_boundary}))
    sns.publish(TopicArn=topic_arn,
                Message=json.dumps({"order": {"total": 150}, "marker": above}))

    control_seen_2 = _await_markers(
        ctx, control_url, {above, at_boundary}, timeout_s=90.0,
        description=("the barrier subscription must receive both nested-body messages before "
                     "the body arm's absence is read"),
        forbidden=set(),
    )
    latency_2 = max(max(control_seen_2.values()) - phase2_started, 1.0)
    _await_markers(
        ctx, body_url, {above}, timeout_s=max(45.0, 3.0 * latency_2 + 15.0),
        description=("a nested MessageBody policy must match order.total=150 against "
                     "{\"numeric\": [\">\", 100]}"),
        forbidden={at_boundary},
    )
    window_2 = max(3.0 * latency_2, 15.0)
    leaked_2 = _drain(ctx, body_url, window_s=window_2)
    assert leaked_2 == [], (
        f"order.total=100 must NOT satisfy a nested {{\"numeric\": [\">\", 100]}} policy: a "
        f"{window_2:.0f}s window (>=3x the measured barrier latency of {latency_2:.1f}s), begun "
        f"after total=150 had arrived, produced {leaked_2!r}"
    )


# ===== helpers =====


def _await_markers(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                   description: str, forbidden: set[str]) -> dict[str, float]:
    """Long-poll until every wanted `marker` has arrived, reading it out of the raw JSON body.

    Returns {marker: monotonic arrival time} so the caller can calibrate an absence window from
    real measured latency. RAISES on the deadline, and RAISES immediately on a forbidden marker
    — a cross-scope match is a failure, not something to wait through. A body that is not JSON,
    or that carries no `marker`, also raises: this check publishes only JSON bodies it built
    itself, so anything else is a real defect rather than noise to filter out.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + timeout_s
    while outstanding:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            marker = json.loads(msg["Body"])["marker"]
            if marker in forbidden:
                raise AssertionError(
                    f"{description}: {marker!r} must not have been delivered here"
                )
            if marker in outstanding:
                outstanding.discard(marker)
                seen[marker] = time.monotonic()
        if outstanding and time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s"
            )
    return seen


def _drain_both(ctx, queues: dict[str, str], *, window_s: float) -> dict[str, list[str]]:
    """Alternate long polls across several queues for one shared window and return every marker
    each produced. The empty lists are correct defaults: they feed an equality-to-empty
    assertion."""
    sqs = ctx.client("sqs")
    out: dict[str, list[str]] = {label: [] for label in queues}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for label, url in queues.items():
            resp = sqs.receive_message(
                QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
                out[label].append(json.loads(msg["Body"])["marker"])
    return out


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    arn = sns.create_topic(
        Name=name, Attributes=dict(attributes or {}), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    url = sqs.create_queue(
        QueueName=name,
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
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"subscription {sub_arn} leaves PendingConfirmation",
    )
    return sub_arn


def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}"
            )
        time.sleep(interval_s)
        value = fn()
    return value


def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll for the whole window and return EVERY body seen, so the caller can assert
    on leakage rather than discard it. The empty default is correct here: it feeds an
    equality-to-empty assertion."""
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
