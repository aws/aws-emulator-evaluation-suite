"""sns-subscription-dlq-captures-the-notification-the-endpoint-policy-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sns-subscription-dlq-captures-the-notification-the-endpoint-policy-denied"
GROUP = "event-propagation"
SERVICES = ["sns", "sqs"]

_SCENARIO = "sns-subscription-dlq"

_DENY_SID = "sim2realDenySnsSend"


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With the endpoint queue's policy denying SNS, a subscription RedrivePolicy captures the
    undelivered notification: it is absent at the endpoint and present in the dead-letter queue,
    and once the policy is restored a new message reaches the endpoint and not the DLQ."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = _create_topic(ctx)
    endpoint_url, endpoint_arn = _create_queue_for_topic(ctx, topic_arn)
    dlq_url, dlq_arn = _create_queue_for_topic(ctx, topic_arn)

    sub_arn = _subscribe_and_confirm(ctx, topic_arn, endpoint_arn,
                                     attributes={"RawMessageDelivery": "true"})
    redrive = {"deadLetterTargetArn": dlq_arn}
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn, AttributeName="RedrivePolicy",
        AttributeValue=json.dumps(redrive))
    stored = _poll_until(
        ctx,
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("RedrivePolicy"),
        lambda raw: bool(raw) and json.loads(raw) == redrive,
        timeout_s=60.0,
        interval_s=2.0,
        description="GetSubscriptionAttributes reflects the subscription RedrivePolicy",
    )
    assert json.loads(stored)["deadLetterTargetArn"] == dlq_arn, (
        f"expected the stored RedrivePolicy to target {dlq_arn!r}, got {stored!r}"
    )

    # ---- beat 1: control. The whole path works, L is measured, and the DLQ stays empty -----
    healthy = ctx.unique_name("sim2real-behav-snsdlq-healthy-")
    started = time.monotonic()
    sns.publish(TopicArn=topic_arn, Message=healthy)
    seen = _await_bodies(
        ctx, endpoint_url, {healthy}, timeout_s=90.0,
        description=("control: SNS must deliver to the endpoint queue while its policy only "
                     "Allows, or the dead-lettering below would be indistinguishable from "
                     "broken wiring"),
    )
    latency = max(seen[healthy] - started, 1.0)
    quiet = max(3.0 * latency, 5.0)
    dlq_during_control = _drain(ctx, dlq_url, window_s=quiet)
    assert dlq_during_control == [], (
        f"a SUCCESSFUL delivery must not also be copied to the dead-letter queue; the DLQ "
        f"received {dlq_during_control!r} during a {quiet:.0f}s window (>=3x the measured "
        f"delivery latency of {latency:.1f}s) after the healthy message had already arrived"
    )

    # ---- beat 2: break exactly one thing — deny SNS on the ENDPOINT queue only -------------
    _add_deny(ctx, endpoint_url, endpoint_arn)

    # ---- beat 3: the producer's call still succeeds ----------------------------------------
    dead = ctx.unique_name("sim2real-behav-snsdlq-dead-")
    resp = sns.publish(TopicArn=topic_arn, Message=dead)
    assert resp.get("MessageId"), (
        "Publish must still succeed and mint a MessageId even though the destination now "
        f"denies delivery — SNS does not evaluate the endpoint's policy synchronously; got "
        f"{resp!r}"
    )

    # ---- beat 4: the NEW leg — the undeliverable notification is recorded at the DLQ -------
    dlq_body = _await_containing(
        ctx, dlq_url, dead, timeout_s=180.0,
        description=("the subscription RedrivePolicy must capture the notification SNS could "
                     "not deliver: this is the only signal that separates 'correctly denied' "
                     "from 'never sent'"),
    )
    # `dead in dlq_body` holds by construction — _await_containing returns only a body that
    # contains it, and RAISES otherwise — so it is deliberately not re-asserted. What can
    # fail here is the DLQ carrying the WRONG message.
    assert healthy not in dlq_body, (
        f"the DLQ must carry the UNDELIVERED message, not a replay of the healthy one; the "
        f"body contained {healthy!r}: {dlq_body!r}"
    )

    # ---- beat 5: effect absent at the original destination ---------------------------------
    leaked = _drain(ctx, endpoint_url, window_s=quiet)
    assert leaked == [], (
        f"the denied message must not reach the endpoint queue: it received {leaked!r} during "
        f"a {quiet:.0f}s window (>=3x the measured latency of {latency:.1f}s) that began after "
        "the same message had already been observed in the dead-letter queue"
    )
    approx = int(sqs.get_queue_attributes(
        QueueUrl=endpoint_url, AttributeNames=["ApproximateNumberOfMessages"],
    )["Attributes"]["ApproximateNumberOfMessages"])
    assert approx == 0, (
        "second independent observable for the absence: expected ApproximateNumberOfMessages "
        f"== 0 on the endpoint queue, got {approx}"
    )

    # ---- beat 6: restore, and delivery goes to the endpoint and NOT to the DLQ -------------
    _remove_deny(ctx, endpoint_url, endpoint_arn)
    restored = ctx.unique_name("sim2real-behav-snsdlq-restored-")
    _republish_until_delivered(
        ctx, topic_arn, endpoint_url, restored,
        attempts=2, per_attempt_s=max(30.0, 3.0 * latency),
        description=("restore: with the Deny removed, the endpoint queue must receive again — "
                     "this proves the DLQ capture was caused by the policy and not by a "
                     "permanently broken subscription"),
    )
    dlq_after_restore = _drain(ctx, dlq_url, window_s=quiet)
    assert dlq_after_restore == [], (
        f"once delivery works again nothing further may be dead-lettered; the DLQ received "
        f"{dlq_after_restore!r} in a {quiet:.0f}s window after the restored message arrived at "
        "the endpoint"
    )


# ===== helpers =====


def _set_queue_policy(ctx, queue_url: str, policy: dict, *, expect_sid: str | None,
                      present: bool) -> None:
    """Replace a queue policy and poll an independent read until it reflects the change."""
    sqs = ctx.client("sqs")
    sqs.set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    if expect_sid is None:
        return
    _poll_until(
        ctx,
        lambda: sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["Policy"])["Attributes"].get("Policy", ""),
        lambda stored: (expect_sid in stored) is present,
        timeout_s=45.0,
        interval_s=3.0,
        description=(
            f"the queue policy reports {expect_sid} "
            f"{'present' if present else 'absent'}"
        ),
    )


def _add_deny(ctx, queue_url: str, queue_arn: str) -> None:
    """Add an explicit Deny alongside the still-present Allow. Exactly one thing changes.

    This Deny stops SNS delivery; this check asserts where the stopped message then goes.
    """
    sqs = ctx.client("sqs")
    current = json.loads(sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["Policy"])["Attributes"]["Policy"])
    current["Statement"] = list(current["Statement"]) + [{
        "Sid": _DENY_SID,
        "Effect": "Deny",
        "Principal": {"Service": "sns.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue_arn,
    }]
    _set_queue_policy(ctx, queue_url, current, expect_sid=_DENY_SID, present=True)


def _remove_deny(ctx, queue_url: str, queue_arn: str) -> None:
    """Drop the Deny statement and nothing else, then wait for the read to agree."""
    sqs = ctx.client("sqs")
    current = json.loads(sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["Policy"])["Attributes"]["Policy"])
    current["Statement"] = [
        s for s in current["Statement"] if s.get("Sid") != _DENY_SID
    ]
    assert current["Statement"], (
        "removing the Deny must leave the original Allow in place, not an empty policy; the "
        f"queue policy for {queue_arn} would have no statements left"
    )
    _set_queue_policy(ctx, queue_url, current, expect_sid=_DENY_SID, present=False)


def _await_containing(ctx, queue_url: str, needle: str, *, timeout_s: float,
                      description: str) -> str:
    """Long-poll until a body containing `needle` arrives; RAISE on the deadline.

    Returns the whole body so the caller can assert on it and so a failure prints the real
    shape — the exact envelope SNS writes to a subscription DLQ is one of this file's
    hypotheses.
    """
    sqs = ctx.client("sqs")
    others: list[str] = []
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            if needle in body:
                return body
            others.append(body[:120])
        if time.monotonic() >= deadline:
            raise _timed_out(
                ctx,
                f"{description}: no dead-letter queue body containing {needle!r} arrived "
                f"within {timeout_s}s; bodies seen: {others!r}"
            )


def _republish_until_delivered(ctx, topic_arn: str, queue_url: str, marker: str, *,
                               attempts: int, per_attempt_s: float,
                               description: str) -> None:
    """Publish the same marker up to `attempts` times, draining between attempts, and RAISE if
    it never lands. A queue-policy change is eventually consistent on SNS's delivery path, so
    the bounded republish is the retry that makes the restored-path assertion correct rather
    than racy; the marker is constant, so the assertion stays exact."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    seen: list[str] = []
    for _ in range(attempts):
        sns.publish(TopicArn=topic_arn, Message=marker)
        deadline = time.monotonic() + _budget_s(ctx, per_attempt_s)
        while time.monotonic() < deadline:
            resp = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                seen.append(msg["Body"])
            if marker in seen:
                return
    raise _timed_out(
        ctx,
        f"{description}: {marker!r} was never delivered across {attempts} republishes of "
        f"{per_attempt_s:.0f}s each; bodies seen: {seen!r}"
    )


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
        ctx,
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"subscription {sub_arn} leaves PendingConfirmation",
    )
    return sub_arn


def _budget_s(ctx, cap_s: float) -> float:
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _timed_out(ctx, message: str) -> Exception:
    """TimeoutError (not graded) when the run budget ended the wait, else AssertionError."""
    if _budget_spent(ctx):
        return TimeoutError(f"run budget spent before the wait ended: {message}")
    return AssertionError(message)


def _poll_until(ctx, fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; RAISES on the deadline so a timeout can never read as a pass."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise _timed_out(
                ctx, f"{description}: not satisfied within {timeout_s}s, last value {value!r}"
            )
        time.sleep(interval_s)
        value = fn()
    return value


def _await_bodies(ctx, queue_url: str, wanted: set[str], *, timeout_s: float,
                  description: str, forbidden: set[str] | None = None) -> dict[str, float]:
    """Long-poll until every wanted body is seen; RAISES on the deadline.

    Returns {body: monotonic time it was first seen} so a caller can measure the real
    latency of this wiring and calibrate an absence window from it. A body in `forbidden`
    that arrives raises immediately: it is a leak, and swallowing it would hide the very
    thing the caller is about to assert.
    """
    sqs = ctx.client("sqs")
    seen: dict[str, float] = {}
    outstanding = set(wanted)
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while outstanding:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        # The empty default only ever means "poll again"; the deadline below RAISES, so an
        # absence can never pass.
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg["Body"]
            if forbidden and body in forbidden:
                raise AssertionError(
                    f"{description}: a body that must never be delivered arrived: {body!r}"
                )
            if body in outstanding:
                outstanding.discard(body)
                seen[body] = time.monotonic()
        if outstanding and time.monotonic() >= deadline:
            raise _timed_out(
                ctx, f"{description}: {sorted(outstanding)} never arrived within {timeout_s}s"
            )
    return seen


def _drain(ctx, queue_url: str, *, window_s: float) -> list[str]:
    """Long-poll for the whole window and return EVERY body seen, so the caller can assert
    on leakage rather than discard it. The empty default is correct here: it feeds an
    equality-to-empty assertion. A window the run budget cannot hold is not graded."""
    left = ctx.time_left()
    if left is not None and window_s > left - 5.0:
        raise TimeoutError(
            f"run budget spent: a {window_s:.0f}s absence window does not fit the {left:.0f}s left")
    sqs = ctx.client("sqs")
    bodies: list[str] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait_s = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            bodies.append(msg["Body"])
    return bodies


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
