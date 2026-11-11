"""delayed-messages-are-counted-separately-from-visible-and-in-flight."""

from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delayed-messages-are-counted-separately-from-visible-and-in-flight"
GROUP = "state"
SERVICES = ["sqs"]

# 300s so the documented >=1 minute counter-consistency window closes long before the delay
# does. The check never waits this delay out.
_LONG_DELAY_S = 300
# Short enough to wait out inside the budget, long enough to be many multiples of the measured
# undelayed-delivery latency L.
_SHORT_DELAY_S = 15
_COUNTER_S = 120.0
_PURGE_S = 90.0
_ABSENCE_MULTIPLIER = 3  # hold absence for >=3x the latency measured on the same queue

_COUNTERS = (
    "ApproximateNumberOfMessages",
    "ApproximateNumberOfMessagesNotVisible",
    "ApproximateNumberOfMessagesDelayed",
)

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "delayed-message-accounting",
}


def _counters(sqs, url) -> dict:
    """All three approximate counters in ONE GetQueueAttributes, so they describe one instant."""
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=list(_COUNTERS))["Attributes"]
    missing = [name for name in _COUNTERS if name not in attrs]
    assert not missing, (
        f"GetQueueAttributes did not return {missing}; SQS documents all three as supported "
        f"attribute names, and a target that omits Delayed cannot be graded on delay accounting. "
        f"Got keys {sorted(attrs)}"
    )
    return {name: attrs[name] for name in _COUNTERS}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _await_counters(sqs, url, want: dict, *, timeout_s, why):
    """Bounded poll until every named counter equals its wanted value; RAISES on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _counters(sqs, url)
        if all(last[name] == value for name, value in want.items()):
            return last
    raise AssertionError(
        f"the queue counters never reached {want} within {timeout_s}s (last={last}); {why}"
    )


def _receive(sqs, url, *, wait_s=1):
    return sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s).get(
        "Messages", []
    )


def _await_body(sqs, url, body, *, timeout_s, what):
    """Bounded poll until `body` is delivered; return the measured latency, raise on timeout."""
    start = time.monotonic()
    deadline = start + timeout_s
    while time.monotonic() < deadline:
        for msg in _receive(sqs, url):
            if msg["Body"] == body:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
                return time.monotonic() - start
            raise AssertionError(
                f"{what}: an unexpected message {msg['Body']!r} was delivered while waiting for "
                f"{body!r}; this queue should carry nothing else"
            )
    raise AssertionError(f"{what}: {body!r} was not delivered within {timeout_s}s")


# timing:real-time — visibility: 15 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-timers.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A message under per-message DelaySeconds is withheld (>=3x an undelayed control's latency)
    and counted as Delayed (polled to >=1, then Visible 0, NotVisible 0, Delayed 1); a short delay
    is delivered once it expires, and PurgeQueue empties all three counters.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html
    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-timers.html
    """
    sqs = ctx.client("sqs")
    # DelaySeconds is left at the queue default of 0, so every delay observed below comes from the
    # per-message parameter and cannot be a queue-level effect.
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    queue_delay = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["DelaySeconds"])[
        "Attributes"
    ]["DelaySeconds"]
    assert queue_delay == "0", (
        f"the queue's own DelaySeconds is {queue_delay!r}, not '0'; every assertion below would be "
        f"unable to attribute a delay to the per-message parameter"
    )

    token = uuid.uuid4().hex[:8]
    control_body = f"undelayed-control-{token}"
    short_body = f"short-delay-{token}"
    long_body = f"long-delay-{token}"

    # --- positive control: an undelayed message, and its measured latency L --------
    sqs.send_message(QueueUrl=url, MessageBody=control_body)
    latency_s = _await_body(
        sqs, url, control_body, timeout_s=40.0, what="the undelayed positive control"
    )
    absence_window_s = max(_ABSENCE_MULTIPLIER * latency_s, 3.0)
    assert absence_window_s < _SHORT_DELAY_S, (
        f"the undelayed control took {latency_s:.2f}s, so a {_ABSENCE_MULTIPLIER}x absence window "
        f"is {absence_window_s:.1f}s -- that is not shorter than the {_SHORT_DELAY_S}s delay under "
        f"test, so the withheld-message leg cannot distinguish 'delayed' from 'slow'"
    )

    # --- the subjects: one short delay (waited out), one long delay (counted) ----------
    send_start = time.monotonic()
    sqs.send_message(QueueUrl=url, MessageBody=short_body, DelaySeconds=_SHORT_DELAY_S)
    sqs.send_message(QueueUrl=url, MessageBody=long_body, DelaySeconds=_LONG_DELAY_S)

    # Withheld: for >=3L nothing is delivered, even though an identical undelayed send on this very
    # queue was delivered in L seconds moments ago.
    absence_deadline = time.monotonic() + absence_window_s
    while time.monotonic() < absence_deadline:
        leaked = _receive(sqs, url)
        assert not leaked, (
            f"a delayed message was delivered {time.monotonic() - send_start:.2f}s after the send, "
            f"inside its DelaySeconds window: {[m['Body'] for m in leaked]!r}. The undelayed "
            f"control on this same queue took {latency_s:.2f}s, so this is not slowness"
        )

    # Second independent observable for the same absence: they are DELAYED, not merely invisible.
    # The counter may lag the sends (SQS GetQueueAttributes docs), so it is polled; the long
    # message stays delayed for _LONG_DELAY_S, far past this poll's budget.
    delayed_wait_s = 60.0
    delayed_budget_s = _budget_s(ctx, delayed_wait_s)
    delayed_start = time.monotonic()
    delayed_stop = delayed_start + min(delayed_wait_s, delayed_budget_s)
    delayed_now = _counters(sqs, url)["ApproximateNumberOfMessagesDelayed"]
    while int(delayed_now) < 1 and time.monotonic() < delayed_stop:
        time.sleep(1)
        delayed_now = _counters(sqs, url)["ApproximateNumberOfMessagesDelayed"]
    if int(delayed_now) < 1 and delayed_budget_s < delayed_wait_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - delayed_start:.1f}s, before "
            f"the {delayed_wait_s}s ApproximateNumberOfMessagesDelayed wait ended; not graded"
        )
    assert int(delayed_now) >= 1, (
        f"two messages are inside their DelaySeconds windows but "
        f"ApproximateNumberOfMessagesDelayed is {delayed_now!r}; a target that hides delayed "
        f"messages without accounting for them reports 0 here"
    )

    # --- delivery is DEMANDED once the short delay expires ----------------------------
    remaining_s = _SHORT_DELAY_S - (time.monotonic() - send_start)
    grace_s = max(remaining_s, 0.0) + absence_window_s + 20.0
    short_latency_s = _await_body(
        sqs,
        url,
        short_body,
        timeout_s=grace_s,
        what=(
            f"a message sent with DelaySeconds={_SHORT_DELAY_S} must become receivable once the "
            f"delay expires"
        ),
    )
    total_s = time.monotonic() - send_start
    assert total_s >= _SHORT_DELAY_S, (
        f"the short-delay message was delivered {total_s:.2f}s after its send, before its "
        f"DelaySeconds={_SHORT_DELAY_S} window closed (the receive itself took "
        f"{short_latency_s:.2f}s)"
    )

    # --- the three-way accounting, on one instant's read ------------------------------
    settled = _await_counters(
        sqs,
        url,
        {
            "ApproximateNumberOfMessages": "0",
            "ApproximateNumberOfMessagesNotVisible": "0",
            "ApproximateNumberOfMessagesDelayed": "1",
        },
        timeout_s=_COUNTER_S,
        why=(
            f"exactly one message ({long_body!r}, DelaySeconds={_LONG_DELAY_S}) remains and it is "
            f"delayed, so it must be counted as Delayed and in neither of the other two buckets. "
            f"The documented counter-consistency window is >=1 minute"
        ),
    )
    assert settled["ApproximateNumberOfMessagesDelayed"] == "1", (
        f"expected exactly one delayed message, got {settled!r}"
    )

    # --- terminal read at the destination: the delayed message is still unreachable ---
    still_hidden = _receive(sqs, url, wait_s=2)
    assert still_hidden == [], (
        f"the message under DelaySeconds={_LONG_DELAY_S} was delivered "
        f"{time.monotonic() - send_start:.1f}s after its send: {[m['Body'] for m in still_hidden]!r}"
    )

    # --- PurgeQueue must clear the Delayed bucket too ---------------------------------
    sqs.purge_queue(QueueUrl=url)
    _await_counters(
        sqs,
        url,
        {name: "0" for name in _COUNTERS},
        timeout_s=_PURGE_S,
        why=(
            "PurgeQueue deletes all messages, so a delayed message must leave the Delayed bucket "
            "as well -- a purge that only clears the Visible bucket strands the delayed message"
        ),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
