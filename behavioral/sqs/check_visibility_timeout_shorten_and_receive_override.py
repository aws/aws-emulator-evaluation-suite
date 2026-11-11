"""visibility-timeout-shorten-and-receive-override."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "visibility-timeout-shorten-and-receive-override"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']

# Queue default kept at 1s so the control leg costs a second. The 30s override is never waited
# out: it only has to outlast the 5s hidden-window probe to prove it beat the default.
QUEUE_DEFAULT_VT = 1
RECEIVE_OVERRIDE_VT = 30
SHORTENED_VT = 2


def _await_visible(sqs, url, *, timeout_s):
    """Poll without long-poll until a message is visible.

    Returns (elapsed_seconds, message_or_None)."""
    start = time.monotonic()
    deadline = start + timeout_s
    while True:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0
        ).get("Messages", [])
        if msgs:
            return time.monotonic() - start, msgs[0]
        if time.monotonic() >= deadline:
            return time.monotonic() - start, None
        time.sleep(0.25)


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


# timing:real-time — visibility: 2 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A per-request ReceiveMessage VisibilityTimeout overrides the queue default, and
    ChangeMessageVisibility can shorten an in-flight message's timeout to a non-zero value,
    after which it reappears on the new schedule rather than instantly."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": str(QUEUE_DEFAULT_VT)},
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])
    assert attrs["Attributes"]["VisibilityTimeout"] == str(QUEUE_DEFAULT_VT), (
        f"queue default did not stick: {attrs['Attributes'].get('VisibilityTimeout')!r}"
    )

    token = uuid.uuid4().hex[:8]
    body = f"vt-override-{token}"
    sqs.send_message(QueueUrl=url, MessageBody=body)

    # The very first receive carries the override, so the hidden-window probe below is
    # measuring the override and nothing else.
    taken = _poll(
        lambda: sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=1,
            VisibilityTimeout=RECEIVE_OVERRIDE_VT,
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=20,
        interval_s=0,
    )
    assert taken, f"could not receive {body} with a per-request VisibilityTimeout"
    handle = taken[0]["ReceiptHandle"]
    assert taken[0]["Body"] == body, f"received {taken[0]['Body']!r}, expected {body!r}"

    # --- the override beat the 1s queue default: still hidden well past 1s -------------
    hidden_probe_s = 5
    elapsed, leaked = _await_visible(sqs, url, timeout_s=hidden_probe_s)
    assert leaked is None, (
        f"message became visible after {elapsed:.1f}s despite a per-request "
        f"VisibilityTimeout={RECEIVE_OVERRIDE_VT}s -- the queue default of "
        f"{QUEUE_DEFAULT_VT}s was applied instead of the request override"
    )

    # In-flight is observable in the approximate counters (direction only, never an exact read).
    notvis = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessagesNotVisible"]
        )["Attributes"].get("ApproximateNumberOfMessagesNotVisible", "0"),
        lambda v: v != "0",
        timeout_s=20,
    )
    assert int(notvis) >= 1, (
        f"ApproximateNumberOfMessagesNotVisible stayed at {notvis!r} while a message was in "
        "flight under a 30s timeout"
    )

    # --- shorten to a NON-ZERO timeout: it reappears, but not instantly ----------------
    sqs.change_message_visibility(
        QueueUrl=url, ReceiptHandle=handle, VisibilityTimeout=SHORTENED_VT
    )
    elapsed, again = _await_visible(sqs, url, timeout_s=25)
    assert again is not None, (
        f"ChangeMessageVisibility({SHORTENED_VT}) did not shorten the remaining "
        f"{RECEIVE_OVERRIDE_VT}s timeout: the message was still hidden {elapsed:.1f}s later"
    )
    assert again["Body"] == body, f"reappeared with body {again['Body']!r}"
    assert elapsed >= 1.0, (
        f"message reappeared after only {elapsed:.2f}s -- ChangeMessageVisibility"
        f"({SHORTENED_VT}) was treated as 0 rather than as a {SHORTENED_VT}s timeout"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=again["ReceiptHandle"])

    # --- control: with no per-request override, the 1s queue default applies -----------
    ctl_body = f"vt-default-{token}"
    sqs.send_message(QueueUrl=url, MessageBody=ctl_body)
    ctl = _poll(
        lambda: sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=20,
        interval_s=0,
    )
    assert ctl and ctl[0]["Body"] == ctl_body, f"control message not received: {ctl}"
    ctl_elapsed, ctl_again = _await_visible(sqs, url, timeout_s=15)
    assert ctl_again is not None, (
        f"a message received with NO override stayed hidden for {ctl_elapsed:.1f}s; with a "
        f"{QUEUE_DEFAULT_VT}s queue default it should have returned promptly -- the override "
        "from the earlier receive appears to have been persisted onto the queue"
    )
    assert ctl_again["Body"] == ctl_body, f"control reappeared as {ctl_again['Body']!r}"
    sqs.delete_message(QueueUrl=url, ReceiptHandle=ctl_again["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
