"""queue-visibility-timeout-change-spares-in-flight-messages."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "queue-visibility-timeout-change-spares-in-flight-messages"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "queue-vt-change-in-flight"}

_ORIGINAL_VT_S = 35
_NEW_VT_S = 2
# Margin kept between the end of the "still hidden" window and the original deadline.
_MARGIN_S = 10.0
# Longest probe round: a 2 s receive and a long poll of _NEW_VT_S + 4 s.
_PROBE_ROUND_S = 2 + _NEW_VT_S + 4
# Bound on how long the lowered queue VisibilityTimeout may take to govern new receives. The probe
# phase, including the round that crosses it, ends inside the old message's hidden window.
_CONVERGE_S = float(_ORIGINAL_VT_S - _MARGIN_S - _PROBE_ROUND_S - 2)


def _receive(sqs, url, wait_s):
    return sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
    ).get("Messages", [])


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lowering VisibilityTimeout governs only later receives: a message already in flight stays
    hidden until its original deadline, while one received after the change reappears on the new
    short timeout."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"VisibilityTimeout": str(_ORIGINAL_VT_S)},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    old_body = f"in-flight-before-change-{token}"
    sqs.send_message(QueueUrl=url, MessageBody=old_body)
    got = []
    deadline = time.monotonic() + 30
    while not got and time.monotonic() < deadline:
        got = _receive(sqs, url, wait_s=2)
    assert [m["Body"] for m in got] == [old_body], (
        f"expected to receive {old_body!r} first, got {[m['Body'] for m in got]!r}")
    old_received_at = time.monotonic()

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": str(_NEW_VT_S)})

    # --- a message received after the change reappears on the new timeout -------------
    hidden_until = old_received_at + _ORIGINAL_VT_S - _MARGIN_S
    seen_early: list[str] = []
    probes: list[str] = []
    reappeared: list[str] = []
    deadline = time.monotonic() + _CONVERGE_S
    while not reappeared and time.monotonic() < deadline:
        probe = f"received-after-change-{len(probes)}-{token}"
        probes.append(probe)
        sqs.send_message(QueueUrl=url, MessageBody=probe)
        first = _receive(sqs, url, wait_s=2)
        seen_early += [m["Body"] for m in first]
        # A long poll returns as soon as a probe's visibility lapses.
        again = _receive(sqs, url, wait_s=_NEW_VT_S + 4)
        seen_early += [m["Body"] for m in again]
        reappeared = [m["Body"] for m in again if m["Body"] in probes]
    assert time.monotonic() < hidden_until, (
        "the probe phase ran past the old message's original deadline, so the in-flight half "
        "below would not be tested")
    assert reappeared, (
        f"no message received after VisibilityTimeout={_NEW_VT_S} reappeared within "
        f"{_CONVERGE_S:.0f}s ({len(probes)} probes), so the queue change never took effect")
    assert old_body not in seen_early, (
        f"the message already in flight under VisibilityTimeout={_ORIGINAL_VT_S} reappeared "
        f"after the queue was lowered to {_NEW_VT_S}; an in-flight message keeps the timeout it "
        f"was received under")

    # Stay inside the original window: the old message must still be hidden there.
    while time.monotonic() < hidden_until:
        for m in _receive(sqs, url, wait_s=min(5, max(1, int(hidden_until - time.monotonic())))):
            assert m["Body"] != old_body, (
                f"{old_body!r} reappeared {time.monotonic() - old_received_at:.0f}s after its "
                f"receive, before its original {_ORIGINAL_VT_S}s timeout")
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])

    # --- and it does come back once the ORIGINAL timeout lapses -----------------------
    back = False
    deadline = old_received_at + _ORIGINAL_VT_S + 60
    while not back and time.monotonic() < deadline:
        for m in _receive(sqs, url, wait_s=5):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            back = back or m["Body"] == old_body
    assert back, (
        f"{old_body!r} never reappeared after its original {_ORIGINAL_VT_S}s timeout; it was "
        f"never deleted, so it must become receivable again")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
