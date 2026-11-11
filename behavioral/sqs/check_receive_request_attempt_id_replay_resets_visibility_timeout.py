"""receive-request-attempt-id-replay-resets-visibility-timeout."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "receive-request-attempt-id-replay-resets-visibility-timeout"
GROUP = 'fifo'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "rraid-replay-resets-vt"}

_VT_S = 20
# The replay happens this long after the first receive, well inside the visibility window.
_REPLAY_AT_S = 12
# The replayed message is asserted still hidden this long after its ORIGINAL deadline.
_PAST_ORIGINAL_S = 5


def _receive_one(sqs, url, **kw):
    return sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, **kw).get("Messages", [])


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Retrying ReceiveMessage with the same ReceiveRequestAttemptId returns the same message and
    restarts its visibility timeout: it stays hidden past its first deadline, while an unretried
    twin on an identical queue reappears first."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    attrs = {"FifoQueue": "true", "VisibilityTimeout": str(_VT_S)}
    replayed_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-replay.fifo", Attributes=attrs,
        tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=replayed_url))
    twin_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-twin.fifo", Attributes=attrs,
        tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=twin_url))

    sqs.send_message(QueueUrl=replayed_url, MessageBody=f"replayed-{token}", MessageGroupId="g",
                     MessageDeduplicationId=token)
    sqs.send_message(QueueUrl=twin_url, MessageBody=f"twin-{token}", MessageGroupId="g",
                     MessageDeduplicationId=token)

    attempt = f"attempt-{token}"
    first = []
    deadline = time.monotonic() + 30
    while not first and time.monotonic() < deadline:
        first = _receive_one(sqs, replayed_url, WaitTimeSeconds=2, ReceiveRequestAttemptId=attempt)
    received_at = time.monotonic()
    twin = _receive_one(sqs, twin_url, WaitTimeSeconds=5)
    assert first and first[0]["Body"] == f"replayed-{token}", f"first receive gave {first!r}"
    assert twin and twin[0]["Body"] == f"twin-{token}", f"twin receive gave {twin!r}"

    while time.monotonic() < received_at + _REPLAY_AT_S:
        time.sleep(0.5)
    replay = _receive_one(sqs, replayed_url, ReceiveRequestAttemptId=attempt)
    assert [m["MessageId"] for m in replay] == [first[0]["MessageId"]], (
        f"a retry with the same ReceiveRequestAttemptId inside the visibility window must return "
        f"the same message: got {[m['MessageId'] for m in replay]!r}")

    # --- the twin reappears on its original schedule ---------------------------------
    twin_back = []
    deadline = received_at + _VT_S + 30
    while not twin_back and time.monotonic() < deadline:
        twin_back = _receive_one(sqs, twin_url, WaitTimeSeconds=2,
                                 ReceiveRequestAttemptId=uuid.uuid4().hex)
    twin_back_at = time.monotonic()
    assert twin_back, f"the never-retried twin did not reappear after its {_VT_S}s timeout"

    # --- the replayed one is still hidden past that original deadline --------------------
    hidden_until = received_at + _VT_S + _PAST_ORIGINAL_S
    assert twin_back_at < hidden_until, (
        f"the twin took {twin_back_at - received_at:.0f}s to reappear, past the instant the "
        f"replayed message is checked, so the comparison below would not be tested")
    while time.monotonic() < hidden_until:
        early = _receive_one(sqs, replayed_url, WaitTimeSeconds=1,
                             ReceiveRequestAttemptId=uuid.uuid4().hex)
        assert early == [], (
            f"the replayed message came back {time.monotonic() - received_at:.0f}s after its "
            f"first receive, on the original {_VT_S}s schedule; a same-attempt retry at "
            f"{_REPLAY_AT_S}s must restart the visibility timeout")

    # --- and it reappears once the restarted timeout lapses ---------------------------
    back = []
    deadline = received_at + _REPLAY_AT_S + _VT_S + 30
    while not back and time.monotonic() < deadline:
        back = _receive_one(sqs, replayed_url, WaitTimeSeconds=2,
                            ReceiveRequestAttemptId=uuid.uuid4().hex)
    assert [m["MessageId"] for m in back] == [first[0]["MessageId"]], (
        f"the replayed message never reappeared after its restarted timeout: {back!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
