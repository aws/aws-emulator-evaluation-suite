"""retention-expiry-discards-an-in-flight-message."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "retention-expiry-discards-an-in-flight-message"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "retention-in-flight"}

_RETENTION_S = 60
# Longer than the retention period: the message is still in flight when it expires.
_VT_S = 90
_COUNTER_S = 120.0


def _receive(sqs, url, wait_s=2, **kw):
    return sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
                               **kw).get("Messages", [])


def _counters(sqs, url):
    a = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[
        "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]
    return (a["ApproximateNumberOfMessages"], a["ApproximateNumberOfMessagesNotVisible"])


# timing:real-time — retention: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Retention runs from the send: a message received under a visibility timeout longer than
    MessageRetentionPeriod expires while in flight and never returns, while a twin on a
    default-retention queue reappears once its timeout lapses."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    short_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-short",
        Attributes={"MessageRetentionPeriod": str(_RETENTION_S), "VisibilityTimeout": str(_VT_S)},
        tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=short_url))
    twin_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-twin",
        Attributes={"VisibilityTimeout": str(_VT_S)}, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=twin_url))

    got = sqs.get_queue_attributes(QueueUrl=short_url, AttributeNames=["MessageRetentionPeriod"])[
        "Attributes"]["MessageRetentionPeriod"]
    assert got == str(_RETENTION_S), f"short queue retention read back {got!r}"

    short_body, twin_body = f"short-{token}", f"twin-{token}"
    sqs.send_message(QueueUrl=short_url, MessageBody=short_body)
    sqs.send_message(QueueUrl=twin_url, MessageBody=twin_body)
    held = {}
    deadline = time.monotonic() + 30
    while len(held) < 2 and time.monotonic() < deadline:
        for url in (short_url, twin_url):
            if url not in held:
                ms = _receive(sqs, url)
                if ms:
                    held[url] = ms[0]
    assert {u: m["Body"] for u, m in held.items()} == {short_url: short_body,
                                                         twin_url: twin_body}, (
        f"expected to take both messages in flight, got {[m['Body'] for m in held.values()]!r}")
    received_at = time.monotonic()

    # --- after the visibility timeout: the twin is back, the expired one is not -----------
    twin_back = []
    deadline = received_at + _VT_S + 60
    while not twin_back and time.monotonic() < deadline:
        twin_back = _receive(sqs, twin_url, wait_s=5)
    assert [m["Body"] for m in twin_back] == [twin_body], (
        f"the default-retention twin did not reappear after its {_VT_S}s timeout: "
        f"{[m['Body'] for m in twin_back]!r}")
    sqs.delete_message(QueueUrl=twin_url, ReceiptHandle=twin_back[0]["ReceiptHandle"])

    # The same window again for the short-retention queue, now past both deadlines.
    late: list[str] = []
    settle = time.monotonic() + 20
    while time.monotonic() < settle:
        late += [m["Body"] for m in _receive(sqs, short_url, wait_s=5)]
    assert late == [], (
        f"a message older than MessageRetentionPeriod={_RETENTION_S}s came back after its "
        f"{_VT_S}s visibility timeout; it expired while in flight: {late!r}")

    counters = _counters(sqs, short_url)
    deadline = time.monotonic() + _COUNTER_S
    while counters != ("0", "0") and time.monotonic() < deadline:
        time.sleep(5)
        counters = _counters(sqs, short_url)
    assert counters == ("0", "0"), (
        f"the expired queue's (visible, in-flight) counters must converge to 0: {counters!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
