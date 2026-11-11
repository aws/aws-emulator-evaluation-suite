"""content-based-deduplication-toggled-on-live-fifo-queue."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "content-based-deduplication-toggled-on-live-fifo-queue"
GROUP = 'fifo'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "cbd-toggle"}

_NO_DEDUP_ID_MESSAGE = (
    "The queue should either have ContentBasedDeduplication enabled or MessageDeduplicationId "
    "provided explicitly"
)
# Bound on how long a ContentBasedDeduplication change may take to govern SendMessage.
_CONVERGE_S = 90.0


def _send_error(fn):
    """(code, message) of the refusal ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the send to be refused, but it succeeded: {result!r}")


def _drain(sqs, url):
    """Receive-and-delete every message until three consecutive empty long polls."""
    bodies: list[str] = []
    empties = 0
    deadline = time.monotonic() + 60
    while empties < 3 and time.monotonic() < deadline:
        batch = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
        ).get("Messages", [])
        if not batch:
            empties += 1
            continue
        empties = 0
        for m in batch:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return bodies


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Toggling ContentBasedDeduplication on a live FIFO queue: on, id-less sends are legal and
    dedupe by body while explicit ids override the hash; off again, id-less sends are refused.
    """
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, msg = _send_error(lambda: sqs.send_message(
        QueueUrl=url, MessageBody=f"refused-while-off-{token}", MessageGroupId="g"))
    assert (code, msg) == ("InvalidParameterValue", _NO_DEDUP_ID_MESSAGE), (
        f"id-less send with ContentBasedDeduplication off gave {(code, msg)!r}")

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"ContentBasedDeduplication": "true"})
    stored = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ContentBasedDeduplication"])[
        "Attributes"].get("ContentBasedDeduplication")
    assert stored == "true", f"ContentBasedDeduplication did not read back 'true': {stored!r}"

    repeated = f"repeated-body-{token}"
    first_id = None
    deadline = time.monotonic() + _CONVERGE_S
    while first_id is None and time.monotonic() < deadline:
        try:
            first_id = sqs.send_message(
                QueueUrl=url, MessageBody=repeated, MessageGroupId="g")["MessageId"]
        except ClientError as exc:
            assert exc.response["Error"]["Code"] == "InvalidParameterValue", (
                f"id-less send while the switch propagates raised {exc.response['Error']!r}")
            time.sleep(2)
    assert first_id is not None, (
        f"an id-less send was still refused {_CONVERGE_S:.0f}s after enabling "
        f"ContentBasedDeduplication")

    again = [sqs.send_message(QueueUrl=url, MessageBody=repeated, MessageGroupId="g")["MessageId"]
             for _ in range(2)]
    assert again == [first_id, first_id], (
        f"re-sending the identical body under content-based dedup must return the original "
        f"MessageId: first {first_id!r}, then {again!r}")

    # An explicit id overrides the content hash: same body, two ids, two messages.
    explicit = f"explicit-ids-body-{token}"
    ids = [sqs.send_message(QueueUrl=url, MessageBody=explicit, MessageGroupId="g",
                            MessageDeduplicationId=f"{token}-{i}")["MessageId"] for i in range(2)]
    assert ids[0] != ids[1], (
        f"two sends of one body under two explicit MessageDeduplicationIds were collapsed to "
        f"MessageId {ids[0]!r}; an explicit id overrides the content hash")

    drained = _drain(sqs, url)
    assert drained == [repeated, explicit, explicit], (
        f"queue must hold the repeated body once, then the explicit-id body twice, in send "
        f"order: {drained!r}")

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"ContentBasedDeduplication": "false"})
    late: list[str] = []
    refused = None
    deadline = time.monotonic() + _CONVERGE_S
    while refused is None and time.monotonic() < deadline:
        body = f"after-disable-{len(late)}-{token}"
        try:
            sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId="g")
            late.append(body)
            time.sleep(2)
        except ClientError as exc:
            refused = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    assert refused == ("InvalidParameterValue", _NO_DEDUP_ID_MESSAGE), (
        f"id-less send after disabling ContentBasedDeduplication was not refused with the "
        f"documented error within {_CONVERGE_S:.0f}s: {refused!r}")
    tail = _drain(sqs, url)
    assert tail == late, (
        f"only the sends accepted while the switch propagated may be on the queue: "
        f"{tail!r} vs {late!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
