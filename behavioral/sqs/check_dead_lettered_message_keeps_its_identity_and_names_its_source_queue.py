"""dead-lettered-message-keeps-its-identity-and-names-its-source-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dead-lettered-message-keeps-its-identity-and-names-its-source-queue"
GROUP = 'dead-letter'
SERVICES = ['sqs']

_SCENARIO = "sqs-dlq-message-identity"

_TRACE = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dead-lettered message keeps its MessageId, body, MD5s, MessageAttributes and AWSTraceHeader,
    gains DeadLetterQueueSourceArn naming the source, and leaves the source; a RedrivePolicy with
    maxReceiveCount "1" reads back as compact JSON with the number 1.
    """
    sqs = ctx.client("sqs")
    dlq = _create_queue(ctx)
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    src = _create_queue(ctx, {"VisibilityTimeout": "1"})
    src_arn = sqs.get_queue_attributes(QueueUrl=src, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    sqs.set_queue_attributes(QueueUrl=src, Attributes={"RedrivePolicy": json.dumps(
        {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "1"})})
    stored = sqs.get_queue_attributes(QueueUrl=src, AttributeNames=["RedrivePolicy"])["Attributes"]
    expected_policy = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1},
                                 separators=(",", ":"))
    assert stored.get("RedrivePolicy") == expected_policy, (
        f"RedrivePolicy must read back as compact JSON with a numeric count, got "
        f"{stored.get('RedrivePolicy', '')[-40:]!r}")

    attrs = {"tenant": {"DataType": "String", "StringValue": "acme"},
             "attempt": {"DataType": "Number", "StringValue": "7"},
             "blob": {"DataType": "Binary", "BinaryValue": b"\x00\x01\xfe"}}
    sent = sqs.send_message(QueueUrl=src, MessageBody="sim2real-poison", MessageAttributes=attrs,
                            MessageSystemAttributes={"AWSTraceHeader": {
                                "DataType": "String", "StringValue": _TRACE}})

    moved = None
    src_deliveries = 0
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and moved is None:
        src_deliveries += len(sqs.receive_message(QueueUrl=src, WaitTimeSeconds=2).get("Messages", []))
        got = sqs.receive_message(QueueUrl=dlq, WaitTimeSeconds=1, MessageAttributeNames=["All"],
                                  MessageSystemAttributeNames=["All"]).get("Messages", [])
        moved = got[0] if got else None
    assert moved is not None, (
        f"the message never reached the DLQ within 90s ({src_deliveries} source deliveries)")
    assert src_deliveries >= 1, "the message reached the DLQ without ever being delivered"

    assert (moved["MessageId"], moved["Body"], moved["MD5OfBody"]) == (
        sent["MessageId"], "sim2real-poison", sent["MD5OfMessageBody"]), (
        f"the dead-lettered message changed identity: MessageId matches="
        f"{moved['MessageId'] == sent['MessageId']}, body={moved['Body']!r}")
    got_attrs = {k: (v["DataType"], v.get("StringValue") or v.get("BinaryValue"))
                 for k, v in moved.get("MessageAttributes", {}).items()}
    assert got_attrs == {"tenant": ("String", "acme"), "attempt": ("Number", "7"),
                         "blob": ("Binary", b"\x00\x01\xfe")}, (
        f"MessageAttributes changed on the move: {got_attrs!r}")
    assert moved.get("MD5OfMessageAttributes") == sent["MD5OfMessageAttributes"], (
        "MD5OfMessageAttributes differs between send and the DLQ copy")
    system = moved.get("Attributes", {})
    assert system.get("AWSTraceHeader") == _TRACE, (
        f"AWSTraceHeader was not carried to the DLQ: {system.get('AWSTraceHeader')!r}")
    assert system.get("DeadLetterQueueSourceArn") == src_arn, (
        "DeadLetterQueueSourceArn must name the source queue, it was "
        f"{'absent' if 'DeadLetterQueueSourceArn' not in system else 'another ARN'}")

    sqs.delete_message(QueueUrl=dlq, ReceiptHandle=moved["ReceiptHandle"])
    again = sqs.receive_message(QueueUrl=src, WaitTimeSeconds=3, VisibilityTimeout=0).get("Messages", [])
    assert again == [], f"the source still delivers the moved message: {[m['Body'] for m in again]!r}"



def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_queue(ctx, attributes=None) -> str:
    """CreateQueue (tagged + prefix-named) and register DeleteQueue immediately."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sqs-"), Attributes=attributes or {},
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
    return url


def _receive_all(ctx, url: str, wanted: set[str], timeout_s: float = 60.0, **kwargs) -> dict:
    """Receive (and delete) until every body in ``wanted`` has been seen; body -> message for
    EVERY message seen on the way."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                       **kwargs).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[msg["Body"]] = msg
    missing = sorted(wanted - set(seen))
    assert not missing, (
        f"within {timeout_s}s the queue never delivered {missing!r}; it delivered {sorted(seen)!r}")
    return seen


def _receive_window(ctx, url: str, window_s: float) -> dict:
    """Receive (and delete) everything delivered within ``window_s``; body -> message."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                       WaitTimeSeconds=1).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[msg["Body"]] = msg
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
