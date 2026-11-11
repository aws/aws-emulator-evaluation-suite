"""message-system-attribute-other-than-aws-trace-header-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-system-attribute-other-than-aws-trace-header-rejected"
GROUP = 'message-attributes'
SERVICES = ['sqs']

_SCENARIO = "sqs-system-attribute-name"

_TRACE = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """AWSTraceHeader is the only system attribute a producer may set: 'traceparent' is refused in
    SendMessage and fails alone (SenderFault) in SendMessageBatch, nothing refused is enqueued,
    and accepted messages arrive carrying their AWSTraceHeader."""
    sqs = ctx.client("sqs")
    url = _create_queue(ctx)
    trace = {"AWSTraceHeader": {"DataType": "String", "StringValue": _TRACE}}
    bogus = {"traceparent": {"DataType": "String",
                             "StringValue": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}}
    expected = "Message system attribute name 'traceparent' is invalid."

    code, message = _error(lambda: sqs.send_message(
        QueueUrl=url, MessageBody="sim2real-refused-single", MessageSystemAttributes=bogus))
    assert (code, message) == ("InvalidParameterValue", expected), (
        f"SendMessage with system attribute 'traceparent': got {code!r} {message!r}")

    sqs.send_message(QueueUrl=url, MessageBody="sim2real-accepted-single",
                     MessageSystemAttributes=trace)
    batch = sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": "good", "MessageBody": "sim2real-accepted-batch", "MessageSystemAttributes": trace},
        {"Id": "bad", "MessageBody": "sim2real-refused-batch", "MessageSystemAttributes": bogus},
    ])
    assert [e["Id"] for e in batch.get("Successful", [])] == ["good"], (
        f"only the AWSTraceHeader entry may succeed, got {batch.get('Successful')!r}")
    failed = [(e["Id"], e["Code"], e["Message"], e["SenderFault"]) for e in batch.get("Failed", [])]
    assert failed == [("bad", "InvalidParameterValue", expected, True)], (
        f"the 'traceparent' entry must fail alone with the same refusal, got {failed!r}")

    accepted = {"sim2real-accepted-single", "sim2real-accepted-batch"}
    seen = _receive_all(ctx, url, accepted, MessageSystemAttributeNames=["AWSTraceHeader"])
    seen.update(_receive_window(ctx, url, 5.0))
    for body in accepted:
        got = seen[body].get("Attributes", {}).get("AWSTraceHeader")
        assert got == _TRACE, f"{body!r} arrived with AWSTraceHeader {got!r}"
    assert set(seen) == accepted, (
        f"refused messages were enqueued: {sorted(set(seen) - accepted)!r}")


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
