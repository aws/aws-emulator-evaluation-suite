"""send-message-malformed-awstraceheader-accepted-then-dropped."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-message-malformed-awstraceheader-accepted-then-dropped"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_VALID_TRACE = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1"

_SILENTLY_DROPPED = {
    "garbage": {"DataType": "String", "StringValue": "not-a-trace-header"},
    "wrong-datatype-number": {"DataType": "Number", "StringValue": "1"},
    "wrong-datatype-binary": {"DataType": "Binary", "BinaryValue": b"abc"},
}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage refuses an empty AWSTraceHeader with its exact message; a message whose header is
    not DataType String or does not parse as a trace header is delivered without the header, and a
    well-formed header round-trips unchanged.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-traceheader-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, message = _error(lambda: sqs.send_message(
        QueueUrl=url, MessageBody="sim2real-empty",
        MessageSystemAttributes={"AWSTraceHeader": {"DataType": "String", "StringValue": ""}}))
    assert code == "InvalidParameterValue", f"empty AWSTraceHeader: expected InvalidParameterValue, got {code!r}"
    assert message == (
        "Message system attribute 'AWSTraceHeader' must contain a non-empty value of type 'String'."
    ), f"empty AWSTraceHeader: unexpected message {message!r}"

    bodies_sent = {"sim2real-valid"}
    sqs.send_message(QueueUrl=url, MessageBody="sim2real-valid",
                     MessageSystemAttributes={"AWSTraceHeader": {
                         "DataType": "String", "StringValue": _VALID_TRACE}})
    for label, sysattr in _SILENTLY_DROPPED.items():
        body = f"sim2real-{label}"
        bodies_sent.add(body)
        sqs.send_message(QueueUrl=url, MessageBody=body, MessageSystemAttributes={
            "AWSTraceHeader": sysattr})

    seen = _receive_all(sqs, url, bodies_sent, timeout_s=_budget_s(ctx, 60.0))
    assert set(seen) == bodies_sent, (
        f"the queue must deliver exactly the sent bodies; got {sorted(seen)!r}"
    )

    got_valid = seen["sim2real-valid"].get("Attributes", {}).get("AWSTraceHeader")
    assert got_valid == _VALID_TRACE, (
        f"the well-formed header must round-trip unchanged, got {got_valid!r}"
    )
    for label in _SILENTLY_DROPPED:
        got = seen[f"sim2real-{label}"].get("Attributes", {})
        assert "AWSTraceHeader" not in got, (
            f"{label}: the message must be delivered without the AWSTraceHeader, got {got!r}"
        )


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _receive_all(sqs, url: str, wanted: set[str], timeout_s: float) -> dict:
    """Receive (and delete) until every body in ``wanted`` has been seen; body -> message."""
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        for msg in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
            MessageSystemAttributeNames=["AWSTraceHeader"],
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            seen[msg["Body"]] = msg
    missing = sorted(wanted - set(seen))
    if missing:
        raise TimeoutError(
            f"within {timeout_s:.0f}s the queue never delivered {missing!r}; it delivered "
            f"{sorted(seen)!r}"
        )
    return seen


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
