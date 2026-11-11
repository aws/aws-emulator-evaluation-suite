"""message-attribute-value-in-the-wrong-field-for-its-data-type-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-attribute-value-in-the-wrong-field-for-its-data-type-rejected"
GROUP = 'message-attributes'
SERVICES = ['sqs']

_SCENARIO = "sqs-attribute-value-field"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """SendMessage refuses an attribute whose value is in the wrong field for its DataType, or has
    no value, with the exact message; in SendMessageBatch such entries fail alone (SenderFault) and
    only well-formed messages are delivered, attributes intact."""
    sqs = ctx.client("sqs")
    url = _create_queue(ctx)

    cases = [
        ("blob", {"DataType": "Binary", "StringValue": "aGk="},
         "Message (user) attribute 'blob' with type 'Binary' must use field 'Binary'."),
        ("label", {"DataType": "String", "BinaryValue": b"hi"},
         "Message (user) attribute 'label' with type 'String' must use field 'String'."),
        ("count", {"DataType": "Number", "BinaryValue": b"1"},
         "Message (user) attribute 'count' with type 'Number' must use field 'String'."),
        ("label", {"DataType": "String"},
         "Message (user) attribute 'label' must contain a non-empty value of type 'String'."),
    ]
    for i, (name, value, expected) in enumerate(cases):
        code, message = _error(lambda n=name, v=value, b=f"sim2real-refused-{i}": sqs.send_message(
            QueueUrl=url, MessageBody=b, MessageAttributes={n: v}))
        assert (code, message) == ("InvalidParameterValue", expected), (
            f"attribute {name!r} with fields {sorted(value)!r}: got {code!r} {message!r}")

    mixed = sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": "good", "MessageBody": "sim2real-accepted",
         "MessageAttributes": {"blob": {"DataType": "Binary", "BinaryValue": b"\x00\xff"}}},
        {"Id": "bad", "MessageBody": "sim2real-refused-mixed",
         "MessageAttributes": {"blob": {"DataType": "Binary", "StringValue": "aGk="}}},
    ])
    assert [e["Id"] for e in mixed.get("Successful", [])] == ["good"], (
        f"only the well-formed entry may succeed, got {mixed.get('Successful')!r}")
    failed = [(e["Id"], e["Code"], e["Message"], e["SenderFault"]) for e in mixed.get("Failed", [])]
    assert failed == [("bad", "InvalidParameterValue", cases[0][2], True)], (
        f"the malformed entry must fail alone, got {failed!r}")

    all_bad = sqs.send_message_batch(QueueUrl=url, Entries=[
        {"Id": f"bad{i}", "MessageBody": f"sim2real-refused-all-{i}", "MessageAttributes": {n: v}}
        for i, (n, v, _) in enumerate(cases[:2])])
    assert "Successful" not in all_bad or all_bad["Successful"] == [], (
        f"a batch of only malformed entries must report no success, got {all_bad.get('Successful')!r}")
    failed = sorted((e["Id"], e["Code"], e["Message"]) for e in all_bad.get("Failed", []))
    assert failed == [("bad0", "InvalidParameterValue", cases[0][2]),
                      ("bad1", "InvalidParameterValue", cases[1][2])], (
        f"every malformed entry must be listed as Failed, got {failed!r}")

    seen = _receive_all(ctx, url, {"sim2real-accepted"}, MessageAttributeNames=["All"])
    seen.update(_receive_window(ctx, url, 5.0))
    blob = seen["sim2real-accepted"].get("MessageAttributes", {}).get("blob", {})
    assert (blob.get("DataType"), blob.get("BinaryValue")) == ("Binary", b"\x00\xff"), (
        f"the accepted entry's Binary attribute arrived as {blob!r}")
    assert set(seen) == {"sim2real-accepted"}, (
        f"refused messages were enqueued: {sorted(set(seen) - {'sim2real-accepted'})!r}")


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
