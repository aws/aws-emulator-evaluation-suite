"""more-than-ten-message-attributes-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "more-than-ten-message-attributes-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_TOO_MANY_MESSAGE = "Number of message attributes [11] exceeds the allowed maximum [10]."


def _attrs(n: int) -> dict:
    return {f"attr{i:02d}": {"DataType": "String", "StringValue": f"value-{i}"} for i in range(n)}


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: an 11-attribute message that is accepted must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message may carry at most 10 attributes: 10 round-trip intact, 11 are refused by
    SendMessage, and in SendMessageBatch the 11-attribute entry fails alone; the sibling lands."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-attrcap-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    ten = _attrs(10)
    sqs.send_message(QueueUrl=url, MessageBody="ten-attributes", MessageAttributes=ten)

    err = _error(
        lambda: sqs.send_message(QueueUrl=url, MessageBody="eleven-single", MessageAttributes=_attrs(11))
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"SendMessage with 11 message attributes gave code {err.get('Code')!r}"
    )
    assert err.get("Message") == _TOO_MANY_MESSAGE, (
        f"expected message {_TOO_MANY_MESSAGE!r}, got {err.get('Message')!r}"
    )

    batch = sqs.send_message_batch(
        QueueUrl=url,
        Entries=[
            {"Id": "ok", "MessageBody": "batch-sibling"},
            {"Id": "bad", "MessageBody": "eleven-batch", "MessageAttributes": _attrs(11)},
        ],
    )
    ok_ids = [e["Id"] for e in batch.get("Successful", [])]
    failed = {e["Id"]: e for e in batch.get("Failed", [])}
    assert ok_ids == ["ok"] and sorted(failed) == ["bad"], (
        f"expected entry 'ok' to succeed and 'bad' to fail; Successful ids {ok_ids!r}, "
        f"Failed {batch.get('Failed')!r}"
    )
    bad = failed["bad"]
    assert (bad.get("Code"), bad.get("SenderFault"), bad.get("Message")) == (
        "InvalidParameterValue", True, _TOO_MANY_MESSAGE
    ), f"the 11-attribute batch entry failed with {bad!r}"

    got: dict[str, dict] = {}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        ).get("Messages", [])
        if not msgs and len(got) >= 2:
            break
        for m in msgs:
            got[m["Body"]] = m.get("MessageAttributes", {})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(got) == ["batch-sibling", "ten-attributes"], (
        f"the queue must hold exactly the 10-attribute message and the batch sibling, none of the "
        f"refused ones; received {sorted(got)!r}"
    )
    values = {k: v.get("StringValue") for k, v in got["ten-attributes"].items()}
    assert values == {k: v["StringValue"] for k, v in ten.items()}, (
        f"the 10 attributes did not round-trip: received {values!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
