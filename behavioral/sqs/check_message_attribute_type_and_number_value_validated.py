"""message-attribute-type-and-number-value-validated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-attribute-type-and-number-value-validated"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_NOT_A_NUMBER = "Can't cast the value of message (user) attribute 'N' to a number."
_BAD_TYPE = (
    "The type of message (user) attribute 'N' is invalid. You must use only the following "
    "supported type prefixes: Binary, Number, String."
)
_TOO_PRECISE = "4" * 39
_REFUSED = [
    ("non-numeric", {"DataType": "Number", "StringValue": "abc"}, _NOT_A_NUMBER),
    ("leading-space", {"DataType": "Number", "StringValue": " 1"}, _NOT_A_NUMBER),
    (
        "too-precise",
        {"DataType": "Number", "StringValue": _TOO_PRECISE},
        f"Message (user) attribute 'N' number value [{_TOO_PRECISE}] must contain fewer than 38 "
        f"precision digits.",
    ),
    ("unknown-type", {"DataType": "Strin", "StringValue": "1"}, _BAD_TYPE),
    ("empty-custom-label", {"DataType": "Number.", "StringValue": "1"}, _BAD_TYPE),
]
_ACCEPTED = {
    "negative-decimal": {"DataType": "Number", "StringValue": "-12.5"},
    "exponent": {"DataType": "Number", "StringValue": "1e3"},
    "custom-number": {"DataType": "Number.float", "StringValue": "0.000001"},
    "custom-binary": {"DataType": "Binary.png", "BinaryValue": b"\x89PNG"},
}

# A Number in exponent form is stored in plain notation; every other accepted value comes back
# exactly as sent.
_READ_BACK = {"exponent": {"StringValue": "1000"}}


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: an invalid attribute that is accepted must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage refuses a non-numeric, space-padded or over-38-digit Number, an unknown type
    prefix and an empty custom label, each with its exact message; valid values and custom labels
    are stored and returned as sent, except '1e3' which reads back as '1000'."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-attrtype-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for body, attr in _ACCEPTED.items():
        try:
            sqs.send_message(QueueUrl=url, MessageBody=body, MessageAttributes={"N": attr})
        except ClientError as exc:
            raise AssertionError(f"{body}: attribute {attr!r} must be accepted, got {exc.response['Error']!r}") from exc

    for label, attr, want in _REFUSED:
        err = _error(
            lambda attr=attr: sqs.send_message(QueueUrl=url, MessageBody="refused", MessageAttributes={"N": attr})
        )
        assert err.get("Code") == "InvalidParameterValue", f"{label}: code {err.get('Code')!r}"
        assert err.get("Message") == want, (
            f"{label}: expected message {want!r}, got {err.get('Message')!r}"
        )

    got: dict[str, dict] = {}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        ).get("Messages", [])
        if not msgs and len(got) >= len(_ACCEPTED):
            break
        for m in msgs:
            got[m["Body"]] = m.get("MessageAttributes", {}).get("N", {})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(got) == sorted(_ACCEPTED), (
        f"the queue must hold exactly the accepted messages, none refused; received {sorted(got)!r}"
    )
    for body, sent in _ACCEPTED.items():
        want = dict(sent, **_READ_BACK.get(body, {}))
        back = {k: v for k, v in got[body].items() if k in ("DataType", "StringValue", "BinaryValue")}
        assert back == want, f"{body}: attribute came back as {back!r}, expected {want!r} (sent {sent!r})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
