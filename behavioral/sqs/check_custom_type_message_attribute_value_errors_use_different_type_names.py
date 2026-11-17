"""custom-type-message-attribute-value-errors-use-different-type-names."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-type-message-attribute-value-errors-use-different-type-names"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_REFUSED = [
    (
        "missing-value-string-custom",
        {"DataType": "String.custom"},
        "Message (user) attribute 'N' must contain a non-empty value of type 'String.custom'.",
    ),
    (
        "missing-value-binary-custom",
        {"DataType": "Binary.custom"},
        "Message (user) attribute 'N' must contain a non-empty value of type 'Binary.custom'.",
    ),
    (
        "wrong-field-binary-custom",
        {"DataType": "Binary.custom", "StringValue": "abc"},
        "Message (user) attribute 'N' with type 'Binary' must use field 'Binary'.",
    ),
    (
        "wrong-field-string-custom",
        {"DataType": "String.custom", "BinaryValue": b"abc"},
        "Message (user) attribute 'N' with type 'String' must use field 'String'.",
    ),
]


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: a malformed custom-typed attribute that is accepted must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SendMessage refuses a custom-typed attribute with a missing or misplaced value: the
    missing-value message names the full custom DataType, the wrong-field message names only
    its base type; a well-formed custom-typed attribute is accepted and round-trips unchanged.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-attrcustom-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for label, attr, want_message in _REFUSED:
        err = _error(
            lambda attr=attr: sqs.send_message(
                QueueUrl=url, MessageBody=f"refused-{label}", MessageAttributes={"N": attr}
            )
        )
        assert err.get("Code") == "InvalidParameterValue", f"{label}: code {err.get('Code')!r}"
        assert err.get("Message") == want_message, (
            f"{label}: expected message {want_message!r}, got {err.get('Message')!r}"
        )

    accepted = {"DataType": "String.custom", "StringValue": "ok-value"}
    sqs.send_message(QueueUrl=url, MessageBody="accepted", MessageAttributes={"N": accepted})

    got: dict[str, dict] = {}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and "accepted" not in got:
        for msg in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        ).get("Messages", []):
            got[msg["Body"]] = msg.get("MessageAttributes", {}).get("N", {})
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    assert set(got) == {"accepted"}, (
        f"the queue must hold exactly the accepted message, none of the refused ones; "
        f"received {sorted(got)!r}"
    )
    back = {k: v for k, v in got["accepted"].items() if k in ("DataType", "StringValue")}
    assert back == accepted, f"accepted attribute came back as {back!r}, expected {accepted!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
