"""message-size-counts-attribute-name-type-and-value."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-size-counts-attribute-name-type-and-value"
GROUP = "limits"
SERVICES = ["sqs"]

_LIMIT = 1024
_OVERSIZE_MESSAGE = (
    "One or more parameters are invalid. Reason: Message must be shorter than 1024 bytes."
)
_TRACE_HEADER = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1"


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: a target that accepts an oversize message must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _drain_bodies(sqs, url, *, want: int, timeout_s: float) -> list[str]:
    """Bodies receivable within the bounded window (deleted as read), stopping once ``want`` are
    in hand and a further receive comes back empty."""
    got: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])
        if not msgs and len(got) >= want:
            break
        for m in msgs:
            got.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MaximumMessageSize counts the body plus each attribute's name, DataType (custom label in full)
    and value, but not AWSTraceHeader: exactly 1024 counted bytes is accepted, one more is
    refused, and only accepted messages are enqueued."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-msgsize-"),
        Attributes={"MaximumMessageSize": str(_LIMIT)},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    limit = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["MaximumMessageSize"])[
        "Attributes"
    ]["MaximumMessageSize"]
    assert limit == str(_LIMIT), f"MaximumMessageSize read back as {limit!r}, expected {str(_LIMIT)!r}"

    # 'Pad' + 'String' + 'ppp' = 12 bytes, so a 1012-byte body totals exactly 1024.
    pad = {"Pad": {"DataType": "String", "StringValue": "ppp"}}
    custom = {"Pad": {"DataType": "String.ab", "StringValue": "ppp"}}

    accepted = {
        "body-only-at-limit": ("c" * 1024, None, None),
        "string-attr-at-limit": ("d" * 1012, pad, None),
        "custom-type-at-limit": ("e" * 1009, custom, None),
        "trace-header-not-counted": (
            "f" * 1024, None, {"AWSTraceHeader": {"DataType": "String", "StringValue": _TRACE_HEADER}}
        ),
    }
    for label, (body, attrs, sys_attrs) in accepted.items():
        kwargs = {"QueueUrl": url, "MessageBody": body}
        if attrs:
            kwargs["MessageAttributes"] = attrs
        if sys_attrs:
            kwargs["MessageSystemAttributes"] = sys_attrs
        try:
            sqs.send_message(**kwargs)
        except ClientError as exc:
            raise AssertionError(
                f"{label}: a message totalling exactly {_LIMIT} counted bytes must be accepted, got "
                f"{exc.response['Error'].get('Code')!r}: {exc.response['Error'].get('Message')!r}"
            ) from exc

    refused = {
        "string-attr-one-over": ("g" * 1013, pad),
        "custom-type-one-over": ("h" * 1010, custom),
    }
    for label, (body, attrs) in refused.items():
        err = _error(
            lambda body=body, attrs=attrs: sqs.send_message(
                QueueUrl=url, MessageBody=body, MessageAttributes=attrs
            )
        )
        assert err.get("Code") == "InvalidParameterValue", (
            f"{label}: a message one byte over {_LIMIT} once its attribute is counted gave code "
            f"{err.get('Code')!r}, expected 'InvalidParameterValue'"
        )
        assert err.get("Message") == _OVERSIZE_MESSAGE, (
            f"{label}: expected message {_OVERSIZE_MESSAGE!r}, got {err.get('Message')!r}"
        )

    bodies = _drain_bodies(sqs, url, want=len(accepted), timeout_s=30)
    got = sorted((b[0], len(b)) for b in bodies)
    want = sorted((body[0], len(body)) for body, _, _ in accepted.values())
    assert got == want, (
        f"the queue must hold exactly the four accepted messages and none of the refused ones; "
        f"received (first char, length) {got!r}, expected {want!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
