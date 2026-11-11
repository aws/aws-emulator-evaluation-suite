"""message-attribute-name-rules-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-attribute-name-rules-rejected"
GROUP = "message-attributes"
SERVICES = ["sqs"]

_RESERVED = (
    "You can't use message attribute names beginning with 'AWS.' or 'Amazon'. These strings are "
    "reserved for internal use."
)
_REFUSED = {
    "AWS.Trace": _RESERVED,
    "aws.trace": _RESERVED,
    "Amazon.Route": _RESERVED,
    ".leading": "Message (user) attribute name must not begin with character '.'.",
    "trailing.": "Message (user) attribute name must not end with character '.'.",
    "two..dots": "Message (user) attribute name must not have successive '.' characters.",
    "has space": (
        "Message (user) attribute name contains invalid non-alphanumeric character '#x20'. You can "
        "use only alphanumeric characters, hyphens (-), underscores (_), or periods (.)."
    ),
    "n" * 257: "Message (user) attribute name must be shorter than 256 bytes.",
}
_ACCEPTED = ["Corp.Trace-Id_v2", "AWSRegionHint", "amazonroute", "n" * 256]


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: an illegal attribute name that is accepted must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage refuses attribute names with a reserved 'AWS.'/'Amazon.' prefix (any case), a
    leading, trailing or doubled '.', a space, or over 256 bytes, with exact messages and nothing
    enqueued; look-alikes (no dot, hyphens, exactly 256 bytes) round-trip under their exact names."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-attrname-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for i, name in enumerate(_ACCEPTED):
        try:
            sqs.send_message(
                QueueUrl=url, MessageBody=f"accepted-{i}",
                MessageAttributes={name: {"DataType": "String", "StringValue": "v"}},
            )
        except ClientError as exc:
            raise AssertionError(
                f"attribute name of length {len(name)} starting {name[:16]!r} must be accepted, got "
                f"{exc.response['Error']!r}"
            ) from exc

    for name, want in _REFUSED.items():
        err = _error(
            lambda name=name: sqs.send_message(
                QueueUrl=url, MessageBody="refused",
                MessageAttributes={name: {"DataType": "String", "StringValue": "v"}},
            )
        )
        assert err.get("Code") == "InvalidParameterValue", (
            f"attribute name {name[:24]!r} (length {len(name)}) gave code {err.get('Code')!r}"
        )
        assert err.get("Message") == want, (
            f"attribute name {name[:24]!r}: expected message {want!r}, got {err.get('Message')!r}"
        )

    got: dict[str, list[str]] = {}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
        ).get("Messages", [])
        if not msgs and len(got) >= len(_ACCEPTED):
            break
        for m in msgs:
            got[m["Body"]] = sorted(m.get("MessageAttributes", {}))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    want_got = {f"accepted-{i}": [name] for i, name in enumerate(_ACCEPTED)}
    assert got == want_got, (
        f"the queue must hold exactly the {len(_ACCEPTED)} accepted messages under their exact "
        f"attribute names and no refused one; received bodies {sorted(got)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
