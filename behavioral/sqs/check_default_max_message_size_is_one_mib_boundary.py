"""default-max-message-size-is-one-mib-boundary."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-max-message-size-is-one-mib-boundary"
GROUP = "limits"
SERVICES = ["sqs"]

_ONE_MIB = 1048576
_OVERSIZE_MESSAGE = (
    "One or more parameters are invalid. Reason: Message must be shorter than 1048576 bytes."
)


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: a target that accepts a body real SQS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _drain(sqs, url, *, timeout_s: float) -> list[dict]:
    """Every message receivable within the bounded window, each deleted once read."""
    got: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])
        if not msgs and got:
            break
        for m in msgs:
            got.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue created with no attributes reports MaximumMessageSize 1 MiB, accepts a 1 MiB body that
    comes back byte-exact, and refuses 1 MiB + 1, which is then absent from the queue.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-1mib-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    default = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["MaximumMessageSize"])[
        "Attributes"
    ]["MaximumMessageSize"]
    assert default == str(_ONE_MIB), (
        f"a queue created with no attributes reports MaximumMessageSize={default!r}, expected "
        f"{str(_ONE_MIB)!r} (the 1 MiB default)"
    )

    at_limit = "a" * _ONE_MIB
    sent = sqs.send_message(QueueUrl=url, MessageBody=at_limit)
    want_md5 = hashlib.md5(at_limit.encode("utf-8")).hexdigest()
    assert sent["MD5OfMessageBody"] == want_md5, (
        f"MD5OfMessageBody for the 1 MiB body was {sent['MD5OfMessageBody']!r}, computed {want_md5!r}"
    )

    err = _error(lambda: sqs.send_message(QueueUrl=url, MessageBody="b" * (_ONE_MIB + 1)))
    assert err.get("Code") == "InvalidParameterValue", (
        f"a {_ONE_MIB + 1}-byte body gave code {err.get('Code')!r}, expected 'InvalidParameterValue'"
    )
    assert err.get("Message") == _OVERSIZE_MESSAGE, (
        f"expected message {_OVERSIZE_MESSAGE!r}, got {err.get('Message')!r}"
    )

    got = _drain(sqs, url, timeout_s=30)
    lengths = sorted(len(m["Body"]) for m in got)
    assert lengths == [_ONE_MIB], (
        f"expected exactly the one {_ONE_MIB}-byte message on the queue, received bodies of "
        f"lengths {lengths!r}"
    )
    body = got[0]["Body"]
    assert body == at_limit, (
        f"the 1 MiB body did not round-trip byte-exact: first differing prefix "
        f"{body[:16]!r}..., length {len(body)}"
    )
    assert got[0]["MD5OfBody"] == want_md5, (
        f"MD5OfBody on receive was {got[0]['MD5OfBody']!r}, computed {want_md5!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
