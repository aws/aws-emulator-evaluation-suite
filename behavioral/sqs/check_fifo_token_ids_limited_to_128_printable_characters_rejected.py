"""fifo-token-ids-limited-to-128-printable-characters-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-token-ids-limited-to-128-printable-characters-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "fifo-token-ids-limited-to-128-printable-characters-rejected"}
_PUNCT = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _msg(param: str, value: str) -> str:
    return (f"Value {value} for parameter {param} is invalid. Reason: {param} can only include "
            "alphanumeric and punctuation characters. 1 to 128 in length.")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """FIFO group, dedup and receive-attempt ids over 128 chars or with spaces are refused.

    Refused sends enqueue nothing; 128-char and all-punctuation ids are accepted and kept verbatim.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-fifo-ids-") + ".fifo",
        Attributes={"FifoQueue": "true"}, tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for bad in ("g" * 129, "g g"):
        err = _error(lambda bad=bad: sqs.send_message(
            QueueUrl=url, MessageBody="refused", MessageGroupId=bad, MessageDeduplicationId="d0"))
        assert (err.get("Code"), err.get("Message")) == (
            "InvalidParameterValue", _msg("MessageGroupId", bad)), (
            f"MessageGroupId of {len(bad)} chars {bad[:8]!r} answered {err!r}"
        )
    for bad in ("d" * 129, "d d", ""):
        err = _error(lambda bad=bad: sqs.send_message(
            QueueUrl=url, MessageBody="refused", MessageGroupId="g", MessageDeduplicationId=bad))
        assert (err.get("Code"), err.get("Message")) == (
            "InvalidParameterValue", _msg("MessageDeduplicationId", bad)), (
            f"MessageDeduplicationId of {len(bad)} chars {bad[:8]!r} answered {err!r}"
        )
    for bad in ("r" * 129, "r r"):
        err = _error(lambda bad=bad: sqs.receive_message(
            QueueUrl=url, ReceiveRequestAttemptId=bad, WaitTimeSeconds=1))
        assert (err.get("Code"), err.get("Message")) == (
            "InvalidParameterValue", _msg("ReceiveRequestAttemptId", bad)), (
            f"ReceiveRequestAttemptId of {len(bad)} chars {bad[:8]!r} answered {err!r}"
        )

    empty = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert empty.get("Messages", []) == [], (
        f"refused sends enqueued {[m['Body'] for m in empty['Messages']]!r}"
    )

    accepted = [("g" * 128, "d" * 128), (_PUNCT, _PUNCT)]
    for gid, did in accepted:
        sqs.send_message(QueueUrl=url, MessageBody=f"ok-{len(gid)}", MessageGroupId=gid,
                         MessageDeduplicationId=did)
    got: dict[str, tuple[str, str]] = {}
    deadline = time.monotonic() + 30
    attempt = "a" * 128
    while len(got) < 2 and time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
            ReceiveRequestAttemptId=attempt,
            MessageSystemAttributeNames=["MessageGroupId", "MessageDeduplicationId"],
        ).get("Messages", []):
            got[m["Body"]] = (m["Attributes"]["MessageGroupId"],
                              m["Attributes"]["MessageDeduplicationId"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        attempt = attempt[:-1] + ("b" if attempt[-1] == "a" else "a")
    want = {f"ok-{len(g)}": (g, d) for g, d in accepted}
    assert got == want, (
        f"boundary ids came back as {got!r}; expected the 128-character and all-punctuation "
        f"values verbatim"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
