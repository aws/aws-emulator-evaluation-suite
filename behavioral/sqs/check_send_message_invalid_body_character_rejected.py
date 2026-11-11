"""send-message-invalid-body-character-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-message-invalid-body-character-rejected"
GROUP = "message-body"
SERVICES = ["sqs"]

_ALLOWED_SET = (
    "#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]"
)
_REFUSED = {"\x00": "#x0", "\x01": "#x1", "\x1f": "#x1F", "\ufffe": "#xFFFE", "\uffff": "#xFFFF"}
_ACCEPTED = [
    "tab\tnewline\ncarriage\r",
    "edges \x20\ud7ff\ue000\ufffd",
    "astral \U00010000\U0010ffff\U0001f600",
]


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: a body real SQS refuses that is accepted must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage refuses a body with a character outside the XML 1.0 set with
    InvalidMessageContents naming it and enqueues nothing; edge characters of the allowed
    ranges (tab, CR, U+D7FF, U+E000, U+FFFD, U+10000, U+10FFFF) round-trip byte-exact."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-bodychar-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for body in _ACCEPTED:
        try:
            sqs.send_message(QueueUrl=url, MessageBody=body)
        except ClientError as exc:
            raise AssertionError(f"body {body!r} must be accepted, got {exc.response['Error']!r}") from exc

    for ch, shown in _REFUSED.items():
        err = _error(lambda ch=ch: sqs.send_message(QueueUrl=url, MessageBody=f"bad{ch}body"))
        want = (
            f"Invalid binary character '{shown}' was found in the message body, the set of "
            f"allowed characters is {_ALLOWED_SET}."
        )
        assert err.get("Code") == "InvalidMessageContents", (
            f"a body containing {ch!r} gave code {err.get('Code')!r}"
        )
        assert err.get("Message") == want, (
            f"a body containing {ch!r}: expected message {want!r}, got {err.get('Message')!r}"
        )

    bodies: list[str] = []
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )
        if not msgs and len(bodies) >= len(_ACCEPTED):
            break
        for m in msgs:
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(bodies) == sorted(_ACCEPTED), (
        f"the queue must hold exactly the accepted bodies, byte-exact, and no refused one; "
        f"received {sorted(bodies)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
