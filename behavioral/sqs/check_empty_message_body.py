"""empty-message-body."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-message-body"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_MISSING_PARAMETER = "MissingParameter"


class _UnexpectedSuccess(Exception):
    """Raised when a call real AWS rejects is accepted."""


def _error_code(fn, **kwargs) -> tuple[str, str]:
    """The exact AWS error (code, message); raises if the call succeeds."""
    try:
        resp = fn(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if not code:
            raise AssertionError(f"call raised with no AWS error code: {exc.response!r}") from exc
        return code, exc.response.get("Error", {}).get("Message")
    raise _UnexpectedSuccess(f"the empty-body send was ACCEPTED and returned {resp!r}")


def _await_visible(sqs, url: str, want: int, timeout: float = 60) -> str:
    """Poll ApproximateNumberOfMessages until it reads `want`, else fail with the last value."""
    seen = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        seen = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"],
        )["Attributes"]["ApproximateNumberOfMessages"]
        if seen == str(want):
            return seen
        time.sleep(2)
    raise AssertionError(f"queue never reported {want} visible messages; last read {seen!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage with an empty body is rejected and nothing reaches the queue, while a normal send
    on the same queue is accepted and delivered.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # ---- positive control: the queue accepts and delivers a normal send ------------------ #
    control_body = "control-body"
    sent = sqs.send_message(QueueUrl=url, MessageBody=control_body)
    assert sent.get("MessageId"), f"control send returned no MessageId: {sent!r}"
    _await_visible(sqs, url, 1)
    received = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    messages = received.get("Messages", [])
    assert messages, f"control message never became receivable: {received!r}"
    assert messages[0]["Body"] == control_body, (
        f"control message body was {messages[0]['Body']!r}, expected {control_body!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=messages[0]["ReceiptHandle"])
    _await_visible(sqs, url, 0)

    # ---- break exactly one thing: an empty body on the same queue ------------------------- #
    code = _error_code(sqs.send_message, QueueUrl=url, MessageBody="")
    assert code == (ERR_MISSING_PARAMETER, "The request must contain the parameter MessageBody."), (
        f"expected {ERR_MISSING_PARAMETER}, got {code!r}"
    )

    # ---- effect absent: an independent read shows nothing landed -------------------------- #
    _await_visible(sqs, url, 0)
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    assert not resp.get("Messages"), (
        f"the rejected empty-body send appears to have landed anyway: {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
