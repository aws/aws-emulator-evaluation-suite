"""standard-queue-message-group-id-validated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "standard-queue-message-group-id-validated"
GROUP = "fair-queues"
SERVICES = ["sqs"]

_REASON = "MessageGroupId can only include alphanumeric and punctuation characters. 1 to 128 in length."


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises too, naming what came
    back: a malformed group id that is accepted must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A MessageGroupId on a standard queue must be 1 to 128 alphanumeric/punctuation characters:
    128 characters and punctuation are accepted and surface verbatim on receive; 129 characters,
    an empty id and a space are refused, and nothing refused is enqueued."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-fairval-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    accepted = {"max-length": "g" * 128, "punctuation": "tenant:a/b-c_d.e!"}
    for body, group in accepted.items():
        try:
            sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId=group)
        except ClientError as exc:
            raise AssertionError(
                f"{body}: MessageGroupId {group!r} must be accepted on a standard queue, got "
                f"{exc.response['Error']!r}"
            ) from exc

    for label, group in (("too-long", "g" * 129), ("empty", ""), ("space", "tenant a")):
        err = _error(
            lambda group=group, label=label: sqs.send_message(
                QueueUrl=url, MessageBody=f"refused-{label}", MessageGroupId=group
            )
        )
        want = f"Value {group} for parameter MessageGroupId is invalid. Reason: {_REASON}"
        assert err.get("Code") == "InvalidParameterValue", (
            f"{label}: MessageGroupId of length {len(group)} gave code {err.get('Code')!r}"
        )
        assert err.get("Message") == want, (
            f"{label}: expected message {want!r}, got {err.get('Message')!r}"
        )

    seen: dict[str, str | None] = {}
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
            MessageSystemAttributeNames=["MessageGroupId"],
        ).get("Messages", [])
        if not msgs and len(seen) >= len(accepted):
            break
        for m in msgs:
            seen[m["Body"]] = m.get("Attributes", {}).get("MessageGroupId")
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    assert seen == accepted, (
        f"the queue must hold exactly the accepted messages with their group ids verbatim; "
        f"received {seen!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
