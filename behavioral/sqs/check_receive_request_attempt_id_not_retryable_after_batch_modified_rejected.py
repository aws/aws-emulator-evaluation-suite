"""receive-request-attempt-id-not-retryable-after-batch-modified-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receive-request-attempt-id-not-retryable-after-batch-modified-rejected"
GROUP = 'fifo'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "rraid-not-retryable"}


def _error(fn):
    """(code, message) of the refusal ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _not_retryable(attempt: str) -> str:
    return (f"Value {attempt} for parameter ReceiveRequestAttemptId is invalid. Reason: The "
            f"receiveRequestAttemptId is not valid anymore since the receive call is not "
            f"retryable.")


def _receive(sqs, url, attempt, wait_s=2):
    return sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
                               ReceiveRequestAttemptId=attempt).get("Messages", [])


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A FIFO retry with a ReceiveRequestAttemptId replays the batch until one of its messages is
    deleted or has its visibility changed; then it is refused as not retryable and hands out
    nothing, leaving the group's untouched in-flight messages locked."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "VisibilityTimeout": "120"}, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    bodies = [f"m{i}-{token}" for i in range(3)]
    for i, b in enumerate(bodies):
        sqs.send_message(QueueUrl=url, MessageBody=b, MessageGroupId="g",
                         MessageDeduplicationId=f"{token}-{i}")

    # Wait until all three are on the queue, so one receive can take them as one batch.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"][
            "ApproximateNumberOfMessages"] != "3":
        time.sleep(1)

    # --- leg 1: modification by DeleteMessage ------------------------------------------
    attempt_a = f"attempt-a-{token}"
    batch = []
    deadline = time.monotonic() + 30
    while not batch and time.monotonic() < deadline:
        batch = _receive(sqs, url, attempt_a)
    assert [m["Body"] for m in batch] == bodies[:len(batch)] and len(batch) >= 2, (
        f"expected a send-order batch of at least two of {bodies!r}, got "
        f"{[m['Body'] for m in batch]!r}")
    replay = _receive(sqs, url, attempt_a)
    assert [m["MessageId"] for m in replay] == [m["MessageId"] for m in batch], (
        f"positive control: an unmodified batch must replay under its attempt id, got "
        f"{[m['Body'] for m in replay]!r}")
    victim = replay[0]
    sqs.delete_message(QueueUrl=url, ReceiptHandle=victim["ReceiptHandle"])

    code, msg = _error(lambda: _receive(sqs, url, attempt_a))
    assert (code, msg) == ("InvalidParameterValue", _not_retryable(attempt_a)), (
        f"retrying a batch after one of its messages was deleted gave {(code, msg)!r}")

    # Nothing was handed out by the refusal: the group is still locked by its in-flight messages.
    leaked = _receive(sqs, url, f"probe-{token}")
    assert leaked == [], (
        f"after the refused retry the group's in-flight messages must stay hidden: "
        f"{[m['Body'] for m in leaked]!r}")

    # --- leg 2: modification by ChangeMessageVisibility --------------------------------
    for m in replay[1:]:
        sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"],
                                      VisibilityTimeout=0)
    attempt_b = f"attempt-b-{token}"
    rest = []
    deadline = time.monotonic() + 30
    while not rest and time.monotonic() < deadline:
        rest = _receive(sqs, url, attempt_b)
    remaining = [b for b in bodies if b != victim["Body"]]
    assert [m["Body"] for m in rest] == remaining[:len(rest)] and rest, (
        f"after releasing the in-flight messages the group must resume in order at "
        f"{remaining!r}, got {[m['Body'] for m in rest]!r}")
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=rest[0]["ReceiptHandle"],
                                  VisibilityTimeout=60)
    code, msg = _error(lambda: _receive(sqs, url, attempt_b))
    assert (code, msg) == ("InvalidParameterValue", _not_retryable(attempt_b)), (
        f"retrying a batch after one of its messages had its visibility changed gave "
        f"{(code, msg)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
