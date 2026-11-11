"""operations-fail-after-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "operations-fail-after-delete"
GROUP = 'errors'
SERVICES = ['sqs']

QUEUE_NOT_FOUND = "AWS.SimpleQueueService.NonExistentQueue"

# Exact messages real SQS returns for these refusals.
MSG_NOT_FOUND = 'The specified queue does not exist.'

_TAGS = {"sim2real:managed": "true", "sim2real": "operations-fail-after-delete"}


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


def _safe_delete(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _send_until_rejected(sqs, url, *, timeout_s, interval_s):
    """Send until the deleted queue refuses the call; return that Error dict. Sends that still
    succeed inside the propagation window are retried; the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sqs.send_message(QueueUrl=url, MessageBody="x")
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == QUEUE_NOT_FOUND:
                return err
            raise AssertionError(f"expected {QUEUE_NOT_FOUND}, got {err!r}") from exc
        if time.monotonic() >= deadline:
            raise AssertionError(f"SendMessage still succeeded {timeout_s}s after DeleteQueue")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """After DeleteQueue, subsequent data-plane and control-plane calls fail with QueueDoesNotExist."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_delete(sqs, url))

    # Positive control: the queue accepts a message while it still exists, so a target that
    # rejects every send_message call cannot pass merely by always answering QueueDoesNotExist.
    control = sqs.send_message(QueueUrl=url, MessageBody="control")
    assert control.get("MessageId"), f"positive control send_message returned no MessageId: {control}"

    sqs.delete_queue(QueueUrl=url)

    # DeleteQueue propagation is documented to take up to 60s; the poll ceiling covers it.
    err = _send_until_rejected(sqs, url, timeout_s=240, interval_s=10)
    assert err.get("Message") == MSG_NOT_FOUND, f"got {err!r}"

    # Independent read, at the destination, through a different operation than any of the above.
    err_read = _client_error(lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]))
    assert err_read.get("Code") == QUEUE_NOT_FOUND, f"expected {QUEUE_NOT_FOUND}, got {err_read!r}"
    assert err_read.get("Message") == MSG_NOT_FOUND, f"got {err_read!r}"

    err_delete = _client_error(lambda: sqs.delete_queue(QueueUrl=url))
    assert err_delete.get("Code") == QUEUE_NOT_FOUND, f"expected {QUEUE_NOT_FOUND}, got {err_delete!r}"
    assert err_delete.get("Message") == MSG_NOT_FOUND, f"got {err_delete!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
