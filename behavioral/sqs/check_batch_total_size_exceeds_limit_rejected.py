"""batch-total-size-exceeds-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-total-size-exceeds-limit-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# The aggregate limit for one SendMessageBatch is the queue's MaximumMessageSize (a new queue
# reports 1048576), so it is read off the queue; this is only the documented floor.
MIN_PLAUSIBLE_LIMIT = 262144
# awsQueryCompatible code for BatchRequestTooLong, which botocore surfaces as Error.Code.
ERR_BATCH_TOO_LONG = "AWS.SimpleQueueService.BatchRequestTooLong"


def _poll(fn, pred, *, timeout_s, interval_s=0.5):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; raise if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("expected the call to be refused with an error, but it succeeded")


def _drain(sqs, url, *, timeout_s):
    """Receive-and-delete every distinct message inside timeout_s; returns their sizes."""
    seen, sizes = set(), []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for msg in resp.get("Messages", []):
            if msg["MessageId"] not in seen:
                seen.add(msg["MessageId"])
                sizes.append(len(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return sizes


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SendMessageBatch of individually legal entries whose total exceeds MaximumMessageSize is
    refused with BatchRequestTooLong and enqueues nothing; the same entries split in two succeed.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real:managed": "true", "sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    drain_s = 15
    # Negative window: poll for a violation to APPEAR. Kept short because the drain below
    # is the stronger absence evidence and this window is spent whether or not it fires.
    attr_s = 8

    limit = int(
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["MaximumMessageSize"])["Attributes"][
            "MaximumMessageSize"
        ]
    )
    assert limit >= MIN_PLAUSIBLE_LIMIT, (
        f"MaximumMessageSize={limit} is below the smallest bound SQS documents "
        f"({MIN_PLAUSIBLE_LIMIT}); the queue attribute cannot be trusted as the batch bound"
    )

    # Four entries at limit//3 + 1: each is individually legal (a third of the limit), their sum
    # (~4/3 of the limit) is not.
    entry_bytes = limit // 3 + 1
    assert entry_bytes < limit, "test entry must be individually legal"
    over = [
        {"Id": f"big-{i}", "MessageBody": chr(ord("a") + i) * entry_bytes}
        for i in range(4)
    ]
    total_bytes = sum(len(e["MessageBody"]) for e in over)
    assert total_bytes > limit, "batch must exceed the limit"

    code, message = _err(lambda: sqs.send_message_batch(QueueUrl=url, Entries=over))
    assert code == ERR_BATCH_TOO_LONG, (
        f"expected {ERR_BATCH_TOO_LONG} for a {total_bytes}-byte batch of 4 individually-legal "
        f"{entry_bytes}-byte entries, got {code!r} ({message!r})"
    )
    # The refusal names the bound it enforced and the size it measured, so a BatchRequestTooLong
    # raised for some other reason (or against a different, hardcoded limit) cannot satisfy it.
    expected_message = (
        f"Batch requests cannot be longer than {limit} bytes. You have sent {total_bytes} bytes."
    )
    assert message == expected_message, (
        f"expected refusal message {expected_message!r}, got {message!r}"
    )

    # All-or-nothing: none of the four entries enqueued.
    depth = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: v != "0",
        timeout_s=attr_s,
    )
    assert depth == "0", f"rejected batch enqueued something: ApproximateNumberOfMessages={depth}"
    leaked = _drain(sqs, url, timeout_s=drain_s)
    assert leaked == [], f"rejected batch delivered {len(leaked)} message(s) of sizes {leaked}"

    # The same entries, split so each request is under the limit, succeed.
    for half in (over[:2], over[2:]):
        resp = sqs.send_message_batch(QueueUrl=url, Entries=half)
        assert not resp.get("Failed"), f"split batch failed: {resp.get('Failed')}"
        assert {e["Id"] for e in resp["Successful"]} == {e["Id"] for e in half}, (
            f"split batch Successful Ids {sorted(e['Id'] for e in resp['Successful'])}"
        )
    sizes = _drain(sqs, url, timeout_s=drain_s)
    assert sorted(sizes) == [entry_bytes] * 4, (
        f"expected 4 messages of {entry_bytes} bytes after the split sends, got {sorted(sizes)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
