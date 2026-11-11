"""change-message-visibility-expired-handle-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-message-visibility-expired-handle-accepted"
GROUP = 'visibility_dlq'
SERVICES = ['sqs']


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)
        val = fn()
    return val


def _receive_messages(sqs, url, *, min_count, max_batch=10, attempts=15):
    received = []
    _seen = set()
    _idle = 0
    for _ in range(attempts):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_batch, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if received and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                received.append(_m)
        if len(received) >= min_count:
            break
    return received


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A receipt handle whose visibility window lapsed stays valid: ChangeMessageVisibility with it
    re-hides the message rather than failing with MessageNotInflight, and it can release it again.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), Attributes={"VisibilityTimeout": "1"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    sqs.send_message(QueueUrl=url, MessageBody="expiring")
    first = _receive_messages(sqs, url, min_count=1, max_batch=1, attempts=20)
    assert first, "message never became visible"
    stale_handle = first[0]["ReceiptHandle"]

    # observe the 1s visibility window lapse service-natively: the in-flight counter returns
    # to zero without any consuming receive.
    _poll(
        lambda: int(
            sqs.get_queue_attributes(
                QueueUrl=url, AttributeNames=["ApproximateNumberOfMessagesNotVisible"]
            )["Attributes"].get("ApproximateNumberOfMessagesNotVisible", "0")
        ),
        lambda n: n == 0,
        timeout_s=90,
        interval_s=3,
    )

    # the lapsed handle is still accepted and must re-hide the message
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=stale_handle, VisibilityTimeout=120)

    hidden = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3).get("Messages", [])
    assert hidden == [], "message stayed visible after re-hiding it with the lapsed receipt handle"

    # and the same handle can release it again
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=stale_handle, VisibilityTimeout=0)
    released = _receive_messages(sqs, url, min_count=1, max_batch=1, attempts=30)
    assert released and released[0]["Body"] == "expiring", "released message body mismatch"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
