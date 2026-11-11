"""op-visibility-timeout-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-visibility-timeout-out-of-range-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Exact messages real SQS returns for these refusals.
MSG_HIGH = 'Value 43201 for parameter VisibilityTimeout is invalid. Reason: VisibilityTimeout must be an integer between 0 and 43200.'
MSG_NEG = 'Value -1 for parameter VisibilityTimeout is invalid. Reason: VisibilityTimeout must be an integer between 0 and 43200.'


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VisibilityTimeout above the 12-hour maximum must be rejected, not silently clamped."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.send_message(QueueUrl=url, MessageBody="range-test")
    msgs = _receive_messages(sqs, url, min_count=1, max_batch=1, attempts=20)
    assert msgs, "message never became visible"
    handle = msgs[0]["ReceiptHandle"]

    err = _client_error(
        lambda: sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=handle, VisibilityTimeout=43201)
    )
    assert err.get("Code") == "InvalidParameterValue", f"expected InvalidParameterValue for VisibilityTimeout=43201, got {err!r}"
    assert err.get("Message") == MSG_HIGH, f"got {err!r}"

    err_neg = _client_error(
        lambda: sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=handle, VisibilityTimeout=-1)
    )
    assert err_neg.get("Code") == "InvalidParameterValue", f"expected InvalidParameterValue for VisibilityTimeout=-1, got {err_neg!r}"
    assert err_neg.get("Message") == MSG_NEG, f"got {err_neg!r}"

    # Positive control: an in-range value is accepted, and the effect is confirmed by an
    # independent read (a fresh receive), not just the mutating call's own 200.
    sqs.change_message_visibility(QueueUrl=url, ReceiptHandle=handle, VisibilityTimeout=0)
    redelivered = _receive_messages(sqs, url, min_count=1, max_batch=1, attempts=10)
    assert redelivered, "VisibilityTimeout=0 must make the message immediately receivable again"
    assert redelivered[0]["MessageId"] == msgs[0]["MessageId"], (
        f"expected the same message {msgs[0]['MessageId']!r} to reappear, "
        f"got {redelivered[0]['MessageId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
