"""op-delay-seconds-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-delay-seconds-out-of-range-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_DELAY_OUT_OF_RANGE_MESSAGE = (
    "Value 901 for parameter DelaySeconds is invalid. Reason: DelaySeconds must be >= 0 and <= 900."
)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected DelaySeconds=901 to be rejected, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage DelaySeconds above the 900s maximum must be rejected, not clamped."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # positive control: the boundary value itself (900s, the documented maximum) must be
    # accepted, so a rejection below can only mean "out of range", not "every DelaySeconds fails"
    try:
        ok_id = sqs.send_message(QueueUrl=url, MessageBody="boundary-ok", DelaySeconds=900)["MessageId"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        raise AssertionError(f"DelaySeconds=900 (the documented maximum) must be accepted, got {code}") from exc
    assert ok_id, "SendMessage at the boundary did not return a MessageId"

    error = _client_error(lambda: sqs.send_message(QueueUrl=url, MessageBody="x", DelaySeconds=901))
    assert error.get("Code") == "InvalidParameterValue", f"got {error.get('Code')}"
    assert error.get("Message") == _DELAY_OUT_OF_RANGE_MESSAGE, (
        f"expected message {_DELAY_OUT_OF_RANGE_MESSAGE!r}, got {error.get('Message')!r}"
    )

    # the rejection must not have enqueued anything (the boundary-ok message is still delayed
    # 900s, so it cannot appear here either -- this reads only what DelaySeconds=901 caused)
    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert msgs == [], f"rejected send still enqueued a message: {msgs}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
