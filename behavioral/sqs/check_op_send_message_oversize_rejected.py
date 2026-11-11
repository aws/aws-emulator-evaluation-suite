"""op-send-message-oversize-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-send-message-oversize-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Exact messages real SQS returns for these refusals.
MSG_OVERSIZE = 'One or more parameters are invalid. Reason: Message must be shorter than 1024 bytes.'


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage rejects a body larger than MaximumMessageSize rather than truncating it; an
    in-bounds body on the same queue enqueues and reads back first as a positive control."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        Attributes={"MaximumMessageSize": "1024"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # --- positive control: an in-bounds body on this exact queue enqueues and reads back ---
    control_body = "c" * 100
    sqs.send_message(QueueUrl=url, MessageBody=control_body)
    control_msgs = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5
    ).get("Messages", [])
    assert len(control_msgs) == 1 and control_msgs[0]["Body"] == control_body, (
        f"positive control failed: expected one message with body {control_body!r}, "
        f"got {control_msgs}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=control_msgs[0]["ReceiptHandle"])

    # --- break: a body over MaximumMessageSize on the SAME queue is refused, not truncated ---
    err = _client_error(lambda: sqs.send_message(QueueUrl=url, MessageBody="a" * 2048))
    assert err.get("Code") == "InvalidParameterValue", f"got {err!r}"
    assert err.get("Message") == MSG_OVERSIZE, f"got {err!r}"

    msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
    assert msgs == [], f"oversized body was accepted anyway: {msgs}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
