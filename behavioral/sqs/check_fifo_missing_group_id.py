"""fifo-missing-group-id."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fifo-missing-group-id"
GROUP = 'errors'
SERVICES = ['sqs']

ERR_MISSING_PARAMETER = "MissingParameter"

@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage to a FIFO queue without MessageGroupId is rejected; with it, it lands."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        tags={"sim2real": "true", "check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    control_body = "control-has-group-id"
    control = sqs.send_message(QueueUrl=url, MessageBody=control_body, MessageGroupId="control-group")
    assert control.get("MessageId"), (
        f"positive control SendMessage WITH MessageGroupId must succeed, got {control!r} "
        f"(otherwise a target that rejects every FIFO SendMessage would also pass this check)"
    )

    try:
        sqs.send_message(QueueUrl=url, MessageBody="no-group")
        code = None
    except ClientError as exc:
        code = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
    assert code == (ERR_MISSING_PARAMETER, "The request must contain the parameter MessageGroupId."), (
        f"expected {ERR_MISSING_PARAMETER}, got {code!r} "
        f"(FIFO send without MessageGroupId must be rejected)"
    )

    received: list[dict] = []
    for _ in range(6):
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        received.extend(resp.get("Messages", []))
        if received:
            break
    bodies = [m["Body"] for m in received]
    assert bodies == [control_body], (
        f"expected only the positive control message {control_body!r} to have landed in the "
        f"queue, got {bodies!r} (the rejected SendMessage without MessageGroupId must never "
        f"be enqueued, checked via an independent ReceiveMessage)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
