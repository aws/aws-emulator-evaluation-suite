"""op-receive-message-param-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-receive-message-param-bounds-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Exact messages real SQS returns for these refusals.
MSG_MAX = 'Value 11 for parameter MaxNumberOfMessages is invalid. Reason: Must be between 1 and 10, if provided.'
MSG_WAIT = 'Value 21 for parameter WaitTimeSeconds is invalid. Reason: Must be >= 0 and <= 20, if provided.'


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReceiveMessage must reject MaxNumberOfMessages > 10 and WaitTimeSeconds > 20, while a
    well-formed call on the same queue keeps working before and after."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    def _well_formed_receive_works():
        sqs.send_message(QueueUrl=url, MessageBody="bounds-control")
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
        assert msgs, "well-formed ReceiveMessage returned no messages"

    # positive control: this queue and this API accept a well-formed call before we test the bound
    _well_formed_receive_works()

    err_max = _client_error(lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=11))
    assert err_max.get("Code") == "InvalidParameterValue", f"got {err_max!r}"
    assert err_max.get("Message") == MSG_MAX, f"got {err_max!r}"

    err_wait = _client_error(lambda: sqs.receive_message(QueueUrl=url, WaitTimeSeconds=21))
    assert err_wait.get("Code") == "InvalidParameterValue", f"got {err_wait!r}"
    assert err_wait.get("Message") == MSG_WAIT, f"got {err_wait!r}"

    # the rejections are specific to the out-of-bounds input, not a queue left broken by them
    _well_formed_receive_works()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
