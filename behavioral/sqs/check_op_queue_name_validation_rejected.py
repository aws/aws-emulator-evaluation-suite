"""op-queue-name-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-queue-name-validation-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Exact messages real SQS returns for these refusals.
MSG_NAME = 'Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length'
MSG_SUFFIX = 'The name of a FIFO queue can only include alphanumeric characters, hyphens, or underscores, must end with .fifo suffix and be 1 to 80 in length.'


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQueue must reject illegal queue names and FIFO/suffix mismatches, but accept a valid one."""
    sqs = ctx.client("sqs")

    ok_name = ctx.unique_name("sim2real-behav-name-ok-")
    ok_url = sqs.create_queue(QueueName=ok_name, tags={"sim2real-audit": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=ok_url))
    looked_up = sqs.get_queue_url(QueueName=ok_name)["QueueUrl"]
    assert looked_up == ok_url, f"positive control: valid queue name not visible via GetQueueUrl: {looked_up}"

    bad_char_name = ctx.unique_name("sim2real-behav-bad!name-")
    err_chars = _client_error(lambda: sqs.create_queue(QueueName=bad_char_name))
    assert err_chars.get("Code") == "InvalidParameterValue", f"got {err_chars!r}"
    assert err_chars.get("Message") == MSG_NAME, f"got {err_chars!r}"

    fifo_no_suffix = ctx.unique_name("sim2real-behav-nofifo-")
    err_suffix = _client_error(
        lambda: sqs.create_queue(QueueName=fifo_no_suffix, Attributes={"FifoQueue": "true"})
    )
    assert err_suffix.get("Code") == "InvalidParameterValue", f"got {err_suffix!r}"
    assert err_suffix.get("Message") == MSG_SUFFIX, f"got {err_suffix!r}"

    too_long = "sim2real-behav-" + ("z" * 100)
    err_long = _client_error(lambda: sqs.create_queue(QueueName=too_long))
    assert err_long.get("Code") == "InvalidParameterValue", f"got {err_long!r}"
    assert err_long.get("Message") == MSG_NAME, f"got {err_long!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
