"""delete-stream-with-active-consumer-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stream-with-active-consumer-blocked"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStream on a stream with a registered enhanced fan-out consumer fails with ResourceInUseException
    (HTTP 400, exact message) and the stream stays ACTIVE; once the consumer is deregistered, the same delete
    succeeds and the stream is gone from DescribeStreamSummary and ListStreams."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinstrm-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, name))
    _wait_stream_status(ctx, name, {"ACTIVE"}, timeout_s=180)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

    consumer_name = ctx.unique_name("sim2real-kincons-")
    kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    _wait_consumer_status(ctx, stream_arn, consumer_name, {"ACTIVE"}, timeout_s=180)

    # --- Negative: plain DeleteStream is blocked while the consumer is still registered. ---
    code, message, status = _error_code(lambda: kinesis.delete_stream(StreamName=name))
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    assert status == 400, f"expected HTTP 400 for the blocked delete, got {status!r}"
    expected_message = f"DeleteStream can’t delete {ctx.account}:{name} because there are consumers associated with this data stream. To delete {name} anyway, set the EnforceConsumerDeletion parameter to true to force the deletion of all the consumers that are associated with it."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Effect absent: the stream is still there, describable, ACTIVE.
    status_after = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
    assert status_after == "ACTIVE", f"expected stream to remain ACTIVE after blocked delete, got {status_after}"

    # --- Restore: deregister the consumer and prove it gone (read, listing, mutation). ---
    kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    deadline = time.monotonic() + 180
    gone = None
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
        except ClientError as e:
            gone = (e.response["Error"]["Code"], e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
            gone_message = e.response["Error"].get("Message")
            if gone[0] == "ResourceNotFoundException":
                break
            raise
        time.sleep(3)
    assert gone == ("ResourceNotFoundException", 400), (
        f"expected the deregistered consumer to read ResourceNotFoundException/400, got {gone}"
    )
    expected_message = f"Consumer {consumer_name} under stream: {name}, account {ctx.account} not found."
    assert gone_message == expected_message, f"expected the message {expected_message!r}, got {gone_message!r}"
    consumers = [
        c["ConsumerName"]
        for page in kinesis.get_paginator("list_stream_consumers").paginate(StreamARN=stream_arn)
        for c in page.get("Consumers", [])
    ]
    assert consumer_name not in consumers, (
        f"expected {consumer_name!r} absent from ListStreamConsumers after deregistration, got {consumers!r}"
    )
    rereg_code, message, rereg_status = _error_code(
        lambda: kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    )
    assert (rereg_code, rereg_status) == ("ResourceNotFoundException", 400), (
        f"expected DeregisterStreamConsumer on the gone consumer to fail ResourceNotFoundException/400, "
        f"got {rereg_code}/{rereg_status}"
    )
    expected_message = f"Consumer {consumer_name} under stream: {name}, account {ctx.account} not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # --- The identical plain DeleteStream succeeds, and the stream is gone. ---
    kinesis.delete_stream(StreamName=name)
    deadline = time.monotonic() + 180
    final = None
    while time.monotonic() < deadline:
        final = _describe_outcome(kinesis, name)
        if final[0] == "ResourceNotFoundException":
            break
        time.sleep(3)
    assert final[0] == "ResourceNotFoundException", f"expected stream removed, got {final}"
    assert final[2] == 400, f"expected HTTP 400 for the not-found read, got {final[2]!r}"
    expected_message = f"Stream {name} under account {ctx.account} not found."
    assert final[1] == expected_message, f"expected the message {expected_message!r}, got {final[1]!r}"

    listed = [
        n
        for page in kinesis.get_paginator("list_streams").paginate()
        for n in page.get("StreamNames", [])
    ]
    assert name not in listed, f"expected {name!r} absent from ListStreams after delete, got {listed!r}"

    # Deletes prove gone AND unusable: a further mutation against the dead stream must also
    # fail with the same specific not-found code, not silently no-op or resurrect it.
    redelete_code, redelete_message, redelete_status = _error_code(
        lambda: kinesis.delete_stream(StreamName=name)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected DeleteStream on an already-deleted stream to fail with ResourceNotFoundException, "
        f"got {redelete_code}"
    )
    assert redelete_status == 400, f"expected HTTP 400 for the re-delete, got {redelete_status!r}"
    expected_message = f"Stream {name} under account {ctx.account} not found."
    assert redelete_message == expected_message, f"expected the message {expected_message!r}, got {redelete_message!r}"


def _error_code(fn):
    """Call fn(); return (code, message, HTTP status) of its ClientError. An unexpected success
    raises."""
    try:
        result = fn()
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"].get("Message"),
                e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _describe_outcome(kinesis, name: str):
    """(code, message, HTTP status) of DescribeStreamSummary's error, or ("OK", status, None)
    while the stream exists."""
    try:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"].get("Message"),
                e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    return "OK", status, None


def _delete_stream_ignore_missing(ctx, name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_status(ctx, name: str, target_statuses, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"stream {name} did not reach {target_statuses} in {timeout_s}s (last={status})")


def _wait_consumer_status(ctx, stream_arn: str, consumer_name: str, target_statuses, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )["ConsumerDescription"]["ConsumerStatus"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"consumer {consumer_name} did not reach {target_statuses} in {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

