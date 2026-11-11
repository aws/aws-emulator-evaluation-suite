"""list-shards-stream-creation-timestamp-mismatch-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")


CHECK = "list-shards-stream-creation-timestamp-mismatch-rejected"
GROUP = 'error-semantics'
SERVICES = ['kinesis']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListShards rejects a StreamCreationTimestamp that does not match the stream's creation time.

    The real timestamp from DescribeStreamSummary, or none at all, is accepted for the same name."""
    c = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=1)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)

    real_timestamp = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamCreationTimestamp"]

    # Positive control: the stream's own, real creation timestamp is accepted.
    accepted = c.list_shards(StreamName=name, StreamCreationTimestamp=real_timestamp)
    assert accepted["Shards"], (
        f"ListShards(StreamName={name!r}, StreamCreationTimestamp=<the real value>) must "
        f"succeed and return shards, got {accepted!r}"
    )

    # Negative: a timestamp a full day earlier cannot be this stream's real creation time.
    wrong_timestamp = real_timestamp - datetime.timedelta(days=1)
    code, message = _error(
        lambda: c.list_shards(StreamName=name, StreamCreationTimestamp=wrong_timestamp)
    )
    assert code == "ResourceNotFoundException", (
        f"ListShards with a StreamCreationTimestamp that does not match {name!r}'s real "
        f"creation time must fail ResourceNotFoundException (no stream named {name!r} was "
        f"created at that time), got {code!r}: {message!r}"
    )
    expected_message = (
        f"Stream {name} under account {ctx.account} with creation time "
        f"{wrong_timestamp.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} not found."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent / no corruption: the real timestamp is still accepted afterward.
    still_accepted = c.list_shards(StreamName=name, StreamCreationTimestamp=real_timestamp)
    assert still_accepted["Shards"], (
        f"ListShards with the real StreamCreationTimestamp stopped succeeding after the "
        f"mismatched call was refused: {still_accepted!r}"
    )

    # Control: StreamCreationTimestamp is optional disambiguation, not a requirement.
    unqualified = c.list_shards(StreamName=name)
    assert unqualified["Shards"], f"plain ListShards(StreamName={name!r}) must still succeed, got {unqualified!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
